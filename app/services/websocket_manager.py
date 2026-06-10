"""
WebSocket Manager for Real-Time Dashboard Updates

This module provides WebSocket functionality for:
- Live scan updates
- Real-time threat alerts
- Dashboard statistics streaming
- Connection management
"""
import json
import traceback
import uuid
import asyncio
from datetime import datetime
from typing import Dict, Set, Optional, Callable, Any
from dataclasses import dataclass, field
from enum import Enum
import structlog

logger = structlog.get_logger(__name__)

REDIS_EVENTS_CHANNEL = "phishguard:scan_events"


class WebSocketEventType(str, Enum):
    """WebSocket event types."""
    SCAN_STARTED = "scan:started"
    SCAN_PROGRESS = "scan:progress"
    SCAN_COMPLETED = "scan:completed"
    THREAT_DETECTED = "threat:detected"
    ALERT_TRIGGERED = "alert:triggered"
    STATS_UPDATE = "stats:update"
    CONNECTION_ACK = "connection:ack"
    ERROR = "error"
    HEARTBEAT = "heartbeat"
    SUBSCRIBE = "subscribe"
    UNSUBSCRIBE = "unsubscribe"


@dataclass
class WebSocketMessage:
    """Standard WebSocket message format."""
    event: str
    data: Dict[str, Any]
    metadata: Dict[str, str] = field(default_factory=lambda: {
        "version": "1.0",
        "message_id": str(uuid.uuid4())
    })
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps({
            "event": self.event,
            "data": self.data,
            "metadata": self.metadata
        })
    
    @classmethod
    def from_json(cls, json_str: str) -> 'WebSocketMessage':
        """Create from JSON string."""
        data = json.loads(json_str)
        return cls(
            event=data.get("event", ""),
            data=data.get("data", {}),
            metadata=data.get("metadata", {})
        )


@dataclass
class ClientConnection:
    """Represents a connected WebSocket client."""
    client_id: str
    websocket: Any
    channels: Set[str] = field(default_factory=set)
    authenticated: bool = False
    user_id: Optional[str] = None
    connected_at: datetime = field(default_factory=datetime.utcnow)
    last_heartbeat: datetime = field(default_factory=datetime.utcnow)
    
    def is_expired(self, timeout_seconds: int = 60) -> bool:
        """Check if connection has expired."""
        delta = datetime.utcnow() - self.last_heartbeat
        return delta.total_seconds() > timeout_seconds


class WebSocketManager:
    """
    Manages WebSocket connections and message broadcasting.
    
    Features:
    - Connection pooling
    - Channel-based subscriptions
    - Heartbeat monitoring
    - Auto-reconnection support
    - Message queuing for offline clients
    """
    
    def __init__(self):
        self.clients: Dict[str, ClientConnection] = {}
        self.channels: Dict[str, Set[str]] = {}  # channel_name -> set of client_ids
        self.message_queue: asyncio.Queue = asyncio.Queue()
        self.running = False
        self._heartbeat_task: Optional[asyncio.Task] = None
        self._queue_processor_task: Optional[asyncio.Task] = None
        
        # Callbacks for external integration
        self.on_client_connect: Optional[Callable] = None
        self.on_client_disconnect: Optional[Callable] = None
        self.on_message_received: Optional[Callable] = None
        
        # Statistics
        self.stats = {
            "total_connections": 0,
            "messages_sent": 0,
            "messages_received": 0,
            "errors": 0
        }
        self._redis_pubsub = None
        self._redis_subscriber_task: Optional[asyncio.Task] = None

        logger.info("WebSocketManager initialized")
    
    async def start(self):
        """Start the WebSocket manager."""
        print("DEBUG: WS_MANAGER_START_ENTERED", "id:", id(self))
        self.running = True
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        self._queue_processor_task = asyncio.create_task(self._process_queue())
        print("DEBUG: CREATING_REDIS_SUBSCRIBER")
        self._redis_subscriber_task = asyncio.create_task(self._redis_event_subscriber())
        print("DEBUG: REDIS_SUBSCRIBER_TASK_CREATED")
        logger.info("WebSocketManager started")
    
    async def stop(self):
        """Stop the WebSocket manager."""
        self.running = False
        
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass
        
        if self._queue_processor_task:
            self._queue_processor_task.cancel()
            try:
                await self._queue_processor_task
            except asyncio.CancelledError:
                pass
        
        if self._redis_subscriber_task:
            self._redis_subscriber_task.cancel()
            try:
                await self._redis_subscriber_task
            except asyncio.CancelledError:
                pass
        
        if self._redis_pubsub:
            try:
                await self._redis_pubsub.close()
            except Exception:
                pass
        
        # Close all connections
        for client in list(self.clients.values()):
            await self.disconnect(client.websocket)
        
        logger.info("WebSocketManager stopped")
    
    async def connect(self, websocket, client_id: Optional[str] = None) -> str:
        """
        Register a new WebSocket connection.
        
        Args:
            websocket: The WebSocket connection
            client_id: Optional client ID (generated if not provided)
            
        Returns:
            The client ID
        """
        if client_id is None:
            client_id = str(uuid.uuid4())
        
        client = ClientConnection(
            client_id=client_id,
            websocket=websocket,
            channels={"global", "scans", "stats"}  # Default channels
        )
        
        self.clients[client_id] = client
        self.stats["total_connections"] += 1
        
        # Add to default channels
        for ch in ("global", "scans", "stats"):
            if ch not in self.channels:
                self.channels[ch] = set()
            self.channels[ch].add(client_id)
        
        # Send connection acknowledgment
        ack_message = WebSocketMessage(
            event=WebSocketEventType.CONNECTION_ACK.value,
            data={
                "client_id": client_id,
                "message": "Connected to PhishGuard Real-Time Stream",
                "channels": list(client.channels),
                "heartbeat_interval": 30
            }
        )
        await self.send_personal_message(ack_message, websocket)
        
        logger.info("Client connected", client_id=client_id, total=len(self.clients))
        
        if self.on_client_connect:
            await self.on_client_connect(client_id)
        
        return client_id
    
    async def disconnect(self, websocket):
        """Disconnect a WebSocket client."""
        # Find client by websocket
        client_to_remove = None
        for client_id, client in self.clients.items():
            if client.websocket == websocket:
                client_to_remove = client_id
                break
        
        if client_to_remove:
            client = self.clients.pop(client_to_remove)
            
            # Remove from all channels
            for channel in client.channels:
                if channel in self.channels:
                    self.channels[channel].discard(client_to_remove)
            
            logger.info("Client disconnected", 
                       client_id=client_to_remove, 
                       remaining=len(self.clients))
            
            if self.on_client_disconnect:
                await self.on_client_disconnect(client_to_remove)
    
    async def send_personal_message(self, message: WebSocketMessage, websocket):
        """Send message to a specific client."""
        try:
            await websocket.send_text(message.to_json())
            self.stats["messages_sent"] += 1
        except Exception as e:
            logger.error("Error sending personal message", error=str(e))
            self.stats["errors"] += 1
    
    async def broadcast(self, message: WebSocketMessage, channel: Optional[str] = None):
        """
        Broadcast message to all connected clients or a specific channel.
        
        Args:
            message: The message to broadcast
            channel: Optional channel name (broadcasts to all if not specified)
        """
        if channel:
            # Send to specific channel
            client_ids = self.channels.get(channel, set())
        else:
            # Send to all clients
            client_ids = set(self.clients.keys())
        
        logger.info("WS channel subscribers",
                    channel=channel,
                    subscriber_count=len(client_ids))

        disconnected_clients = []
        
        for client_id in client_ids:
            if client_id not in self.clients:
                continue
            
            client = self.clients[client_id]
            try:
                await client.websocket.send_text(message.to_json())
                self.stats["messages_sent"] += 1
            except Exception as e:
                logger.warning("Error broadcasting to client", 
                            client_id=client_id, 
                            error=str(e))
                disconnected_clients.append(client.websocket)
        
        # Clean up disconnected clients
        for ws in disconnected_clients:
            await self.disconnect(ws)
    
    async def broadcast_scan_started(self, scan_id: str, url: str, source: str = "api"):
        """Broadcast scan started event."""
        message = WebSocketMessage(
            event=WebSocketEventType.SCAN_STARTED.value,
            data={
                "scan_id": scan_id,
                "url": url,
                "source": source,
                "timestamp": datetime.utcnow().isoformat()
            }
        )
        await self.broadcast(message, "scans")
    
    async def broadcast_scan_progress(self, scan_id: str, progress: int, stage: str):
        """Broadcast scan progress update."""
        message = WebSocketMessage(
            event=WebSocketEventType.SCAN_PROGRESS.value,
            data={
                "scan_id": scan_id,
                "progress": progress,
                "stage": stage,
                "timestamp": datetime.utcnow().isoformat()
            }
        )
        await self.broadcast(message, "scans")
    
    async def broadcast_scan_completed(self, scan_id: str, result: Dict[str, Any]):
        """Broadcast scan completed event."""
        message = WebSocketMessage(
            event=WebSocketEventType.SCAN_COMPLETED.value,
            data={
                "scan_id": scan_id,
                "result": result,
                "timestamp": datetime.utcnow().isoformat()
            }
        )
        await self.broadcast(message, "scans")
    
    async def broadcast_threat_detected(self, threat: Dict[str, Any]):
        """Broadcast threat detected event."""
        message = WebSocketMessage(
            event=WebSocketEventType.THREAT_DETECTED.value,
            data={
                "threat": threat,
                "timestamp": datetime.utcnow().isoformat()
            }
        )
        await self.broadcast(message, "threats")
    
    async def broadcast_alert(self, alert: Dict[str, Any]):
        """Broadcast alert event."""
        message = WebSocketMessage(
            event=WebSocketEventType.ALERT_TRIGGERED.value,
            data={
                "alert": alert,
                "timestamp": datetime.utcnow().isoformat()
            }
        )
        await self.broadcast(message, "alerts")
    
    async def broadcast_stats_update(self, stats: Dict[str, Any]):
        """Broadcast statistics update."""
        message = WebSocketMessage(
            event=WebSocketEventType.STATS_UPDATE.value,
            data={
                "stats": stats,
                "timestamp": datetime.utcnow().isoformat()
            }
        )
        await self.broadcast(message, "stats")
    
    async def subscribe(self, client_id: str, channel: str):
        """Subscribe client to a channel."""
        if client_id in self.clients:
            self.clients[client_id].channels.add(channel)
            
            if channel not in self.channels:
                self.channels[channel] = set()
            self.channels[channel].add(client_id)
            
            logger.info("WS client subscribed", 
                       client_id=client_id, 
                       channel=channel,
                       subscribers=len(self.channels.get(channel, set())))
    
    async def unsubscribe(self, client_id: str, channel: str):
        """Unsubscribe client from a channel."""
        if client_id in self.clients:
            self.clients[client_id].channels.discard(channel)
            
            if channel in self.channels:
                self.channels[channel].discard(client_id)
            
            logger.info("Client unsubscribed from channel", 
                       client_id=client_id, 
                       channel=channel)
    
    async def _heartbeat_loop(self):
        """Send periodic heartbeats and clean up expired connections."""
        while self.running:
            try:
                await asyncio.sleep(30)  # Heartbeat every 30 seconds
                
                # Send heartbeat to all clients
                heartbeat = WebSocketMessage(
                    event=WebSocketEventType.HEARTBEAT.value,
                    data={"timestamp": datetime.utcnow().isoformat()}
                )
                
                # Clean up expired connections
                expired_clients = []
                for client_id, client in self.clients.items():
                    if client.is_expired():
                        expired_clients.append(client.websocket)
                
                for ws in expired_clients:
                    await self.disconnect(ws)
                
                if expired_clients:
                    logger.info("Cleaned up expired connections", count=len(expired_clients))
                    
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Heartbeat loop error", error=str(e))
    
    async def _process_queue(self):
        """Process queued messages."""
        while self.running:
            try:
                message = await asyncio.wait_for(
                    self.message_queue.get(), 
                    timeout=1.0
                )
                
                await self.broadcast(
                    message["message"], 
                    message.get("channel")
                )
                
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Queue processor error", error=str(e))
    
    async def _redis_event_subscriber(self):
        """Subscribe to Redis scan events and forward to WebSocket clients.
        Retries forever on connection errors.
        """
        print("DEBUG: REDIS_SUBSCRIBER_ENTERED")
        # Retry loop for Redis initialization
        while self.running:
            try:
                from app.services.redis import get_redis_client
                from app.config import settings
                print("SUBSCRIBE REDIS URL:", settings.REDIS_URL)
                redis = await get_redis_client()
                print("SUBSCRIBE REDIS CLIENT:", redis)
                self._redis_pubsub = redis.pubsub()
                await self._redis_pubsub.subscribe(REDIS_EVENTS_CHANNEL)
                print("DEBUG: REDIS_SUBSCRIBED", "channel:", REDIS_EVENTS_CHANNEL)
                logger.info("Redis event subscriber started",
                            channel=REDIS_EVENTS_CHANNEL)
                break
            except Exception as e:
                logger.warning("Redis subscriber init failed, retrying in 3s",
                               error=str(e),
                               traceback=traceback.format_exc())
                await asyncio.sleep(3)

        # Message loop
        while self.running:
            try:
                message = await self._redis_pubsub.get_message(
                    ignore_subscribe_messages=True,
                    timeout=1.0
                )
                if message is None:
                    continue
                if message["type"] not in ("message",):
                    continue

                data = json.loads(message["data"])
                print("REDIS_PAYLOAD:", data)
                event = data["event"]
                scan_id = data.get("scan_id", "")
                payload = data.get("data", {})

                logger.info("WS broadcast received from Redis",
                            redis_event=event, scan_id=scan_id,
                            payload_keys=list(payload.keys()))

                if event == "scan:processing":
                    ws_msg = WebSocketMessage(
                        event=WebSocketEventType.SCAN_PROGRESS.value,
                        data={
                            "scan_id": scan_id,
                            "progress": 50,
                            "stage": "processing",
                            "timestamp": datetime.utcnow().isoformat(),
                        },
                    )
                    print("ABOUT_TO_BROADCAST", event)
                    await self.broadcast(ws_msg, "scans")
                    logger.info("WS scan processing event emitted",
                                scan_id=scan_id)

                elif event == "scan:completed":
                    ws_msg = WebSocketMessage(
                        event=WebSocketEventType.SCAN_COMPLETED.value,
                        data={
                            "scan_id": scan_id,
                            "risk_score": payload.get("risk_score", 0),
                            "threat_level": payload.get("threat_level", "unknown"),
                            "processing_time_ms": payload.get("processing_time_ms", 0),
                            "timestamp": datetime.utcnow().isoformat(),
                        },
                    )
                    print("ABOUT_TO_BROADCAST", event)
                    await self.broadcast(ws_msg, "scans")
                    logger.info("WS scan completed event emitted",
                                scan_id=scan_id,
                                risk_score=payload.get("risk_score"),
                                threat_level=payload.get("threat_level"))

                elif event == "scan:failed":
                    ws_msg = WebSocketMessage(
                        event=WebSocketEventType.ERROR.value,
                        data={
                            "scan_id": scan_id,
                            "error": payload.get("error", "Scan processing failed"),
                            "timestamp": datetime.utcnow().isoformat(),
                        },
                    )
                    print("ABOUT_TO_BROADCAST", event)
                    await self.broadcast(ws_msg, "scans")
                    logger.info("WS scan failed event emitted",
                                scan_id=scan_id,
                                error=payload.get("error"))

                elif event == "threat:detected":
                    ws_msg = WebSocketMessage(
                        event=WebSocketEventType.THREAT_DETECTED.value,
                        data={
                            "threat": payload,
                            "timestamp": datetime.utcnow().isoformat(),
                        },
                    )
                    print("ABOUT_TO_BROADCAST", event)
                    await self.broadcast(ws_msg, "threats")
                    logger.info("WS threat detected event emitted",
                                scan_id=scan_id,
                                threat_type=payload.get("type"))

            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error("Redis subscriber error",
                             error=str(e),
                             traceback=traceback.format_exc())
                await asyncio.sleep(1)

    def get_connected_clients_count(self) -> int:
        """Get count of connected clients."""
        return len(self.clients)
    
    def get_channels(self) -> Dict[str, int]:
        """Get channel names and subscriber counts."""
        return {
            channel: len(clients) 
            for channel, clients in self.channels.items()
        }
    
    def get_stats(self) -> Dict[str, Any]:
        """Get WebSocket manager statistics."""
        return {
            **self.stats,
            "connected_clients": len(self.clients),
            "channels": self.get_channels()
        }


# Global WebSocket manager instance
ws_manager = WebSocketManager()


# WebSocket endpoint dependency
async def websocket_endpoint(websocket):
    """
    FastAPI WebSocket endpoint handler.
    
    Usage:
        from fastapi import WebSocket
        @app.websocket("/ws")
        await websocket_endpoint(websocket)
    """
    client_id = None
    try:
        # Accept connection
        await websocket.accept()
        print("WS_ENDPOINT WS_MANAGER ID:", id(ws_manager))
        
        # Register connection
        client_id = await ws_manager.connect(websocket)
        
        # Handle incoming messages
        while True:
            data = await websocket.receive_text()
            ws_manager.stats["messages_received"] += 1
            
            try:
                message = WebSocketMessage.from_json(data)
                
                # Handle subscription messages
                if message.event == WebSocketEventType.SUBSCRIBE.value:
                    channel = message.data.get("channel")
                    if channel:
                        await ws_manager.subscribe(client_id, channel)
                
                elif message.event == WebSocketEventType.UNSUBSCRIBE.value:
                    channel = message.data.get("channel")
                    if channel:
                        await ws_manager.unsubscribe(client_id, channel)
                
                elif message.event == WebSocketEventType.HEARTBEAT.value:
                    # Update last heartbeat
                    if client_id in ws_manager.clients:
                        ws_manager.clients[client_id].last_heartbeat = datetime.utcnow()
                
                # Call external handler if configured
                if ws_manager.on_message_received:
                    await ws_manager.on_message_received(client_id, message)
                    
            except json.JSONDecodeError:
                error_msg = WebSocketMessage(
                    event=WebSocketEventType.ERROR.value,
                    data={"error": "Invalid JSON message"}
                )
                await ws_manager.send_personal_message(error_msg, websocket)
                
    except Exception as e:
        logger.error("WebSocket error", client_id=client_id, error=str(e))
        
    finally:
        await ws_manager.disconnect(websocket)


# FastAPI dependency for WebSocket authentication
async def get_websocket_manager() -> WebSocketManager:
    """Get the global WebSocket manager instance."""
    return ws_manager
