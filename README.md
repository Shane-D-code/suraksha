# PhishGuard - Enterprise Phishing Detection Platform

A scalable, secure Endpoint Threat Intelligence Platform built with FastAPI, designed for real-time phishing and threat detection. Includes a Chrome browser extension for real-time protection.

## Features

- **REST API**: High-performance async API using FastAPI
- **Graph-Based Intelligence**: NetworkX for threat graph analysis (MVP), Neo4j for production
- **ML Integration**: ML-based and rule-based phishing detection
- **Chrome Extension**: Real-time browser protection
- **Caching**: Redis for caching scan results
- **Rate Limiting**: Protect against abuse
- **JWT Authentication**: Secure API access
- **Dashboard**: SOC-style dashboard for threat monitoring
- **Structured Logging**: JSON-based logging with structlog
- **Observability**: OpenTelemetry integration

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      PhishGuard Platform                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐      │
│  │   Chrome    │────▶│  FastAPI   │────▶│ PostgreSQL   │      │
│  │  Extension  │     │    API     │     └─────────────┘      │
│  └─────────────┘     │    (8000)   │            │              │
│         │            └─────────────┘            │              │
│         │                   │                  ▼              │
│         ▼                   ▼           ┌─────────────┐       │
│  ┌─────────────┐     ┌─────────────┐    │    Redis    │       │
│  │Local AI     │     │    Graph    │    │   (Cache)   │       │
│  │Inference    │     │  (NetworkX) │    └─────────────┘       │
│  └─────────────┘     └─────────────┘                          │
│                             │                                   │
│                             ▼                                   │
│                      ┌─────────────┐                           │
│                      │ intelligence│                           │
│                      │    (NLP)    │                           │
│                      └─────────────┘                           │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- Python 3.11+
- Docker & Docker Compose
- PostgreSQL 15+
- Redis 7+

### Installation

1. Clone the repository
2. Copy environment variables:
   
```bash
cp .env.example .env
```

3. Start with Docker Compose:
   
```bash
docker-compose up -d
```

4. Access the API at http://localhost:8000

### Local Development

1. Create virtual environment:
   
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate  # Windows
```

2. Install dependencies:
   
```bash
pip install -r requirements.txt
```

3. Create database tables:
   
```bash
python create_tables.py
```

4. Run the server:
   
```bash
uvicorn app.main:app --reload
```

## Components

### Main API Server (`app/`)
FastAPI-based REST API server with:
- `/scan` - Scan URLs, emails, and content for phishing
- `/feedback` - Submit feedback on scan results
- `/api/v1/scan` - Standard API endpoint
- `/api/v1/threat-intel/{domain}` - Domain intelligence
- `/health` - Health check

### Chrome Extension (`aws/Chrome_extensions/`)
Browser extension for real-time protection:
- `manifest.json` - Extension configuration
- `background.js` - Background service worker
- `content.js` - Page content analysis
- `blocker.js` - URL blocking
- `popup.html/js` - User interface

### Intelligence Engine (`intelligence/`)
ML-based detection:
- `nlp/predictor.py` - Phishing prediction with ML + rules
- `nlp/train.py` - Model training
- `web/url_checks.py` - URL analysis

## API Endpoints

### Chrome Extension Compatible (Root Level)
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /scan | Scan URL for threats |
| POST | /feedback | Submit feedback |
| GET | /status | Server status |
| GET | /threat-cache | Threat intelligence cache |

### Standard API (v1)
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /api/v1/scan | Scan content for threats |
| POST | /api/v1/feedback | Submit feedback on scan |
| GET | /api/v1/threat-intel/{domain} | Get domain intelligence |
| GET | /api/v1/model-health | Get model metrics |
| GET | /health | Health check |

### Dashboard API (JWT Auth Required)
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /auth/login | Login |
| GET | /dashboard/summary | Dashboard overview |
| GET | /dashboard/live-threats | Live threat feed |
| GET | /dashboard/campaigns | Campaign intelligence |
| GET | /dashboard/graph | Infrastructure graph |
| GET | /dashboard/endpoint-stats | Endpoint statistics |
| GET | /dashboard/investigate/{domain} | Domain investigation |

## Testing

Run tests:
```bash
pytest
```

## Chrome Extension Setup

1. Open Chrome and navigate to `chrome://extensions/`
2. Enable "Developer mode"
3. Click "Load unpacked"
4. Select the `aws/Chrome_extensions` directory
5. The extension will appear in your toolbar

## Project Structure

```
phishguard/
├── app/                    # Main API application
│   ├── api/               # API routes
│   ├── models/            # Pydantic & SQLAlchemy models
│   ├── services/          # Business logic
│   │   ├── database.py    # PostgreSQL operations
│   │   ├── redis.py       # Redis caching
│   │   ├── graph.py       # NetworkX graph analysis
│   │   └── scoring.py     # Risk score calculation
│   ├── middleware/        # Auth, rate limiting
│   └── tasks/             # Celery tasks
├── aws/
│   └── Chrome_extensions/ # Chrome extension
│       ├── backend/       # Extension backend
│       │   ├── ml/        # GNN model
│       │   └── threat_intel/
│       └── dashboard/     # React dashboard
├── intelligence/          # ML/AI engine
│   ├── nlp/             # NLP models
│   └── web/             # Web analysis
└── config/              # Configuration files
```

## Configuration
See `.env.example` for available configuration options:
- `DATABASE_URL` - PostgreSQL connection
- `REDIS_URL` - Redis connection
- `SECRET_KEY` - JWT secret key
- `RATE_LIMIT_PER_MINUTE` - API rate limit

## License
MIT
# phishguard_awsfinal
