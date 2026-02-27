"""
PhishGuard GNN Retraining Pipeline
Daily automated model retraining with model hot-reload
"""

import os
import sys
import logging
import json
from datetime import datetime, timedelta
from pathlib import Path

# Add paths
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'threat_intel'))
sys.path.insert(0, os.path.dirname(__file__))

import torch
import pandas as pd
import numpy as np
from torch_geometric.data import Data
from sklearn.model_selection import train_test_split

from gnn_model import PhishGuardGNN, GNNTrainer
from graph_dataset import GraphDatasetExporter

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class RetrainingPipeline:
    """
    Automated GNN retraining pipeline
    Supports daily/weekly retraining with zero-downtime model reload
    """
    
    def __init__(self, 
                 db_path: str = '../threat_intel.db',
                 data_dir: str = 'data',
                 model_dir: str = 'models'):
        self.db_path = db_path
        self.data_dir = data_dir
        self.model_dir = model_dir
        
        # Ensure directories exist
        os.makedirs(data_dir, exist_ok=True)
        os.makedirs(model_dir, exist_ok=True)
        
        # Model paths
        self.model_path = os.path.join(model_dir, 'gnn_model.pt')
        self.best_model_path = os.path.join(model_dir, 'gnn_best.pt')
        self.backup_model_path = os.path.join(model_dir, 'gnn_backup.pt')
        
        # Training history
        self.history_file = os.path.join(model_dir, 'training_history.json')
        
        # Track last training
        self.last_training = None
        self.load_training_history()
    
    def load_training_history(self):
        """Load previous training history"""
        if os.path.exists(self.history_file):
            try:
                with open(self.history_file, 'r') as f:
                    history = json.load(f)
                    self.last_training = history.get('last_training')
                    logger.info(f"Last training: {self.last_training}")
            except Exception as e:
                logger.warning(f"Could not load training history: {e}")
    
    def save_training_history(self, metrics: dict):
        """Save training history"""
        history = {
            'last_training': datetime.now().isoformat(),
            'last_metrics': metrics
        }
        
        # Load existing
        if os.path.exists(self.history_file):
            try:
                with open(self.history_file, 'r') as f:
                    existing = json.load(f)
                    if 'history' not in existing:
                        existing['history'] = []
                    existing['history'].append(history)
                    history = existing
            except:
                history = {'history': [history]}
        
        with open(self.history_file, 'w') as f:
            json.dump(history, f, indent=2)
    
    def should_retrain(self, min_interval_hours: int = 24) -> bool:
        """Check if model should be retrained"""
        if not os.path.exists(self.model_path):
            logger.info("No model exists, should retrain")
            return True
        
        if not self.last_training:
            logger.info("No training history, should retrain")
            return True
        
        # Check interval
        last_train = datetime.fromisoformat(self.last_training)
        hours_since = (datetime.now() - last_train).total_seconds() / 3600
        
        if hours_since >= min_interval_hours:
            logger.info(f"{hours_since:.1f} hours since last training, should retrain")
            return True
        
        logger.info(f"{hours_since:.1f} hours since last training, no retrain needed")
        return False
    
    def export_data(self) -> bool:
        """Export fresh data from database"""
        logger.info("Exporting graph data from database...")
        
        try:
            exporter = GraphDatasetExporter(self.db_path)
            files = exporter.export_dataset(self.data_dir)
            
            logger.info(f"Data exported: {len(files)} files")
            return True
        except Exception as e:
            logger.error(f"Data export failed: {e}")
            return False
    
    def load_graph_data(self) -> Data:
        """Load graph data from CSV files"""
        logger.info("Loading graph data...")
        
        # Load nodes
        nodes_df = pd.read_csv(os.path.join(self.data_dir, 'nodes.csv'))
        logger.info(f"Loaded {len(nodes_df)} nodes")
        
        # Load edges
        edges_df = pd.read_csv(os.path.join(self.data_dir, 'edges.csv'))
        logger.info(f"Loaded {len(edges_df)} edges")
        
        # Load labels
        labels_df = pd.read_csv(os.path.join(self.data_dir, 'labels.csv'))
        logger.info(f"Loaded {len(labels_df)} labels")
        
        # Load features
        features_df = pd.read_csv(os.path.join(self.data_dir, 'features.csv'))
        logger.info(f"Loaded features for {len(features_df)} nodes")
        
        # Prepare node features
        feature_cols = [col for col in features_df.columns if col != 'node_id']
        x = torch.tensor(features_df[feature_cols].values, dtype=torch.float)
        
        # Prepare edge index
        edge_index = torch.tensor([
            edges_df['source_id'].values,
            edges_df['target_id'].values
        ], dtype=torch.long)
        
        # Prepare labels
        y = torch.full((len(nodes_df),), -1, dtype=torch.long)
        for _, row in labels_df.iterrows():
            y[int(row['node_id'])] = int(row['label'])
        
        # Create PyG Data object
        data = Data(x=x, edge_index=edge_index, y=y)
        
        return data
    
    def create_splits(self, data: Data):
        """Create train/val/test splits"""
        labeled_mask = data.y != -1
        labeled_indices = torch.where(labeled_mask)[0].numpy()
        
        train_idx, temp_idx = train_test_split(
            labeled_indices,
            train_size=0.6,
            random_state=42,
            stratify=data.y[labeled_indices].numpy()
        )
        
        val_idx, test_idx = train_test_split(
            temp_idx,
            train_size=0.5,
            random_state=42,
            stratify=data.y[temp_idx].numpy()
        )
        
        train_mask = torch.zeros(data.num_nodes, dtype=torch.bool)
        val_mask = torch.zeros(data.num_nodes, dtype=torch.bool)
        test_mask = torch.zeros(data.num_nodes, dtype=torch.bool)
        
        train_mask[train_idx] = True
        val_mask[val_idx] = True
        test_mask[test_idx] = True
        
        logger.info(f"Splits - Train: {train_mask.sum()}, Val: {val_mask.sum()}, Test: {test_mask.sum()}")
        
        return train_mask, val_mask, test_mask
    
    def train(self, epochs: int = 100) -> dict:
        """Train GNN model"""
        logger.info("Initializing model...")
        
        # Create model
        data = self.load_graph_data()
        
        if data.num_node_features == 0:
            logger.error("No features available")
            return {'success': False, 'error': 'No features'}
        
        model = PhishGuardGNN(
            input_dim=data.num_node_features,
            hidden_dim=64,
            output_dim=32,
            num_layers=3,
            dropout=0.3
        )
        
        logger.info(f"Model parameters: {sum(p.numel() for p in model.parameters())}")
        
        # Create trainer
        trainer = GNNTrainer(model, learning_rate=0.001)
        
        # Create splits
        train_mask, val_mask, test_mask = self.create_splits(data)
        
        # Train
        logger.info(f"Training for {epochs} epochs...")
        history = trainer.train(
            data,
            train_mask,
            val_mask,
            epochs=epochs,
            patience=15
        )
        
        # Evaluate
        model.eval()
        with torch.no_grad():
            predictions, _ = model(data.x, data.edge_index)
            
            test_predictions = predictions[test_mask].squeeze()
            test_labels = data.y[test_mask].float()
            
            pred_labels = (test_predictions > 0.5).float()
            accuracy = (pred_labels == test_labels).float().mean()
            
            tp = ((pred_labels == 1) & (test_labels == 1)).sum().float()
            fp = ((pred_labels == 1) & (test_labels == 0)).sum().float()
            fn = ((pred_labels == 0) & (test_labels == 1)).sum().float()
            
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0
            f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        metrics = {
            'accuracy': accuracy.item(),
            'precision': precision.item(),
            'recall': recall.item(),
            'f1': f1.item(),
            'train_loss': history.get('train_losses', [0])[-1],
            'val_loss': history.get('val_losses', [0])[-1]
        }
        
        logger.info(f"Test Results: Acc={metrics['accuracy']:.4f}, F1={metrics['f1']:.4f}")
        
        return {
            'success': True,
            'metrics': metrics
        }
    
    def update_model(self) -> bool:
        """Update model with hot-reload capability"""
        logger.info("Updating model...")
        
        # Backup current model
        if os.path.exists(self.model_path):
            import shutil
            shutil.copy(self.model_path, self.backup_model_path)
            logger.info("Backed up current model")
        
        # Load best model as current
        if os.path.exists(self.best_model_path):
            import shutil
            shutil.copy(self.best_model_path, self.model_path)
            logger.info("Updated model to best version")
            return True
        
        return False
    
    def run(self, force: bool = False, epochs: int = 100) -> dict:
        """
        Run full retraining pipeline
        
        Args:
            force: Force retraining even if not needed
            epochs: Number of training epochs
            
        Returns:
            Dict with results
        """
        logger.info("=" * 60)
        logger.info("Starting GNN Retraining Pipeline")
        logger.info("=" * 60)
        
        # Check if retrain needed
        if not force and not self.should_retrain():
            return {
                'success': True,
                'retrained': False,
                'reason': 'Not enough time since last training'
            }
        
        # Export data
        if not self.export_data():
            return {
                'success': False,
                'error': 'Data export failed'
            }
        
        # Train model
        result = self.train(epochs)
        
        if result.get('success'):
            # Save history
            self.save_training_history(result['metrics'])
            
            # Update model
            self.update_model()
            
            logger.info("Retraining completed successfully!")
        
        return result


# Global pipeline instance
_pipeline = None


def get_pipeline() -> RetrainingPipeline:
    """Get global pipeline instance"""
    global _pipeline
    if _pipeline is None:
        _pipeline = RetrainingPipeline()
    return _pipeline


def run_retraining(force: bool = False, epochs: int = 100) -> dict:
    """Convenience function to run retraining"""
    pipeline = get_pipeline()
    return pipeline.run(force=force, epochs=epochs)


# CLI interface
if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='GNN Retraining Pipeline')
    parser.add_argument('--force', action='store_true', help='Force retraining')
    parser.add_argument('--epochs', type=int, default=100, help='Number of epochs')
    parser.add_argument('--check', action='store_true', help='Check if retraining needed')
    
    args = parser.parse_args()
    
    pipeline = get_pipeline()
    
    if args.check:
        should = pipeline.should_retrain()
        print(f"Should retrain: {should}")
    else:
        result = pipeline.run(force=args.force, epochs=args.epochs)
        print(f"\nResult: {json.dumps(result, indent=2)}")

