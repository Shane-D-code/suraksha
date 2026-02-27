"""
PhishGuard GNN Training Script
Trains GraphSAGE model on threat intelligence graph
"""

import torch
import pandas as pd
import numpy as np
from torch_geometric.data import Data
from sklearn.model_selection import train_test_split
import logging
import os

from gnn_model import PhishGuardGNN, GNNTrainer
from graph_dataset import GraphDatasetExporter

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def load_graph_data(data_dir: str = 'data') -> Data:
    """Load graph data from CSV files"""
    logger.info("Loading graph data...")
    
    # Load nodes
    nodes_df = pd.read_csv(os.path.join(data_dir, 'nodes.csv'))
    logger.info(f"Loaded {len(nodes_df)} nodes")
    
    # Load edges
    edges_df = pd.read_csv(os.path.join(data_dir, 'edges.csv'))
    logger.info(f"Loaded {len(edges_df)} edges")
    
    # Load labels
    labels_df = pd.read_csv(os.path.join(data_dir, 'labels.csv'))
    logger.info(f"Loaded {len(labels_df)} labels")
    
    # Load features
    features_df = pd.read_csv(os.path.join(data_dir, 'features.csv'))
    logger.info(f"Loaded features for {len(features_df)} nodes")
    
    # Prepare node features
    feature_cols = [col for col in features_df.columns if col != 'node_id']
    x = torch.tensor(features_df[feature_cols].values, dtype=torch.float)
    
    # Prepare edge index
    edge_index = torch.tensor([
        edges_df['source_id'].values,
        edges_df['target_id'].values
    ], dtype=torch.long)
    
    # Prepare labels (initialize all as -1, then fill labeled nodes)
    y = torch.full((len(nodes_df),), -1, dtype=torch.long)
    for _, row in labels_df.iterrows():
        y[int(row['node_id'])] = int(row['label'])
    
    # Create PyG Data object
    data = Data(x=x, edge_index=edge_index, y=y)
    
    logger.info(f"Graph data prepared:")
    logger.info(f"  Nodes: {data.num_nodes}")
    logger.info(f"  Edges: {data.num_edges}")
    logger.info(f"  Features: {data.num_node_features}")
    logger.info(f"  Labeled nodes: {(y != -1).sum().item()}")
    
    return data


def create_train_val_test_masks(data: Data, 
                                  train_ratio: float = 0.6,
                                  val_ratio: float = 0.2,
                                  test_ratio: float = 0.2) -> tuple:
    """Create train/val/test masks"""
    # Get labeled nodes
    labeled_mask = data.y != -1
    labeled_indices = torch.where(labeled_mask)[0].numpy()
    
    logger.info(f"Creating splits from {len(labeled_indices)} labeled nodes...")
    
    # Split indices
    train_idx, temp_idx = train_test_split(
        labeled_indices,
        train_size=train_ratio,
        random_state=42,
        stratify=data.y[labeled_indices].numpy()
    )
    
    val_idx, test_idx = train_test_split(
        temp_idx,
        train_size=val_ratio / (val_ratio + test_ratio),
        random_state=42,
        stratify=data.y[temp_idx].numpy()
    )
    
    # Create masks
    train_mask = torch.zeros(data.num_nodes, dtype=torch.bool)
    val_mask = torch.zeros(data.num_nodes, dtype=torch.bool)
    test_mask = torch.zeros(data.num_nodes, dtype=torch.bool)
    
    train_mask[train_idx] = True
    val_mask[val_idx] = True
    test_mask[test_idx] = True
    
    logger.info(f"Split sizes:")
    logger.info(f"  Train: {train_mask.sum().item()}")
    logger.info(f"  Val: {val_mask.sum().item()}")
    logger.info(f"  Test: {test_mask.sum().item()}")
    
    return train_mask, val_mask, test_mask


def train_model(data: Data, 
                train_mask: torch.Tensor,
                val_mask: torch.Tensor,
                epochs: int = 100,
                learning_rate: float = 0.001):
    """Train GNN model"""
    logger.info("Initializing model...")
    
    # Create model
    model = PhishGuardGNN(
        input_dim=data.num_node_features,
        hidden_dim=64,
        output_dim=32,
        num_layers=3,
        dropout=0.3
    )
    
    logger.info(f"Model parameters: {sum(p.numel() for p in model.parameters())}")
    
    # Create trainer
    trainer = GNNTrainer(model, learning_rate=learning_rate)
    
    # Train
    history = trainer.train(
        data,
        train_mask,
        val_mask,
        epochs=epochs,
        patience=15
    )
    
    return model, trainer, history


def evaluate_model(model: PhishGuardGNN, 
                   data: Data,
                   test_mask: torch.Tensor):
    """Evaluate model on test set"""
    logger.info("Evaluating on test set...")
    
    model.eval()
    with torch.no_grad():
        predictions, embeddings = model(data.x, data.edge_index)
        
        # Test metrics
        test_predictions = predictions[test_mask].squeeze()
        test_labels = data.y[test_mask].float()
        
        # Accuracy
        pred_labels = (test_predictions > 0.5).float()
        accuracy = (pred_labels == test_labels).float().mean()
        
        # Precision, Recall, F1
        tp = ((pred_labels == 1) & (test_labels == 1)).sum().float()
        fp = ((pred_labels == 1) & (test_labels == 0)).sum().float()
        fn = ((pred_labels == 0) & (test_labels == 1)).sum().float()
        
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    
    logger.info("Test Results:")
    logger.info(f"  Accuracy: {accuracy:.4f}")
    logger.info(f"  Precision: {precision:.4f}")
    logger.info(f"  Recall: {recall:.4f}")
    logger.info(f"  F1 Score: {f1:.4f}")
    
    return {
        'accuracy': accuracy.item(),
        'precision': precision.item(),
        'recall': recall.item(),
        'f1': f1.item()
    }


def main():
    """Main training pipeline"""
    logger.info("=" * 60)
    logger.info("PhishGuard GNN Training Pipeline")
    logger.info("=" * 60)
    
    # Step 1: Export dataset (if needed)
    if not os.path.exists('data/nodes.csv'):
        logger.info("\nStep 1: Exporting dataset from database...")
        exporter = GraphDatasetExporter('../threat_intel.db')
        exporter.export_dataset('data')
    else:
        logger.info("\nStep 1: Dataset already exists, skipping export")
    
    # Step 2: Load graph data
    logger.info("\nStep 2: Loading graph data...")
    data = load_graph_data('data')
    
    # Step 3: Create splits
    logger.info("\nStep 3: Creating train/val/test splits...")
    train_mask, val_mask, test_mask = create_train_val_test_masks(data)
    
    # Step 4: Train model
    logger.info("\nStep 4: Training GNN model...")
    model, trainer, history = train_model(
        data,
        train_mask,
        val_mask,
        epochs=100,
        learning_rate=0.001
    )
    
    # Step 5: Evaluate
    logger.info("\nStep 5: Evaluating model...")
    test_results = evaluate_model(model, data, test_mask)
    
    # Step 6: Save final model
    logger.info("\nStep 6: Saving final model...")
    trainer.save_model('models/gnn_model.pt')
    
    logger.info("\n" + "=" * 60)
    logger.info("Training completed successfully!")
    logger.info("=" * 60)
    
    return model, history, test_results


if __name__ == '__main__':
    model, history, results = main()
    
    print("\nFinal Results:")
    print(f"  Test Accuracy: {results['accuracy']:.4f}")
    print(f"  Test F1 Score: {results['f1']:.4f}")
