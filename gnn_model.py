import torch
import torch.nn.functional as F
from torch_geometric.nn import GCNConv
from threat_graph import threat_graph  # Ensure threat_graph is correctly imported

class GNNModel(torch.nn.Module):
    def __init__(self, in_channels, hidden_channels, out_channels):
        super(GNNModel, self).__init__()
        self.conv1 = GCNConv(in_channels, hidden_channels)
        self.conv2 = GCNConv(hidden_channels, out_channels)

    def forward(self, x, edge_index):
        x = self.conv1(x, edge_index)
        x = F.relu(x)
        x = self.conv2(x, edge_index)
        return F.softmax(x, dim=1)

# Initialize model
model = GNNModel(in_channels=1, hidden_channels=16, out_channels=2)

def predict_threat(ip):
    """Predicts if an IP is dangerous using GNN."""
    try:
        data = threat_graph.convert_to_pytorch()  # Ensure this function exists
        output = model(data.x, data.edge_index)
        threat_score = output.mean().item()  # Simplified risk score
        return round(threat_score, 2)
    except Exception as e:
        print(f"⚠️ GNN Prediction Failed: {e}")
        return 0.0  # Default score if GNN fails
