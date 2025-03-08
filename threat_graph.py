import networkx as nx
import torch
from torch_geometric.data import Data
from torch_geometric.utils import from_networkx

class ThreatGraph:
    def __init__(self):
        self.graph = nx.Graph()  

    def add_threat(self, ip, related_ips):
        """Adds a threat node and its related connections."""
        self.graph.add_node(ip, label="Threat")
        for related_ip in related_ips:
            self.graph.add_edge(ip, related_ip)

    def convert_to_pytorch(self):
        """Converts the NetworkX threat graph to PyTorch Geometric format."""
        if len(self.graph.nodes) == 0:
            raise ValueError("⚠️ No threats detected yet!")
        
        data = from_networkx(self.graph)  # Convert to PyTorch Geometric format
        data.x = torch.ones((data.num_nodes, 1))  # Feature matrix (dummy values)
        return data

    def visualize(self):
        """Displays the threat graph using NetworkX."""
        if not self.graph.nodes:
            print("⚠️ No threats to display!")
            return
        
        import matplotlib.pyplot as plt
        plt.figure(figsize=(10, 6))
        pos = nx.spring_layout(self.graph)
        nx.draw(self.graph, pos, with_labels=True, node_color="red", edge_color="gray", node_size=2000, font_size=10)
        plt.title("Threat Actor Network")
        plt.show()

# Initialize global instance
threat_graph = ThreatGraph()
