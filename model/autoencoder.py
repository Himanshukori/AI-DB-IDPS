"""
model/autoencoder.py

PyTorch Autoencoder for anomaly detection.
Architecture: 16 → 64 → 32 → 16 → 32 → 64 → 16

Uses LayerNorm (not BatchNorm) so it works correctly on single-sample
inference at runtime — BatchNorm fails on batch_size=1 in eval mode.

Trained ONLY on normal queries.
Anomaly score = MSE reconstruction error.
"""

import torch
import torch.nn as nn


class SQLAutoencoder(nn.Module):
    def __init__(self, input_dim: int = 16):
        super().__init__()

        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 64),
            nn.LayerNorm(64),
            nn.ReLU(),
            nn.Linear(64, 32),
            nn.LayerNorm(32),
            nn.ReLU(),
            nn.Linear(32, 16),
            nn.ReLU(),
        )

        self.decoder = nn.Sequential(
            nn.Linear(16, 32),
            nn.LayerNorm(32),
            nn.ReLU(),
            nn.Linear(32, 64),
            nn.LayerNorm(64),
            nn.ReLU(),
            nn.Linear(64, input_dim),
            nn.Sigmoid(),   # features are normalized [0,1]
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded

    def reconstruction_error(self, x: torch.Tensor) -> torch.Tensor:
        """Returns per-sample MSE reconstruction error."""
        with torch.no_grad():
            reconstructed = self.forward(x)
            error = torch.mean((x - reconstructed) ** 2, dim=1)
        return error
