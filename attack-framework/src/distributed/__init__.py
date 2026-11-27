"""
Distributed coordination modules.

Модули:
- invitation: Invitation system для P2P mesh
- campaigns: Distributed attack campaigns
- federated: Federated adversarial training
- mesh_math: Mathematical modules over mesh
"""

from .invitation import InvitationSystem
from .campaigns import DistributedCampaigns
from .federated import FederatedTraining
from .mesh_math import MeshMathIntegration

__all__ = [
    "InvitationSystem",
    "DistributedCampaigns",
    "FederatedTraining",
    "MeshMathIntegration",
]
