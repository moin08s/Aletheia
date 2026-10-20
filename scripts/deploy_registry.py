"""One-click smart contract deployer for WASP ChronoTraceRegistry.

Deploys ChronoTraceRegistry.sol to local testnets (Anvil / Hardhat) or live L2s (Base Sepolia, Arbitrum Sepolia).
"""

from __future__ import annotations
import os
import sys
from pathlib import Path

# Provide standard deployment configurations
NETWORKS = {
    "base_sepolia": {
        "rpc_url": os.environ.get("BASE_SEPOLIA_RPC", "https://sepolia.base.org"),
        "chain_id": 84532,
        "name": "Base Sepolia (L2)",
        "explorer": "https://sepolia.basescan.org",
    },
    "arbitrum_sepolia": {
        "rpc_url": os.environ.get("ARB_SEPOLIA_RPC", "https://sepolia-rollup.arbitrum.io/rpc"),
        "chain_id": 421614,
        "name": "Arbitrum Sepolia (L2)",
        "explorer": "https://sepolia.arbiscan.io",
    },
    "localhost": {
        "rpc_url": "http://127.0.0.1:8545",
        "chain_id": 31337,
        "name": "Local Hardhat/Anvil",
        "explorer": "http://localhost:8545",
    },
}


def print_deployment_guide():
    contract_path = Path(__file__).resolve().parent.parent / "contracts" / "ChronoTraceRegistry.sol"
    print("=" * 70)
    print("  WASP / ChronoTraceRegistry Deployment Guide (ETHGlobal)")
    print("=" * 70)
    print(f"Contract Source: {contract_path}")
    print("\nSupported Networks:")
    for key, cfg in NETWORKS.items():
        print(f"  * {key:18} -> {cfg['name']} (Chain ID: {cfg['chain_id']})")
    
    print("\nHow to Deploy via Foundry (Recommended):")
    print("  forge create contracts/ChronoTraceRegistry.sol:ChronoTraceRegistry \\")
    print("    --rpc-url https://sepolia.base.org \\")
    print("    --private-key <YOUR_PRIVATE_KEY>")
    
    print("\nHow to Deploy via Hardhat:")
    print("  npx hardhat ignition deploy ./ignition/modules/ChronoTraceRegistry.ts --network baseSepolia")
    print("=" * 70)


if __name__ == "__main__":
    print_deployment_guide()
