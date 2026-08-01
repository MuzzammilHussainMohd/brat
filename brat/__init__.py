"""BRAT - BLE Recon and Attack Toolkit.

The peripheral-side half of BLE security testing: clone a device into a
portable profile, then stand that profile up as a rogue peripheral.

Central-side recon and posture checking are included so the toolkit stands
alone, but the centre of gravity is `brat clone` -> `brat impersonate`.
"""

__version__ = "0.1.0"
__all__ = ["__version__"]
