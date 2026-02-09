"""Minimal SMB1 client for New Nintendo 3DS microSD Management."""

from n3ds_smb.client import N3DSClient
from n3ds_smb.discovery import discover_3ds

__all__ = ["N3DSClient", "discover_3ds"]
