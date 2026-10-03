"""Offline, bounded transparency proof mathematics; external trust stays OPEN."""

from .evidence import Limits, check_bytes
from .input import check_file

__all__ = ["Limits", "check_bytes", "check_file"]
__version__ = "0.1.1"
