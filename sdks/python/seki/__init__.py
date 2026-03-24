"""seki-client — Python SDK for the seki Admin API."""

from .client import SekiClient
from .errors import SekiAPIError

__all__ = ["SekiClient", "SekiAPIError"]
