"""Python wrapper for NextDNS API."""
from __future__ import annotations

from aiohttp import ClientConnectorError, ClientResponseError, ClientSession


class NextDNS:
    """Main class of NextDNS API wrapper."""

    def __init__(self, api_key: str, session: ClientSession) -> None:
        """Initialize NextDNS API wrapper."""
        self.api_key = api_key

