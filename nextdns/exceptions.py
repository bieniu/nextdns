"""NextDNS exceptions."""


class NextDnsError(Exception):
    """Base class for nextdns errors."""


class InvalidApiKeyError(NextDnsError):
    """Raised to indicate invalid API key error."""


class ApiError(NextDnsError):
    """Raised to indicate API error."""

    def __init__(self, status: str) -> None:
        """Initialize."""
        super().__init__(status)
        self.status = status
