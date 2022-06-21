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


class ProfileIdNotFoundError(NextDnsError):
    """Raised to indicate profile ID not found error."""


class ProfileNameNotFoundError(NextDnsError):
    """Raised to indicate profile name not found error."""


class SettingNotSupportedError(NextDnsError):
    """Raised to indicate setting not supported error."""
