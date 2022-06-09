"""Type definitions for NextDNS."""
from dataclasses import dataclass


@dataclass
class AnalyticsStatus:
    """AnalyticsStatus class."""

    default_queries: int = 0
    blocked_queries: int = 0
    allowed_queries: int = 0
    all_queries: int = 0
    blocked_percentage: float = 0

    def __post_init__(self) -> None:
        """Call after initialization."""
        self.all_queries: int = sum(
            [self.default_queries, self.blocked_queries, self.allowed_queries]
        )
        self.blocked_percentage: float = (
            0
            if not self.all_queries
            else round(self.blocked_queries / self.all_queries * 100, 1)
        )
