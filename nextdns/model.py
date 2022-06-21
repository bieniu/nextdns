"""Type definitions for NextDNS."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class NextDnsData:
    """NextDNS data class."""


@dataclass
class AnalyticsStatus(NextDnsData):
    """AnalyticsStatus class."""

    all_queries: int = 0
    allowed_queries: int = 0
    blocked_queries: int = 0
    default_queries: int = 0
    relayed_queries: int = 0
    blocked_queries_ratio: float = 0

    def __post_init__(self) -> None:
        """Call after initialization."""
        self.all_queries = sum(
            [
                self.default_queries,
                self.blocked_queries,
                self.allowed_queries,
                self.relayed_queries,
            ]
        )

        self.blocked_queries_ratio = (
            0
            if not self.all_queries
            else round(self.blocked_queries / self.all_queries * 100, 1)
        )


@dataclass
class AnalyticsDnssec(NextDnsData):
    """AnalyticsDnssec class."""

    not_validated_queries: int = 0
    validated_queries: int = 0
    validated_queries_ratio: float = 0

    def __post_init__(self) -> None:
        """Call after initialization."""
        all_queries = sum([self.validated_queries, self.not_validated_queries])

        self.validated_queries_ratio = (
            0
            if not all_queries
            else round(self.validated_queries / all_queries * 100, 1)
        )


@dataclass
class AnalyticsEncryption(NextDnsData):
    """AnalyticsEncryption class."""

    encrypted_queries: int = 0
    unencrypted_queries: int = 0
    encrypted_queries_ratio: float = 0

    def __post_init__(self) -> None:
        """Call after initialization."""
        all_queries = sum([self.encrypted_queries, self.unencrypted_queries])

        self.encrypted_queries_ratio = (
            0
            if not all_queries
            else round(self.encrypted_queries / all_queries * 100, 1)
        )


@dataclass
class AnalyticsIpVersions(NextDnsData):
    """AnalyticsIpVersions class."""

    ipv6_queries: int = 0
    ipv4_queries: int = 0
    ipv6_queries_ratio: float = 0

    def __post_init__(self) -> None:
        """Call after initialization."""
        all_queries = sum([self.ipv6_queries, self.ipv4_queries])

        self.ipv6_queries_ratio = (
            0 if not all_queries else round(self.ipv6_queries / all_queries * 100, 1)
        )


@dataclass
class AnalyticsProtocols(NextDnsData):
    """AnalyticsProtocols class."""

    doh_queries: int = 0
    doq_queries: int = 0
    dot_queries: int = 0
    udp_queries: int = 0
    doh_queries_ratio: float = 0
    doq_queries_ratio: float = 0
    dot_queries_ratio: float = 0
    udp_queries_ratio: float = 0

    def __post_init__(self) -> None:
        """Call after initialization."""
        all_queries = sum([self.doh_queries, self.dot_queries, self.udp_queries])

        self.doh_queries_ratio = (
            0 if not all_queries else round(self.doh_queries / all_queries * 100, 1)
        )
        self.doq_queries_ratio = (
            0 if not all_queries else round(self.doq_queries / all_queries * 100, 1)
        )
        self.dot_queries_ratio = (
            0 if not all_queries else round(self.dot_queries / all_queries * 100, 1)
        )
        self.udp_queries_ratio = (
            0 if not all_queries else round(self.udp_queries / all_queries * 100, 1)
        )


@dataclass
class AllAnalytics(NextDnsData):
    """AllAnalytics class."""

    dnssec: AnalyticsDnssec
    encrypted: AnalyticsEncryption
    ip_versions: AnalyticsIpVersions
    protocols: AnalyticsProtocols
    status: AnalyticsStatus


@dataclass
class Profile(NextDnsData):
    """Profile class."""

    allowlist: list[dict[str, Any]]
    denylist: list[dict[str, Any]]
    fingerprint: str
    id: str
    name: str
    parental_control: dict[str, Any]
    privacy: dict[str, Any]
    rewrites: list
    security: dict[str, Any]
    settings: dict[str, Any]
    setup: dict[str, Any]


@dataclass
class Settings(NextDnsData):
    """Settings class."""

    block_page: bool
    cache_boost: bool
    cname_flattening: bool
    anonymized_ecs: bool
    logs: bool
    web3: bool

    allow_affiliate: bool
    block_disguised_trackers: bool

    ai_threat_detection: bool
    block_csam: bool
    block_nrd: bool
    block_parked_domains: bool
    cryptojacking_protection: bool
    dga_protection: bool
    dns_rebinding_protection: bool
    google_safe_browsing: bool
    idn_homograph_attacks_protection: bool
    threat_intelligence_feeds: bool
    typosquatting_protection: bool

    block_bypass_methods: bool
    safesearch: bool
    youtube_restricted_mode: bool


@dataclass
class ProfileInfo(NextDnsData):
    """ProfileInfo class."""

    id: str
    fingerprint: str
    name: str


@dataclass
class ConnectionStatus(NextDnsData):
    """ConnectionStatus class."""

    connected: bool
    profile_id: str | None = None
