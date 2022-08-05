"""Type definitions for NextDNS."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, TypeVar

_StrEnumSelfT = TypeVar("_StrEnumSelfT", bound="StrEnum")


class StrEnum(str, Enum):
    """Partial backport of Python 3.11's StrEnum for our basic use cases."""

    def __new__(
        cls: type[_StrEnumSelfT], value: str, *args: Any, **kwargs: Any
    ) -> _StrEnumSelfT:
        """Create a new StrEnum instance."""
        if not isinstance(value, str):
            raise TypeError(f"{value!r} is not a string")
        return super().__new__(cls, value, *args, **kwargs)

    def __str__(self) -> str:
        """Return self.value."""
        return str(self.value)

    @staticmethod
    def _generate_next_value_(
        name: str, start: int, count: int, last_values: list[Any]
    ) -> Any:
        """Make `auto()` explicitly unsupported."""
        raise TypeError("auto() is not supported by this implementation")


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
    doh3_queries: int = 0
    doq_queries: int = 0
    dot_queries: int = 0
    tcp_queries: int = 0
    udp_queries: int = 0
    doh_queries_ratio: float = 0
    doh3_queries_ratio: float = 0
    doq_queries_ratio: float = 0
    dot_queries_ratio: float = 0
    tcp_queries_ratio: float = 0
    udp_queries_ratio: float = 0

    def __post_init__(self) -> None:
        """Call after initialization."""
        all_queries = sum(
            [
                self.doh_queries,
                self.doh3_queries,
                self.doq_queries,
                self.dot_queries,
                self.tcp_queries,
                self.udp_queries,
            ]
        )

        self.doh_queries_ratio = (
            0 if not all_queries else round(self.doh_queries / all_queries * 100, 1)
        )
        self.doh3_queries_ratio = (
            0 if not all_queries else round(self.doh3_queries / all_queries * 100, 1)
        )
        self.doq_queries_ratio = (
            0 if not all_queries else round(self.doq_queries / all_queries * 100, 1)
        )
        self.dot_queries_ratio = (
            0 if not all_queries else round(self.dot_queries / all_queries * 100, 1)
        )
        self.tcp_queries_ratio = (
            0 if not all_queries else round(self.tcp_queries / all_queries * 100, 1)
        )
        self.udp_queries_ratio = (
            0 if not all_queries else round(self.udp_queries / all_queries * 100, 1)
        )


@dataclass
class AllAnalytics(NextDnsData):
    """AllAnalytics class."""

    dnssec: AnalyticsDnssec
    encryption: AnalyticsEncryption
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
    block_ddns: bool
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

    block_9gag: bool
    block_amazon: bool
    block_blizzard: bool
    block_dailymotion: bool
    block_discord: bool
    block_disneyplus: bool
    block_ebay: bool
    block_facebook: bool
    block_fortnite: bool
    block_hulu: bool
    block_imgur: bool
    block_instagram: bool
    block_leagueoflegends: bool
    block_messenger: bool
    block_minecraft: bool
    block_netflix: bool
    block_pinterest: bool
    block_primevideo: bool
    block_reddit: bool
    block_roblox: bool
    block_signal: bool
    block_skype: bool
    block_snapchat: bool
    block_spotify: bool
    block_steam: bool
    block_telegram: bool
    block_tiktok: bool
    block_tinder: bool
    block_tumblr: bool
    block_twitch: bool
    block_twitter: bool
    block_vimeo: bool
    block_vk: bool
    block_whatsapp: bool
    block_xboxlive: bool
    block_youtube: bool
    block_zoom: bool

    block_dating: bool
    block_gambling: bool
    block_piracy: bool
    block_porn: bool
    block_social_networks: bool


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


class ParentalControlServices(StrEnum):
    """Service type for parental control."""

    AMAZON = "amazon"
    BLIZZARD = "blizzard"
    DAILYMOTION = "dailymotion"
    DISCORD = "discord"
    DISNEYPLUS = "disneyplus"
    EBAY = "ebay"
    FACEBOOK = "facebook"
    FORTNITE = "fortnite"
    HULU = "hulu"
    IMGUR = "imgur"
    INSTAGRAM = "instagram"
    LEAGUEOFLEGENDS = "leagueoflegends"
    MESSENGER = "messenger"
    MINECRAFT = "minecraft"
    NETFLIX = "netflix"
    NINEGAG = "9gag"
    PINTEREST = "pinterest"
    PRIMEVIDEO = "primevideo"
    REDDIT = "reddit"
    ROBLOX = "roblox"
    SIGNAL = "signal"
    SKYPE = "skype"
    SNAPCHAT = "snapchat"
    SPOTIFY = "spotify"
    STEAM = "steam"
    TELEGRAM = "telegram"
    TIKTOK = "tiktok"
    TINDER = "tinder"
    TUMBLR = "tumblr"
    TWITCH = "twitch"
    TWITTER = "twitter"
    VIMEO = "vimeo"
    VK = "vk"
    WHATSAPP = "whatsapp"
    XBOXLIVE = "xboxlive"
    YOUTUBE = "youtube"
    ZOOM = "zoom"


class ParentalControlServicesAttrs(StrEnum):
    """Service type attributes for parental control."""

    BLOCK_9GAG = "block_9gag"
    BLOCK_AMAZON = "block_amazon"
    BLOCK_BLIZZARD = "block_blizzard"
    BLOCK_DAILYMOTION = "block_dailymotion"
    BLOCK_DISCORD = "block_discord"
    BLOCK_DISNEYPLUS = "block_disneyplus"
    BLOCK_EBAY = "block_ebay"
    BLOCK_FACEBOOK = "block_facebook"
    BLOCK_FORTNITE = "block_fortnite"
    BLOCK_HULU = "block_hulu"
    BLOCK_IMGUR = "block_imgur"
    BLOCK_INSTAGRAM = "block_instagram"
    BLOCK_LEAGUEOFLEGENDS = "block_leagueoflegends"
    BLOCK_MESSENGER = "block_messenger"
    BLOCK_MINECRAFT = "block_minecraft"
    BLOCK_NETFLIX = "block_netflix"
    BLOCK_PINTEREST = "block_pinterest"
    BLOCK_PRIMEVIDEO = "block_primevideo"
    BLOCK_REDDIT = "block_reddit"
    BLOCK_ROBLOX = "block_roblox"
    BLOCK_SIGNAL = "block_signal"
    BLOCK_SKYPE = "block_skype"
    BLOCK_SNAPCHAT = "block_snapchat"
    BLOCK_SPOTIFY = "block_spotify"
    BLOCK_STEAM = "block_steam"
    BLOCK_TELEGRAM = "block_telegram"
    BLOCK_TIKTOK = "block_tiktok"
    BLOCK_TINDER = "block_tinder"
    BLOCK_TUMBLR = "block_tumblr"
    BLOCK_TWITCH = "block_twitch"
    BLOCK_TWITTER = "block_twitter"
    BLOCK_VIMEO = "block_vimeo"
    BLOCK_VK = "block_vk"
    BLOCK_WHATSAPP = "block_whatsapp"
    BLOCK_XBOXLIVE = "block_xboxlive"
    BLOCK_YOUTUBE = "block_youtube"
    BLOCK_ZOOM = "block_zoom"


class ParentalControlCategories(StrEnum):
    """Categories type for parental control."""

    DATING = "dating"
    GAMBLING = "gambling"
    PIRACY = "piracy"
    PORN = "porn"
    SOCIAL_NETWORKS = "social-networks"


class ParentalControlCategoriesAttrs(StrEnum):
    """Categories type attributes for parental control."""

    BLOCK_DATING = "block_dating"
    BLOCK_GAMBLING = "block_gambling"
    BLOCK_PIRACY = "block_piracy"
    BLOCK_PORN = "block_porn"
    BLOCK_SOCIAL_NETWORKS = "block_social_networks"


class ApiNames(StrEnum):
    """Names type for API."""

    AI_THREAT_TETECTION = "aiThreatDetection"
    ALLOW_AFFILIATE = "allowAffiliate"
    BLOCK_BYPASS = "blockBypass"
    CACHE_BOOST = "cacheBoost"
    CATEGORIES = "categories"
    CNAME_FLATTENING = "cnameFlattening"
    CRYPTOJACKING = "cryptojacking"
    CSAM = "csam"
    DDNS = "ddns"
    DGA = "dga"
    DISGUISED_TRACKERS = "disguisedTrackers"
    DNS_REBINDING = "dnsRebinding"
    ECS = "ecs"
    GOOGLE_SAFE_BROWSING = "googleSafeBrowsing"
    IDN_HOMOGRAPHS = "idnHomographs"
    NRD = "nrd"
    PARKING = "parking"
    SAFESEARCH = "safeSearch"
    SERVICES = "services"
    THREAT_INTELLIGENCE_FEEDS = "threatIntelligenceFeeds"
    TYPOSQUATTING = "typosquatting"
    YOUTUBE_RESTRICTED_MODE = "youtubeRestrictedMode"


@dataclass
class SettingDescription:
    """SettingDescription class."""

    url: str
    name: str
