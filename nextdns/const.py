"""NextDNS constants."""
from .model import ParentalControlServices, ParentalControlServicesAttrs

API_ENDPOINT = "https://api.nextdns.io"

API_AI_THREAT_TETECTION = "aiThreatDetection"
API_ALLOW_AFFILIATE = "allowAffiliate"
API_BLOCK_BYPASS = "blockBypass"
API_CACHE_BOOST = "cacheBoost"
API_CNAME_FLATTENING = "cnameFlattening"
API_CRYPTOJACKING = "cryptojacking"
API_CSAM = "csam"
API_DDNS = "ddns"
API_DGA = "dga"
API_DISGUISED_TRACKERS = "disguisedTrackers"
API_DNS_REBINDING = "dnsRebinding"
API_ECS = "ecs"
API_GOOGLE_SAFE_BROWSING = "googleSafeBrowsing"
API_IDN_HOMOGRAPHS = "idnHomographs"
API_NRD = "nrd"
API_PARKING = "parking"
API_SAFESEARCH = "safeSearch"
API_SERVICES = "services"
API_THREAT_INTELLIGENCE_FEEDS = "threatIntelligenceFeeds"
API_TYPOSQUATTING = "typosquatting"
API_YOUTUBE_RESTRICTED_MODE = "youtubeRestrictedMode"

ATTR_ANALYTICS = "analytics"
ATTR_ENABLED = "enabled"
ATTR_NAME = "name"
ATTR_PARENTAL_CONTROL = "parental_control"
ATTR_PARENTAL_CONTROL_SERVICE = "parental_control_service"
ATTR_PARENTAL_CONTROL_SERVICES = "parental_control_services"
ATTR_PERFORMANCE = "performance"
ATTR_PRIVACY = "privacy"
ATTR_PROFILE = "profile"
ATTR_PROFILES = "profiles"
ATTR_SECURITY = "security"
ATTR_SECURITY = "security"
ATTR_SETTINGS = "settings"
ATTR_TEST = "test"
ATTR_URL = "url"
ATTR_CLEAR_LOGS = "clear_logs"

ATTR_BLOCK_PAGE = "block_page"
ATTR_CACHE_BOOST = "cache_boost"
ATTR_CNAME_FLATTENING = "cname_flattening"
ATTR_ANONYMIZED_ECS = "anonymized_ecs"
ATTR_LOGS = "logs"
ATTR_WEB3 = "web3"

ATTR_ALLOW_AFFILIATE = "allow_affiliate"
ATTR_BLOCK_DISGUISED_TRACKERS = "block_disguised_trackers"

ATTR_AI_THREAT_DETECTION = "ai_threat_detection"
ATTR_BLOCK_CSAM = "block_csam"
ATTR_BLOCK_DDNS = "block_ddns"
ATTR_BLOCK_NRD = "block_nrd"
ATTR_BLOCK_PARKED_DOMAINS = "block_parked_domains"
ATTR_CRYPTOJACKING_PROTECTION = "cryptojacking_protection"
ATTR_DGA_PROTECTION = "dga_protection"
ATTR_DNS_REBINDING_PROTECTION = "dns_rebinding_protection"
ATTR_GOOGLE_SAFE_BROWSING = "google_safe_browsing"
ATTR_IDN_HOMOGRAPH_ATTACKS_PROTECTION = "idn_homograph_attacks_protection"
ATTR_THREAT_INTELLIGENCE_FEEDS = "threat_intelligence_feeds"
ATTR_TYPOSQUATTING_PROTECTION = "typosquatting_protection"

ATTR_BLOCK_BYPASS_METHODS = "block_bypass_methods"
ATTR_SAFESEARCH = "safesearch"
ATTR_YOUTUBE_RESTRICTED_MODE = "youtube_restricted_mode"

PARENTAL_CONTROL_SERVICES = (
    ParentalControlServicesAttrs.BLOCK_9GAG,
    ParentalControlServicesAttrs.BLOCK_AMAZON,
    ParentalControlServicesAttrs.BLOCK_BLIZZARD,
    ParentalControlServicesAttrs.BLOCK_DAILYMOTION,
    ParentalControlServicesAttrs.BLOCK_DISCORD,
    ParentalControlServicesAttrs.BLOCK_DISNEYPLUS,
    ParentalControlServicesAttrs.BLOCK_EBAY,
    ParentalControlServicesAttrs.BLOCK_FACEBOOK,
    ParentalControlServicesAttrs.BLOCK_FORTNITE,
    ParentalControlServicesAttrs.BLOCK_HULU,
    ParentalControlServicesAttrs.BLOCK_IMGUR,
    ParentalControlServicesAttrs.BLOCK_INSTAGRAM,
    ParentalControlServicesAttrs.BLOCK_LEAGUEOFLEGENDS,
    ParentalControlServicesAttrs.BLOCK_MESSENGER,
    ParentalControlServicesAttrs.BLOCK_MINECRAFT,
    ParentalControlServicesAttrs.BLOCK_NETFLIX,
    ParentalControlServicesAttrs.BLOCK_PINTEREST,
    ParentalControlServicesAttrs.BLOCK_PRIMEVIDEO,
    ParentalControlServicesAttrs.BLOCK_REDDIT,
    ParentalControlServicesAttrs.BLOCK_ROBLOX,
    ParentalControlServicesAttrs.BLOCK_SIGNAL,
    ParentalControlServicesAttrs.BLOCK_SKYPE,
    ParentalControlServicesAttrs.BLOCK_SNAPCHAT,
    ParentalControlServicesAttrs.BLOCK_SPOTIFY,
    ParentalControlServicesAttrs.BLOCK_STEAM,
    ParentalControlServicesAttrs.BLOCK_TELEGRAM,
    ParentalControlServicesAttrs.BLOCK_TIKTOK,
    ParentalControlServicesAttrs.BLOCK_TINDER,
    ParentalControlServicesAttrs.BLOCK_TUMBLR,
    ParentalControlServicesAttrs.BLOCK_TWITCH,
    ParentalControlServicesAttrs.BLOCK_TWITTER,
    ParentalControlServicesAttrs.BLOCK_VIMEO,
    ParentalControlServicesAttrs.BLOCK_VK,
    ParentalControlServicesAttrs.BLOCK_WHATSAPP,
    ParentalControlServicesAttrs.BLOCK_XBOXLIVE,
    ParentalControlServicesAttrs.BLOCK_YOUTUBE,
    ParentalControlServicesAttrs.BLOCK_ZOOM,
)

ENDPOINTS = {
    ATTR_ANALYTICS: "https://api.nextdns.io/profiles/{profile_id}/analytics/{type}",
    ATTR_CLEAR_LOGS: "https://api.nextdns.io/profiles/{profile_id}/logs",
    ATTR_PROFILE: "https://api.nextdns.io/profiles/{profile_id}",
    ATTR_PROFILES: "https://api.nextdns.io/profiles",
    ATTR_TEST: "https://{profile_id}.test.nextdns.io",
    ATTR_SECURITY: "https://api.nextdns.io/profiles/{profile_id}/security",
    ATTR_SETTINGS: "https://api.nextdns.io/profiles/{profile_id}/settings",
    ATTR_PERFORMANCE: "https://api.nextdns.io/profiles/{profile_id}/settings/performance",
    ATTR_PRIVACY: "https://api.nextdns.io/profiles/{profile_id}/privacy",
    ATTR_SECURITY: "https://api.nextdns.io/profiles/{profile_id}/security",
    ATTR_PARENTAL_CONTROL: "https://api.nextdns.io/profiles/{profile_id}/parentalControl",
    ATTR_PARENTAL_CONTROL_SERVICE: "https://api.nextdns.io/profiles/{profile_id}/parentalControl/services/{service}",
    ATTR_PARENTAL_CONTROL_SERVICES: "https://api.nextdns.io/profiles/{profile_id}/parentalControl/services",
    ATTR_LOGS: "https://api.nextdns.io/profiles/{profile_id}/settings/logs",
    ATTR_BLOCK_PAGE: "https://api.nextdns.io/profiles/{profile_id}/settings/blockPage",
}

MAP_DNSSEC = {False: "not_validated_queries", True: "validated_queries"}
MAP_ENCRYPTED = {False: "unencrypted_queries", True: "encrypted_queries"}
MAP_IP_VERSIONS = {4: "ipv4_queries", 6: "ipv6_queries"}
MAP_PROFILE = {"parentalControl": "parental_control"}
MAP_PROTOCOLS = {
    "DNS-over-HTTPS": "doh_queries",
    "DNS-over-QUIC": "doq_queries",
    "DNS-over-TLS": "dot_queries",
    "TCP": "tcp_queries",
    "UDP": "udp_queries",
}
MAP_STATUS = {
    "allowed": "allowed_queries",
    "blocked": "blocked_queries",
    "default": "default_queries",
    "relayed": "relayed_queries",
}

MAP_SETTING = {  # pylint: disable=consider-using-namedtuple-or-dataclass
    ATTR_BLOCK_PAGE: {
        ATTR_URL: ENDPOINTS[ATTR_BLOCK_PAGE],
        ATTR_NAME: ATTR_ENABLED,
    },
    ATTR_CACHE_BOOST: {
        ATTR_URL: ENDPOINTS[ATTR_PERFORMANCE],
        ATTR_NAME: API_CACHE_BOOST,
    },
    ATTR_CNAME_FLATTENING: {
        ATTR_URL: ENDPOINTS[ATTR_PERFORMANCE],
        ATTR_NAME: API_CNAME_FLATTENING,
    },
    ATTR_ANONYMIZED_ECS: {
        ATTR_URL: ENDPOINTS[ATTR_PERFORMANCE],
        ATTR_NAME: API_ECS,
    },
    ATTR_WEB3: {
        ATTR_URL: ENDPOINTS[ATTR_SETTINGS],
        ATTR_NAME: ATTR_WEB3,
    },
    ATTR_LOGS: {
        ATTR_URL: ENDPOINTS[ATTR_LOGS],
        ATTR_NAME: ATTR_ENABLED,
    },
    ATTR_ALLOW_AFFILIATE: {
        ATTR_URL: ENDPOINTS[ATTR_PRIVACY],
        ATTR_NAME: API_ALLOW_AFFILIATE,
    },
    ATTR_BLOCK_DISGUISED_TRACKERS: {
        ATTR_URL: ENDPOINTS[ATTR_PRIVACY],
        ATTR_NAME: API_DISGUISED_TRACKERS,
    },
    ATTR_AI_THREAT_DETECTION: {
        ATTR_URL: ENDPOINTS[ATTR_SECURITY],
        ATTR_NAME: API_AI_THREAT_TETECTION,
    },
    ATTR_BLOCK_CSAM: {
        ATTR_URL: ENDPOINTS[ATTR_SECURITY],
        ATTR_NAME: API_CSAM,
    },
    ATTR_BLOCK_DDNS: {
        ATTR_URL: ENDPOINTS[ATTR_SECURITY],
        ATTR_NAME: API_DDNS,
    },
    ATTR_BLOCK_NRD: {
        ATTR_URL: ENDPOINTS[ATTR_SECURITY],
        ATTR_NAME: API_NRD,
    },
    ATTR_BLOCK_PARKED_DOMAINS: {
        ATTR_URL: ENDPOINTS[ATTR_SECURITY],
        ATTR_NAME: API_PARKING,
    },
    ATTR_CRYPTOJACKING_PROTECTION: {
        ATTR_URL: ENDPOINTS[ATTR_SECURITY],
        ATTR_NAME: API_CRYPTOJACKING,
    },
    ATTR_DGA_PROTECTION: {
        ATTR_URL: ENDPOINTS[ATTR_SECURITY],
        ATTR_NAME: API_DGA,
    },
    ATTR_DNS_REBINDING_PROTECTION: {
        ATTR_URL: ENDPOINTS[ATTR_SECURITY],
        ATTR_NAME: API_DNS_REBINDING,
    },
    ATTR_GOOGLE_SAFE_BROWSING: {
        ATTR_URL: ENDPOINTS[ATTR_SECURITY],
        ATTR_NAME: API_GOOGLE_SAFE_BROWSING,
    },
    ATTR_IDN_HOMOGRAPH_ATTACKS_PROTECTION: {
        ATTR_URL: ENDPOINTS[ATTR_SECURITY],
        ATTR_NAME: API_IDN_HOMOGRAPHS,
    },
    ATTR_THREAT_INTELLIGENCE_FEEDS: {
        ATTR_URL: ENDPOINTS[ATTR_SECURITY],
        ATTR_NAME: API_THREAT_INTELLIGENCE_FEEDS,
    },
    ATTR_TYPOSQUATTING_PROTECTION: {
        ATTR_URL: ENDPOINTS[ATTR_SECURITY],
        ATTR_NAME: API_TYPOSQUATTING,
    },
    ATTR_BLOCK_BYPASS_METHODS: {
        ATTR_URL: ENDPOINTS[ATTR_PARENTAL_CONTROL],
        ATTR_NAME: API_BLOCK_BYPASS,
    },
    ATTR_SAFESEARCH: {
        ATTR_URL: ENDPOINTS[ATTR_PARENTAL_CONTROL],
        ATTR_NAME: API_SAFESEARCH,
    },
    ATTR_YOUTUBE_RESTRICTED_MODE: {
        ATTR_URL: ENDPOINTS[ATTR_PARENTAL_CONTROL],
        ATTR_NAME: API_YOUTUBE_RESTRICTED_MODE,
    },
    ParentalControlServicesAttrs.BLOCK_TIKTOK: {
        ATTR_URL: ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE],
        ATTR_NAME: ParentalControlServices.TIKTOK,
    },
    ParentalControlServicesAttrs.BLOCK_TINDER: {
        ATTR_URL: ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE],
        ATTR_NAME: ParentalControlServices.TINDER,
    },
    ParentalControlServicesAttrs.BLOCK_FACEBOOK: {
        ATTR_URL: ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE],
        ATTR_NAME: ParentalControlServices.FACEBOOK,
    },
    ParentalControlServicesAttrs.BLOCK_SNAPCHAT: {
        ATTR_URL: ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE],
        ATTR_NAME: ParentalControlServices.SNAPCHAT,
    },
    ParentalControlServicesAttrs.BLOCK_INSTAGRAM: {
        ATTR_URL: ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE],
        ATTR_NAME: ParentalControlServices.INSTAGRAM,
    },
    ParentalControlServicesAttrs.BLOCK_FORTNITE: {
        ATTR_URL: ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE],
        ATTR_NAME: ParentalControlServices.FORTNITE,
    },
    ParentalControlServicesAttrs.BLOCK_MESSENGER: {
        ATTR_URL: ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE],
        ATTR_NAME: ParentalControlServices.MESSENGER,
    },
    ParentalControlServicesAttrs.BLOCK_LEAGUEOFLEGENDS: {
        ATTR_URL: ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE],
        ATTR_NAME: ParentalControlServices.LEAGUEOFLEGENDS,
    },
    ParentalControlServicesAttrs.BLOCK_VK: {
        ATTR_URL: ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE],
        ATTR_NAME: ParentalControlServices.VK,
    },
    ParentalControlServicesAttrs.BLOCK_9GAG: {
        ATTR_URL: ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE],
        ATTR_NAME: ParentalControlServices.NINEGAG,
    },
    ParentalControlServicesAttrs.BLOCK_TUMBLR: {
        ATTR_URL: ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE],
        ATTR_NAME: ParentalControlServices.TUMBLR,
    },
    ParentalControlServicesAttrs.BLOCK_ROBLOX: {
        ATTR_URL: ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE],
        ATTR_NAME: ParentalControlServices.ROBLOX,
    },
    ParentalControlServicesAttrs.BLOCK_TWITCH: {
        ATTR_URL: ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE],
        ATTR_NAME: ParentalControlServices.TWITCH,
    },
    ParentalControlServicesAttrs.BLOCK_MINECRAFT: {
        ATTR_URL: ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE],
        ATTR_NAME: ParentalControlServices.MINECRAFT,
    },
    ParentalControlServicesAttrs.BLOCK_TWITTER: {
        ATTR_URL: ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE],
        ATTR_NAME: ParentalControlServices.TWITTER,
    },
    ParentalControlServicesAttrs.BLOCK_DISCORD: {
        ATTR_URL: ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE],
        ATTR_NAME: ParentalControlServices.DISCORD,
    },
    ParentalControlServicesAttrs.BLOCK_DAILYMOTION: {
        ATTR_URL: ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE],
        ATTR_NAME: ParentalControlServices.DAILYMOTION,
    },
    ParentalControlServicesAttrs.BLOCK_PINTEREST: {
        ATTR_URL: ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE],
        ATTR_NAME: ParentalControlServices.PINTEREST,
    },
    ParentalControlServicesAttrs.BLOCK_YOUTUBE: {
        ATTR_URL: ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE],
        ATTR_NAME: ParentalControlServices.YOUTUBE,
    },
    ParentalControlServicesAttrs.BLOCK_STEAM: {
        ATTR_URL: ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE],
        ATTR_NAME: ParentalControlServices.STEAM,
    },
    ParentalControlServicesAttrs.BLOCK_HULU: {
        ATTR_URL: ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE],
        ATTR_NAME: ParentalControlServices.HULU,
    },
    ParentalControlServicesAttrs.BLOCK_WHATSAPP: {
        ATTR_URL: ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE],
        ATTR_NAME: ParentalControlServices.WHATSAPP,
    },
    ParentalControlServicesAttrs.BLOCK_REDDIT: {
        ATTR_URL: ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE],
        ATTR_NAME: ParentalControlServices.REDDIT,
    },
    ParentalControlServicesAttrs.BLOCK_BLIZZARD: {
        ATTR_URL: ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE],
        ATTR_NAME: ParentalControlServices.BLIZZARD,
    },
    ParentalControlServicesAttrs.BLOCK_NETFLIX: {
        ATTR_URL: ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE],
        ATTR_NAME: ParentalControlServices.NETFLIX,
    },
    ParentalControlServicesAttrs.BLOCK_IMGUR: {
        ATTR_URL: ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE],
        ATTR_NAME: ParentalControlServices.IMGUR,
    },
    ParentalControlServicesAttrs.BLOCK_TELEGRAM: {
        ATTR_URL: ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE],
        ATTR_NAME: ParentalControlServices.TELEGRAM,
    },
    ParentalControlServicesAttrs.BLOCK_DISNEYPLUS: {
        ATTR_URL: ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE],
        ATTR_NAME: ParentalControlServices.DISNEYPLUS,
    },
    ParentalControlServicesAttrs.BLOCK_VIMEO: {
        ATTR_URL: ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE],
        ATTR_NAME: ParentalControlServices.VIMEO,
    },
    ParentalControlServicesAttrs.BLOCK_SKYPE: {
        ATTR_URL: ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE],
        ATTR_NAME: ParentalControlServices.SKYPE,
    },
    ParentalControlServicesAttrs.BLOCK_EBAY: {
        ATTR_URL: ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE],
        ATTR_NAME: ParentalControlServices.EBAY,
    },
    ParentalControlServicesAttrs.BLOCK_SPOTIFY: {
        ATTR_URL: ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE],
        ATTR_NAME: ParentalControlServices.SPOTIFY,
    },
    ParentalControlServicesAttrs.BLOCK_PRIMEVIDEO: {
        ATTR_URL: ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE],
        ATTR_NAME: ParentalControlServices.PRIMEVIDEO,
    },
    ParentalControlServicesAttrs.BLOCK_ZOOM: {
        ATTR_URL: ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE],
        ATTR_NAME: ParentalControlServices.ZOOM,
    },
    ParentalControlServicesAttrs.BLOCK_AMAZON: {
        ATTR_URL: ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE],
        ATTR_NAME: ParentalControlServices.AMAZON,
    },
    ParentalControlServicesAttrs.BLOCK_XBOXLIVE: {
        ATTR_URL: ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE],
        ATTR_NAME: ParentalControlServices.XBOXLIVE,
    },
    ParentalControlServicesAttrs.BLOCK_SIGNAL: {
        ATTR_URL: ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE],
        ATTR_NAME: ParentalControlServices.SIGNAL,
    },
}
