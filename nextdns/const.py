"""NextDNS constants."""
from .model import (
    ApiNames,
    ParentalControlCategories,
    ParentalControlCategoriesAttrs,
    ParentalControlServices,
    ParentalControlServicesAttrs,
    SettingDescription,
)

API_ENDPOINT = "https://api.nextdns.io"

ATTR_ANALYTICS = "analytics"
ATTR_CLEAR_LOGS = "clear_logs"
ATTR_ENABLED = "enabled"
ATTR_PARENTAL_CONTROL = "parental_control"
ATTR_PARENTAL_CONTROL_CATEGORIES = "parental_control_categories"
ATTR_PARENTAL_CONTROL_CATEGORY = "parental_control_category"
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

PARENTAL_CONTROL_CATEGORIES = tuple(item for item in ParentalControlCategoriesAttrs)
PARENTAL_CONTROL_SERVICES = tuple(item for item in ParentalControlServicesAttrs)

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
    ATTR_PARENTAL_CONTROL_CATEGORY: "https://api.nextdns.io/profiles/{profile_id}/parentalControl/categories/{category}",
    ATTR_PARENTAL_CONTROL_CATEGORIES: "https://api.nextdns.io/profiles/{profile_id}/parentalControl/categories",
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
    "DNS-over-HTTP/3": "doh3_queries",
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

MAP_SETTING = {
    ATTR_BLOCK_PAGE: SettingDescription(ENDPOINTS[ATTR_BLOCK_PAGE], ATTR_ENABLED),
    ATTR_CACHE_BOOST: SettingDescription(
        ENDPOINTS[ATTR_PERFORMANCE], ApiNames.CACHE_BOOST
    ),
    ATTR_CNAME_FLATTENING: SettingDescription(
        ENDPOINTS[ATTR_PERFORMANCE], ApiNames.CNAME_FLATTENING
    ),
    ATTR_ANONYMIZED_ECS: SettingDescription(ENDPOINTS[ATTR_PERFORMANCE], ApiNames.ECS),
    ATTR_WEB3: SettingDescription(ENDPOINTS[ATTR_SETTINGS], ATTR_WEB3),
    ATTR_LOGS: SettingDescription(ENDPOINTS[ATTR_LOGS], ATTR_ENABLED),
    ATTR_ALLOW_AFFILIATE: SettingDescription(
        ENDPOINTS[ATTR_PRIVACY], ApiNames.ALLOW_AFFILIATE
    ),
    ATTR_BLOCK_DISGUISED_TRACKERS: SettingDescription(
        ENDPOINTS[ATTR_PRIVACY], ApiNames.DISGUISED_TRACKERS
    ),
    ATTR_AI_THREAT_DETECTION: SettingDescription(
        ENDPOINTS[ATTR_SECURITY], ApiNames.AI_THREAT_TETECTION
    ),
    ATTR_BLOCK_CSAM: SettingDescription(ENDPOINTS[ATTR_SECURITY], ApiNames.CSAM),
    ATTR_BLOCK_DDNS: SettingDescription(ENDPOINTS[ATTR_SECURITY], ApiNames.DDNS),
    ATTR_BLOCK_NRD: SettingDescription(ENDPOINTS[ATTR_SECURITY], ApiNames.NRD),
    ATTR_BLOCK_PARKED_DOMAINS: SettingDescription(
        ENDPOINTS[ATTR_SECURITY], ApiNames.PARKING
    ),
    ATTR_CRYPTOJACKING_PROTECTION: SettingDescription(
        ENDPOINTS[ATTR_SECURITY], ApiNames.CRYPTOJACKING
    ),
    ATTR_DGA_PROTECTION: SettingDescription(ENDPOINTS[ATTR_SECURITY], ApiNames.DGA),
    ATTR_DNS_REBINDING_PROTECTION: SettingDescription(
        ENDPOINTS[ATTR_SECURITY], ApiNames.DNS_REBINDING
    ),
    ATTR_GOOGLE_SAFE_BROWSING: SettingDescription(
        ENDPOINTS[ATTR_SECURITY], ApiNames.GOOGLE_SAFE_BROWSING
    ),
    ATTR_IDN_HOMOGRAPH_ATTACKS_PROTECTION: SettingDescription(
        ENDPOINTS[ATTR_SECURITY], ApiNames.IDN_HOMOGRAPHS
    ),
    ATTR_THREAT_INTELLIGENCE_FEEDS: SettingDescription(
        ENDPOINTS[ATTR_SECURITY], ApiNames.THREAT_INTELLIGENCE_FEEDS
    ),
    ATTR_TYPOSQUATTING_PROTECTION: SettingDescription(
        ENDPOINTS[ATTR_SECURITY], ApiNames.TYPOSQUATTING
    ),
    ATTR_BLOCK_BYPASS_METHODS: SettingDescription(
        ENDPOINTS[ATTR_PARENTAL_CONTROL], ApiNames.BLOCK_BYPASS
    ),
    ATTR_SAFESEARCH: SettingDescription(
        ENDPOINTS[ATTR_PARENTAL_CONTROL], ApiNames.SAFESEARCH
    ),
    ATTR_YOUTUBE_RESTRICTED_MODE: SettingDescription(
        ENDPOINTS[ATTR_PARENTAL_CONTROL], ApiNames.YOUTUBE_RESTRICTED_MODE
    ),
    ParentalControlServicesAttrs.BLOCK_TIKTOK: SettingDescription(
        ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE], ParentalControlServices.TIKTOK
    ),
    ParentalControlServicesAttrs.BLOCK_TINDER: SettingDescription(
        ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE], ParentalControlServices.TINDER
    ),
    ParentalControlServicesAttrs.BLOCK_FACEBOOK: SettingDescription(
        ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE], ParentalControlServices.FACEBOOK
    ),
    ParentalControlServicesAttrs.BLOCK_SNAPCHAT: SettingDescription(
        ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE], ParentalControlServices.SNAPCHAT
    ),
    ParentalControlServicesAttrs.BLOCK_INSTAGRAM: SettingDescription(
        ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE], ParentalControlServices.INSTAGRAM
    ),
    ParentalControlServicesAttrs.BLOCK_FORTNITE: SettingDescription(
        ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE], ParentalControlServices.FORTNITE
    ),
    ParentalControlServicesAttrs.BLOCK_MESSENGER: SettingDescription(
        ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE], ParentalControlServices.MESSENGER
    ),
    ParentalControlServicesAttrs.BLOCK_LEAGUEOFLEGENDS: SettingDescription(
        ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE],
        ParentalControlServices.LEAGUEOFLEGENDS,
    ),
    ParentalControlServicesAttrs.BLOCK_VK: SettingDescription(
        ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE], ParentalControlServices.VK
    ),
    ParentalControlServicesAttrs.BLOCK_9GAG: SettingDescription(
        ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE], ParentalControlServices.NINEGAG
    ),
    ParentalControlServicesAttrs.BLOCK_TUMBLR: SettingDescription(
        ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE], ParentalControlServices.TUMBLR
    ),
    ParentalControlServicesAttrs.BLOCK_ROBLOX: SettingDescription(
        ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE], ParentalControlServices.ROBLOX
    ),
    ParentalControlServicesAttrs.BLOCK_TWITCH: SettingDescription(
        ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE], ParentalControlServices.TWITCH
    ),
    ParentalControlServicesAttrs.BLOCK_MINECRAFT: SettingDescription(
        ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE], ParentalControlServices.MINECRAFT
    ),
    ParentalControlServicesAttrs.BLOCK_TWITTER: SettingDescription(
        ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE], ParentalControlServices.TWITTER
    ),
    ParentalControlServicesAttrs.BLOCK_DISCORD: SettingDescription(
        ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE], ParentalControlServices.DISCORD
    ),
    ParentalControlServicesAttrs.BLOCK_DAILYMOTION: SettingDescription(
        ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE], ParentalControlServices.DAILYMOTION
    ),
    ParentalControlServicesAttrs.BLOCK_PINTEREST: SettingDescription(
        ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE], ParentalControlServices.PINTEREST
    ),
    ParentalControlServicesAttrs.BLOCK_YOUTUBE: SettingDescription(
        ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE], ParentalControlServices.YOUTUBE
    ),
    ParentalControlServicesAttrs.BLOCK_STEAM: SettingDescription(
        ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE], ParentalControlServices.STEAM
    ),
    ParentalControlServicesAttrs.BLOCK_HULU: SettingDescription(
        ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE], ParentalControlServices.HULU
    ),
    ParentalControlServicesAttrs.BLOCK_WHATSAPP: SettingDescription(
        ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE], ParentalControlServices.WHATSAPP
    ),
    ParentalControlServicesAttrs.BLOCK_REDDIT: SettingDescription(
        ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE], ParentalControlServices.REDDIT
    ),
    ParentalControlServicesAttrs.BLOCK_BLIZZARD: SettingDescription(
        ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE], ParentalControlServices.BLIZZARD
    ),
    ParentalControlServicesAttrs.BLOCK_NETFLIX: SettingDescription(
        ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE], ParentalControlServices.NETFLIX
    ),
    ParentalControlServicesAttrs.BLOCK_IMGUR: SettingDescription(
        ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE], ParentalControlServices.IMGUR
    ),
    ParentalControlServicesAttrs.BLOCK_TELEGRAM: SettingDescription(
        ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE], ParentalControlServices.TELEGRAM
    ),
    ParentalControlServicesAttrs.BLOCK_DISNEYPLUS: SettingDescription(
        ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE], ParentalControlServices.DISNEYPLUS
    ),
    ParentalControlServicesAttrs.BLOCK_VIMEO: SettingDescription(
        ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE], ParentalControlServices.VIMEO
    ),
    ParentalControlServicesAttrs.BLOCK_SKYPE: SettingDescription(
        ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE],
        ParentalControlServices.SKYPE,
    ),
    ParentalControlServicesAttrs.BLOCK_EBAY: SettingDescription(
        ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE], ParentalControlServices.EBAY
    ),
    ParentalControlServicesAttrs.BLOCK_SPOTIFY: SettingDescription(
        ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE], ParentalControlServices.SPOTIFY
    ),
    ParentalControlServicesAttrs.BLOCK_PRIMEVIDEO: SettingDescription(
        ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE], ParentalControlServices.PRIMEVIDEO
    ),
    ParentalControlServicesAttrs.BLOCK_ZOOM: SettingDescription(
        ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE], ParentalControlServices.ZOOM
    ),
    ParentalControlServicesAttrs.BLOCK_AMAZON: SettingDescription(
        ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE], ParentalControlServices.AMAZON
    ),
    ParentalControlServicesAttrs.BLOCK_XBOXLIVE: SettingDescription(
        ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE], ParentalControlServices.XBOXLIVE
    ),
    ParentalControlServicesAttrs.BLOCK_SIGNAL: SettingDescription(
        ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE], ParentalControlServices.SIGNAL
    ),
    ParentalControlCategoriesAttrs.BLOCK_DATING: SettingDescription(
        ENDPOINTS[ATTR_PARENTAL_CONTROL_CATEGORY], ParentalControlCategories.DATING
    ),
    ParentalControlCategoriesAttrs.BLOCK_GAMBLING: SettingDescription(
        ENDPOINTS[ATTR_PARENTAL_CONTROL_CATEGORY], ParentalControlCategories.GAMBLING
    ),
    ParentalControlCategoriesAttrs.BLOCK_PIRACY: SettingDescription(
        ENDPOINTS[ATTR_PARENTAL_CONTROL_CATEGORY], ParentalControlCategories.PIRACY
    ),
    ParentalControlCategoriesAttrs.BLOCK_PORN: SettingDescription(
        ENDPOINTS[ATTR_PARENTAL_CONTROL_CATEGORY], ParentalControlCategories.PORN
    ),
    ParentalControlCategoriesAttrs.BLOCK_SOCIAL_NETWORKS: SettingDescription(
        ENDPOINTS[ATTR_PARENTAL_CONTROL_CATEGORY],
        ParentalControlCategories.SOCIAL_NETWORKS,
    ),
}
