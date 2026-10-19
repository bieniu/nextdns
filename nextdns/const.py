"""NextDNS constants."""

from aiohttp import ClientTimeout

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
ATTR_GET_LOGS = "get_logs"
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
ATTR_SETTINGS = "settings"
ATTR_TEST = "test"

ATTR_ANONYMIZED_ECS = "anonymized_ecs"
ATTR_BAV = "bav"
ATTR_BLOCK_PAGE = "block_page"
ATTR_CACHE_BOOST = "cache_boost"
ATTR_CNAME_FLATTENING = "cname_flattening"
ATTR_LOGS = "logs"
ATTR_LOGS_LOCATION = "logs_location"
ATTR_LOGS_RETENTION = "logs_retention"
ATTR_RETENTION = "retention"
ATTR_LOCATION = "location"
ATTR_WEB3 = "web3"

ATTR_ALLOW_AFFILIATE = "allow_affiliate"
ATTR_BLOCK_DISGUISED_TRACKERS = "block_disguised_trackers"

ATTR_AI_THREAT_DETECTION = "ai_threat_detection"
ATTR_BLOCK_CSAM = "block_csam"
ATTR_BLOCK_DATA_DROP_SERVICES = "block_data_drop_services"
ATTR_BLOCK_DECENTRALIZED_WEB_GATEWAYS = "block_decentralized_web_gateways"
ATTR_BLOCK_DDNS = "block_ddns"
ATTR_BLOCK_FAST_FLUX_NETWORKS = "block_fast_flux_networks"
ATTR_BLOCK_FREE_HOSTING_DOMAINS = "block_free_hosting_domains"
ATTR_BLOCK_HIGH_RISK_TLDS = "block_high_risk_tlds"
ATTR_BLOCK_NEWLY_ACTIVE_DOMAINS = "block_newly_active_domains"
ATTR_BLOCK_NRD = "block_nrd"
ATTR_BLOCK_PARKED_DOMAINS = "block_parked_domains"
ATTR_BLOCK_RESIDENTIAL_HOSTING = "block_residential_hosting"
ATTR_BLOCK_TUNNELING_ENDPOINTS = "block_tunneling_endpoints"
ATTR_BLOCK_UNTRUSTED_CERTIFICATES = "block_untrusted_certificates"
ATTR_CRYPTOJACKING_PROTECTION = "cryptojacking_protection"
ATTR_DGA_PROTECTION = "dga_protection"
ATTR_DNS_DATA_EXFILTRATION_PROTECTION = "dns_data_exfiltration_protection"
ATTR_DNS_PAYLOAD_DELIVERY_PROTECTION = "dns_payload_delivery_protection"
ATTR_DNS_REBINDING_PROTECTION = "dns_rebinding_protection"
ATTR_GOOGLE_SAFE_BROWSING = "google_safe_browsing"
ATTR_IDN_HOMOGRAPH_ATTACKS_PROTECTION = "idn_homograph_attacks_protection"
ATTR_THREAT_INTELLIGENCE_FEEDS = "threat_intelligence_feeds"
ATTR_TYPOSQUATTING_PROTECTION = "typosquatting_protection"

ATTR_BLOCK_BYPASS_METHODS = "block_bypass_methods"
ATTR_SAFESEARCH = "safesearch"
ATTR_YOUTUBE_RESTRICTED_MODE = "youtube_restricted_mode"

PARENTAL_CONTROL_CATEGORIES = frozenset(ParentalControlCategoriesAttrs)
PARENTAL_CONTROL_SERVICES = frozenset(ParentalControlServicesAttrs)

_PROFILES = API_ENDPOINT + "/profiles/{profile_id}"

ENDPOINTS = {
    ATTR_ANALYTICS: _PROFILES + "/analytics/{type}",
    ATTR_CLEAR_LOGS: _PROFILES + "/logs",
    ATTR_GET_LOGS: _PROFILES + "/logs/download",
    ATTR_PROFILE: _PROFILES,
    ATTR_PROFILES: API_ENDPOINT + "/profiles",
    ATTR_TEST: "https://{profile_id}.test.nextdns.io",
    ATTR_SECURITY: _PROFILES + "/security",
    ATTR_SETTINGS: _PROFILES + "/settings",
    ATTR_PERFORMANCE: _PROFILES + "/settings/performance",
    ATTR_PRIVACY: _PROFILES + "/privacy",
    ATTR_PARENTAL_CONTROL: _PROFILES + "/parentalControl",
    ATTR_PARENTAL_CONTROL_CATEGORY: _PROFILES
    + "/parentalControl/categories/{category}",
    ATTR_PARENTAL_CONTROL_CATEGORIES: _PROFILES + "/parentalControl/categories",
    ATTR_PARENTAL_CONTROL_SERVICE: _PROFILES + "/parentalControl/services/{service}",
    ATTR_PARENTAL_CONTROL_SERVICES: _PROFILES + "/parentalControl/services",
    ATTR_LOGS: _PROFILES + "/settings/logs",
    ATTR_LOGS_LOCATION: _PROFILES + "/settings/logs/location",
    ATTR_LOGS_RETENTION: _PROFILES + "/settings/logs/retention",
    ATTR_BLOCK_PAGE: _PROFILES + "/settings/blockPage",
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
    ATTR_BAV: SettingDescription(ENDPOINTS[ATTR_SETTINGS], ATTR_BAV),
    ATTR_WEB3: SettingDescription(ENDPOINTS[ATTR_SETTINGS], ATTR_WEB3),
    ATTR_LOGS: SettingDescription(ENDPOINTS[ATTR_LOGS], ATTR_ENABLED),
    ATTR_LOGS_LOCATION: SettingDescription(ENDPOINTS[ATTR_LOGS], ATTR_LOCATION),
    ATTR_LOGS_RETENTION: SettingDescription(ENDPOINTS[ATTR_LOGS], ATTR_RETENTION),
    ATTR_ALLOW_AFFILIATE: SettingDescription(
        ENDPOINTS[ATTR_PRIVACY], ApiNames.ALLOW_AFFILIATE
    ),
    ATTR_BLOCK_DISGUISED_TRACKERS: SettingDescription(
        ENDPOINTS[ATTR_PRIVACY], ApiNames.DISGUISED_TRACKERS
    ),
    ATTR_AI_THREAT_DETECTION: SettingDescription(
        ENDPOINTS[ATTR_SECURITY], ApiNames.AI_THREAT_DETECTION
    ),
    ATTR_BLOCK_CSAM: SettingDescription(ENDPOINTS[ATTR_SECURITY], ApiNames.CSAM),
    ATTR_BLOCK_DATA_DROP_SERVICES: SettingDescription(
        ENDPOINTS[ATTR_SECURITY], ApiNames.DATA_DROP_SERVICES
    ),
    ATTR_BLOCK_DECENTRALIZED_WEB_GATEWAYS: SettingDescription(
        ENDPOINTS[ATTR_SECURITY], ApiNames.DECENTRALIZED_WEB_GATEWAYS
    ),
    ATTR_BLOCK_DDNS: SettingDescription(ENDPOINTS[ATTR_SECURITY], ApiNames.DDNS),
    ATTR_BLOCK_FAST_FLUX_NETWORKS: SettingDescription(
        ENDPOINTS[ATTR_SECURITY], ApiNames.FAST_FLUX_NETWORKS
    ),
    ATTR_BLOCK_FREE_HOSTING_DOMAINS: SettingDescription(
        ENDPOINTS[ATTR_SECURITY], ApiNames.FREE_HOSTING_DOMAINS
    ),
    ATTR_BLOCK_HIGH_RISK_TLDS: SettingDescription(
        ENDPOINTS[ATTR_SECURITY], ApiNames.HIGH_RISK_TLDS
    ),
    ATTR_BLOCK_NEWLY_ACTIVE_DOMAINS: SettingDescription(
        ENDPOINTS[ATTR_SECURITY], ApiNames.NEWLY_ACTIVE_DOMAINS
    ),
    ATTR_BLOCK_NRD: SettingDescription(ENDPOINTS[ATTR_SECURITY], ApiNames.NRD),
    ATTR_BLOCK_PARKED_DOMAINS: SettingDescription(
        ENDPOINTS[ATTR_SECURITY], ApiNames.PARKING
    ),
    ATTR_BLOCK_RESIDENTIAL_HOSTING: SettingDescription(
        ENDPOINTS[ATTR_SECURITY], ApiNames.RESIDENTIAL_HOSTING
    ),
    ATTR_BLOCK_TUNNELING_ENDPOINTS: SettingDescription(
        ENDPOINTS[ATTR_SECURITY], ApiNames.TUNNELING_ENDPOINTS
    ),
    ATTR_BLOCK_UNTRUSTED_CERTIFICATES: SettingDescription(
        ENDPOINTS[ATTR_SECURITY], ApiNames.UNTRUSTED_CERTIFICATES
    ),
    ATTR_CRYPTOJACKING_PROTECTION: SettingDescription(
        ENDPOINTS[ATTR_SECURITY], ApiNames.CRYPTOJACKING
    ),
    ATTR_DGA_PROTECTION: SettingDescription(ENDPOINTS[ATTR_SECURITY], ApiNames.DGA),
    ATTR_DNS_DATA_EXFILTRATION_PROTECTION: SettingDescription(
        ENDPOINTS[ATTR_SECURITY], ApiNames.DNS_DATA_EXFILTRATION
    ),
    ATTR_DNS_PAYLOAD_DELIVERY_PROTECTION: SettingDescription(
        ENDPOINTS[ATTR_SECURITY], ApiNames.DNS_PAYLOAD_DELIVERY
    ),
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
    # Derived from the *Attrs enums: services by value (block_google_chat ->
    # google-chat), categories by member name (BLOCK_X -> X).
    **{
        attr: SettingDescription(
            ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICE],
            ParentalControlServices(attr.removeprefix("block_").replace("_", "-")),
        )
        for attr in ParentalControlServicesAttrs
    },
    **{
        attr: SettingDescription(
            ENDPOINTS[ATTR_PARENTAL_CONTROL_CATEGORY],
            ParentalControlCategories[attr.name.removeprefix("BLOCK_")],
        )
        for attr in ParentalControlCategoriesAttrs
    },
}

ALLOWED_LOGS_LOCATION = ("ch", "eu", "gb", "us")
ALLOWED_LOGS_RETENTION = (1, 6, 24, 168, 720, 2160, 4320, 8760, 17520)

TIMEOUT = ClientTimeout(total=5)
STOP_AFTER_ATTEMPT = 3
WAIT_INCREMENT = 2
WAIT_START = 2

HTTP_STATUS_TIMEOUT = 524
