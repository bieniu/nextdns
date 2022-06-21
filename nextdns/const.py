"""NextDNS constants."""
API_ENDPOINT = "https://api.nextdns.io"

ATTR_ANALYTICS = "analytics"
ATTR_BLOCK_PAGE = "block_page"
ATTR_CACHE_BOOST = "cache_boost"
ATTR_CNAME_FLATTENING = "cname_flattening"
ATTR_ECS = "ecs"
ATTR_LOGS = "logs"
ATTR_PROFILE = "profile"
ATTR_PROFILES = "profiles"
ATTR_SETTING_NAME = "setting_name"
ATTR_TEST = "test"
ATTR_URL = "url"
ATTR_WEB3 = "web3"


ENDPOINTS = {
    ATTR_ANALYTICS: "https://api.nextdns.io/profiles/{profile_id}/analytics/{type}",
    ATTR_LOGS: "https://api.nextdns.io/profiles/{profile_id}/logs",
    ATTR_PROFILE: "https://api.nextdns.io/profiles/{profile_id}",
    ATTR_PROFILES: "https://api.nextdns.io/profiles",
    ATTR_TEST: "https://{profile_id}.test.nextdns.io",
}

MAP_DNSSEC = {False: "not_validated_queries", True: "validated_queries"}
MAP_ENCRYPTED = {False: "unencrypted_queries", True: "encrypted_queries"}
MAP_IP_VERSIONS = {4: "ipv4_queries", 6: "ipv6_queries"}
MAP_PROFILE = {"parentalControl": "parental_control"}
MAP_PROTOCOLS = {
    "DNS-over-HTTPS": "doh_queries",
    "DNS-over-QUIC": "doq_queries",
    "DNS-over-TLS": "dot_queries",
    "UDP": "udp_queries",
}
MAP_STATUS = {
    "allowed": "allowed_queries",
    "blocked": "blocked_queries",
    "default": "default_queries",
    "relayed": "relayed_queries",
}

MAP_SETTING = {
    ATTR_BLOCK_PAGE: {
        ATTR_URL: "https://api.nextdns.io/profiles/{profile_id}/settings",
        ATTR_SETTING_NAME: "blockPage",
    },
    ATTR_CACHE_BOOST: {
        ATTR_URL: "https://api.nextdns.io/profiles/{profile_id}/settings/performance",
        ATTR_SETTING_NAME: "cacheBoost",
    },
    ATTR_CNAME_FLATTENING: {
        ATTR_URL: "https://api.nextdns.io/profiles/{profile_id}/settings/performance",
        ATTR_SETTING_NAME: "cnameFlattening",
    },
    ATTR_ECS: {
        ATTR_URL: "https://api.nextdns.io/profiles/{profile_id}/settings/performance",
        ATTR_SETTING_NAME: "web3",
    },
    ATTR_LOGS: {
        ATTR_URL: "https://api.nextdns.io/profiles/{profile_id}/settings",
        ATTR_SETTING_NAME: "ecs",
    },
    ATTR_WEB3: {
        ATTR_URL: "https://api.nextdns.io/profiles/{profile_id}/settings",
        ATTR_SETTING_NAME: "web3",
    },
}
