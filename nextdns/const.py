"""NextDNS constants."""
API_ENDPOINT = "https://api.nextdns.io"

ATTR_ANALYTICS = "analytics"
ATTR_LOGS = "logs"
ATTR_PROFILE = "profile"
ATTR_PROFILES = "profiles"
ATTR_TEST = "test"
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
    ATTR_WEB3: "https://api.nextdns.io/profiles/{profile_id}/settings",
}
