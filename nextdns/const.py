"""NextDNS constants."""
ATTR_ANALYTICS = "analytics"
ATTR_PROFILE = "profile"
ATTR_PROFILES = "profiles"

ENDPOINTS = {
    ATTR_ANALYTICS: "https://api.nextdns.io/profiles/{profile}/analytics/{type}",
    ATTR_PROFILE: "https://api.nextdns.io/profiles/{profile}",
    ATTR_PROFILES: "https://api.nextdns.io/profiles",
}

DNSSEC_MAP = {
    False: "not_validated_queries",
    True: "validated_queries",
}
ENCRYPTED_MAP = {
    False: "unencrypted_queries",
    True: "encrypted_queries",
}
IP_VERSIONS_MAP = {
    4: "ipv4_queries",
    6: "ipv6_queries",
}
PROTOCOLS_MAP = {
    "DNS-over-HTTPS": "doh_queries",
    "DNS-over-TLS": "dot_queries",
    "UDP": "udp_queries",
}
STATUS_MAP = {
    "allowed": "allowed_queries",
    "blocked": "blocked_queries",
    "default": "default_queries",
}
