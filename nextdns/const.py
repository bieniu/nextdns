"""NextDNS constants."""
ATTR_ANALYTICS = "analytics"
ATTR_PROFILE = "profile"
ATTR_PROFILES = "profiles"

ENDPOINTS = {
    ATTR_ANALYTICS: "https://api.nextdns.io/profiles/{profile}/analytics/{type}",
    ATTR_PROFILE: "https://api.nextdns.io/profiles/{profile}",
    ATTR_PROFILES: "https://api.nextdns.io/profiles",
}

MAP_DNSSEC = {False: "not_validated_queries", True: "validated_queries"}
MAP_ENCRYPTED = {False: "unencrypted_queries", True: "encrypted_queries"}
MAP_IP_VERSIONS = {4: "ipv4_queries", 6: "ipv6_queries"}
MAP_PROFILE = {"parentalControl": "parental_control"}
MAP_PROTOCOLS = {
    "DNS-over-HTTPS": "doh_queries",
    "DNS-over-TLS": "dot_queries",
    "UDP": "udp_queries",
}
MAP_STATUS = {
    "allowed": "allowed_queries",
    "blocked": "blocked_queries",
    "default": "default_queries",
}
