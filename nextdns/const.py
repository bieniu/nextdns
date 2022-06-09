"""NextDNS constants."""
ATTR_ANALYTICS = "analytics"
ATTR_PROFILE = "profile"
ATTR_PROFILES = "profiles"

ENDPOINTS = {
    ATTR_ANALYTICS: "https://api.nextdns.io/profiles/{profile}/analytics/{type}",
    ATTR_PROFILE: "https://api.nextdns.io/profiles/{profile}",
    ATTR_PROFILES: "https://api.nextdns.io/profiles",
}
