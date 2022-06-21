"""Python wrapper for NextDNS API."""
from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Iterable
from http import HTTPStatus
from typing import Any, cast

from aiohttp import ClientSession

from .const import (
    API_AI_THREAT_TETECTION,
    API_ALLOW_AFFILIATE,
    API_BLOCK_BYPASS,
    API_CACHE_BOOST,
    API_CNAME_FLATTENING,
    API_CRYPTOJACKING,
    API_CSAM,
    API_DGA,
    API_DISGUISED_TRACKERS,
    API_DNS_REBINDING,
    API_ECS,
    API_GOOGLE_SAFE_BROWSING,
    API_IDN_HOMOGRAPHS,
    API_NRD,
    API_PARKING,
    API_SAFESEARCH,
    API_THREAT_INTELLIGENCE_FEEDS,
    API_TYPOSQUATTING,
    API_YOUTUBE_RESTRICTED_MODE,
    ATTR_ANALYTICS,
    ATTR_CLEAR_LOGS,
    ATTR_ENABLED,
    ATTR_LOGS,
    ATTR_NAME,
    ATTR_PERFORMANCE,
    ATTR_PROFILE,
    ATTR_PROFILES,
    ATTR_TEST,
    ATTR_URL,
    ATTR_WEB3,
    ENDPOINTS,
    MAP_DNSSEC,
    MAP_ENCRYPTED,
    MAP_IP_VERSIONS,
    MAP_PROFILE,
    MAP_PROTOCOLS,
    MAP_SETTING,
    MAP_STATUS,
)
from .exceptions import (
    ApiError,
    InvalidApiKeyError,
    ProfileIdNotFoundError,
    ProfileNameNotFoundError,
    SettingNotSupportedError,
)
from .model import (
    AllAnalytics,
    AnalyticsDnssec,
    AnalyticsEncryption,
    AnalyticsIpVersions,
    AnalyticsProtocols,
    AnalyticsStatus,
    ConnectionStatus,
    Profile,
    ProfileInfo,
    Settings,
)

_LOGGER = logging.getLogger(__name__)


class NextDns:
    """Main class of NextDNS API wrapper."""

    def __init__(self, session: ClientSession, api_key: str) -> None:
        """Initialize NextDNS API wrapper."""
        self._session = session
        self._headers = {"X-Api-Key": api_key, "Content-Type": "application/json"}
        self._api_key = api_key
        self._profiles: list[ProfileInfo]

    @classmethod
    async def create(cls, session: ClientSession, api_key: str) -> NextDns:
        """Create a new instance."""
        instance = cls(session, api_key)
        await instance.initialize()

        return instance

    async def initialize(self) -> None:
        """Initialize."""
        _LOGGER.debug("Initializing with API Key: %s...", self._api_key[:10])
        self._profiles = list(self._parse_profiles(await self.get_profiles()))

    async def get_profiles(self) -> list[dict[str, str]]:
        """Get all profiles."""
        url = ENDPOINTS[ATTR_PROFILES]

        return cast(list[dict[str, str]], await self._http_request("get", url))

    async def get_profile(self, profile_id: str) -> Profile:
        """Get profile."""
        url = ENDPOINTS[ATTR_PROFILE].format(profile_id=profile_id)
        resp = await self._http_request("get", url)

        return Profile(
            **{MAP_PROFILE.get(key, key): value for key, value in resp.items()}
        )

    async def get_settings(self, profile_id: str) -> Settings:
        """Get profile settings."""
        profile_data = await self.get_profile(profile_id)

        return Settings(
            block_page=profile_data.settings["blockPage"][ATTR_ENABLED],
            cache_boost=profile_data.settings[ATTR_PERFORMANCE][API_CACHE_BOOST],
            cname_flattening=profile_data.settings[ATTR_PERFORMANCE][
                API_CNAME_FLATTENING
            ],
            anonymized_ecs=profile_data.settings[ATTR_PERFORMANCE][API_ECS],
            logs=profile_data.settings[ATTR_LOGS][ATTR_ENABLED],
            web3=profile_data.settings[ATTR_WEB3],
            allow_affiliate=profile_data.privacy[API_ALLOW_AFFILIATE],
            block_disguised_trackers=profile_data.privacy[API_DISGUISED_TRACKERS],
            ai_threat_detection=profile_data.security[API_AI_THREAT_TETECTION],
            block_csam=profile_data.security[API_CSAM],
            block_nrd=profile_data.security[API_NRD],
            block_parked_domains=profile_data.security[API_PARKING],
            cryptojacking_protection=profile_data.security[API_CRYPTOJACKING],
            dga_protection=profile_data.security[API_DGA],
            dns_rebinding_protection=profile_data.security[API_DNS_REBINDING],
            google_safe_browsing=profile_data.security[API_GOOGLE_SAFE_BROWSING],
            idn_homograph_attacks_protection=profile_data.security[API_IDN_HOMOGRAPHS],
            threat_intelligence_feeds=profile_data.security[
                API_THREAT_INTELLIGENCE_FEEDS
            ],
            typosquatting_protection=profile_data.security[API_TYPOSQUATTING],
            block_bypass_methods=profile_data.parental_control[API_BLOCK_BYPASS],
            safesearch=profile_data.parental_control[API_SAFESEARCH],
            youtube_restricted_mode=profile_data.parental_control[
                API_YOUTUBE_RESTRICTED_MODE
            ],
        )

    async def get_analytics_status(self, profile_id: str) -> AnalyticsStatus:
        """Get profile analytics status."""
        url = ENDPOINTS[ATTR_ANALYTICS].format(profile_id=profile_id, type="status")
        resp = await self._http_request("get", url)

        return AnalyticsStatus(
            **{MAP_STATUS[item["status"]]: item["queries"] for item in resp}
        )

    async def get_analytics_dnssec(self, profile_id: str) -> AnalyticsDnssec:
        """Get profile analytics dnssec."""
        url = ENDPOINTS[ATTR_ANALYTICS].format(profile_id=profile_id, type="dnssec")
        resp = await self._http_request("get", url)

        return AnalyticsDnssec(
            **{MAP_DNSSEC[item["validated"]]: item["queries"] for item in resp}
        )

    async def get_analytics_encryption(self, profile_id: str) -> AnalyticsEncryption:
        """Get profile analytics encryption."""
        url = ENDPOINTS[ATTR_ANALYTICS].format(profile_id=profile_id, type="encryption")
        resp = await self._http_request("get", url)

        return AnalyticsEncryption(
            **{MAP_ENCRYPTED[item["encrypted"]]: item["queries"] for item in resp}
        )

    async def get_analytics_ip_versions(self, profile_id: str) -> AnalyticsIpVersions:
        """Get profile analytics IP versions."""
        url = ENDPOINTS[ATTR_ANALYTICS].format(profile_id=profile_id, type="ipVersions")
        resp = await self._http_request("get", url)

        return AnalyticsIpVersions(
            **{MAP_IP_VERSIONS[item["version"]]: item["queries"] for item in resp}
        )

    async def get_analytics_protocols(self, profile_id: str) -> AnalyticsProtocols:
        """Get profile analytics protocols."""
        url = ENDPOINTS[ATTR_ANALYTICS].format(profile_id=profile_id, type="protocols")
        resp = await self._http_request("get", url)

        return AnalyticsProtocols(
            **{MAP_PROTOCOLS[item["protocol"]]: item["queries"] for item in resp}
        )

    async def connection_status(self, profile_id: str) -> ConnectionStatus:
        """Return True if the device is using NextDNS."""
        url = ENDPOINTS[ATTR_TEST].format(profile_id=profile_id)
        resp = await self._http_request("get", url)

        used_profile_id = None
        if status := resp["status"] == "ok":
            for item in self.profiles:
                if item.fingerprint == resp.get("profile"):
                    used_profile_id = item.id

        return ConnectionStatus(status, used_profile_id)

    async def clear_logs(self, profile_id: str) -> bool:
        """Get profile analytics dnssec."""
        url = ENDPOINTS[ATTR_CLEAR_LOGS].format(profile_id=profile_id)
        result = await self._http_request("delete", url)

        return result.get("success", False) is True

    async def get_all_analytics(self, profile_id: str) -> AllAnalytics:
        """Get profile analytics."""
        resp = await asyncio.gather(
            self.get_analytics_dnssec(profile_id),
            self.get_analytics_encryption(profile_id),
            self.get_analytics_ip_versions(profile_id),
            self.get_analytics_protocols(profile_id),
            self.get_analytics_status(profile_id),
        )

        return AllAnalytics(*resp)

    async def set_setting(self, profile_id: str, setting: str, state: bool) -> bool:
        """Toggle settings."""
        if setting not in MAP_SETTING:
            raise SettingNotSupportedError

        url = MAP_SETTING[setting][ATTR_URL].format(profile_id=profile_id)
        resp = await self._http_request(
            "patch", url, data={MAP_SETTING[setting][ATTR_NAME]: state}
        )

        return resp.get("success", False) is True

    async def _http_request(
        self, method: str, url: str, data: dict[str, Any] | None = None
    ) -> Any:
        """Make an HTTP request."""
        _LOGGER.debug("Requesting %s, method: %s, data: %s", url, method, data)

        if data:
            resp = await self._session.request(
                method, url, headers=self._headers, data=json.dumps(data)
            )
        else:
            resp = await self._session.request(method, url, headers=self._headers)

        _LOGGER.debug("Response status: %s", resp.status)

        if resp.status == HTTPStatus.FORBIDDEN.value:
            raise InvalidApiKeyError
        if resp.status == HTTPStatus.NO_CONTENT.value and method in ("delete", "patch"):
            return {"success": True}
        if resp.status != HTTPStatus.OK.value:
            result = await resp.json()
            raise ApiError(f"{resp.status}, {result['errors'][0]['code']}")

        result = await resp.json()

        _LOGGER.debug("Response: %s", result)

        return result["data"] if "data" in result else result

    def get_profile_name(self, profile_id: str) -> str:
        """Get profile name."""
        for profile in self.profiles:
            if profile.id == profile_id:
                return profile.name

        raise ProfileIdNotFoundError

    def get_profile_id(self, profile_name: str) -> str:
        """Get profile ID."""
        for profile in self.profiles:
            if profile.name == profile_name:
                return profile.id

        raise ProfileNameNotFoundError

    @staticmethod
    def _parse_profiles(profiles: list[dict[str, str]]) -> Iterable[ProfileInfo]:
        """Parse profiles."""
        for profile in profiles:
            yield ProfileInfo(profile["id"], profile["fingerprint"], profile["name"])

    @property
    def profiles(self) -> list[ProfileInfo]:
        """Return profiles."""
        return self._profiles
