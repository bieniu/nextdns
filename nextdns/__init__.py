"""Python wrapper for NextDNS API."""
from __future__ import annotations

import asyncio
import logging
from collections.abc import Iterable
from http import HTTPStatus
from random import randrange
from typing import Any, cast

from aiohttp import ClientSession

from .const import (
    ATTR_ANALYTICS,
    ATTR_LOGS,
    ATTR_PROFILE,
    ATTR_PROFILES,
    ATTR_TEST,
    ENDPOINTS,
    MAP_DNSSEC,
    MAP_ENCRYPTED,
    MAP_IP_VERSIONS,
    MAP_PROFILE,
    MAP_PROTOCOLS,
    MAP_STATUS,
)
from .exceptions import ApiError, InvalidApiKeyError
from .model import (
    AllAnalytics,
    AnalyticsDnssec,
    AnalyticsEncrypted,
    AnalyticsIpVersions,
    AnalyticsProtocols,
    AnalyticsStatus,
    Profile,
    ProfileInfo,
)

_LOGGER = logging.getLogger(__name__)


class NextDns:
    """Main class of NextDNS API wrapper."""

    def __init__(self, session: ClientSession, api_key: str) -> None:
        """Initialize NextDNS API wrapper."""
        self._session = session
        self._headers = {"X-Api-Key": api_key}
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

    async def get_profile(self, profile: str) -> Profile:
        """Get profile."""
        url = ENDPOINTS[ATTR_PROFILE].format(profile=profile)
        resp = await self._http_request("get", url)

        return Profile(
            **{MAP_PROFILE.get(key, key): value for key, value in resp.items()}
        )

    async def get_analytics_status(self, profile: str) -> AnalyticsStatus:
        """Get profile analytics status."""
        url = ENDPOINTS[ATTR_ANALYTICS].format(profile=profile, type="status")
        resp = await self._http_request("get", url)

        return AnalyticsStatus(
            **{MAP_STATUS[item["status"]]: item["queries"] for item in resp}
        )

    async def get_analytics_dnssec(self, profile: str) -> AnalyticsDnssec:
        """Get profile analytics dnssec."""
        url = ENDPOINTS[ATTR_ANALYTICS].format(profile=profile, type="dnssec")
        resp = await self._http_request("get", url)

        return AnalyticsDnssec(
            **{MAP_DNSSEC[item["validated"]]: item["queries"] for item in resp}
        )

    async def get_analytics_encryption(self, profile: str) -> AnalyticsEncrypted:
        """Get profile analytics encryption."""
        url = ENDPOINTS[ATTR_ANALYTICS].format(profile=profile, type="encryption")
        resp = await self._http_request("get", url)

        return AnalyticsEncrypted(
            **{MAP_ENCRYPTED[item["encrypted"]]: item["queries"] for item in resp}
        )

    async def get_analytics_ip_versions(self, profile: str) -> AnalyticsIpVersions:
        """Get profile analytics IP versions."""
        url = ENDPOINTS[ATTR_ANALYTICS].format(profile=profile, type="ipVersions")
        resp = await self._http_request("get", url)

        return AnalyticsIpVersions(
            **{MAP_IP_VERSIONS[item["version"]]: item["queries"] for item in resp}
        )

    async def get_analytics_protocols(self, profile: str) -> AnalyticsProtocols:
        """Get profile analytics protocols."""
        url = ENDPOINTS[ATTR_ANALYTICS].format(profile=profile, type="protocols")
        resp = await self._http_request("get", url)

        return AnalyticsProtocols(
            **{MAP_PROTOCOLS[item["protocol"]]: item["queries"] for item in resp}
        )

    async def using_nextdns(self) -> bool:
        """Return True if the device is using NextDNS."""
        url = ENDPOINTS[ATTR_TEST].format(identifier=randrange(99999))
        resp = await self._http_request("get", url)

        return cast(bool, resp["status"] == "ok")

    async def clear_logs(self, profile: str) -> bool:
        """Get profile analytics dnssec."""
        url = ENDPOINTS[ATTR_LOGS].format(profile=profile)
        result = await self._http_request("delete", url)

        return result.get("success", False) is True

    async def get_all_analytics(self, profile: str) -> AllAnalytics:
        """Get profile analytics."""
        resp = await asyncio.gather(
            self.get_analytics_dnssec(profile),
            self.get_analytics_encryption(profile),
            self.get_analytics_ip_versions(profile),
            self.get_analytics_protocols(profile),
            self.get_analytics_status(profile),
        )

        return AllAnalytics(*resp)

    async def _http_request(self, method: str, url: str) -> Any:
        """Retrieve data from the device."""
        _LOGGER.debug("Requesting %s, method: %s", url, method)

        resp = await self._session.request(
            method, url, headers=self._headers, allow_redirects=False
        )

        _LOGGER.debug("Response status: %s", resp.status)

        if resp.status == HTTPStatus.FORBIDDEN.value:
            raise InvalidApiKeyError
        if resp.status == HTTPStatus.NO_CONTENT.value and method == "delete":
            return {"success": True}
        if resp.status != HTTPStatus.OK.value:
            result = await resp.json()
            raise ApiError(f"{resp.status}, {result['errors'][0]['code']}")

        result = await resp.json()

        return result["data"] if "data" in result else result

    @staticmethod
    def _parse_profiles(profiles: list[dict[str, str]]) -> Iterable[ProfileInfo]:
        """Parse profiles."""
        for profile in profiles:
            yield ProfileInfo(profile["id"], profile["fingerprint"], profile["name"])

    @property
    def profiles(self) -> list[ProfileInfo]:
        """Return profiles."""
        return self._profiles
