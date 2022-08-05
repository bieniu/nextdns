"""Python wrapper for NextDNS API."""
from __future__ import annotations

import asyncio
import logging
from collections.abc import Iterable
from http import HTTPStatus
from typing import Any, cast

import orjson
from aiohttp import ClientSession

from .const import (
    ATTR_ANALYTICS,
    ATTR_CLEAR_LOGS,
    ATTR_ENABLED,
    ATTR_LOGS,
    ATTR_PARENTAL_CONTROL_CATEGORIES,
    ATTR_PARENTAL_CONTROL_SERVICES,
    ATTR_PERFORMANCE,
    ATTR_PROFILE,
    ATTR_PROFILES,
    ATTR_TEST,
    ATTR_WEB3,
    ENDPOINTS,
    MAP_DNSSEC,
    MAP_ENCRYPTED,
    MAP_IP_VERSIONS,
    MAP_PROFILE,
    MAP_PROTOCOLS,
    MAP_SETTING,
    MAP_STATUS,
    PARENTAL_CONTROL_CATEGORIES,
    PARENTAL_CONTROL_SERVICES,
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
    ApiNames,
    ConnectionStatus,
    ParentalControlCategories,
    ParentalControlServices,
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

        services = {
            service["id"]: service["active"]
            for service in profile_data.parental_control[ApiNames.SERVICES]
        }

        categories = {
            category["id"]: category["active"]
            for category in profile_data.parental_control[ApiNames.CATEGORIES]
        }

        return Settings(
            block_page=profile_data.settings["blockPage"][ATTR_ENABLED],
            cache_boost=profile_data.settings[ATTR_PERFORMANCE][ApiNames.CACHE_BOOST],
            cname_flattening=profile_data.settings[ATTR_PERFORMANCE][
                ApiNames.CNAME_FLATTENING
            ],
            anonymized_ecs=profile_data.settings[ATTR_PERFORMANCE][ApiNames.ECS],
            logs=profile_data.settings[ATTR_LOGS][ATTR_ENABLED],
            web3=profile_data.settings[ATTR_WEB3],
            allow_affiliate=profile_data.privacy[ApiNames.ALLOW_AFFILIATE],
            block_disguised_trackers=profile_data.privacy[ApiNames.DISGUISED_TRACKERS],
            ai_threat_detection=profile_data.security[ApiNames.AI_THREAT_TETECTION],
            block_csam=profile_data.security[ApiNames.CSAM],
            block_ddns=profile_data.security[ApiNames.DDNS],
            block_nrd=profile_data.security[ApiNames.NRD],
            block_parked_domains=profile_data.security[ApiNames.PARKING],
            cryptojacking_protection=profile_data.security[ApiNames.CRYPTOJACKING],
            dga_protection=profile_data.security[ApiNames.DGA],
            dns_rebinding_protection=profile_data.security[ApiNames.DNS_REBINDING],
            google_safe_browsing=profile_data.security[ApiNames.GOOGLE_SAFE_BROWSING],
            idn_homograph_attacks_protection=profile_data.security[
                ApiNames.IDN_HOMOGRAPHS
            ],
            threat_intelligence_feeds=profile_data.security[
                ApiNames.THREAT_INTELLIGENCE_FEEDS
            ],
            typosquatting_protection=profile_data.security[ApiNames.TYPOSQUATTING],
            block_bypass_methods=profile_data.parental_control[ApiNames.BLOCK_BYPASS],
            safesearch=profile_data.parental_control[ApiNames.SAFESEARCH],
            youtube_restricted_mode=profile_data.parental_control[
                ApiNames.YOUTUBE_RESTRICTED_MODE
            ],
            block_9gag=services.get(ParentalControlServices.NINEGAG, False),
            block_amazon=services.get(ParentalControlServices.AMAZON, False),
            block_blizzard=services.get(ParentalControlServices.BLIZZARD, False),
            block_dailymotion=services.get(ParentalControlServices.DAILYMOTION, False),
            block_discord=services.get(ParentalControlServices.DISCORD, False),
            block_disneyplus=services.get(ParentalControlServices.DISNEYPLUS, False),
            block_ebay=services.get(ParentalControlServices.EBAY, False),
            block_facebook=services.get(ParentalControlServices.FACEBOOK, False),
            block_fortnite=services.get(ParentalControlServices.FORTNITE, False),
            block_hulu=services.get(ParentalControlServices.HULU, False),
            block_imgur=services.get(ParentalControlServices.IMGUR, False),
            block_instagram=services.get(ParentalControlServices.INSTAGRAM, False),
            block_leagueoflegends=services.get(
                ParentalControlServices.LEAGUEOFLEGENDS, False
            ),
            block_messenger=services.get(ParentalControlServices.MESSENGER, False),
            block_minecraft=services.get(ParentalControlServices.MINECRAFT, False),
            block_netflix=services.get(ParentalControlServices.NETFLIX, False),
            block_pinterest=services.get(ParentalControlServices.PINTEREST, False),
            block_primevideo=services.get(ParentalControlServices.PRIMEVIDEO, False),
            block_reddit=services.get(ParentalControlServices.REDDIT, False),
            block_roblox=services.get(ParentalControlServices.ROBLOX, False),
            block_signal=services.get(ParentalControlServices.SIGNAL, False),
            block_skype=services.get(ParentalControlServices.SKYPE, False),
            block_snapchat=services.get(ParentalControlServices.SNAPCHAT, False),
            block_spotify=services.get(ParentalControlServices.SPOTIFY, False),
            block_steam=services.get(ParentalControlServices.STEAM, False),
            block_telegram=services.get(ParentalControlServices.TELEGRAM, False),
            block_tiktok=services.get(ParentalControlServices.TIKTOK, False),
            block_tinder=services.get(ParentalControlServices.TINDER, False),
            block_tumblr=services.get(ParentalControlServices.TUMBLR, False),
            block_twitch=services.get(ParentalControlServices.TWITCH, False),
            block_twitter=services.get(ParentalControlServices.TWITTER, False),
            block_vimeo=services.get(ParentalControlServices.VIMEO, False),
            block_vk=services.get(ParentalControlServices.VK, False),
            block_whatsapp=services.get(ParentalControlServices.WHATSAPP, False),
            block_xboxlive=services.get(ParentalControlServices.XBOXLIVE, False),
            block_youtube=services.get(ParentalControlServices.YOUTUBE, False),
            block_zoom=services.get(ParentalControlServices.ZOOM, False),
            block_dating=categories.get(ParentalControlCategories.DATING, False),
            block_gambling=categories.get(ParentalControlCategories.GAMBLING, False),
            block_piracy=categories.get(ParentalControlCategories.PIRACY, False),
            block_porn=categories.get(ParentalControlCategories.PORN, False),
            block_social_networks=categories.get(
                ParentalControlCategories.SOCIAL_NETWORKS, False
            ),
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
        data: dict[str, Any]
        resp = {}

        if setting not in MAP_SETTING:
            raise SettingNotSupportedError

        if setting in PARENTAL_CONTROL_CATEGORIES:
            url = MAP_SETTING[setting].url.format(
                profile_id=profile_id, category=MAP_SETTING[setting].name
            )
            data = {"active": state}
            try:
                resp = await self._http_request("patch", url, data=data)
            except ApiError as exc:
                if exc.status == "404, notFound" and state is True:
                    url = ENDPOINTS[ATTR_PARENTAL_CONTROL_CATEGORIES].format(
                        profile_id=profile_id
                    )
                    data = {"id": MAP_SETTING[setting].name}
                    resp = await self._http_request("post", url, data=data)
        elif setting in PARENTAL_CONTROL_SERVICES:
            url = MAP_SETTING[setting].url.format(
                profile_id=profile_id, service=MAP_SETTING[setting].name
            )
            data = {"active": state}
            try:
                resp = await self._http_request("patch", url, data=data)
            except ApiError as exc:
                if exc.status == "404, notFound" and state is True:
                    url = ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICES].format(
                        profile_id=profile_id
                    )
                    data = {"id": MAP_SETTING[setting].name}
                    resp = await self._http_request("post", url, data=data)
        else:
            url = MAP_SETTING[setting].url.format(profile_id=profile_id)
            data = {MAP_SETTING[setting].name: state}
            resp = await self._http_request("patch", url, data=data)

        return resp.get("success", False) is True

    async def _http_request(
        self, method: str, url: str, data: dict[str, Any] | None = None
    ) -> Any:
        """Make an HTTP request."""
        _LOGGER.debug("Requesting %s, method: %s, data: %s", url, method, data)

        if data:
            resp = await self._session.request(
                method,
                url,
                headers=self._headers,
                data=orjson.dumps(data),  # pylint: disable=no-member
            )
        else:
            resp = await self._session.request(method, url, headers=self._headers)

        _LOGGER.debug("Response status: %s", resp.status)

        if resp.status == HTTPStatus.FORBIDDEN.value:
            raise InvalidApiKeyError
        if resp.status == HTTPStatus.NO_CONTENT.value and method in (
            "delete",
            "patch",
            "post",
        ):
            return {"success": True}
        if resp.status != HTTPStatus.OK.value:
            result = await resp.json(loads=orjson.loads)  # pylint: disable=no-member
            raise ApiError(f"{resp.status}, {result['errors'][0]['code']}")

        result = await resp.json(loads=orjson.loads)  # pylint: disable=no-member

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
