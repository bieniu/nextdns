"""Tests for nextdns package."""
import json
import re
from http import HTTPStatus

import aiohttp
import pytest
from aioresponses import aioresponses

from nextdns import (
    ATTR_ANALYTICS,
    ATTR_CLEAR_LOGS,
    ATTR_GET_LOGS,
    ATTR_LOGS,
    ATTR_PARENTAL_CONTROL_CATEGORIES,
    ATTR_PARENTAL_CONTROL_SERVICES,
    ATTR_PROFILE,
    ATTR_PROFILES,
    ATTR_TEST,
    ENDPOINTS,
    MAP_SETTING,
    ApiError,
    InvalidApiKeyError,
    NextDns,
    ProfileIdNotFoundError,
    ProfileNameNotFoundError,
    SettingNotSupportedError,
)
from nextdns.const import ATTR_BLOCK_PAGE

PROFILE_ID = "fakepr"


@pytest.mark.asyncio
async def test_valid_data():  # pylint: disable=too-many-locals,too-many-statements
    """Test with valid data."""
    with open("tests/fixtures/profiles.json", encoding="utf-8") as file:
        profiles_data = json.load(file)
    with open("tests/fixtures/dnssec.json", encoding="utf-8") as file:
        dnssec_data = json.load(file)
    with open("tests/fixtures/encryption.json", encoding="utf-8") as file:
        encryption_data = json.load(file)
    with open("tests/fixtures/ip_versions.json", encoding="utf-8") as file:
        ip_versions_data = json.load(file)
    with open("tests/fixtures/protocols.json", encoding="utf-8") as file:
        protocols_data = json.load(file)
    with open("tests/fixtures/status.json", encoding="utf-8") as file:
        status_data = json.load(file)
    with open("tests/fixtures/test.json", encoding="utf-8") as file:
        test_data = json.load(file)
    with open("tests/fixtures/profile.json", encoding="utf-8") as file:
        profile_data = json.load(file)

    session = aiohttp.ClientSession()

    with aioresponses() as session_mock:
        session_mock.get(ENDPOINTS[ATTR_PROFILES], payload=profiles_data)
        session_mock.get(
            ENDPOINTS[ATTR_ANALYTICS].format(profile_id=PROFILE_ID, type="dnssec"),
            payload=dnssec_data,
        )
        session_mock.get(
            ENDPOINTS[ATTR_ANALYTICS].format(profile_id=PROFILE_ID, type="encryption"),
            payload=encryption_data,
        )
        session_mock.get(
            ENDPOINTS[ATTR_ANALYTICS].format(profile_id=PROFILE_ID, type="ipVersions"),
            payload=ip_versions_data,
        )
        session_mock.get(
            ENDPOINTS[ATTR_ANALYTICS].format(profile_id=PROFILE_ID, type="protocols"),
            payload=protocols_data,
        )
        session_mock.get(
            ENDPOINTS[ATTR_ANALYTICS].format(profile_id=PROFILE_ID, type="status"),
            payload=status_data,
        )
        session_mock.get(
            ENDPOINTS[ATTR_TEST].format(profile_id=PROFILE_ID), payload=test_data
        )
        session_mock.get(
            ENDPOINTS[ATTR_PROFILE].format(profile_id=PROFILE_ID), payload=profile_data
        )

        nextdns = await NextDns.create(session, "fakeapikey")

        analitycs = await nextdns.get_all_analytics(PROFILE_ID)
        dnssec = analitycs.dnssec
        encryption = analitycs.encryption
        ip_versions = analitycs.ip_versions
        protocols = analitycs.protocols
        status = analitycs.status
        connection_status = await nextdns.connection_status(PROFILE_ID)
        settings = await nextdns.get_settings(PROFILE_ID)

    await session.close()

    assert len(nextdns.profiles) == 1
    assert nextdns.profiles[0].id == PROFILE_ID
    assert nextdns.profiles[0].fingerprint == "fakeprofile12"
    assert nextdns.profiles[0].name == "Fake Profile"

    assert dnssec.not_validated_queries == 793765
    assert dnssec.validated_queries == 49451
    assert dnssec.validated_queries_ratio == 5.9

    assert encryption.encrypted_queries == 1380260
    assert encryption.unencrypted_queries == 40
    assert encryption.encrypted_queries_ratio == 100.0

    assert ip_versions.ipv6_queries == 42117
    assert ip_versions.ipv4_queries == 1338183
    assert ip_versions.ipv6_queries_ratio == 3.1

    assert protocols.doh_queries == 99999
    assert protocols.doh3_queries == 88888
    assert protocols.doq_queries == 55555
    assert protocols.dot_queries == 101010
    assert protocols.tcp_queries == 33333
    assert protocols.udp_queries == 44444
    assert protocols.doh_queries_ratio == 23.6
    assert protocols.doh3_queries_ratio == 21.0
    assert protocols.doq_queries_ratio == 13.1
    assert protocols.dot_queries_ratio == 23.9
    assert protocols.tcp_queries_ratio == 7.9
    assert protocols.udp_queries_ratio == 10.5

    assert status.all_queries == 1380300
    assert status.allowed_queries == 5452
    assert status.blocked_queries == 530805
    assert status.default_queries == 837764
    assert status.relayed_queries == 6279
    assert status.blocked_queries_ratio == 38.5

    assert connection_status.connected is True
    assert connection_status.profile_id == PROFILE_ID

    assert settings.block_page is False
    assert settings.cache_boost is True
    assert settings.cname_flattening is True
    assert settings.anonymized_ecs is True
    assert settings.logs is True
    assert settings.logs_location == "ch"
    assert settings.logs_retention == 720
    assert settings.web3 is True
    assert settings.allow_affiliate is True
    assert settings.block_disguised_trackers is True
    assert settings.ai_threat_detection is True
    assert settings.block_csam is True
    assert settings.block_ddns is True
    assert settings.block_nrd is True
    assert settings.block_parked_domains is True
    assert settings.cryptojacking_protection is True
    assert settings.dga_protection is True
    assert settings.dns_rebinding_protection is True
    assert settings.google_safe_browsing is True
    assert settings.idn_homograph_attacks_protection is True
    assert settings.threat_intelligence_feeds is True
    assert settings.typosquatting_protection is True
    assert settings.block_bypass_methods is True
    assert settings.safesearch is False
    assert settings.youtube_restricted_mode is False

    assert settings.block_9gag is False
    assert settings.block_amazon is False
    assert settings.block_bereal is False
    assert settings.block_blizzard is False
    assert settings.block_chatgpt is False
    assert settings.block_dailymotion is False
    assert settings.block_discord is False
    assert settings.block_disneyplus is False
    assert settings.block_ebay is False
    assert settings.block_facebook is False
    assert settings.block_fortnite is False
    assert settings.block_google_chat is False
    assert settings.block_hbomax is False
    assert settings.block_hulu is False
    assert settings.block_imgur is False
    assert settings.block_instagram is False
    assert settings.block_leagueoflegends is False
    assert settings.block_mastodon is False
    assert settings.block_messenger is False
    assert settings.block_minecraft is False
    assert settings.block_netflix is False
    assert settings.block_pinterest is False
    assert settings.block_playstation_network is False
    assert settings.block_primevideo is False
    assert settings.block_reddit is False
    assert settings.block_roblox is False
    assert settings.block_signal is False
    assert settings.block_skype is False
    assert settings.block_snapchat is False
    assert settings.block_spotify is False
    assert settings.block_steam is False
    assert settings.block_telegram is False
    assert settings.block_tiktok is False
    assert settings.block_tinder is False
    assert settings.block_tumblr is False
    assert settings.block_twitch is False
    assert settings.block_twitter is False
    assert settings.block_vimeo is False
    assert settings.block_vk is False
    assert settings.block_whatsapp is False
    assert settings.block_xboxlive is False
    assert settings.block_youtube is False
    assert settings.block_zoom is False

    assert settings.block_dating is True
    assert settings.block_gambling is True
    assert settings.block_piracy is True
    assert settings.block_porn is True
    assert settings.block_social_networks is False
    assert settings.block_online_gaming is False
    assert settings.block_video_streaming is False

    assert nextdns.get_profile_name(PROFILE_ID) == "Fake Profile"
    assert nextdns.get_profile_id("Fake Profile") == PROFILE_ID


@pytest.mark.asyncio
async def test_profile_id_not_found():
    """Test with wrong profile id."""
    with open("tests/fixtures/profiles.json", encoding="utf-8") as file:
        profiles_data = json.load(file)

    session = aiohttp.ClientSession()

    with aioresponses() as session_mock:
        session_mock.get(ENDPOINTS[ATTR_PROFILES], payload=profiles_data)

        nextdns = await NextDns.create(session, "fakeapikey")

    await session.close()

    with pytest.raises(ProfileIdNotFoundError):
        nextdns.get_profile_name("xxyyxx")


@pytest.mark.asyncio
async def test_profile_name_not_found():
    """Test with wrong name id."""
    with open("tests/fixtures/profiles.json", encoding="utf-8") as file:
        profiles_data = json.load(file)

    session = aiohttp.ClientSession()

    with aioresponses() as session_mock:
        session_mock.get(ENDPOINTS[ATTR_PROFILES], payload=profiles_data)

        nextdns = await NextDns.create(session, "fakeapikey")

    await session.close()

    with pytest.raises(ProfileNameNotFoundError):
        nextdns.get_profile_id("Profile Name")


@pytest.mark.asyncio
async def test_clear_logs():
    """Test clear_logs() method."""
    with open("tests/fixtures/profiles.json", encoding="utf-8") as file:
        profiles_data = json.load(file)

    session = aiohttp.ClientSession()

    with aioresponses() as session_mock:
        session_mock.get(ENDPOINTS[ATTR_PROFILES], payload=profiles_data)
        session_mock.delete(
            ENDPOINTS[ATTR_CLEAR_LOGS].format(profile_id=PROFILE_ID),
            status=HTTPStatus.NO_CONTENT.value,
        )

        nextdns = await NextDns.create(session, "fakeapikey")

        result = await nextdns.clear_logs(PROFILE_ID)

    await session.close()

    assert result is True


@pytest.mark.asyncio
async def test_get_logs():
    """Test get_logs() method."""
    with open("tests/fixtures/profiles.json", encoding="utf-8") as file:
        profiles_data = json.load(file)

    with open("tests/fixtures/logs.csv", encoding="utf-8") as file:
        logs = file.read()

    session = aiohttp.ClientSession()

    with aioresponses() as session_mock:
        session_mock.get(ENDPOINTS[ATTR_PROFILES], payload=profiles_data)
        session_mock.get(
            ENDPOINTS[ATTR_GET_LOGS].format(profile_id=PROFILE_ID),
            status=HTTPStatus.OK.value,
            payload=logs,
        )

        nextdns = await NextDns.create(session, "fakeapikey")

        result = await nextdns.get_logs(PROFILE_ID)

    await session.close()

    assert result == logs


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("setting", "url"),
    [
        ("block_page", ENDPOINTS[ATTR_BLOCK_PAGE].format(profile_id=PROFILE_ID)),
        (
            "block_tinder",
            MAP_SETTING["block_tinder"].url.format(
                profile_id=PROFILE_ID, service=MAP_SETTING["block_tinder"].name
            ),
        ),
        (
            "block_piracy",
            MAP_SETTING["block_piracy"].url.format(
                profile_id=PROFILE_ID, category=MAP_SETTING["block_piracy"].name
            ),
        ),
    ],
)
async def test_set_setting(setting, url):
    """Test set_setting() method."""
    with open("tests/fixtures/profiles.json", encoding="utf-8") as file:
        profiles_data = json.load(file)

    session = aiohttp.ClientSession()

    with aioresponses() as session_mock:
        session_mock.get(ENDPOINTS[ATTR_PROFILES], payload=profiles_data)
        session_mock.patch(url, status=HTTPStatus.NO_CONTENT.value)

        nextdns = await NextDns.create(session, "fakeapikey")

        result = await nextdns.set_setting(PROFILE_ID, setting, True)

    await session.close()

    assert result is True


@pytest.mark.asyncio
async def test_set_parental_contrl_service():
    """Test set_setting() method for parental control service."""
    with open("tests/fixtures/profiles.json", encoding="utf-8") as file:
        profiles_data = json.load(file)

    session = aiohttp.ClientSession()

    with aioresponses() as session_mock:
        session_mock.get(ENDPOINTS[ATTR_PROFILES], payload=profiles_data)
        session_mock.patch(
            MAP_SETTING["block_tinder"].url.format(
                profile_id=PROFILE_ID, service=MAP_SETTING["block_tinder"].name
            ),
            status=HTTPStatus.NOT_FOUND.value,
            payload={"errors": [{"code": "notFound"}]},
        )
        session_mock.post(
            ENDPOINTS[ATTR_PARENTAL_CONTROL_SERVICES].format(profile_id=PROFILE_ID),
            status=HTTPStatus.NO_CONTENT.value,
        )

        nextdns = await NextDns.create(session, "fakeapikey")

        result = await nextdns.set_setting(PROFILE_ID, "block_tinder", True)

    await session.close()

    assert result is True


@pytest.mark.asyncio
async def test_set_parental_contrl_category():
    """Test set_setting() method for parental control category."""
    with open("tests/fixtures/profiles.json", encoding="utf-8") as file:
        profiles_data = json.load(file)

    session = aiohttp.ClientSession()

    with aioresponses() as session_mock:
        session_mock.get(ENDPOINTS[ATTR_PROFILES], payload=profiles_data)
        session_mock.patch(
            MAP_SETTING["block_piracy"].url.format(
                profile_id=PROFILE_ID, category=MAP_SETTING["block_piracy"].name
            ),
            status=HTTPStatus.NOT_FOUND.value,
            payload={"errors": [{"code": "notFound"}]},
        )
        session_mock.post(
            ENDPOINTS[ATTR_PARENTAL_CONTROL_CATEGORIES].format(profile_id=PROFILE_ID),
            status=HTTPStatus.NO_CONTENT.value,
        )

        nextdns = await NextDns.create(session, "fakeapikey")

        result = await nextdns.set_setting(PROFILE_ID, "block_piracy", True)

    await session.close()

    assert result is True


@pytest.mark.asyncio
async def test_set_not_supported_setting():
    """Test set_setting() method with not supported setting."""
    with open("tests/fixtures/profiles.json", encoding="utf-8") as file:
        profiles_data = json.load(file)

    session = aiohttp.ClientSession()

    with aioresponses() as session_mock:
        session_mock.get(ENDPOINTS[ATTR_PROFILES], payload=profiles_data)

        nextdns = await NextDns.create(session, "fakeapikey")

        with pytest.raises(SettingNotSupportedError):
            await nextdns.set_setting(PROFILE_ID, "unsupported_setting", True)

    await session.close()


@pytest.mark.asyncio
async def test_invalid_api_key():
    """Test error when provided API key is invalid."""
    session = aiohttp.ClientSession()

    with aioresponses() as session_mock:
        session_mock.get(ENDPOINTS[ATTR_PROFILES], status=HTTPStatus.FORBIDDEN.value)

        with pytest.raises(InvalidApiKeyError):
            await NextDns.create(session, "fakeapikey")

    await session.close()


@pytest.mark.asyncio
async def test_api_error():
    """Test API error."""
    session = aiohttp.ClientSession()

    with aioresponses() as session_mock:
        session_mock.get(
            ENDPOINTS[ATTR_PROFILES],
            status=HTTPStatus.BAD_REQUEST.value,
            payload={"errors": [{"code": "badRequest"}]},
        )

        with pytest.raises(ApiError) as exc:
            await NextDns.create(session, "fakeapikey")

        assert "400, badRequest, None" in str(exc.value)

    await session.close()


@pytest.mark.asyncio
async def test_set_logs_retention():
    """Test set_logs_retention() method."""
    with open("tests/fixtures/profiles.json", encoding="utf-8") as file:
        profiles_data = json.load(file)

    session = aiohttp.ClientSession()

    with aioresponses() as session_mock:
        session_mock.get(ENDPOINTS[ATTR_PROFILES], payload=profiles_data)
        session_mock.patch(
            ENDPOINTS[ATTR_LOGS].format(profile_id=PROFILE_ID),
            status=HTTPStatus.NO_CONTENT.value,
        )

        nextdns = await NextDns.create(session, "fakeapikey")

        result = await nextdns.set_logs_retention(PROFILE_ID, 1)

    await session.close()

    assert result is True


@pytest.mark.asyncio
async def test_set_logs_retention_with_invalid_value():
    """Test set_logs_retention() method with invalid value."""
    with open("tests/fixtures/profiles.json", encoding="utf-8") as file:
        profiles_data = json.load(file)

    session = aiohttp.ClientSession()

    with aioresponses() as session_mock:
        session_mock.get(ENDPOINTS[ATTR_PROFILES], payload=profiles_data)

        nextdns = await NextDns.create(session, "fakeapikey")

    await session.close()

    with pytest.raises(
        ValueError,
        match=re.escape(
            "Invalid logs retention value. "
            "Allowed values are: (1, 6, 24, 168, 720, 2160, 4320, 8760, 17520)"
        ),
    ):
        await nextdns.set_logs_retention(PROFILE_ID, 999)


@pytest.mark.asyncio
async def test_set_logs_location():
    """Test set_logs_location() method."""
    with open("tests/fixtures/profiles.json", encoding="utf-8") as file:
        profiles_data = json.load(file)

    session = aiohttp.ClientSession()

    with aioresponses() as session_mock:
        session_mock.get(ENDPOINTS[ATTR_PROFILES], payload=profiles_data)
        session_mock.patch(
            ENDPOINTS[ATTR_LOGS].format(profile_id=PROFILE_ID),
            status=HTTPStatus.NO_CONTENT.value,
        )

        nextdns = await NextDns.create(session, "fakeapikey")

        result = await nextdns.set_logs_location(PROFILE_ID, "us")

    await session.close()

    assert result is True


@pytest.mark.asyncio
async def test_set_logs_location_with_invalid_value():
    """Test set_logs_location() method with invalid value."""
    with open("tests/fixtures/profiles.json", encoding="utf-8") as file:
        profiles_data = json.load(file)

    session = aiohttp.ClientSession()

    with aioresponses() as session_mock:
        session_mock.get(ENDPOINTS[ATTR_PROFILES], payload=profiles_data)

        nextdns = await NextDns.create(session, "fakeapikey")

    await session.close()

    with pytest.raises(
        ValueError,
        match=re.escape(
            "Invalid logs location value. Allowed values are: ('ch', 'eu', 'gb', 'us')"
        ),
    ):
        await nextdns.set_logs_location(PROFILE_ID, "pl")
