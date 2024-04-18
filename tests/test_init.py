"""Tests for nextdns package."""

import json
import re
from http import HTTPStatus
from pathlib import Path
from typing import Any

import aiohttp
import pytest
from aioresponses import aioresponses
from syrupy import SnapshotAssertion

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


@pytest.mark.asyncio()
async def test_valid_data(
    snapshot: SnapshotAssertion, profiles_data: dict[str, Any]
) -> None:
    """Test with valid data."""
    with Path.open("tests/fixtures/dnssec.json", encoding="utf-8") as file:
        dnssec_data = json.load(file)
    with Path.open("tests/fixtures/encryption.json", encoding="utf-8") as file:
        encryption_data = json.load(file)
    with Path.open("tests/fixtures/ip_versions.json", encoding="utf-8") as file:
        ip_versions_data = json.load(file)
    with Path.open("tests/fixtures/protocols.json", encoding="utf-8") as file:
        protocols_data = json.load(file)
    with Path.open("tests/fixtures/status.json", encoding="utf-8") as file:
        status_data = json.load(file)
    with Path.open("tests/fixtures/test.json", encoding="utf-8") as file:
        test_data = json.load(file)
    with Path.open("tests/fixtures/profile.json", encoding="utf-8") as file:
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
        connection_status = await nextdns.connection_status(PROFILE_ID)
        settings = await nextdns.get_settings(PROFILE_ID)

    await session.close()

    assert nextdns == snapshot
    assert analitycs == snapshot
    assert connection_status == snapshot
    assert settings == snapshot

    assert nextdns.get_profile_name(PROFILE_ID) == snapshot
    assert nextdns.get_profile_id("Fake Profile") == snapshot


@pytest.mark.asyncio()
async def test_profile_id_not_found(profiles_data: dict[str, Any]) -> None:
    """Test with wrong profile id."""
    session = aiohttp.ClientSession()

    with aioresponses() as session_mock:
        session_mock.get(ENDPOINTS[ATTR_PROFILES], payload=profiles_data)

        nextdns = await NextDns.create(session, "fakeapikey")

    await session.close()

    with pytest.raises(ProfileIdNotFoundError):
        nextdns.get_profile_name("xxyyxx")


@pytest.mark.asyncio()
async def test_profile_name_not_found(profiles_data: dict[str, Any]) -> None:
    """Test with wrong name id."""
    session = aiohttp.ClientSession()

    with aioresponses() as session_mock:
        session_mock.get(ENDPOINTS[ATTR_PROFILES], payload=profiles_data)

        nextdns = await NextDns.create(session, "fakeapikey")

    await session.close()

    with pytest.raises(ProfileNameNotFoundError):
        nextdns.get_profile_id("Profile Name")


@pytest.mark.asyncio()
async def test_clear_logs(profiles_data: dict[str, Any]) -> None:
    """Test clear_logs() method."""
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


@pytest.mark.asyncio()
async def test_get_logs(profiles_data: dict[str, Any]) -> None:
    """Test get_logs() method."""
    with Path.open("tests/fixtures/logs.csv", encoding="utf-8") as file:
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


@pytest.mark.asyncio()
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
async def test_set_setting(
    setting: str, url: str, profiles_data: dict[str, Any]
) -> None:
    """Test set_setting() method."""
    session = aiohttp.ClientSession()

    with aioresponses() as session_mock:
        session_mock.get(ENDPOINTS[ATTR_PROFILES], payload=profiles_data)
        session_mock.patch(url, status=HTTPStatus.NO_CONTENT.value)

        nextdns = await NextDns.create(session, "fakeapikey")

        result = await nextdns.set_setting(PROFILE_ID, setting, True)

    await session.close()

    assert result is True


@pytest.mark.asyncio()
async def test_set_parental_contrl_service(profiles_data: dict[str, Any]) -> None:
    """Test set_setting() method for parental control service."""
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


@pytest.mark.asyncio()
async def test_set_parental_contrl_category(profiles_data: dict[str, Any]):
    """Test set_setting() method for parental control category."""
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


@pytest.mark.asyncio()
async def test_set_not_supported_setting(profiles_data: dict[str, Any]):
    """Test set_setting() method with not supported setting."""
    session = aiohttp.ClientSession()

    with aioresponses() as session_mock:
        session_mock.get(ENDPOINTS[ATTR_PROFILES], payload=profiles_data)

        nextdns = await NextDns.create(session, "fakeapikey")

        with pytest.raises(SettingNotSupportedError):
            await nextdns.set_setting(PROFILE_ID, "unsupported_setting", True)

    await session.close()


@pytest.mark.asyncio()
async def test_invalid_api_key():
    """Test error when provided API key is invalid."""
    session = aiohttp.ClientSession()

    with aioresponses() as session_mock:
        session_mock.get(ENDPOINTS[ATTR_PROFILES], status=HTTPStatus.FORBIDDEN.value)

        with pytest.raises(InvalidApiKeyError):
            await NextDns.create(session, "fakeapikey")

    await session.close()


@pytest.mark.asyncio()
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


@pytest.mark.asyncio()
async def test_set_logs_retention(profiles_data: dict[str, Any]):
    """Test set_logs_retention() method."""
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


@pytest.mark.asyncio()
async def test_set_logs_retention_with_invalid_value(profiles_data: dict[str, Any]):
    """Test set_logs_retention() method with invalid value."""
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


@pytest.mark.asyncio()
async def test_set_logs_location(profiles_data: dict[str, Any]):
    """Test set_logs_location() method."""
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


@pytest.mark.asyncio()
async def test_set_logs_location_with_invalid_value(profiles_data: dict[str, Any]):
    """Test set_logs_location() method with invalid value."""
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
