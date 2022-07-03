"""Tests for nextdns package."""
import json

import aiohttp
import pytest
from aioresponses import aioresponses

from nextdns import (
    ATTR_ANALYTICS,
    ATTR_PROFILE,
    ATTR_PROFILES,
    ATTR_TEST,
    ENDPOINTS,
    NextDns,
    ProfileIdNotFoundError,
    ProfileNameNotFoundError,
)


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

    profile_id = "fakepr"

    session = aiohttp.ClientSession()

    with aioresponses() as session_mock:
        session_mock.get(ENDPOINTS[ATTR_PROFILES], payload=profiles_data)
        session_mock.get(
            ENDPOINTS[ATTR_ANALYTICS].format(profile_id=profile_id, type="dnssec"),
            payload=dnssec_data,
        )
        session_mock.get(
            ENDPOINTS[ATTR_ANALYTICS].format(profile_id=profile_id, type="encryption"),
            payload=encryption_data,
        )
        session_mock.get(
            ENDPOINTS[ATTR_ANALYTICS].format(profile_id=profile_id, type="ipVersions"),
            payload=ip_versions_data,
        )
        session_mock.get(
            ENDPOINTS[ATTR_ANALYTICS].format(profile_id=profile_id, type="protocols"),
            payload=protocols_data,
        )
        session_mock.get(
            ENDPOINTS[ATTR_ANALYTICS].format(profile_id=profile_id, type="status"),
            payload=status_data,
        )
        session_mock.get(
            ENDPOINTS[ATTR_TEST].format(profile_id=profile_id), payload=test_data
        )
        session_mock.get(
            ENDPOINTS[ATTR_PROFILE].format(profile_id=profile_id), payload=profile_data
        )

        nextdns = await NextDns.create(session, "fakeapikey")

        analitycs = await nextdns.get_all_analytics(profile_id)
        dnssec = analitycs.dnssec
        encryption = analitycs.encryption
        ip_versions = analitycs.ip_versions
        protocols = analitycs.protocols
        status = analitycs.status
        connection_status = await nextdns.connection_status(profile_id)
        settings = await nextdns.get_settings(profile_id)

    await session.close()

    assert len(nextdns.profiles) == 1
    assert nextdns.profiles[0].id == "fakepr"
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

    assert protocols.doh_queries == 118488
    assert protocols.doq_queries == 0
    assert protocols.dot_queries == 1261772
    assert protocols.udp_queries == 40
    assert protocols.doh_queries_ratio == 8.6
    assert protocols.doq_queries_ratio == 0.0
    assert protocols.dot_queries_ratio == 91.4
    assert protocols.udp_queries_ratio == 0.0

    assert status.all_queries == 1380300
    assert status.allowed_queries == 5452
    assert status.blocked_queries == 530805
    assert status.default_queries == 837764
    assert status.relayed_queries == 6279
    assert status.blocked_queries_ratio == 38.5

    assert connection_status.connected is True
    assert connection_status.profile_id == profile_id

    assert settings.block_page is False
    assert settings.cache_boost is True
    assert settings.cname_flattening is True
    assert settings.anonymized_ecs is True
    assert settings.logs is True
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

    assert nextdns.get_profile_name(profile_id) == "Fake Profile"
    assert nextdns.get_profile_id("Fake Profile") == profile_id


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

    try:
        nextdns.get_profile_name("xxyyxx")
    except Exception as exc:  # pylint: disable=broad-except
        assert isinstance(exc, ProfileIdNotFoundError) is True


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

    try:
        nextdns.get_profile_id("Profile Name")
    except Exception as exc:  # pylint: disable=broad-except
        assert isinstance(exc, ProfileNameNotFoundError) is True
