"""Example of usage."""
import asyncio
import logging
from dataclasses import astuple

import aiohttp
import orjson
from aiohttp import ClientConnectorError, ClientSession

from nextdns import ApiError, InvalidApiKeyError, NextDns

API_KEY = "xxx"

logging.basicConfig(level=logging.DEBUG)


class ExampleClientResponse(aiohttp.ClientResponse):
    """aiohttp.ClientResponse with a json method that uses json_loads by default."""

    async def json(
        self, *args, loads=orjson.loads, **kwargs  # pylint: disable=no-member
    ):
        """Send a json request and parse the json response."""
        return await super().json(*args, loads=loads, **kwargs)


async def main():
    """Main function."""
    async with ClientSession(
        json_serialize=orjson.dumps,  # pylint: disable=no-member
        response_class=ExampleClientResponse,
    ) as websession:
        try:
            nextdns = await NextDns.create(websession, API_KEY)
            profile_id, profile_fingerprint, profile_name = astuple(nextdns.profiles[0])
            status = await nextdns.get_analytics_status(profile_id)
            dnssec = await nextdns.get_analytics_dnssec(profile_id)
            encryption = await nextdns.get_analytics_encryption(profile_id)
            ip_versions = await nextdns.get_analytics_ip_versions(profile_id)
            protocols = await nextdns.get_analytics_protocols(profile_id)
            connection_status = await nextdns.connection_status(profile_id)
            settings = await nextdns.get_settings(profile_id)

            # clear logs
            # await nextdns.clear_logs(profile_id)

            # enable block page
            # await nextdns.set_setting(profile_id, "block_page", True)

        except InvalidApiKeyError:
            print("Invalid API Key")
        except ApiError as error:
            print(f"API Error: {error.status}")
        except ClientConnectorError as error:
            print(f"ClientConnectorError: {error}")
        else:
            print(
                f"Profile: {profile_name} (id: {profile_id}, fingerprint: {profile_fingerprint})"
            )
            print(
                f"Does this device use NextDNS?: {connection_status.connected}, using profile: {connection_status.profile_id}"
            )
            print(status)
            print(dnssec)
            print(encryption)
            print(ip_versions)
            print(protocols)
            print(settings)


loop = asyncio.new_event_loop()
loop.run_until_complete(main())
loop.close()
