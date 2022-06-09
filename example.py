"""Example of usage."""
import asyncio
import logging

from aiohttp import ClientConnectorError, ClientSession

from nextdns import ApiError, InvalidApiKeyError, NextDns

API_KEY = "xxx"

logging.basicConfig(level=logging.DEBUG)


async def main():
    """Main function."""
    async with ClientSession() as websession:
        try:
            nextdns = await NextDns.create(websession, API_KEY)
            profile_id, profile_name = nextdns.profiles[2]
            profile = await nextdns.get_profile(profile_id)
            status = await nextdns.get_analytics_status(profile_id)
            dnssec = await nextdns.get_analytics_dnssec(profile_id)
            encryption = await nextdns.get_analytics_encryption(profile_id)
            ip_versions = await nextdns.get_analytics_ip_versions(profile_id)
            protocols = await nextdns.get_analytics_protocols(profile_id)
        except InvalidApiKeyError:
            print("Invalid API Key")
        except ApiError as error:
            print(f"API Error: {error.status}")
        except ClientConnectorError as error:
            print(f"ClientConnectorError: {error}")
        else:
            print(f"Profile: {profile_name} ({profile_id})")
            print(profile)
            print(status)
            print(dnssec)
            print(encryption)
            print(ip_versions)
            print(protocols)


loop = asyncio.new_event_loop()
loop.run_until_complete(main())
loop.close()
