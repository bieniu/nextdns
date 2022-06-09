"""Example of usage."""
import asyncio
import logging

from aiohttp import ClientSession

from nextdns import ApiError, InvalidApiKeyError, NextDns

API_KEY = "xxx"

logging.basicConfig(level=logging.DEBUG)


async def main():
    """Main function."""
    async with ClientSession() as websession:
        try:
            nextdns = await NextDns.create(websession, API_KEY)

            profile_id, profile_name = nextdns.profiles[0]
            print(f"Profile: {profile_name} ({profile_id})")
            profile = await nextdns.get_profile(profile_id)
            print(f"Profile fingerprint: {profile['fingerprint']}")
            status = await nextdns.get_analytics_status(profile_id)
            print(f"Status: {status}")
            dnssec = await nextdns.get_analytics_dnssec(profile_id)
            print(f"Status: {dnssec}")
            encryption = await nextdns.get_analytics_encryption(profile_id)
            print(f"Status: {encryption}")
        except InvalidApiKeyError:
            print("Invalid API Key")
        except ApiError as error:
            print(f"API Error: {error.status}")


loop = asyncio.new_event_loop()
loop.run_until_complete(main())
loop.close()
