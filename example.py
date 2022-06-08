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

            for profile_id, profile_name in nextdns.profiles:
                print(f"Profile: {profile_name} ({profile_id})")
                status = await nextdns.get_status(profile_id)
                print(f"Status: {status}")
        except InvalidApiKeyError:
            print("Invalid API Key")
        except ApiError as error:
            print(f"API Error: {error.status}")


loop = asyncio.new_event_loop()
loop.run_until_complete(main())
loop.close()
