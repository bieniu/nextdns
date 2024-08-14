"""Example of usage."""

import asyncio
import logging
from dataclasses import astuple

from aiohttp import ClientConnectorError, ClientSession
from tenacity import RetryError

from nextdns import ApiError, InvalidApiKeyError, NextDns, TooManyRequestsError

API_KEY = "xxx"

logging.basicConfig(level=logging.DEBUG)


async def main() -> None:
    """Run main function."""
    async with ClientSession() as websession:
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

            # set logs retention to 1 month (30 days)
            # allowed values are: 1, 6, 24, 168, 720, 960, 4320, 8760, 17520
            # await nextdns.set_logs_retention(profile_id, 720)

            # set logs location to Switzerland
            # allowed values are: ch, eu, gb, us
            # await nextdns.set_logs_location(profile_id, "ch")

            # clear logs
            # await nextdns.clear_logs(profile_id)

            # get CSV logs and save to file
            # logs = await nextdns.get_logs(profile_id)
            # with open(
            #     f"nextdns_{profile_id}_logs.csv", "w", encoding="utf-8"
            # ) as file:
            #     file.write(logs)

            # enable block page
            # await nextdns.set_setting(profile_id, "block_page", True)
        except ValueError as error:
            print(error)
        except InvalidApiKeyError:
            print("Invalid API Key")
        except TooManyRequestsError:
            print("Too many requests")
        except ApiError as error:
            print(f"API Error: {error.status}")
        except ClientConnectorError as error:
            print(f"ClientConnectorError: {error}")
        except TimeoutError as error:
            print(f"TimeoutError: {error}")
        except RetryError as error:
            print(f"RetryError: {error}")
        else:
            print(
                f"Profile: {profile_name} "
                f"(id: {profile_id}, fingerprint: {profile_fingerprint})"
            )
            print(
                f"Does this device use NextDNS?: {connection_status.connected}, "
                f"using profile: {connection_status.profile_id}"
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
