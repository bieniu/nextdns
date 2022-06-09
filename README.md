[![GitHub Release][releases-shield]][releases]
[![PyPI][pypi-releases-shield]][pypi-releases]
[![PyPI - Downloads][pypi-downloads]][pypi-statistics]
[![Buy me a coffee][buy-me-a-coffee-shield]][buy-me-a-coffee]
[![PayPal_Me][paypal-me-shield]][paypal-me]

# nextdns

Python wrapper for [NextDNS](https://nextdns.io/?from=u4xqh6ud) API.


## How to use package

```python
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
```

[releases]: https://github.com/bieniu/nextdns/releases
[releases-shield]: https://img.shields.io/github/release/bieniu/nextdns.svg?style=popout
[pypi-releases]: https://pypi.org/project/nextdns/
[pypi-statistics]: https://pepy.tech/project/nextdns
[pypi-releases-shield]: https://img.shields.io/pypi/v/nextdns
[pypi-downloads]: https://pepy.tech/badge/nextdns/month
[buy-me-a-coffee-shield]: https://img.shields.io/static/v1.svg?label=%20&message=Buy%20me%20a%20coffee&color=6f4e37&logo=buy%20me%20a%20coffee&logoColor=white
[buy-me-a-coffee]: https://www.buymeacoffee.com/QnLdxeaqO
[paypal-me-shield]: https://img.shields.io/static/v1.svg?label=%20&message=PayPal.Me&logo=paypal
[paypal-me]: https://www.paypal.me/bieniu79
