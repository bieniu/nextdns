"""Setup module for nextdns."""

from pathlib import Path

from setuptools import setup

PROJECT_DIR = Path(__file__).parent.resolve()
README_FILE = PROJECT_DIR / "README.md"
VERSION = "4.0.0"

setup(
    name="nextdns",
    version=VERSION,
    author="Maciej Bieniek",
    description="Python wrapper for NextDNS API.",
    long_description=README_FILE.read_text(encoding="utf-8"),
    long_description_content_type="text/markdown",
    include_package_data=True,
    url="https://github.com/bieniu/nextdns",
    license="Apache-2.0 License",
    packages=["nextdns"],
    package_data={"nextdns": ["py.typed"]},
    python_requires=">=3.12",
    install_requires=["aiohttp>=3.10.6"],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Programming Language :: Python :: 3 :: Only",
        "Typing :: Typed",
    ],
)
