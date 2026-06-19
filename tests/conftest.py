"""Set up some common test helper things."""

import json
from collections.abc import AsyncGenerator
from pathlib import Path
from typing import Any

import aiohttp
import pytest
import pytest_asyncio
from aiointercept import aiointercept
from syrupy.assertion import SnapshotAssertion
from syrupy.extensions.amber import AmberSnapshotExtension
from syrupy.location import PyTestLocation


@pytest_asyncio.fixture(loop_scope="function")
async def session(session_mock: aiointercept) -> AsyncGenerator[aiohttp.ClientSession]:  # noqa: ARG001
    """Return a mock ClientSession."""
    session = aiohttp.ClientSession()
    yield session
    await session.close()


@pytest_asyncio.fixture(loop_scope="function")
async def session_mock() -> AsyncGenerator[aiointercept]:
    """Create a reusable aiointercept mock."""
    async with aiointercept(mock_external_urls=True) as mock:
        yield mock


@pytest.fixture
def profiles_data() -> dict[str, Any]:
    """Return the profiles data from the fixture file."""
    with Path.open(Path("tests/fixtures/profiles.json"), encoding="utf-8") as file:
        return json.load(file)


@pytest.fixture
def snapshot(snapshot: SnapshotAssertion) -> SnapshotAssertion:
    """Return snapshot assertion fixture."""
    return snapshot.use_extension(SnapshotExtension)


class SnapshotExtension(AmberSnapshotExtension):
    """Extension for Syrupy."""

    @classmethod
    def dirname(cls, *, test_location: PyTestLocation) -> str:
        """Return the directory for the snapshot files."""
        test_dir = Path(test_location.filepath).parent
        return str(test_dir.joinpath("snapshots"))
