"""Set up some common test helper things."""

import json
from pathlib import Path
from typing import Any

import pytest
from syrupy.assertion import SnapshotAssertion
from syrupy.extensions.amber import AmberSnapshotExtension
from syrupy.location import PyTestLocation


@pytest.fixture
def profiles_data() -> dict[str, Any]:
    """Return the profiles data from the fixture file."""
    with Path.open("tests/fixtures/profiles.json", encoding="utf-8") as file:
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
