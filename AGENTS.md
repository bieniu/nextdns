<!-- CLAUDE.md is a symlink to this file — edit only AGENTS.md -->
# Instructions for AI Agents (Copilot, Claude, Codex)

## Repository context

- This repository is a Python async wrapper for the NextDNS API
- The publishable package is `nextdns` (PyPI name: `nextdns`)
- The public API surface is the `NextDns` class in `nextdns/__init__.py`, models in `nextdns/model.py`, and exceptions in `nextdns/exceptions.py`
- API base URL: `https://api.nextdns.io`

## Project layout

```text
nextdns/
├── __init__.py    # Main client (NextDns)
├── const.py       # ENDPOINTS dict, ATTR_* constants, MAP_* dicts, MAP_SETTING
├── exceptions.py  # NextDnsError (base), InvalidApiKeyError, ApiError, ProfileIdNotFoundError, ProfileNameNotFoundError, SettingNotSupportedError
└── model.py       # Dataclasses (AnalyticsStatus, Profile, Settings, etc.) and StrEnums (ApiNames, ParentalControlServices, etc.)

tests/
├── conftest.py       # Fixtures (session, session_mock, profiles_data, snapshot)
├── test_init.py      # All tests
├── fixtures/         # JSON/CSV response fixtures
└── snapshots/        # syrupy snapshot files
```

## Python and environment

- Target Python: >=3.13 (also tested on 3.14)
- Use the local venv in `./.venv`
- `scripts/setup-local-env.sh` creates the venv, installs `uv`, then installs all dependencies from `pyproject.toml`
- Package manager: `uv` — dependencies declared in `pyproject.toml`

## Linting, formatting, typing

```bash
uv sync --group dev
uv run ruff check .              # lint
uv run ruff check . --fix        # lint with auto-fix
uv run ruff format .             # format
uv run ruff format --check .     # check formatting without changes
uv run ty check nextdns          # type check
```

## Testing

```bash
uv sync --group test
uv run pytest --timeout=30 --cov=nextdns --cov-report=xml --error-for-skips   # full suite
uv run pytest tests/test_init.py::test_name                                     # single test
uv run pytest --snapshot-update                                                 # update syrupy snapshots
```

- Mock HTTP via `aiointercept`; never hit real endpoints in tests
- Snapshots use `syrupy` (`tests/snapshots/`) — update with `--snapshot-update` when response structures change
- Update both snapshots and fixtures together when response shapes change

## Architecture and key patterns

**Client lifecycle**: `NextDns` is instantiated via the async class method `NextDns.create(session, api_key)`, which calls `initialize()` to fetch and cache the list of profiles. The caller owns the `aiohttp.ClientSession`.

**HTTP layer**: `_http_request()` in `NextDns` handles all HTTP communication. It unwraps `{"data": ...}` response envelopes, treats HTTP 204 on mutating methods as `{"success": True}`, and raises typed exceptions: `InvalidApiKeyError` on 403, `ApiError` on other non-200 statuses. All GET/mutating methods that may see transient errors are decorated with `@retry` (tenacity) using incrementing wait (start=2s, increment=2s, max 3 attempts) for `TimeoutError` and `ClientConnectorError`.

**Settings mutations**: `set_setting(profile_id, setting, state)` dispatches via `MAP_SETTING` in `const.py`, which maps every setting name string to a `SettingDescription(url, api_field_name)`. Parental control categories and services use PATCH, but fall back to POST if the item doesn't exist yet (404 response).

**Constants and mappings**: All endpoint URL templates live in the `ENDPOINTS` dict in `const.py`. Response field names are mapped to Python attribute names via `MAP_STATUS`, `MAP_DNSSEC`, `MAP_ENCRYPTED`, `MAP_IP_VERSIONS`, `MAP_PROTOCOLS`. API camelCase field names are centralised in the `ApiNames` StrEnum in `model.py`.

**Models**: Analytics dataclasses compute ratio fields in `__post_init__`. `Settings` is a flat dataclass containing all profile settings (security, privacy, parental control services, parental control categories). `ProfileInfo` holds `id`, `fingerprint`, and `name`.

## Implementation guidelines

- Keep all I/O async; accept `aiohttp.ClientSession` from the caller
- Use `aiohttp`'s built-in `.json()` for response parsing
- Keep all URLs/constants in `nextdns/const.py`; use `ApiNames` StrEnum for API field names
- Preserve the public API and model shapes; breaking changes require explicit discussion
- Use lazy logging: `_LOGGER.debug("msg %s", value)` — never f-strings in log calls
- Prefer specific exception types over the base `NextDnsError`
- Avoid very long docstrings; one-line docstrings preferred, three lines at most
