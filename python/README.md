# [lkapi](https://lightkeeper.com/)

The Python client for the [Lightkeeper](https://lightkeeper.com/) Web API. It handles the OAuth2 client credentials flow, secure credential storage, and returns API data as pandas data frames.

If you'd like to know more about API access to your existing Lightkeeper environment, or have any enquiries about working with Lightkeeper, [please contact us](https://lightkeeper.com/).

## Installation

Requires `python>=3.10`.

```bash
pip install lkapi
```

For development on this repo, use [uv](https://docs.astral.sh/uv/guides/projects/) from the `python/` directory:
```bash
uv sync
uv run --group dev pytest
```

## Usage

Prior to using the API, you will need a `client_id` and `client_secret` from Lightkeeper. These credentials are required to make requests against your Lightkeeper environment.

The quickest start is to copy a url from the Lightkeeper UI (Grid > Api Routes) and pass credentials directly:

```python
import lkapi

frames = lkapi.get_grid_data(
    url="https://YOUR-ENVIRONMENT.lightkeeperhq.com/lightstation/api/reports/query/layout/YOUR_GRID/v2?focus=PORT&rollup=ISSUER&bd=20250101&ed=20250131",
    username="YOUR_CLIENT_ID",
    password="YOUR_CLIENT_SECRET",
)
```

The keys in the returned dictionary are:
- `request`: Details about the request made including endpoint and parameters.
- `portfolio`: Details on the portfolio the data was requested for including available dates and data update times.
- `rollup`: A data frame of information summarized at the rollup level (e.g. one row per rollup).
- `time`: A data frame of information summarized at the time level (e.g. one row per time period). If data is grouped in the view it will be one row per time period per group.
- `total`: The total values. If data is grouped in the view it will be one row per group.

If you would like to work with the raw response object instead, set `debug=True` in the `get_grid_data` call.

### Stored credentials

In a longer term development or production environment, store credentials once in secure credential storage (via the [keyring](https://pypi.org/project/keyring/) python module if installed) or environment variables, rather than passing them in code.

```python
import lkapi

# a long-lived credential manager which stores to the keyring if available or environment variables otherwise
credential_manager = lkapi.get_credential_manager(url="https://YOUR-ENVIRONMENT.lightkeeperhq.com")
credential_manager.set_secret('YOUR_CLIENT_ID', 'YOUR_CLIENT_SECRET')
```

The `CredentialManager` base class can be extended to provide custom credential storage mechanisms.

With credentials stored, requests can be built from components instead of a copied url:

```python
import lkapi

frames = lkapi.get_grid_data(
    grid="YOUR_GRID",
    environment="YOUR-ENVIRONMENT",
    portfolio="PORT",
    rollup="ISSUER",
    begin_date="2025-01-01",
    end_date="2025-01-31",
)
```

## Contributing

If you have any suggestions or requests regarding examples, features or additional languages for clients, please submit an issue to this repository or reach out to [Lightkeeper support](https://lightkeeper.com/).

## License

[MIT](https://choosealicense.com/licenses/mit/)
