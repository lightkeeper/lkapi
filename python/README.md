# [lkapi](https://lightkeeper.com/)
This repo providers example client code to work with the Lightkeeper API in python.

Access to the Lightkeeper API is handled via the OAuth2 client credentials flow.

If you'd like to know more about API access to your existing Lightkeeper environment, or have any enqiuries about working with Lightkeeper, [please contact us](https://lightkeeper.com/).

## Usage

Prior to running any of those commands, you'll be provided with a `client_id`, and `client_secret` from Lightkeeper.  These credentials are required to make requests against your Lightkeeper environment.

## Installation

This repo provides sample code that relies on:
- `python>3.10`
- `requests`
- `pandas`

You can use the package manager [pip](https://pip.pypa.io/en/stable/) to install these to your current python environment.

```bash
pip install requirements.txt
```

There's also support for more modern tools like [poetry via pyproject.toml](https://python-poetry.org/docs/managing-environments/) or [uv via the lockfile](https://docs.astral.sh/uv/guides/projects/).
```bash
uv sync
uv run python your_script.py
```
## Usage

Prior to using the API, you will need to get a `client_id`, and `client_secret` from Lightkeeper.  These credentials are required to make requests against your Lightkeeper environment.

In a longer term development or production environment, you can set the environment variables or in secure credential storage if the [keyring](https://pypi.org/project/keyring/) python module is installed.

```python
import lkapi.credential as lkcredential

# get a long-lived credential manager which will store to the keyring if available or environment variables otherwise
credential_manager = lkcredential.get_credential_manager(url="https://YOUR-LIGHTKEEPER-ENVIRONMENT.COM")
credential_manager.set_secret('CLIENT_ID_XXXXXX', 'CLIENT_SECRET_XXXX')
```
The credential manager provides a base class that can be extended to provide custom credential storage mechanisms.

The python client can be imported and run with stored credentials or by directly passing credentials.

```python
import lkapi.client as lkapi

lkapi.get_grid_data(
    url="https://YOUR-LIGHTKEEPER-ENVIRONMENT.COM/lightstation/api/reports/query/layout/Portfolio_Grid__user@lightkeeper.com/v1?bd=YYYYMMDD&ed=YYYYMMDD&focus=PORT&rollup=ROLLUP",
    username="CLIENT_ID_XXXXXX", password="CLIENT_SECRET_XXXXXXX")
```

The return format defaults to a dictionary of information. If you would like to work with the raw response object you can set the argument `debug=True` in the `make_api_request` call.

The keys in the returned dictionary are:
- `request`: Details about the request made including endpoint and parameters.
- `portfolio`: Details on the portfolio the data was requested for including available dates and data update times.
- `rollup`: A data frame of information summarized at the rollup level (e.g. one row per rollup).
- `time`: A data frame of information summarized at the time level (e.g. one row per time period). If data is grouped in the view it will be one row per time period per group.
- `total`: The total values. If data is grouped in the view it will be one row per group.

## Contributing

If you have any suggestions or requests regarding examples, features or additional languages for clients.  Please submit an issue to this repository or reach out to [Lightkeeper support](lightkeeper.com).

## License

[MIT](https://choosealicense.com/licenses/mit/)
