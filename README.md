# [lkapi](https://lightkeeper.com/)
This repo providers example client code to work with the Lightkeeper API.

Access to the Lightkeeper API is handled via the OAuth2 client credentials flow.

If you'd like to know more about API access to your existing Lightkeeper environment, or have any enqiuries about working with Lightkeeper, [please contact us](https://lightkeeper.com/).


## Installation

This repo provides sample code that relies on:
- `python>3.10`
- `requests`
- `pandas`.


Use the package manager [pip](https://pip.pypa.io/en/stable/) to install these to your current python environment.

```bash
pip install requirements.txt
```

There's also support for more modern tools like [poetry via pyproject.toml](https://python-poetry.org/docs/managing-environments/) or [uv via the lockfile](https://docs.astral.sh/uv/guides/projects/).

## Usage

Prior to running any of those commands, you'll be provided with a `client_id`, and `client_secret` from Lightkeeper.  These credentials are required to make requests against your Lightkeeper environment.

[There's more detailed documentation provided in `lkapi.py` directly](https://github.com/lightkeeper/lkapi/blob/9af7807e0e2e787afe504d18ee3d88834794824a/client/python/lkapi.py#L7-L20).

The python client can be imported and run.

```python
from client.python import lkapi

lkapi.make_api_request(url="https://YOUR-LIGHTKEEPER-ENVIRONMENT.COM/lightstation/api/reports/query/layout/Portfolio_Grid__user@lightkeeper.com/v1?bd=YYYYMMDD&ed=YYYYMMDD&focus=PORT&rollup=ROLLUP", username="CLIENT_ID_XXXXXX", password="CLIENT_SECRET_XXXXXXX")
```

or run from the CLI after passing the appropriate URL, client ID and client secret variables to `lkapi.py`

```bash
cd client/python/
python lkapi.py
```

## Contributing

If you have any suggestions or requests regarding examples, features or additional languages for clients.  Please submit an issue to this repository or reach out to [Lightkeeper support](lightkeeper.com).

## License

[MIT](https://choosealicense.com/licenses/mit/)
