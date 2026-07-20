# [lkapi](https://lightkeeper.com/)

Client libraries and API tooling for the [Lightkeeper](https://lightkeeper.com/) Web API.

Access to the Lightkeeper API is handled via the OAuth2 client credentials flow. To make requests against your Lightkeeper environment, regardless of programming language, you will need a `client_id` and `client_secret` from Lightkeeper.

If you'd like to know more about API access to your existing Lightkeeper environment, or have any enquiries about working with Lightkeeper, [please contact us](https://lightkeeper.com/).

## Python client (PyPI)

The supported Python client is published to PyPI as [`lkapi`](https://pypi.org/project/lkapi/) and returns API data as pandas data frames.

```bash
pip install lkapi
```

See [python/README.md](python/README.md) for the full Python documentation, including secure credential storage and building requests from components instead of a copied url. The example below is a quick preview.

```python
import lkapi

# The url is available in the Lightkeeper UI under Grid > Api Routes
frames = lkapi.get_grid_data(
    url="https://YOUR-ENVIRONMENT.lightkeeperhq.com/lightstation/api/reports/query/layout/YOUR_LAYOUT_ID/v2?focus=LKP_YOUR_PORTFOLIO__PORT&rollup=ISSUER&bd=20250101&ed=20250131",
    username="YOUR_CLIENT_ID",
    password="YOUR_CLIENT_SECRET",
)

frames['rollup']  # summary per rollup for the full period, as a pandas DataFrame
frames['time']    # summary per time period
frames['total']   # totals
```

## Using the API directly

The API can be called from any language with two HTTPS requests: exchange your client credentials for a bearer token, then request the grid data.

```bash
# 1) Exchange client credentials for a bearer token (valid for one hour)
curl -s -X POST "https://api.auth.YOUR-ENVIRONMENT.lightkeeperhq.com/oauth2/token" \
  -d grant_type=client_credentials \
  -d client_id="$LK_CLIENT_ID" \
  -d client_secret="$LK_CLIENT_SECRET"
# -> {"token_type": "Bearer", "access_token": "eyJ...", "expires_in": 3600}

# 2) Request grid data (copy the url from the Lightkeeper UI under Grid > Api Routes)
curl -s "https://YOUR-ENVIRONMENT.lightkeeperhq.com/lightstation/api/reports/query/layout/YOUR_LAYOUT_ID/v2?focus=LKP_YOUR_PORTFOLIO__PORT&rollup=ISSUER&bd=20250101&ed=20250131" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

The response is JSON with a `Payload` of rollup, time, and total blocks plus request and portfolio metadata.

[`openapi/lkapi.yaml`](openapi/lkapi.yaml) provides an [OpenAPI](https://www.openapis.org/) specification for building clients in other languages. Note that the OAuth2 token exchange above is not embedded in the generated clients, so bearer token retrieval needs to be implemented in the native client language.

Example build instructions for a csharp OpenAPI client using the [openapi-generator](https://openapi-generator.tech/) CLI:
```bash
npm install @openapitools/openapi-generator-cli -g
openapi-generator-cli generate -i openapi/lkapi.yaml -g csharp -o csharp --additional-properties=apiName=LKApi
```

Swap `-g csharp` (and the output/properties) for another [supported generator](https://openapi-generator.tech/docs/generators), e.g. `-g javascript -o javascript --additional-properties=apiPackage=lkapi`.

## Contributing

If you have any suggestions or requests regarding examples, features or additional languages for clients, please submit an issue to this repository or reach out to [Lightkeeper support](https://lightkeeper.com/).

Releases are managed with [release-please](https://github.com/googleapis/release-please); please use [conventional commit](https://www.conventionalcommits.org/) messages (`fix:`, `feat:`, ...) so changes are picked up in the changelog and version bumps.

## License

[MIT](LICENSE)
