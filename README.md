# [lkapi](https://lightkeeper.com/)
This repo providers example client code to work with the Lightkeeper API.

Access to the Lightkeeper API is handled via the OAuth2 client credentials flow.

If you'd like to know more about API access to your existing Lightkeeper environment, or have any enquiries about working with Lightkeeper, [please contact us](https://lightkeeper.com/).

## Usage

To access the Lightkeeper API, regardless of programming language, you will need a `client_id`, and `client_secret` from Lightkeeper.  These credentials are required to make requests against your Lightkeeper environment.

The python directory includes a supported API client that intereacts with API data via pandas data frames. If you would like to build your own client in a different language `lkapi.yaml` provides an [OpenApi](https://www.openapis.org/) specification. Do note that the OAuth2 workflow does not naturally embed in OpenAPI client so extra coding work around retrieving the bearer token will need to be implemented in the native client language.

Example build instructions for a csharp OpenAPI client using a npm tool chain:
```bash
npm install @openapitools/openapi-generator-cli -g
npm run lkapi_csharp_build
```

## Contributing

If you have any suggestions or requests regarding examples, features or additional languages for clients.  Please submit an issue to this repository or reach out to [Lightkeeper support](lightkeeper.com).

## License

[MIT](https://choosealicense.com/licenses/mit/)
