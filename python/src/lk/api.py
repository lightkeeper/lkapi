
#! /usr/bin/env python
# Copyright (c) 2025 LightKeeper LLC
# ANY REDISTRIBUTION OR COPYING OF THIS MATERIAL WITHOUT THE EXPRESS CONSENT
# OF LIGHTKEEPER IS PROHIBITED.
# All rights reserved.
#
"""
Provides methods to retrieve data from a Lightkeeper environment as a data frame.  The core response from the
Web API is JSON, and the library manages the conversion of JSON data objects into pandas data frames.
The data returned from the Web API is designed to be "complete" for the date range requested returning "rollup", "time", and "group"
information.  The API calls fully respects the settings of the requested view (e.g. filters and groups will be applied
as seen in the view).
  + **rollup**: Data at the specified granularity requested summarized for *the entire time period** using per statistic
                net time summaries selected in the UI view.
  + **groups**: Summarized data for the specified groupings aggregated across rollup and time by the statistics net
               summaries.  If no groups are specified this will default to the full portfolio summary.
  + **time**: Data at the specified time granularity summarized for *all rollups* using per statistic net item
              summaries.
To retrieve all rollups per time period (e.g. all holdings in a day), use multiple web requests, adjusting the dates,
and combined the resulting data.
"""
import json
import typing
import collections

import requests
import pandas as pd
from . import credential as lkcred
from . import parser as lkparser

CURRENT_VERSION = 2  # The current version of the API we are using

def parse_api_url(url: str) -> typing.Dict[str, typing.Union[str,int]]:
    """
    Parses the data grid API url to a server returning a dictionary of parameters.
    Args:
        url: The url string to parse which was copied from the LK UI.
    Returns: A dictionary of parameters parsed from the url.
    """
    if url is None:
        raise ValueError("A url must be provided.")

    # Example URL:
    # https://environment.domain/lightstation/api/reports/query/layout/<template>/v2?focus=portfolio&rollup=rollup&bd=YYYY-MM-DD&ed=YYYY-MM-DD

    parsed_url = {}
    try:
        base, query = url.split('?', 1)
        parts = base.split('/')
        if len(parts) >= 1 and parts[-1].startswith('v'):
            parsed_url['api_version'] = int(parts[-1][1:])
        if len(parts) >= 2:
            parsed_url['grid'] = parts[-2]
        if len(parts) >= 1:
            full_host = base.split('//')[1].split('/')[0]
            full_host_parts = full_host.split('.')
            if len(full_host_parts) > 1:
                parsed_url['domain'] = ".".join(full_host_parts[-2:])
            parsed_url['environment'] = ".".join(full_host_parts[:-2])
        if parsed_url.get('environment') and '-' in parsed_url['environment']:
            environment_parts = parsed_url['environment'].split('-')
            parsed_url['mode'] = "-".join(environment_parts[:-1])
            parsed_url['environment'] = environment_parts[-1]
        query_params = query.split('&')
        for param in query_params:
            key_value = param.split('=')
            if len(key_value) == 2:
                parsed_url[key_value[0]] = key_value[1]
    except Exception as e:
        raise ValueError(f"Failed to parse URL: {e}")

    return parsed_url

def build_api_url(url:typing.Optional[str]=None,
                  grid:typing.Optional[str]=None, domain:typing.Optional[str]=None,
                  environment:typing.Optional[str]=None, mode:typing.Optional[str]=None,
                  begin_date:typing.Optional[str]=None, end_date:typing.Optional[str]=None,
                  date_snap:typing.Optional[str]=None,
                  portfolio:typing.Optional[str]=None, rollup:typing.Optional[str]=None,
                  credential_manager:typing.Optional[lkcred.CredentialManager]=None,
                  api_version:typing.Optional[int]=None) -> str:
    """
    Builds the data grid API url to a server returning a string url.
    Args:
        url: The url string to query which was copied from the LK UI.  If provided it will be used as the base data set for
        all other parameters.
        grid: The grid name to request.  If not provided, the url must be provided.
        domain: The domain name to use for the request.  If not provided, the default credential manager domain will be used.
        environment: The environment name to use for the request.  If not provided, the default credential manager environment will be used.
        mode: The mode name to use for the request.  If not provided, no mode will be used.
        begin_date: The beginning date for the request in YYYY-MM-DD format.
        end_date: The end date for the request in YYYY-MM-DD format.
        date_snap: The date snap to use for the request.  If provided, begin_date and end_date will be ignored.
        portfolio: The portfolio ID to use for the request.  If not provided, the default portfolio for the user will be used.
        rollup: The rollup/granularity to use for the request.  If not provided, the default rollup for the view will be used.
        credential_manager: The credential manager to use to securely retrieve credentials. If provided, it will override
                            any url, domain, or environment parameters.
        api_version: The API version to use for the request.  If not provided, the default API version will be used.
    Returns: A string url built from the component parts.
    """
    if url is not None:
        url_parts = parse_api_url(url)
    else:
        url_parts = {}

    if grid is None and not url_parts:
        raise ValueError("Either a url or grid name must be provided.")

    if credential_manager is None:
        credential_kwargs = url_parts.copy()
        credential_kwargs['domain'] = domain
        credential_kwargs['environment'] = environment
        credential_manager = lkcred.get_credential_manager_from_kwargs(**credential_kwargs)
        url_parts['domain'] = credential_manager.domain
        url_parts['environment'] = credential_manager.environment

    if mode is not None:
        url_parts['mode'] = mode

    if grid is not None:
        url_parts['grid'] = grid

    if portfolio is not None:
        url_parts['portfolio'] = portfolio
    if not url_parts.get('portfolio'):
        raise ValueError("A portfolio ID must be provided either in the url or as a parameter.")

    base_url = '.'.join([url_parts['domain'], url_parts['environment']])
    if url_parts.get('mode'):
        base_url = f"{url_parts['mode']}-{base_url}"
    api_url = f"{base_url}/api/v{api_version or CURRENT_VERSION}/data/grid/{url_parts['grid']}?focus={url_parts['portfolio']}"

    if begin_date is not None:
        api_url += f"&bd={begin_date}"
    if end_date is not None:
        api_url += f"&ed={end_date}"
    if rollup is not None:
        api_url += f"&rollup={rollup}"

    return api_url

#---------------
# Basic Client
#---------------
def make_api_request(url:typing.Optional[str]=None, grid:typing.Optional[str]=None,
                     environment:typing.Optional[str]=None,
                     credential_manager:typing.Optional[typing.Union[str, lkcred.CredentialManager]]=None,
                     **kwargs):
    """
    Makes a data grid API request to a server returning a dictionary of frames for the data.
    Args:
        url: The url string to query which was copied from the LK UI.
        grid: The grid name to request.  If not provided, the url must be provided.
        environment: The environment name to use to look up credentials if url is not provided.
        credential_manager: The credential manager to use to securely retrieve credentials.
        **kwargs: Additional arguments passed to the credential manager to retrieve credentials.
    Returns: A requests response object.
    """
    if credential_manager is None:
        credential_manager = lkcred.get_credential_manager_from_kwargs(environment=environment, **kwargs)
    token = lkcred.get_auth_token(url=url, credential_manager=credential_manager, **kwargs)
    api_headers = {"Authorization": token}

    used_url = build_api_url(url, grid=grid, credential_manager=credential_manager, **kwargs)
    response = requests.get(used_url, headers=api_headers)

    # Tokens are valid for one hour ... check for a 401 Token Expired if they time out
    if response.status_code == 401 and response.json()['detail'] == "Token Expired":
        print("Token expired. Refreshing token...")
        token = lkcred.get_auth_token(url=url, environment=environment, credential_manager=credential_manager, **kwargs)
        api_headers["Authorization"] = token
        response = requests.get(url, headers=api_headers)

    return response

if __name__ == "__main__":

    CONFIG = {
        # You can get an API url by logging into the UI and navigating to:
        # Grid > Api Routes
        # Replace the API url as appropriate
        "url": "XXXXXXXXXXX",
        # Paste you client ID (username)/secret (password) here or load from environment variables.
        "username": "XXXXXXXXXXXX",
        "password": "XXXXXXXXXXXXXXXXX"
    }

    api_response = make_api_request(**CONFIG)

    # access main data
    frames = lkparser.lk_api_response_to_frames(api_response)
    print(frames)
    print("------ end of frames ------")

    # in addition, you can also access additional metadata
    api_response_json = api_response.json()
    payload = api_response_json.get("Payload")
    if payload is not None and len(payload) >= 1:
        version = payload[0].get("version")
    else:
        version = None

    responseId = api_response_json.get("ResponseId")
    timestamp = api_response_json.get("TimeStamp")

    print("Response ID:", responseId)
    print("TimeStamp:", timestamp)
    print("Api Version:", version)
    print("---------------------------")

    # portfolio dates
    portfolioDetails = api_response_json.get("PortfolioDetails")
    lastDate = pd.to_datetime(portfolioDetails.get("LastDate"))
    firstDate = pd.to_datetime(portfolioDetails.get("FirstDate"))
    lastUpdated = pd.to_datetime(portfolioDetails.get("LastUpdated"))

    print("Portfolio First Date:", firstDate)
    print("Portfolio Last Date:", lastDate)
    print("Portfolio Last Updated:", lastUpdated)
    print("---------------------------")

    # Request details
    requestDetails = api_response_json.get("RequestDetails")
    requestPath = requestDetails.get("Path")
    queryString = requestDetails.get("QueryString")
    queryParams = requestDetails.get("QueryParameters")

    print("Request Path:", requestPath)
    print("Request QueryString:", queryString)
    print("Request Parameters:", queryParams)
    print("---------------------------")

    # get specific query parameter values
    portfolioId = queryParams.get("focus")
    bd = queryParams.get("bd")
    ed = queryParams.get("ed")

    print("Portfolio ID:", portfolioId)
    print("Begin date:", bd)
    print("End date:", ed)


