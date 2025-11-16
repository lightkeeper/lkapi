
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
import typing

import requests
from . import credential as lkcred
from . import parser as lkparser

#---------------
# Basic Request
#---------------
def get_grid_data(url:typing.Optional[str]=None, grid:typing.Optional[str]=None,
                  environment:typing.Optional[str]=None,
                  credential_manager:typing.Optional[typing.Union[str, lkcred.CredentialManager]]=None,
                  debug=False, **kwargs):
    """
    Makes a data grid API request to a server returning a dictionary of frames for the data.
    Args:
        url: The url string to query which was copied from the LK UI.
        grid: The grid name to request.  If not provided, the url must be provided.
        environment: The environment name to use to look up credentials if url is not provided.
        credential_manager: The credential manager to use to securely retrieve credentials.
        debug: Return the raw requests response object if True, otherwise parse and return a data dictionary.
        **kwargs: Additional arguments passed to the credential manager to retrieve credentials.
    Returns: A requests response object.
    """
    if credential_manager is None:
        credential_manager = lkcred.get_credential_manager_from_kwargs(url=url, environment=environment, **kwargs)

    # construct the URL details
    used_url = lkparser.build_api_url(url, grid=grid, credential_manager=credential_manager, **kwargs)

    token = lkcred.get_auth_token(url=used_url, credential_manager=credential_manager, **kwargs)
    api_headers = {"Authorization": token}

    if debug:
        print(f"Making API request to URL: {used_url}")
    response = requests.get(used_url, headers=api_headers)

    # Tokens are valid for one hour ... check for a 401 Token Expired if they time out
    if response.status_code == 401 and response.json()['detail'] == "Token Expired":
        token = lkcred.get_auth_token(url=used_url, environment=environment, credential_manager=credential_manager, **kwargs)
        api_headers = {"Authorization": token}
        response = requests.get(used_url, headers=api_headers)

    if debug:
        return response
    else:
        if response.status_code != 200:
            raise ValueError(f"API request failed with status code {response.status_code}: {response.text}")
        return lkparser.lk_api_response_to_frames(response)
