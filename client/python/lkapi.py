
#! /usr/bin/env python
# Copyright (c) 2025 LightKeeper LLC
# ANY REDISTRIBUTION OR COPYING OF THIS MATERIAL WITHOUT THE EXPRESS CONSENT
# OF LIGHTKEEPER IS PROHIBITED.
# All rights reserved.
#
"""
Example code for processing Web API JSON data objects into pandas data frames.  The data returned from the
REST API is designed to be "complete" for the date range requested returning "rollup", "time", and "group"
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
import urllib.parse
from datetime import datetime

import requests
import pandas as pd

def lk_api_response_to_frames(response:typing.Union[str, typing.List[typing.Dict[str, typing.Any]], requests.Response]) -> typing.Optional[typing.Dict[str, pd.DataFrame]]:
    """
    Parses an API json response string to a dictionary of pandas frames.
    Args:
        response: A string like response from the web service to parse into a data frame.
    Returns: A dictionary of pandas data frames.
    """
    if isinstance(response, str):
        response = json.loads(response)
    elif hasattr(response, 'text'):
        if response.url.endswith('/signin'):
            raise RuntimeError(f'Unable to connect to the server because we were forwarded to the signin screen:\n{response.url}')
        response_url = response.url
        response = response.text
        if response[0] not in {'{', '['}:
            # a web page was returned ... this is not expected
            raise RuntimeError(f'Unable to connect to the server. Please retry or contact support:\n{response_url}')
        response = json.loads(response)

    return lk_api_data_to_frames(response)

def lk_api_data_to_frames(data:typing.List[typing.Dict[str, typing.Any]]) -> typing.Optional[typing.Dict[str, pd.DataFrame]]:
    """
    Converts a dictionary representation of JSON data from the API into a dictionary of frames.
    Args:
        data: A json like dictionary
    Returns: A dictionary of frames or None if the request fails.
    """

    # we are assuming layout json but if we could have different types in addition to different versions switch here
    data_type = 'layout'
    if data_type == 'layout':
        # -- layout API
        blocks = [lk_layout_element_to_frames(block) for block in data]
        if len(blocks) == 1:
            return blocks[0]
        else:
            # join into a single frame
            block_dict = collections.defaultdict(list)
            for block in blocks:
                if block is None:
                    continue
                for key, frame in block.items():
                    block_dict[key].append(frame)
            return {k: pd.concat(v, ignore_index=True) for k,v in block_dict.items()}
    else:
        raise RuntimeError(f'Unknown LK API data type: {data_type}')

def lk_layout_element_to_frames(data: typing.Dict[str, typing.Any]) -> typing.Optional[typing.Dict[str, pd.DataFrame]]:
    """
    Convert an LK API data element within a block to pandas frames.  A block data element provides sufficient data to
    present both table and graphical views via sub dictionaries of multiple rows of data.
    Args:
        data: A deserialized data object from the LK API to convert to frames.
    Returns: A dictionary of pandas frames.
    """
    frame_data = {}

    data_version = data['version']

    if data_version == 1:
        for key in ['rollup', 'time', 'net', 'groups']:
            keyFrame = lk_layout_data_to_frame_v1(data[key])
            if keyFrame is not None:
                frame_data[key] = keyFrame
        if not frame_data:
            # empty data set ... return None to skip in upstream processing
            return None
        if 'groups' in frame_data:
            # adjust the net information to include the additional columns for groups
            group_cols = frame_data['groups'].columns.to_list()[:-1 *len(frame_data['net'].columns)]
            frame_data['net'] = pd.concat([pd.DataFrame({col: [""] * len(frame_data['net']) for col in group_cols}),
                                           frame_data['net']], axis=1)

            # combine with net data for complete information
            frame_items = []
            net_frame = frame_data.pop('net')
            if len(net_frame) > 0:
                frame_items.append(net_frame)
            if len(frame_data['groups']) > 0:
                frame_items.append(frame_data['groups'])
            frame_data['groups'] = pd.concat(frame_items).reset_index(drop=True)

            # add in level information
            frame_data['groups'] = pd.concat([pd.DataFrame({'level': [0] * len(frame_data['groups'])}),
                                              frame_data['groups']], axis=1)
            for group_col in group_cols:
                frame_data['groups'].loc[frame_data['groups'][group_col] != "", 'level'] += 1

            frame_data['groups'].sort_values(['level'] + group_cols, inplace=True)
            frame_data['groups'].reset_index(drop=True, inplace=True)

            # don't bother keeping a level column if it is not interesting
            if frame_data['groups']['level'].sum() == 0:
                frame_data['groups'].drop('level', axis=1, inplace=True)

            # add group column names back to the time series for consistency if there are rows of groups
            group_rows = data['groups']['rows']
            if len(group_rows) > 0:
                frame_data['time'].columns = group_cols + frame_data['time'].columns.to_list()[len(group_cols):]
        else:
            frame_data['groups'] = frame_data.pop('net')
    else:
        raise RuntimeError(f'Unknown layout block version: {data_version}')

    return frame_data

#---------------
# Version 1.0
#---------------
def lk_layout_data_to_frame_v1(data: typing.Dict[str, typing.Any]) -> pd.DataFrame:
    """
    Converts an inner Lightkeeper layout data dictionary to simplified frame object for later processing.  This function
    pays special attention to data depth, and provides a flattened frame by "level" for later processing.
    Args:
        data: A inner data dictionary such as rollup from V1 of the layout API.
    Returns: A data frame of the provided data.
    """
    data_type = data['type']
    data_depth = data['depth']
    data_headers = data['headers']
    if data_type == 'Net' and data_headers[0] == 'Total':
        # drop the total since it isn't helpful
        data_headers = data_headers[1:]

    data_frame = pd.DataFrame([r['data'] for r in data['rows']], columns=data_headers)

    # if the depth is greater than 1 we will need to process the path frame for the first column ... adjust the headers
    if data_depth > 1  and data_type != 'Net':
        path_headers = data_headers[0].split(' / ')
        if len(path_headers) == 1:
            # fill in dummy variables for missing path details
            path_headers = [f'Level{l + 1}' for l in range(len(data['rows'][0]['path']) - 1)] + path_headers
        # create a new copy of data headers to avoid clobbering
        data_headers = [path_headers.pop()] + data_headers[1:]
        # instrument is the default rollup so not title cased ... correct that
        if data_headers[0] == 'instrument':
            data_headers[0] = 'Instrument'
        data_frame.columns = data_headers

        path_rows = [r['path'] for r in data['rows']]
        if data_type == 'Groups':
            # In groups the data is sparse, so pad the path data as necessary to get to the total
            path_rows = [(r + ([""] * (len(path_headers) - len(r))))
                         if len(r) < len(path_headers) else r for r in path_rows]
            path_frame = pd.DataFrame(path_rows, columns=path_headers)
            # We will not keep the first column from the data rows
            data_frame.drop(data_frame.columns[0], axis=1, inplace=True)
        else:
            # The last element of the path is also included in the frame.  For Instrument, it is a Lightkeeper Id in the
            # path, and a clean Symbol in the data rows, so we will keep the data row information.
            path_frame = pd.DataFrame(path_rows, columns=path_headers + ['__drop__'])
            path_frame.drop('__drop__', axis=1, inplace=True)
        data_frame = pd.concat([path_frame, data_frame], axis=1)

    return data_frame

def payload_to_frame(responseResult):
    """

    Args:
        responseResult: repsonse dictionary from an api request.

    Returns:
        payload results from the api response as a frame
    """
    try:
        payload = responseResult['Payload']
        payload_frame = lk_api_data_to_frames(payload)
        return payload_frame
    except:
        print("No payload data returned")

#---------------
# Basic Client
#---------------
def get_datetime(iso_time_string):
    """
    Converts an ISO formatted time string into a datetime object.

    Args:
        iso_time_string (str): A string representing a date and time in ISO 8601 format
                                (e.g., "2023-10-26T10:30:00" or "2023-10-26").

    Returns:
        datetime: A datetime object extracted from the ISO string.
                       Returns None if the string is not a valid ISO format
                       or if any other error occurs during parsing.
    """
    try:
        # Parse the ISO formatted string into a datetime object
        datetime_obj = datetime.fromisoformat(iso_time_string)
        # Extract and return only the date part
        return datetime_obj
    except ValueError:
        print(f"Error: The provided string '{iso_time_string}' is not a valid ISO format or is otherwise unparseable.")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None

def get_auth_token(environment:str, hostname:str, username:str, password:str, **kwargs) -> str:
    """
    Generates an authorization token from Cognito using the supplied username and password. Tokens are valid for
    one hour. A 401 Token Expired will be returned if they time out.  Tokens can be refreshed with another request
    to the auth server.
    Args:
        environment: The environment you are connecting (e.g. see)
        username: The user identifier.
        password: The user password.
    Returns: An authentication token to use as a bearer token in authorization headers for API requests.
    """
    auth_data = {
        "grant_type": "client_credentials",
        "client_id": username,
        "client_secret": password
    }
    # we are splitting to accommodate dev-see, beta-see, and see
    apiAuthHostname = f'{environment.split("-")[-1]}.{".".join(hostname.split(".")[1:])}'
    auth_response = requests.post(f"https://api.auth.{apiAuthHostname}/oauth2/token", data=auth_data).json()
    return f"{auth_response['token_type']} {auth_response['access_token']}"

def make_api_request(url:str, username:str, password:str,):
    """
    Makes an API request to a server returning a dictionary of frames for the data.
    Args:
        url: The url string to query which was copied from the LK UI.
        username: The user identifier.
        password: The user password.
    Returns:
    """
    url_parse = urllib.parse.urlparse(url)
    hostname = url_parse.netloc
    environment = hostname.split('.')[0]

    token = get_auth_token(environment=environment, hostname=hostname, username=username, password=password)
    api_headers = {"Authorization": token}

    response = requests.get(url, headers=api_headers)

    # Tokens are valid for one hour ... check for a 401 Token Expired if they time out
    if response.status_code == 401 and response.json()['detail'] == "Token Expired":
        print("Token expired. Refreshing token...")
        token = get_auth_token(environment=environment, username=username, password=password)
        api_headers["Authorization"] = token
        response = requests.get(url, headers=api_headers)

    return response.json()

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
    payload = api_response.get("Payload")
    frames = lk_api_response_to_frames(payload)
    print(frames)
    print("------ end of frames ------")

    # in addition, you can also access additional metadata
    responseId = api_response.get("ResponseId")
    timestamp = api_response.get("TimeStamp")

    print("Response ID:", responseId)
    print("TimeStamp:", timestamp)
    print("---------------------------")

    # portfolio dates
    portfolioDetails = api_response.get("PortfolioDetails")
    lastDate = get_datetime(portfolioDetails.get("LastDate"))
    firstDate = get_datetime(portfolioDetails.get("FirstDate"))
    lastUpdated = get_datetime(portfolioDetails.get("LastUpdated"))

    print("Portfolio First Date:", firstDate)
    print("Portfolio Last Date:", lastDate)
    print("Portfolio Last Updated:", lastUpdated)
    print("---------------------------")

    # Request details
    requestDetails = api_response.get("RequestDetails")
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


