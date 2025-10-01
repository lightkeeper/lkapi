
#! /usr/bin/env python
# Copyright (c) 2025 LightKeeper LLC
# ANY REDISTRIBUTION OR COPYING OF THIS MATERIAL WITHOUT THE EXPRESS CONSENT
# OF LIGHTKEEPER IS PROHIBITED.
# All rights reserved.
#
"""
Methods for processing Web API JSON data objects into pandas data frames.  The data returned from the
REST API is designed to be "complete" for the date range requested returning "rollup", "time", and "group"
information.
"""
import json
import typing
import collections

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
        # this is a raw response object ... convert it to json after confirming it is a good page
        if response.url.endswith('/signin'):
            raise RuntimeError(f'Unable to connect to the server because we were forwarded to the signin screen:\n{response.url}')
        response_url = response.url
        response_text = response.text
        if response_text[0] not in {'{', '['}:
            # a web page was returned ... this is not expected
            raise RuntimeError(f'Unable to connect to the server. Please retry or contact support:\n{response_url}')
        response = json.loads(response_text)

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
        if 'Payload' in data:
            # -- layout API
            blocks = [lk_layout_element_to_frames(block) for block in data['Payload']]
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
            raise RuntimeError(f'LK Layout API data missing: Payload')
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
                net_frame.columns = frame_data['groups'].columns.to_list()[-1 *len(net_frame.columns):]
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
        if 'time' in frame_data:
            # convert time information
            frame_data['time']['Date'] = pd.to_datetime(frame_data['time']['Date'])
    elif data_version == 2:
        for key in ['rollup', 'time']:
            headers = data['headers']
            keyFrame = lk_layout_data_to_frame_v2(data[key], key, headers)
            if keyFrame is not None:
                frame_data[key] = keyFrame
        if not frame_data:
            # empty data set ... return None to skip in upstream processing
            return None
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

#---------------
# Version 2.0
#---------------
def lk_layout_data_to_frame_v2(data: typing.Dict[str, typing.Any], data_type, data_headers) -> pd.DataFrame:
    """

    Args:
        data: A inner data dictionary such as rollup from V1 of the layout API.
    Returns: A data frame of the provided data.
    """
    is_grouped = "groups" in data.keys()

    if data_type == 'Net' and data_headers[0] == 'Total':
        # drop the total since it isn't helpful
        data_headers = data_headers[1:]

    if is_grouped:
        group_headers = data_headers[0].split(' / ')
        base_data_type = group_headers.pop()
        if data_type == 'time':
            # time always has Date as the base data type
            base_data_type = 'Date'
        data_headers = [base_data_type] + data_headers[1:]

        dfs = extract_group_data(data, group_headers)

        if not dfs:
            return pd.DataFrame()

        # Combine all DataFrames
        data_frame = pd.concat(dfs, ignore_index=True)

        num_data_cols = len([col for col in data_frame.columns if isinstance(col, int)])

        # Get group columns (they start with 'Group_Level_')
        group_columns = [col for col in data_frame.columns if isinstance(col, str)]

        # Reorder columns: put group columns after the first data column (Instrument)
        if group_columns:
            # Get the numeric column indices for data
            data_col_indices = [i for i in range(num_data_cols)]

            # New order: first data column, then group columns, then remaining data columns
            new_order = [data_col_indices[0]] + group_columns + data_col_indices[1:]
            data_frame = data_frame[new_order]

            # Set the final column names
            data_frame.columns = [data_headers[0]] + group_columns + data_headers[1:num_data_cols]
        else:
            # No group columns, just set data column names
            data_frame.columns = data_headers[:num_data_cols]

    else:
        if data_type == 'time':
            data_headers[0] = 'Date'
        data_frame = pd.DataFrame([r for r in data['data']], columns=data_headers)

    return clean_frame(data_frame)

def extract_group_data(data, group_headers=None, group_path=None):
    """
    Recursively extract data from nested group structure.

    Args:
        data: The data structure (dict)
        group_headers: Optional list of group header names
        group_path: List to track the current group hierarchy

    Returns:
        List of DataFrames with group information
    """
    dfs = []

    # Check if this level has 'data' key (leaf node)
    if 'data' in data:
        df = pd.DataFrame(data['data'])
        # Add group columns for each level in the hierarchy
        for i, group_name in enumerate(group_path):
            df[group_headers[i] if group_headers else f'Group_Level_{i+1}'] = group_name
        dfs.append(df)

    # Check if this level has 'groups' key (intermediate node)
    elif 'groups' in data:
        if group_path is None:
            group_path = []
        for group_name, group_info in data['groups'].items():
            # Recursively process each group, adding current group to path
            sub_dfs = extract_group_data(group_info, group_headers, group_path + [group_name])
            dfs.extend(sub_dfs)

    return dfs

def clean_frame(df:pd.DataFrame) -> pd.DataFrame:
    """
    Cleans a data frame by dropping duplicate columns and transforming percentage numeric returns from integer
    based outputs to floats.
    Args:
        df: A data frame to process.

    Returns: A data frame cleaned of duplicated columns and transformed percentage numeric values.

    """
    # drop duplicate columns
    df = df.loc[:, ~df.columns.duplicated(keep='last')]

    # clean up percentage columns
    pct_columns = [column for column, dtype in list(df.dtypes.to_dict().items())
                   if dtype.kind == 'f' and column.endswith(' %')]
    if pct_columns:
        df[pct_columns] /= 100.0

    return df