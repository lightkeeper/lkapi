
#! /usr/bin/env python
# Copyright (c) 2025 LightKeeper LLC
# Distributed under the MIT License (see LICENSE).
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
import numpy as np
import pandas as pd

from . import credential as lkcred

# --- URL Fields ---
DOMAIN_FIELD = 'domain'                          # holds the domain name for the server
ENVIRONMENT_FIELD = 'environment'                # holds the environment name for the server
MODE_FIELD = 'mode'                              # holds the mode name for the server (e.g. dev, test, prod)
GRID_FIELD = 'grid'                              # holds the data grid name to request
API_VERSION_FIELD = 'apiVersion'                 # holds the API version to request
PORTFOLIO_FIELD = 'portfolio'                    # holds the portfolio ID to request
ROLLUP_FIELD = 'rollup'                          # holds the rollup/granularity to request
BEGIN_DATE_FIELD = 'bd'                          # holds the beginning date for the request
END_DATE_FIELD = 'ed'                            # holds the end date for the request
DATE_SNAP_FIELD = 'dateSnap'                     # holds the date snap for the request

# --- Response Fields ---
PAYLOAD_FIELD = 'Payload'                        # holds the main data payload
RESPONSE_ID_FIELD = 'ResponseId'                 # API response identifier used for debugging
TIMESTAMP_FIELD = 'Timestamp'                    # Timestamp the request was made
REQUEST_DETAILS_FIELD = 'RequestDetails'         # Holds additional request metadata
PORTFOLIO_DETAILS_FIELD = 'PortfolioDetails'     # Holds portfolio metadata

CURRENT_API_VERSION = 2  # The current version of the API we are using

#---------------
# URL Tools
#---------------
def parse_api_url(url: str) -> typing.Dict[str, typing.Union[str,int]]:
    """
    Parses the data grid API url for a server into a dictionary of parameters.
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
            parsed_url[API_VERSION_FIELD] = int(parts[-1][1:])
        if len(parts) >= 2:
            parsed_url[GRID_FIELD] = parts[-2]
        if len(parts) >= 1:
            full_host = base.split('//')[1].split('/')[0]
            full_host_parts = full_host.split('.')
            if len(full_host_parts) > 1:
                parsed_url[DOMAIN_FIELD] = ".".join(full_host_parts[-2:])
            parsed_url[ENVIRONMENT_FIELD] = ".".join(full_host_parts[:-2])
        if parsed_url.get(ENVIRONMENT_FIELD) and '-' in parsed_url[ENVIRONMENT_FIELD]:
            environment_parts = parsed_url[ENVIRONMENT_FIELD].split('-')
            parsed_url[MODE_FIELD] = "-".join(environment_parts[:-1])
            parsed_url[ENVIRONMENT_FIELD] = environment_parts[-1]
        query_params = query.split('&')
        for param in query_params:
            key_value = param.split('=')
            # we will use the term 'portfolio' rather than 'focus' internally
            if key_value[0] == 'focus':
                key_value[0] = 'portfolio'
            if len(key_value) == 2:
                parsed_url[key_value[0]] = key_value[1]
    except Exception as e:
        raise ValueError(f"Failed to parse URL: {e}")

    return parsed_url

def build_api_url(url:typing.Optional[str]=None,
                  grid:typing.Optional[str]=None, domain:typing.Optional[str]=None,
                  environment:typing.Optional[str]=None, mode:typing.Optional[str]=None,
                  begin_date:typing.Optional[typing.Any]=None, end_date:typing.Optional[typing.Any]=None,
                  portfolio:typing.Optional[str]=None, rollup:typing.Optional[str]=None,
                  credential_manager:typing.Optional[lkcred.CredentialManager]=None,
                  api_version:typing.Optional[int]=None, **kwargs) -> str:
    """
    Builds the data grid API url to a server returning a string url.
    Args:
        url: The url string to query which was copied from the LK UI.  If provided it will be used as the base data set for
        all other parameters.
        grid: The grid name to request.  If not provided, the url must be provided.
        domain: The domain name to use for the request.  If not provided, the default credential manager domain will be used.
        environment: The environment name to use for the request.  If not provided, the default credential manager environment will be used.
        mode: The mode name to use for the request.  If not provided, no mode will be used.
        begin_date: The beginning date for the request in YYYYMMDD format.
        end_date: The end date for the request in YYYYMMDD format.
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
        if domain is not None:
            credential_kwargs[DOMAIN_FIELD] = domain
        if environment is not None:
            credential_kwargs[ENVIRONMENT_FIELD] = environment
        credential_manager = lkcred.get_credential_manager_from_kwargs(**credential_kwargs)
    if credential_manager.domain:
        url_parts[DOMAIN_FIELD] = credential_manager.domain
    if credential_manager.environment:
        url_parts[ENVIRONMENT_FIELD] = credential_manager.environment

    if domain is not None:
        url_parts[DOMAIN_FIELD] = domain
    if environment is not None:
        url_parts[ENVIRONMENT_FIELD] = environment
    if mode is not None:
        url_parts[MODE_FIELD] = mode
    if grid is not None:
        url_parts[GRID_FIELD] = grid
    if portfolio is not None:
        url_parts['portfolio'] = portfolio

    if not url_parts.get('portfolio'):
        raise ValueError("A portfolio ID must be provided either in the url or as a parameter.")

    base_url_parts = ([url_parts[ENVIRONMENT_FIELD]] if url_parts.get(ENVIRONMENT_FIELD) else []) + [url_parts[DOMAIN_FIELD]]
    base_url = '.'.join(base_url_parts)
    if url_parts.get(MODE_FIELD):
        base_url = f"{url_parts[MODE_FIELD]}-{base_url}"
    api_url = f"https://{base_url}/lightstation/api/reports/query/layout/{url_parts[GRID_FIELD]}/v{api_version or CURRENT_API_VERSION}?focus={url_parts['portfolio']}"

    if begin_date is not None:
        api_url += f"&{BEGIN_DATE_FIELD}={pd.to_datetime(begin_date).strftime('%Y%m%d')}"
    elif BEGIN_DATE_FIELD in url_parts:
        api_url += f"&{BEGIN_DATE_FIELD}={url_parts[BEGIN_DATE_FIELD]}"

    if end_date is not None:
        api_url += f"&{END_DATE_FIELD}={pd.to_datetime(end_date).strftime('%Y%m%d')}"
    elif END_DATE_FIELD in url_parts:
        api_url += f"&{END_DATE_FIELD}={url_parts[END_DATE_FIELD]}"

    if rollup is not None:
        api_url += f"&{ROLLUP_FIELD}={rollup}"

    return api_url

#---------------
# Responses
#---------------
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
        if PAYLOAD_FIELD in data:
            # -- layout API
            blocks = [lk_layout_element_to_frames(block) for block in data[PAYLOAD_FIELD]]
            if len(blocks) == 1:
                parsed_data = blocks[0]
            else:
                # join into a single frame
                block_dict = collections.defaultdict(list)
                for block in blocks:
                    if block is None:
                        continue
                    for key, frame in block.items():
                        block_dict[key].append(frame)
                parsed_data = {k: pd.concat(v, ignore_index=True) for k,v in block_dict.items()}
        else:
            raise RuntimeError(f'LK Layout API data missing: {PAYLOAD_FIELD}')
        # fill in the metadata if it is present
        if REQUEST_DETAILS_FIELD in data:
            parsed_data['request'] = data[REQUEST_DETAILS_FIELD]
            if TIMESTAMP_FIELD in data:
                parsed_data['request'][TIMESTAMP_FIELD] = data[TIMESTAMP_FIELD]
            if RESPONSE_ID_FIELD in data:
                parsed_data['request'][RESPONSE_ID_FIELD] = data[RESPONSE_ID_FIELD]
        if PORTFOLIO_DETAILS_FIELD in data:
            parsed_data['portfolio'] = data[PORTFOLIO_DETAILS_FIELD]
        return parsed_data
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
    if data_version == 2:
        for key in ['rollup', 'time', 'total']:
            headers = data['headers']
            # only a totals row may arrive without a value for the label column
            allow_missing_label = key == 'total'
            if key == 'total':
                # totals are either in rollup or time
                used_total_cols = [col for col in ['rollup', 'time'] if col in data]
                if not used_total_cols:
                    continue
                used_total_data = data[used_total_cols[0]]
                if 'totals' in used_total_data:
                    key_data = used_total_data['totals']
                elif 'groups' in used_total_data:
                    # label each group's totals row with the group name so the frame keeps its identity
                    key_data = [[name] + list(group['totals'])
                                for name, group in used_total_data['groups'].items() if 'totals' in group]
                    if not key_data:
                        continue
                    # we supplied the label ourselves ... these rows are never missing it
                    allow_missing_label = False
                else:
                    continue
            else:
                if key not in data:
                    continue
                key_data = data[key]
            keyFrame = lk_layout_data_to_frame_v2(key_data, key, list(headers), allow_missing_label)
            if keyFrame is not None:
                frame_data[key] = keyFrame
        if not frame_data:
            # empty data set ... return None to skip in upstream processing
            return None
    else:
        raise RuntimeError(f'Unknown layout block version: {data_version}')

    return frame_data

# ---- Version 2.0
def align_row_headers(data_headers: typing.List[str], row_width: int,
                      allow_missing_label: bool = False) -> typing.List[str]:
    """
    Matches a block header list to the actual width of its data rows.

    The first v2 header names the label column (e.g. 'Ticker', or 'Sector / Ticker' when grouping is
    enabled).  Data rows always carry that label, so a row narrower than the headers is missing
    trailing statistics and keeps the leftmost headers.  Summary rows -- the totals -- may omit the
    label instead, so those drop it before aligning.

    Args:
        data_headers: The block header names, label column first.
        row_width: The number of values in a data row.
        allow_missing_label: True when the rows may omit a value for the label column.
    Returns: A list of column names of length row_width.
    """
    data_headers = list(data_headers)
    if row_width > len(data_headers):
        # more values than headers ... name the unknown trailing columns positionally
        return data_headers + [f'Column {i + 1}' for i in range(len(data_headers), row_width)]
    if allow_missing_label and row_width < len(data_headers):
        # a totals row without its label column
        return data_headers[1:row_width + 1]
    return data_headers[:row_width]

def lk_layout_data_to_frame_v2(data: typing.Dict[str, typing.Any], data_type, data_headers,
                               allow_missing_label: typing.Optional[bool] = None) -> pd.DataFrame:
    """

    Args:
        data: A inner data dictionary such as rollup from V1 of the layout API.
        data_type: The block key the data came from ('rollup', 'time' or 'total').
        data_headers: The block header names, label column first.
        allow_missing_label: True when the rows may omit a value for the label column.  Defaults to
            the totals rows, the only ones the API sends unlabeled -- pass it explicitly when the
            caller has already labeled them.
    Returns: A data frame of the provided data.
    """
    is_grouped = "groups" in data.keys() if isinstance(data, dict) else False
    if allow_missing_label is None:
        # only the totals rows may arrive without a value for the label column
        allow_missing_label = data_type == 'total'

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
            data_col_headers = align_row_headers(data_headers, num_data_cols, allow_missing_label)
            data_frame.columns = [data_col_headers[0]] + group_columns + data_col_headers[1:]
        else:
            # No group columns, just set data column names
            data_frame.columns = align_row_headers(data_headers, num_data_cols, allow_missing_label)

    else:
        if data_type == 'time':
            data_headers = ['Date'] + data_headers[1:]
        if isinstance(data, list):
            if not data:
                return pd.DataFrame()
            # rows of values label themselves by the outermost tag of the label column
            data_headers = [data_headers[0].split(' / ')[0]] + data_headers[1:]
            if isinstance(data[0], list):
                rows = data
            else:
                # a single summary row of values
                rows = [data]
            data_frame = pd.DataFrame(rows, columns=align_row_headers(data_headers, max(len(r) for r in rows),
                                                                       allow_missing_label))
        else:
            # blocks excluded by a viewby selection are metadata-only stubs without a data key
            rows = [r for r in data.get('data', [])]
            row_width = max((len(r) for r in rows), default=len(data_headers))
            data_frame = pd.DataFrame(rows, columns=align_row_headers(data_headers, row_width,
                                                                      allow_missing_label))

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

#---------------
# Frame Tools
#---------------
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
                   if dtype.kind in {'i', 'f'} and column.endswith(' %')]
    if pct_columns:
        df = df.assign(**{col: df[col] / 100.0 for col in pct_columns})

    if 'Date' in df.columns and df['Date'].dtype == 'O':
        df['Date'] = pd.to_datetime(df['Date'])

    return df

def extract_temporal_field(df:pd.DataFrame, field:str, rollup:str=None) -> pd.DataFrame:
    """
    Extracts a temporal field from a data frame into a frame of rollups as columns and dates as rows.

    Args:
        df: A data frame to process.
        field: The field name to extract temporally.
        rollup: An optional rollup column name to use for grouping.

    Returns: A data frame of rollups as columns and dates as rows for a given field

    """
    if field not in df.columns:
        raise RuntimeError(f'Field {field} not found in data frame columns.')
    if 'Date' not in df.columns:
        raise RuntimeError(f'Date column not found in data frame columns.')
    if rollup is None:
        rollup = [col for col, kind in df.dtypes.to_dict().items() if kind == 'O']
        if not rollup:
            raise RuntimeError(f'No rollup column found in data frame for temporal extraction.')
        rollup = rollup[0]
    if rollup not in df.columns:
        raise RuntimeError(f'Rollup column {rollup} not found in data frame columns.')

    keys = ['Date', rollup]
    rf = df[keys + [field]].set_index(keys).unstack()
    rf.columns = rf.columns.get_level_values(1)
    rf.columns.name = None
    return rf

def extract_temporal_holdings(df:pd.DataFrame, rollup:str=None) -> pd.DataFrame:
    """
    Extracts a temporal holdings from a data frame by dropping rows without tags such as Direction.

    Args:
        df: A data frame to process.
        rollup: An optional rollup column name to use for grouping.

    Returns: A data frame filtered to holdings rather than complete rows for the time range.

    """
    tag_cols = [col for col, kind in df.dtypes.to_dict().items() if kind == 'O']
    if not tag_cols:
        raise RuntimeError(f'No tag column found in data frame for temporal holdings extraction.')
    if rollup is None:
        rollup = tag_cols.pop(0)
    else:
        tag_cols = [col for col in tag_cols if col != rollup]

    if not tag_cols:
        raise RuntimeError(f'No tag column found in data frame for temporal holdings extraction.')
    # filter to rows where at least one tag column is not a blank
    all_empty = [df[col] == "" for col in tag_cols]
    filter_mask = ~pd.concat(all_empty, axis=1).all(axis=1)
    return df[filter_mask]

def correlate_temporal_field(df:pd.DataFrame, field:str, rollup:str=None, half=['lower', 'upper', None][-1]) -> pd.DataFrame:
    """
    Produces a correlation matrix for a temporal field by rollup.

    Args:
        df: A data frame to process.
        field: The field name to extract temporally.
        rollup: An optional rollup column name to use for grouping.
        half: Optionally return only the 'lower' or 'upper' half of the correlation matrix.

    Returns: A correlation data frame

    """
    temporal_frame = extract_temporal_field(df, field, rollup)
    corr = temporal_frame.corr(method="pearson").dropna(axis=1, how='all').dropna(axis=0, how='all')
    if half:
        if half == 'lower':
            corr = corr.where(np.tril(np.ones(corr.shape), k=0).astype(bool))
        elif half == 'upper':
            corr = corr.where(np.triu(np.ones(corr.shape), k=0).astype(bool))
    return corr