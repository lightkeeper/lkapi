# tests/test_parser.py
import pytest
import pandas as pd
import numpy as np
from unittest.mock import Mock, MagicMock
from pandas.testing import assert_frame_equal

from lk import credential

from lk.parser import (
    parse_api_url,
    build_api_url,
    lk_api_response_to_frames,
    lk_api_data_to_frames,
    lk_layout_element_to_frames,
    lk_layout_data_to_frame_v2,
    extract_group_data,
    clean_frame,
    extract_temporal_field,
    extract_temporal_holdings,
    correlate_temporal_field,
    PAYLOAD_FIELD,
    REQUEST_DETAILS_FIELD,
    PORTFOLIO_DETAILS_FIELD,
    TIMESTAMP_FIELD,
    RESPONSE_ID_FIELD
)

# --- Fixtures for Test Data ---
@pytest.fixture
def mock_v2_layout_element():
    """Provides a sample v2 layout element dictionary with grouped data."""
    return {
        'version': 2,
        'headers': ['Sector / Ticker', 'Value', 'Return %'],
        'rollup': {
            'groups': {
                'Tech': {
                    'data': [['MSFT', 150, 5], ['GOOG', 120, 3]],
                    'totals': [270, 4]
                },
                'Finance': {
                    'data': [['JPM', 100, 2]],
                    'totals': [100, 2]
                }
            },
            'totals': [370, 3.5]
        },
        'time': {
            'groups': {
                'Tech': {
                    'data': [['2023-01-01', 150], ['2023-01-02', 155]],
                }
            }
        }
    }

@pytest.fixture
def sample_dataframe():
    """Provides a sample DataFrame for cleaning and extraction tests."""
    data = {
        'Date': pd.to_datetime(['2023-01-01', '2023-01-01', '2023-01-02', '2023-01-02']),
        'Ticker': ['AAPL', 'MSFT', 'AAPL', 'MSFT'],
        'Sector': ['Tech', 'Tech', 'Tech', 'Tech'],
        'Return %': [1.5, 2.0, 1.8, 2.2],
        'Value': [100, 200, 101, 202],
        'Direction': ['Long', 'Long', '', '']
    }
    return pd.DataFrame(data)

@pytest.fixture
def mock_credential_manager():
    """Fixture for a mock CredentialManager."""
    manager = MagicMock(spec=credential.CredentialManager)
    manager.domain = "mockdomain.com"
    manager.environment = "mockenv"
    return manager

# --- Test URL Functions ---
# Test data for parse_api_url
BASE_URL = "https://testenv.testdomain.com/lightstation/api/reports/query/layout/mygrid/v2?focus=myportfolio&rollup=myrollup&bd=2025-01-01&ed=2025-01-31"
URL_WITH_MODE = "https://dev-testenv.testdomain.com/lightstation/api/reports/query/layout/mygrid/v2?focus=myportfolio"
EXPECTED_PARSED_URL = {
    'api_version': 2,
    'grid': 'mygrid',
    'domain': 'testdomain.com',
    'environment': 'testenv',
    'portfolio': 'myportfolio',
    'rollup': 'myrollup',
    'bd': '2025-01-01',
    'ed': '2025-01-31'
}

# --- Test Response Functions ---
def test_lk_api_response_to_frames_signin_redirect():
    """Test RuntimeError on signin redirect."""
    mock_response = Mock()
    mock_response.url = 'http://test.com/signin'
    with pytest.raises(RuntimeError, match='forwarded to the signin screen'):
        lk_api_response_to_frames(mock_response)

def test_lk_api_response_to_frames_non_json_response():
    """Test RuntimeError on non-JSON response text."""
    mock_response = Mock()
    mock_response.text = '<html><body>Error</body></html>'
    mock_response.url = 'http://test.com/api'
    with pytest.raises(RuntimeError, match='Unable to connect to the server'):
        lk_api_response_to_frames(mock_response)

def test_lk_api_data_to_frames_missing_payload():
    """Test RuntimeError when PAYLOAD_FIELD is missing."""
    with pytest.raises(RuntimeError, match='missing: Payload'):
        lk_api_data_to_frames({'some_other_field': []})

# --- Test V2 Layout Functions ---
def test_lk_layout_element_to_frames_v2(mock_v2_layout_element):
    """Test processing a version 2 layout element."""
    result = lk_layout_element_to_frames(mock_v2_layout_element)
    assert isinstance(result, dict)
    assert 'rollup' in result
    assert 'time' in result
    assert 'total' in result
    assert 'Sector' in result['rollup'].columns
    assert len(result['rollup']) == 3

def test_lk_layout_element_to_frames_unknown_version():
    """Test RuntimeError on unknown layout version."""
    with pytest.raises(RuntimeError, match='Unknown layout block version'):
        lk_layout_element_to_frames({'version': 99})

def test_lk_layout_data_to_frame_v2_grouped(mock_v2_layout_element):
    """Test v2 data conversion with grouped data."""
    df = lk_layout_data_to_frame_v2(mock_v2_layout_element['rollup'], 'rollup', mock_v2_layout_element['headers'])
    assert 'Sector' in df.columns
    assert 'Ticker' in df.columns
    assert len(df) == 3
    assert df['Sector'].tolist() == ['Tech', 'Tech', 'Finance']

def test_lk_layout_data_to_frame_v2_non_grouped():
    """Test v2 data conversion with flat data."""
    data = {'data': [['T1', 100], ['T2', 200]]}
    headers = ['Ticker', 'Value']
    df = lk_layout_data_to_frame_v2(data, 'rollup', headers)
    assert_frame_equal(df, pd.DataFrame([['T1', 100], ['T2', 200]], columns=headers))

def test_extract_group_data(mock_v2_layout_element):
    """Test recursive extraction of grouped data."""
    dfs = extract_group_data(mock_v2_layout_element['rollup'], group_headers=['Sector'])
    df = pd.concat(dfs)
    assert len(df) == 3
    assert 'Sector' in df.columns
    assert df['Sector'].tolist() == ['Tech', 'Tech', 'Finance']

# --- Test Frame Tools ---
def test_clean_frame():
    """Test cleaning of a DataFrame."""
    data = {'A': [1], 'B': [100.0], 'B': [100.0], 'C %': [500]}
    df = pd.DataFrame(data)
    cleaned_df = clean_frame(df)
    assert list(cleaned_df.columns) == ['A', 'B', 'C %']
    assert cleaned_df['C %'].iloc[0] == 5.0

def test_extract_temporal_field(sample_dataframe):
    """Test temporal field extraction."""
    temporal_df = extract_temporal_field(sample_dataframe, 'Value', 'Ticker')
    assert list(temporal_df.columns) == ['AAPL', 'MSFT']
    assert len(temporal_df) == 2
    assert temporal_df.loc[pd.Timestamp('2023-01-01'), 'AAPL'] == 100

def test_extract_temporal_field_no_field(sample_dataframe):
    """Test error when extraction field is missing."""
    with pytest.raises(RuntimeError, match='Field BadField not found'):
        extract_temporal_field(sample_dataframe, 'BadField', 'Ticker')

def test_extract_temporal_holdings(sample_dataframe):
    """Test temporal holdings extraction."""
    holdings_df = extract_temporal_holdings(sample_dataframe.drop('Sector', axis=1), 'Ticker')
    # Only first two rows have a 'Direction' tag
    assert len(holdings_df) == 2
    assert holdings_df['Date'].nunique() == 1

def test_correlate_temporal_field(sample_dataframe):
    """Test temporal field correlation."""
    corr_df = correlate_temporal_field(sample_dataframe, 'Value', 'Ticker')
    assert corr_df.shape == (2, 2)
    assert corr_df.loc['AAPL', 'MSFT'] == 1.0 # With 2 points, correlation is 1 or -1
    assert np.isclose(corr_df.loc['AAPL', 'AAPL'], 1.0)

def test_correlate_temporal_field_half(sample_dataframe):
    """Test returning half of the correlation matrix."""
    corr_df = correlate_temporal_field(sample_dataframe, 'Value', 'Ticker', half='lower')
    assert pd.isna(corr_df.loc['AAPL', 'MSFT'])
    assert np.isclose(corr_df.loc['MSFT', 'AAPL'], 1.0)
