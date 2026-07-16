import pytest
from unittest.mock import patch, MagicMock
from lkapi import client

BASE_URL = "https://testenv.testdomain.com/lightstation/api/reports/query/layout/mygrid/v2?focus=myportfolio&rollup=myrollup&bd=2025-01-01&ed=2025-01-31"
MOCK_BUILT_URL = "http://built.url"

@patch('lkapi.client.lkparser.lk_api_response_to_frames')
@patch('lkapi.client.requests.get')
@patch('lkapi.client.lkcred.get_auth_token')
@patch('lkapi.client.lkparser.build_api_url')
def test_make_api_request_success(mock_build_url, mock_get_token, mock_requests_get, mock_parser):
    """Test a successful API request."""
    mock_build_url.return_value = MOCK_BUILT_URL
    mock_get_token.return_value = "test_token"
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_requests_get.return_value = mock_response
    mock_parser.return_value = "parsed_data"

    result = client.get_grid_data(url=BASE_URL, username="CLIENT_ID_XXXXXX", password="CLIENT_SECRET_XXXXXXX")

    mock_build_url.assert_called_once()
    mock_get_token.assert_called_once()
    mock_requests_get.assert_called_once_with(MOCK_BUILT_URL, headers={"Authorization": "test_token"})
    mock_parser.assert_called_once_with(mock_response)
    assert result == "parsed_data"

@patch('lkapi.client.requests.get')
@patch('lkapi.client.lkcred.get_auth_token')
@patch('lkapi.client.lkparser.build_api_url')
def test_make_api_request_http_error(mock_build_url, mock_get_token, mock_requests_get):
    """Test that a non-200 status code raises a ValueError."""
    mock_build_url.return_value = MOCK_BUILT_URL
    mock_get_token.return_value = "test_token"
    mock_response = MagicMock()
    mock_response.status_code = 500
    mock_response.text = "Internal Server Error"
    mock_requests_get.return_value = mock_response

    with pytest.raises(ValueError, match="API request failed with status code 500: Internal Server Error"):
        client.get_grid_data(url=BASE_URL, username="CLIENT_ID_XXXXXX", password="CLIENT_SECRET_XXXXXXX")

@patch('lkapi.client.requests.get')
@patch('lkapi.client.lkcred.get_auth_token')
@patch('lkapi.client.lkparser.build_api_url')
def test_make_api_request_401_non_json_body(mock_build_url, mock_get_token, mock_requests_get):
    """Test that a 401 with a non-JSON body raises ValueError instead of crashing on parse."""
    mock_build_url.return_value = MOCK_BUILT_URL
    mock_get_token.return_value = "test_token"
    mock_response = MagicMock()
    mock_response.status_code = 401
    mock_response.text = "Unauthorized"
    mock_response.json.side_effect = ValueError("No JSON could be decoded")
    mock_requests_get.return_value = mock_response

    with pytest.raises(ValueError, match="API request failed with status code 401"):
        client.get_grid_data(url=BASE_URL, username="CLIENT_ID_XXXXXX", password="CLIENT_SECRET_XXXXXXX")

    # no refresh should be attempted when the 401 body is not a Token Expired detail
    assert mock_get_token.call_count == 1


@patch('lkapi.client.lkparser.lk_api_response_to_frames')
@patch('lkapi.client.requests.get')
@patch('lkapi.client.lkcred.get_auth_token')
@patch('lkapi.client.lkparser.build_api_url')
def test_make_api_request_token_refresh(mock_build_url, mock_get_token, mock_requests_get, mock_parser):
    """Test the token refresh logic on a 401 'Token Expired' response."""
    mock_build_url.return_value = MOCK_BUILT_URL
    mock_get_token.side_effect = ["expired_token", "refreshed_token"]

    expired_response = MagicMock()
    expired_response.status_code = 401
    expired_response.json.return_value = {'detail': 'Token Expired'}

    success_response = MagicMock()
    success_response.status_code = 200
    mock_requests_get.side_effect = [expired_response, success_response]

    mock_parser.return_value = "parsed_data_after_refresh"

    result = client.get_grid_data(url=BASE_URL, username="CLIENT_ID_XXXXXX", password="CLIENT_SECRET_XXXXXXX")

    assert mock_get_token.call_count == 2
    assert mock_requests_get.call_count == 2
    mock_requests_get.assert_any_call(MOCK_BUILT_URL, headers={"Authorization": "expired_token"})
    mock_requests_get.assert_any_call(MOCK_BUILT_URL, headers={"Authorization": "refreshed_token"})
    mock_parser.assert_called_once_with(success_response)
    assert result == "parsed_data_after_refresh"
