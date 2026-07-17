# tests/test_credential.py
import os
import json
import pytest
from unittest.mock import patch

from lkapi.credential import (
    CredentialManager,
    ManualCredentialManager,
    EnvironmentCredentialManager,
    KeyringCredentialManager,
    get_credential_manager,
    get_credential_manager_from_kwargs,
)


@pytest.fixture
def cred_data():
    """Sample credential data."""
    return {'client_id': 'test_id', 'client_secret': 'test_secret'}


@pytest.fixture
def cred_data_with_env():
    """Sample credential data with environment."""
    return {'client_id': 'test_id', 'client_secret': 'test_secret', 'environment': 'beta'}


@pytest.fixture(autouse=True)
def clear_env_vars():
    """Fixture to clear relevant environment variables before and after tests."""
    env_keys_to_clear = [
        'LK_API__LIGHTKEEPERHQ.COM',
        'LK_API__BETA__LIGHTKEEPERHQ.COM',
        'LK_API__DEV__TEST.COM'
    ]
    original_values = {key: os.environ.get(key) for key in env_keys_to_clear}
    for key in env_keys_to_clear:
        if key in os.environ:
            del os.environ[key]
    yield
    for key, value in original_values.items():
        if value is not None:
            os.environ[key] = value
        elif key in os.environ:
            del os.environ[key]


class TestCredentialManager:
    def test_init_with_url(self):
        """Test initialization with a URL."""
        cm = ManualCredentialManager(url="https://beta.lightkeeperhq.com")
        assert cm.environment == 'beta'
        assert cm.domain == 'lightkeeperhq.com'
        assert cm.env_key == 'LK_API__BETA__LIGHTKEEPERHQ.COM'

    def test_init_with_env_and_domain(self):
        """Test initialization with explicit environment and domain."""
        cm = ManualCredentialManager(environment='dev', domain='test.com')
        assert cm.environment == 'dev'
        assert cm.domain == 'test.com'
        assert cm.env_key == 'LK_API__DEV__TEST.COM'

    def test_get_cred_data_from_url(self):
        """Test URL parsing helper."""
        url = "https://beta.lightkeeperhq.com/v1/data"
        data = CredentialManager.get_cred_data_from_url(url)
        assert data == {'environment': 'beta', 'domain': 'lightkeeperhq.com'}

    def test_build_cred_dict(self, cred_data):
        """Test building the credential dictionary."""
        cm = ManualCredentialManager()
        result = cm.build_cred_dict(**cred_data)
        assert result['client_id'] == 'test_id'
        assert result['client_secret'] == 'test_secret'

    def test_build_cred_dict_domain_mismatch(self, cred_data):
        """Test domain mismatch raises ValueError."""
        cm = ManualCredentialManager(domain='lightkeeperhq.com')
        with pytest.raises(ValueError, match="Domain other.com does not match expected lightkeeperhq.com"):
            cm.build_cred_dict(**cred_data, domain='other.com')

    def test_get_secret_not_set(self):
        """Test get_secret raises KeyError if not set."""
        cm = ManualCredentialManager()
        with pytest.raises(KeyError):
            cm.get_secret()

    def test_get_secret_bad_json(self):
        """Test get_secret raises RuntimeError on bad JSON."""
        cm = ManualCredentialManager()
        cm._set_secret("this is not json")
        with pytest.raises(RuntimeError, match="Error parsing"):
            cm.get_secret()

    def test_set_and_get_secret(self, cred_data):
        """Test setting and getting a secret."""
        cm = ManualCredentialManager()
        assert cm.set_secret(**cred_data)
        retrieved = cm.get_secret()
        assert retrieved['client_id'] == cred_data['client_id']
        assert retrieved['client_secret'] == cred_data['client_secret']


class TestEnvironmentCredentialManager:
    def test_set_and_get_secret(self, cred_data_with_env):
        """Test setting and getting a secret from environment variables."""
        cm = EnvironmentCredentialManager(environment='beta')
        assert cm.set_secret(**cred_data_with_env)
        assert 'LK_API__BETA__LIGHTKEEPERHQ.COM' in os.environ
        retrieved = cm.get_secret()
        assert retrieved['client_id'] == cred_data_with_env['client_id']


class TestKeyringCredentialManager:
    @patch('lkapi.credential.keyring', create=True)
    def test_set_secret(self, mock_keyring, cred_data):
        """Test setting a secret using mocked keyring."""
        cm = KeyringCredentialManager()
        cm.set_secret(**cred_data)
        dump_cred_data = json.dumps(cm.build_cred_dict(**cred_data))
        mock_keyring.set_password.assert_called_once_with(
            cm.env_key, cm.env_key, dump_cred_data
        )

    @patch('lkapi.credential.keyring', create=True)
    def test_get_secret(self, mock_keyring, cred_data):
        """Test getting a secret using mocked keyring."""
        cred_json = json.dumps(cred_data)
        mock_keyring.get_password.return_value = cred_json
        cm = KeyringCredentialManager()
        retrieved = cm.get_secret()
        mock_keyring.get_password.assert_called_once_with(cm.env_key, cm.env_key)
        assert retrieved == cred_data


class TestGetCredentialManager:
    def test_get_manager_by_string(self):
        """Test getting a manager by its string name."""
        assert isinstance(get_credential_manager('manual'), ManualCredentialManager)
        assert isinstance(get_credential_manager('environment'), EnvironmentCredentialManager)
        if KeyringCredentialManager:
            assert isinstance(get_credential_manager('keyring'), KeyringCredentialManager)

    def test_get_manager_by_class(self):
        """Test getting a manager by its class type."""
        assert isinstance(get_credential_manager(ManualCredentialManager), ManualCredentialManager)

    def test_get_manager_instance_passthrough(self):
        """Test that passing an instance returns the same instance."""
        instance = ManualCredentialManager()
        assert get_credential_manager(instance) is instance

    def test_get_manager_default(self):
        """Test default manager selection."""
        default_class = KeyringCredentialManager if KeyringCredentialManager is not None else EnvironmentCredentialManager
        assert isinstance(get_credential_manager(), default_class)

    def test_get_manager_invalid_string(self):
        """Test invalid string raises TypeError."""
        with pytest.raises(TypeError, match="Credential manager invalid is not a valid type."):
            get_credential_manager('invalid')

    def test_get_manager_invalid_type(self):
        """Test invalid type raises TypeError."""
        with pytest.raises(TypeError, match="is not a CredentialManager"):
            get_credential_manager(123)


class TestGetCredentialManagerFromKwargs:
    def test_with_client_credentials(self, cred_data):
        """Test creating a Manual manager with client_id/secret."""
        cm = get_credential_manager_from_kwargs(**cred_data)
        assert isinstance(cm, ManualCredentialManager)
        assert cm.get_secret()['client_id'] == cred_data['client_id']

    def test_with_user_pass(self):
        """Test creating a Manual manager with username/password."""
        cm = get_credential_manager_from_kwargs(username='user', password='pw')
        assert isinstance(cm, ManualCredentialManager)
        assert cm.get_secret()['client_id'] == 'user'
        assert cm.get_secret()['client_secret'] == 'pw'

    def test_fallback_to_default(self):
        """Test fallback to the default manager."""
        cm = get_credential_manager_from_kwargs(environment='beta')
        default_class = KeyringCredentialManager if KeyringCredentialManager is not None else EnvironmentCredentialManager
        assert isinstance(cm, default_class)
        assert cm.environment == 'beta'