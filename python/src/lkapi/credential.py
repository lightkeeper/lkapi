
#! /usr/bin/env python
# Copyright (c) 2025 LightKeeper LLC
# ANY REDISTRIBUTION OR COPYING OF THIS MATERIAL WITHOUT THE EXPRESS CONSENT
# OF LIGHTKEEPER IS PROHIBITED.
# All rights reserved.
#
"""
Provides tools for managing credentials. The Lightkeeper API uses bearer tokens provided by Cognito.
This module provides helper functions for managing client secrets through environment variables, local keychains,
or Hashicorp Vault. The secrets are used to generates an authorization tokens used in requests. Tokens are valid for
one hour. A 401 Token Expired will be returned if they time out.  Tokens can be refreshed with another request
to the auth server.

"""
import os
import abc
import json
import typing
import urllib.parse

import requests

# -------------------
# Credential Managers
# -------------------
class CredentialManager(object, metaclass=abc.ABCMeta):
    """
    A Credential Manager provides secure storage of credential information to generate a bearer token.
    """
    def __init__(self, env_key:str="LK_API", environment:typing.Optional[str]=None,
                 domain:typing.Optional[str]=None, url:typing.Optional[str]=None, **kwargs):
        self.env_key_base = env_key
        if url:
            cred_data = self.get_cred_data_from_url(url)
            environment = environment or cred_data.get('environment')
            domain = domain or cred_data.get('domain')
        self.environment = environment
        self.domain = domain or 'lightkeeperhq.com'
        env_key_parts = [self.env_key_base.upper()]
        if self.environment:
            env_key_parts.append(self.environment.upper())
        env_key_parts.append(self.domain.upper())
        self.env_key = '__'.join(env_key_parts)

    @property
    def hostname(self) -> str:
        """
        The API hostname based on the stored environment and domain.

        Returns: The API hostname string.

        """
        if self.environment:
            return f"{self.environment}.{self.domain}"
        else:
            return self.domain

    # --- helper functions
    @classmethod
    def get_cred_data_from_url(cls, url: str) -> typing.Dict[str, str]:
        """
        Extracts credential data from an API url.

        Args:
            url (str): The URL for an api endpoint.

        Returns:
            dict: A dictionary with keys 'environment', and 'domain'.
        """

        parsed_url = urllib.parse.urlparse(url)
        cred_data = {}
        if parsed_url.netloc:
            cred_data['domain'] = ".".join(parsed_url.netloc.split(".")[1:])
            cred_data['environment'] = parsed_url.netloc.split('.')[0].split('-')[-1]
        return cred_data

    def build_cred_dict(self, client_id:str, client_secret:str, **kwargs) -> typing.Dict[str, str]:
        """
        Builds a credential dictionary from keyword arguments and confirms required fields are present.

        Args:
            client_id (str): The client_id for the LK API.
            client_secret (str): The client_secret for the LK API.
            **kwargs: Additional keyword arguments, such as domain.

        Returns: A dictionary with the required keys.

        """
        cred_dict = {'client_id': client_id, 'client_secret': client_secret}
        if 'url' in kwargs:
            cred_data = self.get_cred_data_from_url(kwargs.pop('url'))
            kwargs.update(cred_data)
        # --- domain handling
        domain = kwargs.get('domain')
        # if a domain is provided, it must match the expected domain if stored
        if domain and self.domain and domain != self.domain:
            raise ValueError(f"Domain {domain} does not match expected {self.domain}")
        domain = domain or self.domain
        if domain:
            cred_dict['domain'] = domain

        # --- environment handling
        environment = kwargs.get('environment')
        if environment and self.environment and environment != self.environment:
            raise ValueError(f"Environment {environment} does not match expected {self.environment}")
        environment = environment or self.environment
        if environment:
            cred_dict['environment'] = environment

        return cred_dict

    def set_secret(self, client_id: str, client_secret: str, url:typing.Optional[str]=None, **kwargs) -> bool:
        """
        Sets the secret dictionary for the LK API of a client_id and client_secret.  This dictionary can
        also include a hostname if that should be overridden.
        Args:
            client_id: The client_id form the LK API.
            client_secret: The client_secret for the LK API.
            url: A url for the LK API [optional].

        Returns: Boolean for success.

        """
        cred_dict = self.build_cred_dict(client_id, client_secret, url=url, **kwargs)
        try:
            return self._set_secret(json.dumps(cred_dict))
        except (TypeError, ValueError) as e:
            print(f"Error setting {self.env_key}: {e}")
            return False

    def get_secret(self) -> typing.Dict[str, str]:
        """
        Gets the secret dictionary for the LK API of a client_id and client_secret.  This dictionary can also
        include a hostname if that should be overridden.

        Returns: A credential dictionary.

        """
        value = self._get_secret()
        if value is None:
            raise KeyError(f"Environment variable {self.env_key} not set")
        try:
            return json.loads(value)
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Error parsing {self.env_key} as JSON: {e}")

    @abc.abstractmethod
    def _get_secret(self) -> str:
        """
        Gets the secret, JSON encoded string from the credential store.

        Returns: A credential string.

        """
        raise NotImplementedError()

    def _set_secret(self, credential:str) -> bool:
        """
        Sets the secret JSON encoded string to the credential store.
        Args:
            credential: The JSON encoded credential string.

        Returns: Boolean for success.

        """
        raise NotImplementedError()

class ManualCredentialManager(CredentialManager):
    """
    A Credential Manager that requires directly setting and getting credentials.  This is primarily for testing.
    """
    def __init__(self, env_key:str="LK_API", environment:typing.Optional[str]=None,
                 domain:typing.Optional[str]=None, url:typing.Optional[str]=None, **kwargs):
        super().__init__(env_key=env_key, environment=environment, domain=domain, url=url, **kwargs)
        self._credential = None
        if kwargs:
            self.set_secret(**kwargs)

    # --- helper functions
    def _set_secret(self, credential) -> bool:
        self._credential = credential
        return True

    def _get_secret(self) -> str:
        return self._credential

class EnvironmentCredentialManager(CredentialManager):
    """
    A Credential Manager that leverages credentials in the existing system environment.  This should not
    be used in production but is the default handling for development.
    """
    # --- helper functions
    def _set_secret(self, credential) -> bool:
        os.environ[self.env_key] = credential
        return True

    def _get_secret(self) -> str:
        return os.environ.get(self.env_key)

try:
    import keyring
    class KeyringCredentialManager(CredentialManager):
        """
        A Credential Manager that leverages the keyring library to access OS Credential stores.  This is suitable
        for a user-level credential store.
        """

        # --- helper functions
        def _set_secret(self, credential) -> bool:
            keyring.set_password(self.env_key, self.env_key, credential)
            return True

        def _get_secret(self) -> str:
            return keyring.get_password(self.env_key, self.env_key)

except ImportError:
    KeyringCredentialManager = None

def get_credential_manager(credential_manager:typing.Optional[typing.Union[str, CredentialManager]]=None, **kwargs) -> CredentialManager:
    """
    Returns a credential manager instance based on the supplied type.  If no type is supplied, an environment
    variable manager is returned.

    Args:
        credential_manager: The type of credential manager to return.  If a CredentialManager object is passed
                            It will be returned.  If not the available classes will be searched for a class that
                            contains the given string.
        **kwargs: Additional keyword arguments passed to the credential manager constructor.

    Returns: A CredentialManager instance.

    """
    credential_manager_class = None
    if credential_manager is not None:
        if isinstance(credential_manager, CredentialManager):
            return credential_manager
        elif isinstance(credential_manager, type):
            # working with passed a class
            credential_manager_class = credential_manager
        elif isinstance(credential_manager, str):
            # --- search for a matching class
            for cls in CredentialManager.__subclasses__():
                if credential_manager.lower() in cls.__name__.lower():
                    credential_manager_class = cls
                    break
            if credential_manager_class is None:
                raise TypeError(f"Credential manager {credential_manager} is not a valid type.")
        else:
            raise TypeError(f"Credential manager {credential_manager} is not a CredentialManager")
    if credential_manager_class is None:
        credential_manager_class = EnvironmentCredentialManager if KeyringCredentialManager is None else KeyringCredentialManager
    return credential_manager_class(**kwargs)


# ----------------------
# Auth Token Generation
# ----------------------
def get_credential_manager_from_kwargs(**kwargs) -> CredentialManager:
    """
    Determines the appropriate credential manager from the supplied keyword arguments.
    Args:
        **kwargs:

    Returns: A CredentialManager instance.

    """
    if kwargs.get('client_id') and kwargs.get('client_secret'):
        credential_manager = ManualCredentialManager(**kwargs)
    elif kwargs.get('username') and kwargs.get('password'):
        credential_manager = ManualCredentialManager(client_id=kwargs.pop('username'),
                                                     client_secret=kwargs.pop('password'), **kwargs)
    else:
        credential_manager = get_credential_manager(**kwargs)
    return credential_manager

def get_auth_token(credential_manager:typing.Optional[CredentialManager]=None, **kwargs) -> str:
    """
    Generates an authorization token from Cognito using the supplied username and password. Tokens are valid for
    one hour. A 401 Token Expired will be returned if they time out.  Tokens can be refreshed with another request
    to the auth server.
    Args:
        credential_manager: The credential manager to use to retrieve credentials.  If None, a credential manager
                            will be created based on the supplied kwargs.
    Returns: An authentication token string to use as a bearer token in authorization headers for API requests.
    """
    if credential_manager is None:
        credential_manager = get_credential_manager_from_kwargs(**kwargs)
    cred_data = credential_manager.get_secret()
    auth_data = {
        "grant_type": "client_credentials",
        "client_id": cred_data['client_id'],
        "client_secret": cred_data['client_secret'],
    }
    # we are splitting to accommodate dev-see, beta-see, and see
    auth_response = requests.post(f"https://api.auth.{credential_manager.hostname}/oauth2/token", data=auth_data)
    if auth_response.status_code != 200:
        if auth_response.status_code == 400 and 'invalid_client' in auth_response.text:
            raise PermissionError("Invalid client credentials provided.")
        raise RuntimeError(f"Error obtaining auth token: {auth_response.status_code} {auth_response.text}")
    auth_response_json = auth_response.json()
    return f"{auth_response_json['token_type']} {auth_response_json['access_token']}"
