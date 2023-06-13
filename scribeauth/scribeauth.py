from typing import List, TypedDict, Union
from typing_extensions import Unpack
import boto3
import botocore
from botocore.config import Config


class Tokens(TypedDict):
    refresh_token: str
    access_token: str
    id_token: str


class RefreshToken(TypedDict):
    refresh_token: str


class UsernamePassword(TypedDict):
    username: str
    password: str

class Credentials(TypedDict):
    AccessKeyId: str
    SecretKey: str
    SessionToken: str
    Expiration: str

class PoolConfiguration(TypedDict):
    client_id: str
    user_pool_id: str
    identity_pool_id: str

class UnauthorizedException(Exception):
    """
    Exception raised when a user cannot perform an action.

    Possible reasons:
    - Username and/or Password are incorrect.
    - Refresh_token is incorrect.
    """
    pass

class TooManyRequestsException(Exception):
    """
    Exception raised when an action is performed by a user too many times in a short period.

    Actions that could raise this exception:
    - Changing a Password.
    - Revoke Refresh_token.
    """
    pass

class MissingIdException(Exception):
    pass

class UnknownException(Exception):
    pass

def is_complete_credentials(cred: Credentials) -> bool:
    return 'AccessKeyId' in cred and 'SecretKey' in cred and 'SessionToken' in cred

class ScribeAuth:
    def __init__(self, param: Union[Unpack[PoolConfiguration], str]):
        """Construct an authorisation client.

        Args
        ----
        Union[Unpack[PoolConfiguration], str]
        A parameter that can either be an instance of PoolConfiguration or a string.
        --
        PoolConfiguration:
        
        client_id -- The client ID of the application provided by Scribe.
        
        user_pool_id -- The user pool ID provided by Scribe.
        
        identity_pool_id -- The identity pool ID provided by Scribe.
        --
        str:

        client_id -- The client ID of the application provided by Scribe.
        """
        config = Config(signature_version=botocore.UNSIGNED)
        self.client_unsigned = boto3.client(
            'cognito-idp', config=config, region_name='eu-west-2')
        self.client_signed = boto3.client(
            'cognito-idp', region_name='eu-west-2')
        self.fed_client = boto3.client('cognito-identity', region_name='eu-west-2')
        if isinstance(param, str):
            self.client_id = param
        else:
            self.client_id = param.get('client_id')
            self.user_pool_id = param.get('user_pool_id')
            self.identity_pool_id = param.get('identity_pool_id')


    def change_password(self, username: str, password: str, new_password: str) -> bool: # pragma: no cover
        """Creates a new password for a user.

        Args
        ----
        username -- Username (usually an email address).

        password -- Password associated with this username.

        new_password -- New password for this username.
        
        Returns
        -------
        bool
        """
        try:
            response_initiate = self.__initiate_auth(username, password)
            challenge_name = response_initiate.get('ChallengeName')
            if challenge_name == None:
                try:
                    auth_result = response_initiate.get('AuthenticationResult')
                    access_token = auth_result.get('AccessToken')
                    self.__change_password_cognito(
                        password, new_password, access_token)
                    return True
                except Exception as err:
                    raise err
            else:
                if not self.client_id:
                    raise MissingIdException("Missing client ID")
                session = response_initiate.get("Session")
                challenge_parameters = response_initiate.get("ChallengeParameters")
                user_id_SRP = challenge_parameters.get("USER_ID_FOR_SRP")
                required_attributes = challenge_parameters.get("requiredAttributes")
                try:
                    self.__respond_to_auth_challenge(
                        username, new_password, session, user_id_SRP, required_attributes)
                    return True
                except Exception:
                    raise Exception("InternalServerError: try again later")
        except MissingIdException as err:
            raise err
        except TooManyRequestsException:
            raise TooManyRequestsException("Too many requests. Try again later")
        except Exception as err:
            if err.response['Error']['Code'] == 'NotAuthorizedException':
                raise UnauthorizedException("Username and/or Password are incorrect.")
            raise err

    def forgot_password(self, username: str, password: str, confirmation_code: str) -> bool: # pragma: no cover
        """Allows a user to enter a confirmation code sent to their email to reset a forgotten password.

        Args
        ----
        username -- Username (usually an email address).

        password -- Password associated with this username.
        
        confirmation_code -- Confirmation code sent to the user's email.
        
        Returns
        -------
        bool
        """
        try:
            self.client_signed.confirm_forgot_password(
                ClientId=self.client_id,
                Username=username,
                ConfirmationCode=confirmation_code,
                Password=password
            )
            return True
        except Exception as err:
            if err.response['Error']['Code'] == 'NotAuthorizedException':
                raise UnauthorizedException("Username, Password and/or Confirmation_code are incorrect. Could not reset password")
            raise err
                

    def get_tokens(self, **param: Unpack[UsernamePassword] | Unpack[RefreshToken]) -> Tokens:
        """A user gets their tokens (refresh_token, access_token and id_token).

        Args
        ----
        username -- Username (usually an email address).

        password -- Password associated with this username.

        Or

        refresh_token -- Refresh token to use.
        
        Returns
        -------
        Tokens -- Dictionary {"refresh_token": "str", "access_token": "str", "id_token": "str"}
        """
        refresh_token = param.get('refresh_token')
        username = param.get('username')
        password = param.get('password')
        if refresh_token == None:
            return self.__get_tokens_with_pair(username, password)
        else:
            return self.__get_tokens_with_refresh(refresh_token)

    def revoke_refresh_token(self, refresh_token: str) -> bool:
        """Revokes all of the access tokens generated by the specified refresh token.
        After the token is revoked, the user cannot use the revoked token.

        Args
        ----
        refresh_token -- Refresh token to be revoked.
        
        Returns
        -------
        bool
        """
        response = self.__revoke_token(refresh_token)
        status_code = response.get('ResponseMetadata').get('HTTPStatusCode')
        if(status_code == 200):
            return True
        if(status_code == 400): # pragma: no cover
            raise TooManyRequestsException("Too many requests. Try again later")
        else: # pragma: no cover
            raise Exception("InternalServerError: Try again later")

    def get_federated_id(self, id_token: str) -> str:
        if not self.user_pool_id:
            raise MissingIdException('Missing user pool ID')
        if not self.identity_pool_id:
            raise MissingIdException('Missing federated pool ID')
        try:
            response = self.fed_client.get_id(
                IdentityPoolId=self.identity_pool_id,
                Logins={
                    f'cognito-idp.eu-west-2.amazonaws.com/{self.user_pool_id}': id_token
                }
            )
            if not response.get('IdentityId'):
                raise UnknownException('Could not retrieve federated id')
            return response.get('IdentityId')
        except Exception as err:
            if err.response['Error']['Code'] == 'NotAuthorizedException':
                raise UnauthorizedException('Could not retrieve federated id')
            if err.response['Error']['Code'] == 'TooManyRequestsException':
                raise TooManyRequestsException('Too many requests. Try again later')
            raise err
    

    def get_federated_credentials(self, id: str, id_token:str) -> Credentials:
        if not self.user_pool_id:
            raise MissingIdException('Missing user pool ID')
        try:
            response = self.fed_client.get_credentials_for_identity(
                IdentityId=id,
                Logins={
                    f'cognito-idp.eu-west-2.amazonaws.com/{self.user_pool_id}': id_token
                }
            )
            if not is_complete_credentials(response['Credentials']):
                raise UnknownException('Could not retrieve federated credentials')
            return response['Credentials']
        except Exception as err:
            if err.response['Error']['Code'] == 'NotAuthorizedException':
                raise UnauthorizedException('Could not retrieve federated credentials')
            if err.response['Error']['Code'] == 'TooManyRequestsException':
                raise TooManyRequestsException('Too many requests. Try again later')
            raise err

    def __get_tokens_with_pair(self, username: str, password: str):
        auth_result = 'AuthenticationResult'
        if username != None and password != None:
            try:
                response = self.__initiate_auth(username, password)
                result = response.get(auth_result)
                return {
                    'refresh_token': result.get('RefreshToken'),
                    'access_token': result.get('AccessToken'),
                    'id_token': result.get('IdToken')
                }
            except:
                raise UnauthorizedException("Username and/or Password are incorrect. Could not get tokens")
        else:
            raise UnauthorizedException("Username and/or Password are missing. Could not get tokens")
       
    def __get_tokens_with_refresh(self, refresh_token: str):
        try:
            auth_result = 'AuthenticationResult'
            response = self.client_signed.initiate_auth(ClientId=self.client_id, AuthFlow='REFRESH_TOKEN', AuthParameters={'REFRESH_TOKEN': refresh_token})
            result = response.get(auth_result)
            return {
                'refresh_token': refresh_token,
                'access_token': result.get('AccessToken'),
                'id_token': result.get('IdToken')
            }
        except:
            raise UnauthorizedException("Refresh_token is incorrect. Could not get tokens")


    def __initiate_auth(self, username: str, password: str):
        response = self.client_signed.initiate_auth(
            ClientId=self.client_id,
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': username,
                'PASSWORD': password})
        return response

    def __respond_to_auth_challenge(self, username: str, new_password: str, session: str, user_id_SRP: str, required_attributes: List[str]): # pragma: no cover
        response = self.client_signed.respond_to_auth_challenge(
            ClientId=self.client_id,
            ChallengeName='NEW_PASSWORD_REQUIRED',
            Session=session,
            ChallengeResponses={
                "USER_ID_FOR_SRP": user_id_SRP,
                "requiredAttributes": required_attributes,
                "USERNAME": username,
                "NEW_PASSWORD": new_password
            },
        )
        return response

    def __change_password_cognito(self, password: str, new_password: str, access_token: str): # pragma: no cover
        response = self.client_signed.change_password(
            PreviousPassword=password,
            ProposedPassword=new_password,
            AccessToken=access_token)
        return response

    def __revoke_token(self, refresh_token: str):
        response = self.client_unsigned.revoke_token(
            Token=refresh_token,
            ClientId=self.client_id)
        return response