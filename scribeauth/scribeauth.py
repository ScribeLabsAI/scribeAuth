from typing import List, TypedDict
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


class ScribeAuth:
    def __init__(self, client_id: str):
        """Construct an authorisation client.

        Args
        ----
        client_id -- The client ID of the application provided by Scribe.
        """
        config = Config(signature_version=botocore.UNSIGNED)
        self.client_unsigned = boto3.client(
            'cognito-idp', config=config, region_name='eu-west-2')
        self.client_signed = boto3.client(
            'cognito-idp', region_name='eu-west-2')
        self.client_id = client_id

    def change_password(self, username: str, password: str, new_password: str) -> bool: # pragma: no cover
        """Creates a new password for a user.

        Args
        ----
        username -- Username (usually an email address).
        password -- Password associated with this username.
        new_password -- New password for this username.
        
        Returns
        ----
        bool
        """
        try:
            response_initiate = self.__initiate_auth(username, password)
        except Exception:
            raise Exception("UnauthorizedError: authentication failed")
        challenge_name = response_initiate.get('ChallengeName')
        if challenge_name == None:
            try:
                auth_result = response_initiate.get('AuthenticationResult')
                access_token = auth_result.get('AccessToken')
                self.__change_password_cognito(
                    password, new_password, access_token)
                return True
            except Exception:
                raise Exception(
                    "UnauthorizedError: password has been changed too many times. Try later")
        else:
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

    def forgot_password(self, username: str, password: str, confirmation_code: str) -> bool: # pragma: no cover
        """Allows a user to enter a confirmation code sent to their email to reset a forgotten password.

        Args
        ----
        username -- Username (usually an email address).
        password -- Password associated with this username.
        confirmation_code -- Confirmation code sent to the user's email.
        
        Returns
        ----
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
        except Exception:
            raise Exception(
                "UnauthorizedError: Invalid parameters. Could not reset password")

    def get_tokens(self, **param: Unpack[UsernamePassword] | Unpack[RefreshToken]) -> Tokens:
        """A user gets their tokens (refresh_token, access_token and id_token).

        Args
        ----
        username -- Username (usually an email address).
        password -- Password associated with this username.
        Or
        refresh_token -- Refresh token to use.
        
        Returns
        ----
        Tokens -- Dictionary {"refresh_token": "str", "access_token": "str", "id_token": "str"}
        """
        auth_result = 'AuthenticationResult'
        refresh_token = param.get('refresh_token')
        if refresh_token == None:
            username = param.get('username')
            password = param.get('password')
            if username != None and password != None:
                response = self.__initiate_auth(username, password)
                result = response.get(auth_result)
                return {
                    'refresh_token': result.get('RefreshToken'),
                    'access_token': result.get('AccessToken'),
                    'id_token': result.get('IdToken')
                }
            else:
                raise Exception(
                    "UnauthorizedError: Invalid parameters. Could not get tokens")
        else:
            try:
                response = self.__get_tokens_from_refresh(refresh_token)
                result = response.get(auth_result)
                return {
                    'refresh_token': refresh_token,
                    'access_token': result.get('AccessToken'),
                    'id_token': result.get('IdToken')
                }
            except:
                raise Exception(
                    "UnauthorizedError: Invalid REFRESH_TOKEN. Could not get tokens")


    def revoke_refresh_token(self, refresh_token: str) -> bool:
        """Revokes all of the access tokens generated by the specified refresh token.
        After the token is revoked, the user cannot use the revoked token.

        Args
        ----
        refresh_token -- Refresh token to be revoked.
        
        Returns
        ----
        bool
        """
        response = self.__revoke_token(refresh_token)
        status_code = response.get('ResponseMetadata').get('HTTPStatusCode')
        if(status_code == 200):
            return True
        if(status_code == 400): # pragma: no cover
            raise Exception("BadRequest: Too many requests")
        else: # pragma: no cover
            raise Exception("InternalServerError: Try again later")

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

    def __get_tokens_from_refresh(self, refresh_token: str):
        response = self.client_signed.initiate_auth(
            ClientId=self.client_id,
            AuthFlow='REFRESH_TOKEN',
            AuthParameters={'REFRESH_TOKEN': refresh_token})
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