from typing import List, TypedDict
from typing_extensions import Unpack
import boto3
import botocore
from botocore.config import Config


class Tokens(TypedDict):
    refreshToken: str
    accessToken: str
    idToken: str


class RefreshToken(TypedDict):
    refreshToken: str


class UsernamePassword(TypedDict):
    username: str
    password: str


class ScribeAuth:
    def __init__(self, clientId: str):
        """Construct an authorisation client.

        Args
        ----
        clientId -- The client ID of the application provided by Scribe.
        """
        config = Config(signature_version=botocore.UNSIGNED)
        self.clientUnsigned = boto3.client(
            'cognito-idp', config=config, region_name='eu-west-2')
        self.clientSigned = boto3.client(
            'cognito-idp', region_name='eu-west-2')
        self.clientId = clientId

    def change_password(self, username: str, password: str, newPassword: str) -> bool:
        try:
            responseInitiate = self.__initiate_auth(username, password)
        except Exception:
            raise Exception("UnauthorizedError: authentication failed")
        challengeName = responseInitiate.get('ChallengeName')
        if challengeName == None:
            try:
                authResult = responseInitiate.get('AuthenticationResult')
                accessToken = authResult.get('AccessToken')
                self.__change_password_cognito(
                    password, newPassword, accessToken)
                return True
            except Exception:
                raise Exception(
                    "UnauthorizedError: password has been changed too many times. Try later")
        else:
            session = responseInitiate.get("Session")
            challengeParameters = responseInitiate.get("ChallengeParameters")
            userIdSRP = challengeParameters.get("USER_ID_FOR_SRP")
            requiredAttributes = challengeParameters.get("requiredAttributes")
            try:
                self.__respond_to_auth_challenge(
                    username, newPassword, session, userIdSRP, requiredAttributes)
                return True
            except Exception:
                raise Exception("InternalServerError: try again later")

    def forgot_password(self, username: str, password: str, confirmationCode: str) -> bool:
        try:
            self.clientSigned.confirm_forgot_password(
                ClientId=self.clientId,
                Username=username,
                ConfirmationCode=confirmationCode,
                Password=password
            )
            return True
        except Exception:
            raise Exception(
                "UnauthorizedError: Invalid parameters. Could not reset password")

    def get_tokens(self, **param: Unpack[UsernamePassword] | Unpack[RefreshToken]) -> Tokens:
        authResult = 'AuthenticationResult'
        refreshToken = param.get('refreshToken')
        if refreshToken == None:
            username = param.get('username')
            password = param.get('password')
            if username != None and password != None:
                response = self.__initiate_auth(username, password)
                result = response.get(authResult)
                return {
                    'refreshToken': result.get('RefreshToken'),
                    'accessToken': result.get('AccessToken'),
                    'idToken': result.get('IdToken')
                }
            else:
                raise Exception(
                    "UnauthorizedError: Invalid parameters. Could not get tokens")
        else:
            try:
                response = self.__get_tokens_from_refresh(refreshToken)
                result = response.get(authResult)
                return {
                    'refreshToken': refreshToken,
                    'accessToken': result.get('AccessToken'),
                    'idToken': result.get('IdToken')
                }
            except:
                raise Exception(
                    "UnauthorizedError: Invalid REFRESH_TOKEN. Could not get tokens")


    def revoke_refresh_token(self, refreshToken: str) -> bool:
        response = self.__revoke_token(refreshToken)
        statusCode = response.get('ResponseMetadata').get('HTTPStatusCode')
        if(statusCode == 200):
            return True
        if(statusCode == 400):
            raise Exception("BadRequest: Too many requests")
        else:
            raise Exception("InternalServerError: Try again later")

    def __initiate_auth(self, username: str, password: str):
        response = self.clientSigned.initiate_auth(
            ClientId=self.clientId,
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': username,
                'PASSWORD': password})
        return response

    def __respond_to_auth_challenge(self, username: str, newPassword: str, session: str, userIdSRP: str, requiredAttributes: List[str]):
        response = self.clientSigned.respond_to_auth_challenge(
            ClientId=self.clientId,
            ChallengeName='NEW_PASSWORD_REQUIRED',
            Session=session,
            ChallengeResponses={
                "USER_ID_FOR_SRP": userIdSRP,
                "requiredAttributes": requiredAttributes,
                "USERNAME": username,
                "NEW_PASSWORD": newPassword
            },
        )
        return response

    def __get_tokens_from_refresh(self, refreshToken: str):
        response = self.clientSigned.initiate_auth(
            ClientId=self.clientId,
            AuthFlow='REFRESH_TOKEN',
            AuthParameters={'REFRESH_TOKEN': refreshToken})
        return response

    def __change_password_cognito(self, password: str, newPassword: str, accessToken: str):
        response = self.clientSigned.change_password(
            PreviousPassword=password,
            ProposedPassword=newPassword,
            AccessToken=accessToken)
        return response

    def __revoke_token(self, refreshToken: str):
        response = self.clientUnsigned.revoke_token(
            Token=refreshToken,
            ClientId=self.clientId)
        return response
