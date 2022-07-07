from typing import List
import boto3
import botocore
from botocore.config import Config

config = Config(signature_version=botocore.UNSIGNED)
clientUnsigned = boto3.client(
    'cognito-idp', config=config, region_name='eu-west-2')
clientSigned = boto3.client(
    'cognito-idp', region_name='eu-west-2')
# TODO: TEST ALL


class CognitoAccess:

    def __init__(self, clientId: str):
        self.clientId = clientId

    def change_password(self, username: str, password: str, newPassword: str) -> bool:
        try:
            responseInitiate = self.__initiate_auth(username, password)
        except Exception:
            return False
        challengeName = responseInitiate.get('ChallengeName')
        if challengeName == None:
            try:
                authResult = responseInitiate.get('AuthenticationResult')
                accessToken = authResult.get('AccessToken')
                self.__change_password_cognito(
                    password, newPassword, accessToken)
                return True
            except Exception:
                return False
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
                return False

    def forgot_password(self, username: str, password: str, confirmationCode: str) -> str:
        try:
            clientSigned.confirm_forgot_password(
                ClientId=self.clientId,
                Username=username,
                ConfirmationCode=confirmationCode,
                Password=password
            )
            return "Password successfully updated"
        except Exception:
            raise Exception(
                "UnauthorizedError: Invalid parameters. Could not reset password")

    def get_tokens(self, **param):
        authResult = 'AuthenticationResult'
        refreshToken = param.get('REFRESH_TOKEN')
        if refreshToken == None:
            username = param.get('USERNAME')
            password = param.get('PASSWORD')
            if username != None and password != None:
                response = self.__initiate_auth(username, password)
                result = response.get(authResult)
                return {
                    'REFRESH_TOKEN': result.get('RefreshToken'),
                    'ACCESS_TOKEN': result.get('AccessToken'),
                    'ID_TOKEN': result.get('IdToken')
                }
            else:
                raise Exception(
                    "UnauthorizedError: Invalid parameters. Could not get tokens")
        else:
            try:
                response = self.__get_tokens_from_refresh(refreshToken)
                result = response.get(authResult)
                return {
                    'REFRESH_TOKEN': refreshToken,
                    'ACCESS_TOKEN': result.get('AccessToken'),
                    'ID_TOKEN': result.get('IdToken')
                }
            except:
                raise Exception(
                    "UnauthorizedError: Invalid REFRESH_TOKEN. Could not get tokens")

    def revoke_and_get_new_tokens(self, refreshToken: str, username: str, password: str):
        response = self.__revoke_token(refreshToken)
        try:
            response = self.__initiate_auth(username, password)
            result = response.get('AuthenticationResult')
            return {
                'REFRESH_TOKEN': result.get('RefreshToken'),
                'ACCESS_TOKEN': result.get('AccessToken'),
                'ID_TOKEN': result.get('IdToken')
            }
        except:
            raise Exception("UnauthorizedError: Invalid username or password")

    def __initiate_auth(self, username: str, password: str) -> str:
        response = clientSigned.initiate_auth(
            ClientId=self.clientId,
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': username,
                'PASSWORD': password})
        return response

    def __respond_to_auth_challenge(self, username: str, newPassword: str, session: str, userIdSRP: str, requiredAttributes: List[str]):
        response = clientSigned.respond_to_auth_challenge(
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

    def __get_tokens_from_refresh(self, refreshToken: str) -> str:
        response = clientSigned.initiate_auth(
            ClientId=self.clientId,
            AuthFlow='REFRESH_TOKEN',
            AuthParameters={
                'REFRESH_TOKEN':
                    refreshToken})
        return response

    def __change_password_cognito(password: str, newPassword: str, accessToken: str):
        response = clientSigned.change_password(
            PreviousPassword=password,
            ProposedPassword=newPassword,
            AccessToken=accessToken)
        return response

    def __revoke_token(self, refreshToken: str):
        response = clientUnsigned.revoke_token(
            Token=refreshToken,
            ClientId=self.clientId)
        return response
