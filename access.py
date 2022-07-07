from typing import List
import boto3
import botocore
from botocore.config import Config

config = Config(signature_version=botocore.UNSIGNED)
clientUnsigned = boto3.client(
    'cognito-idp', config=config, region_name='eu-west-2')  # only for revoke_tokens
clientSigned = boto3.client(
    'cognito-idp', region_name='eu-west-2')
# TODO: CREATE OBJECT CLIENT TO EXECUTE METHODS
# TODO: TEST ALL


class Tokens:
    def __init__(self, refreshToken, accessToken, idToken):
        self.tokens = {
            'REFRESH_TOKEN': refreshToken,
            'ACCESS_TOKEN': accessToken,
            'ID_TOKEN': idToken
        }


class CognitoAccess:
    def __init__(self, clientUnsigned, clientSigned):
        self.clientUnsigned = clientUnsigned
        self.clientSigned = clientSigned


def change_password(clientId: str, username: str, password: str, newPassword: str) -> bool:
    try:
        responseInitiate = initiate_auth(
            clientId, username, password)
    except Exception:
        return False
    challengeName = responseInitiate.get('ChallengeName')
    if challengeName == None:
        try:
            authResult = responseInitiate.get('AuthenticationResult')
            accessToken = authResult.get('AccessToken')
            change_password_cognito(
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
            respond_to_auth_challenge(
                clientId, username, newPassword, session, userIdSRP, requiredAttributes)
            return True
        except Exception:
            return False


def forgot_password(clientId: str, username: str, password: str, confirmationCode: str) -> str:
    try:
        clientSigned.confirm_forgot_password(
            ClientId=clientId,
            Username=username,
            ConfirmationCode=confirmationCode,
            Password=password
        )
        return "OK"
    except Exception:
        raise Exception(
            "UnauthorizedError: Invalid parameters. Could not reset password")


def get_tokens(clientId: str, **param) -> Tokens:
    authResult = 'AuthenticationResult'
    refreshToken = param.get('REFRESH_TOKEN')
    if refreshToken == None:
        username = param.get('USERNAME')
        password = param.get('PASSWORD')
        if username != None and password != None:
            response = initiate_auth(clientId, username, password)
            result = response.get(authResult)
            refreshToken = result.get('RefreshToken')
            accessToken = result.get('AccessToken')
            idToken = result.get('IdToken')
            return Tokens(refreshToken, accessToken, idToken)
        else:
            raise Exception(
                "UnauthorizedError: Invalid parameters. Could not get tokens")
    else:
        response = get_tokens_from_refresh(clientId, refreshToken)
        result = response.get(authResult)
        accessToken = result.get('AccessToken')
        idToken = result.get('IdToken')
        return Tokens(refreshToken, accessToken, idToken)


def revoke_and_get_new_tokens(clientId: str, refreshToken: str, username: str, password: str):
    response = revoke_token(clientId, refreshToken)
    try:
        response = initiate_auth(
            clientId, username, password)
        result = response.get('AuthenticationResult')
        refreshToken = result.get('RefreshToken')
        accessToken = result.get('AccessToken')
        idToken = result.get('IdToken')
        return Tokens(refreshToken, accessToken, idToken)
    except:
        raise Exception("UnauthorizedError: Invalid username or password")

# --------------------------------------------------------------------------------------------------------------


def initiate_auth(clientId: str, username: str, password: str) -> str:
    response = clientSigned.initiate_auth(
        ClientId=clientId,
        AuthFlow='USER_PASSWORD_AUTH',
        AuthParameters={
            'USERNAME': username,
            'PASSWORD': password})
    return response


def respond_to_auth_challenge(clientId: str, username: str, newPassword: str, session: str, userIdSRP: str, requiredAttributes: List[str]):
    response = clientSigned.respond_to_auth_challenge(
        ClientId=clientId,
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


def get_tokens_from_refresh(clientId: str, refreshToken: str) -> str:
    response = clientSigned.initiate_auth(
        ClientId=clientId,
        AuthFlow='REFRESH_TOKEN',
        AuthParameters={
            'REFRESH_TOKEN':
                refreshToken})
    return response


def change_password_cognito(password: str, newPassword: str, accessToken: str):
    response = clientSigned.change_password(
        PreviousPassword=password,
        ProposedPassword=newPassword,
        AccessToken=accessToken)
    return response


def revoke_token(clientId: str, refreshToken: str):
    response = clientUnsigned.revoke_token(
        Token=refreshToken,
        ClientId=clientId)
    return response
