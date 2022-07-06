from io import TextIOWrapper
from typing import List
import boto3

client = boto3.client('cognito-idp', region_name='eu-west-2')


def change_password(clientId: str, username: str, password: str, newPassword: str):
    success = "Password successfully changed"
    try:
        responseInitiate = initiate_auth(
            clientId, username, password)
    except Exception as e:
        raise Exception(e)
    challengeName = responseInitiate.get('ChallengeName')
    if challengeName == None:
        try:
            authResult = responseInitiate.get('AuthenticationResult')
            accessToken = authResult.get('AccessToken')
            response = change_password_cognito(
                password, newPassword, accessToken)
            metaData = response.get('ResponseMetadata')
            statusCode = metaData.get('HTTPStatusCode')
            if statusCode == 200:
                print(success)
                return response
            else:
                print(response)
                raise Exception(
                    "Request failed when trying to change password")
        except Exception as e:
            raise Exception(e)
    else:
        session = responseInitiate.get("Session")
        challengeParameters = responseInitiate.get("ChallengeParameters")
        userIdSRP = challengeParameters.get("USER_ID_FOR_SRP")
        requiredAttributes = challengeParameters.get("requiredAttributes")
        try:
            response = respond_to_auth_challenge(
                clientId, username, newPassword, session, userIdSRP, requiredAttributes)
            print(success)
            return response
        except Exception as e:
            raise Exception(e)


# When a ConfirmationCode is received:
def forgot_password(clientId: str, username: str, password: str, confirmationCode: str):
    response = client.confirm_forgot_password(
        ClientId=clientId,
        Username=username,
        ConfirmationCode=confirmationCode,
        Password=password
    )
    return response

    # --------------------------------------------------------------------------------------------------------------


def initiate_auth(clientId: str, username: str, password: str) -> str:
    response = client.initiate_auth(
        ClientId=clientId,
        AuthFlow='USER_PASSWORD_AUTH',
        AuthParameters={
            'USERNAME': username,
            'PASSWORD': password})
    return response


def respond_to_auth_challenge(clientId: str, username: str, newPassword: str, session: str, userIdSRP: str, requiredAttributes: List[str]):
    response = client.respond_to_auth_challenge(
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


def get_access_token(clientId: str, refreshToken: str) -> str:
    response = client.initiate_auth(
        ClientId=clientId,
        AuthFlow='REFRESH_TOKEN',
        AuthParameters={
            'REFRESH_TOKEN':
                refreshToken})
    return response


def change_password_cognito(password: str, newPassword: str, accessToken: str):
    response = client.change_password(
        PreviousPassword=password,
        ProposedPassword=newPassword,
        AccessToken=accessToken)
    return response


# TODO: PENDING
def revoke_token(clientId: str):
    print(clientId)


def read_next(file: TextIOWrapper):
    return file.readline().rstrip()


f = open("credentials.txt", "r")
clientId: str = read_next(f)
username: str = read_next(f)
password: str = read_next(f)
newPassword: str = read_next(f)
confirmationCode: str = read_next(f)

print(change_password(clientId, username, password, newPassword))
