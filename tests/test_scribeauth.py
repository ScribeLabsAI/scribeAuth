import os
import unittest
from time import sleep

import pyotp
from botocore.awsrequest import AWSRequest
from dotenv import load_dotenv

from scribeauth import (
    MissingIdException,
    ResourceNotFoundException,
    ScribeAuth,
    UnauthorizedException,
)

load_dotenv(override=True)

client_id: str = os.environ.get("CLIENT_ID", "")
username: str = os.environ.get("USERNAME", "")
username2: str = os.environ.get("USERNAME2", "")
password: str = os.environ.get("PASSWORD", "")
user_pool_id: str = os.environ.get("USER_POOL_ID", "")
federated_pool_id: str = os.environ.get("FEDERATED_POOL_ID", "")
otp = pyotp.TOTP(os.environ.get("OTPCODE", ""))

access = ScribeAuth({"client_id": client_id, "user_pool_id": user_pool_id})
pool_access = ScribeAuth(
    {
        "client_id": client_id,
        "user_pool_id": user_pool_id,
        "identity_pool_id": federated_pool_id,
    }
)


class TestScribeAuthGetTokensNoMFA(unittest.TestCase):
    def test_get_tokens_username_password_successfully(self):
        user_tokens = access.get_tokens(username=username, password=password)
        assert_tokens(self, user_tokens)

    def test_get_tokens_wrong_username_fails(self):
        with self.assertRaises(UnauthorizedException):
            access.get_tokens(username="username", password=password)

    def test_get_tokens_wrong_password_fails(self):
        with self.assertRaises(UnauthorizedException):
            access.get_tokens(username=username, password="password")

    def test_get_tokens_refresh_token_successfully(self):
        refresh_token = generate_refresh_token_for_test()
        user_tokens = access.get_tokens(refresh_token=refresh_token)
        assert_tokens(self, user_tokens)
        self.assertEqual(refresh_token, user_tokens.get("refresh_token"))

    def test_get_tokens_refresh_token_fails(self):
        with self.assertRaises(UnauthorizedException):
            access.get_tokens(refresh_token="refresh_token")

    def test_get_tokens_refresh_token_multiple_params_successfully(self):
        refresh_token = generate_refresh_token_for_test()
        user_tokens = access.get_tokens(**{"refresh_token": refresh_token})
        assert_tokens(self, user_tokens)
        self.assertEqual(refresh_token, user_tokens.get("refresh_token"))

    def test_get_tokens_refresh_token_multiple_params_fails(self):
        with self.assertRaises(UnauthorizedException):
            access.get_tokens(**{"refresh_token": "refresh_token"})


class TestScribeAuthGetTokensMFA(unittest.TestCase):
    def test_get_tokens_asks_mfa(self):
        challenge = access.get_tokens(username=username2, password=password)
        self.assertEqual(challenge.get("challenge_name"), "SOFTWARE_TOKEN_MFA")

    def test_get_tokens_username_password_successfully(self):
        challenge = access.get_tokens(username=username2, password=password)
        user_tokens = access.respond_to_auth_challenge_mfa(
            username=username2, session=challenge.get("session", ""), code=otp.now()
        )
        sleep(61)
        assert_tokens(self, user_tokens)

    def test_get_tokens_refresh_token_successfully(self):
        refresh_token = generate_refresh_token_for_test_with_mfa()
        sleep(61)
        user_tokens = access.get_tokens(refresh_token=refresh_token)
        assert_tokens(self, user_tokens)
        self.assertEqual(refresh_token, user_tokens.get("refresh_token"))

    def test_get_tokens_fails_with_wrong_mfa_code(self):
        challenge = access.get_tokens(username=username2, password=password)
        with self.assertRaises(UnauthorizedException):
            access.respond_to_auth_challenge_mfa(
                username=username2, session=challenge.get("session", ""), code="000000"
            )

    def test_get_tokens_fails_with_expired_mfa_code(self):
        challenge = access.get_tokens(username=username2, password=password)
        code = otp.now()
        sleep(61)
        with self.assertRaises(UnauthorizedException):
            access.respond_to_auth_challenge_mfa(
                username=username2, session=challenge.get("session", ""), code=code
            )


class TestScribeAuthRevokeRefreshTokens(unittest.TestCase):
    def test_revoke_refresh_token_successfully(self):
        refresh_token = generate_refresh_token_for_test()
        self.assertTrue(access.revoke_refresh_token(refresh_token))

    def test_revoke_refresh_token_unexistent_successfully(self):
        self.assertTrue(access.revoke_refresh_token("refresh_token"))

    def test_revoke_refresh_token_and_use_old_refresh_token_fails(self):
        refresh_token = generate_refresh_token_for_test()
        self.assertTrue(access.revoke_refresh_token(refresh_token))
        with self.assertRaises(UnauthorizedException):
            access.get_tokens(refresh_token=refresh_token)

    def test_revoke_refresh_token_invalid_and_use_valid_refresh_token_successfully(
        self,
    ):
        refresh_token = generate_refresh_token_for_test()
        self.assertTrue(access.revoke_refresh_token("refresh_token"))
        user_tokens = access.get_tokens(refresh_token=refresh_token)
        assert_tokens(self, user_tokens)
        self.assertEqual(refresh_token, user_tokens.get("refresh_token"))


class TestScribeAuthFederatedCredentials(unittest.TestCase):
    def test_get_federated_id_successfully(self):
        id_token = generate_id_token_for_test()
        federated_id = pool_access.get_federated_id(id_token)
        self.assertTrue(federated_id)

    def test_get_federated_id_fails(self):
        with self.assertRaises(UnauthorizedException):
            pool_access.get_federated_id("id_token")

    def test_get_federated_id_with_NO_identityPoolId_fails(self):
        id_token = generate_id_token_for_test()
        with self.assertRaises(MissingIdException):
            access.get_federated_id(id_token)

    def test_get_federated_credentials_successfully(self):
        id_token = generate_id_token_for_test()
        federated_id = pool_access.get_federated_id(id_token)
        federated_credentials = pool_access.get_federated_credentials(
            federated_id, id_token
        )
        self.assertTrue(federated_credentials.get("AccessKeyId"))
        self.assertTrue(federated_credentials.get("SecretKey"))
        self.assertTrue(federated_credentials.get("SessionToken"))
        self.assertTrue(federated_credentials.get("Expiration"))

    def test_get_federated_credentials_fails(self):
        id_token = generate_id_token_for_test()
        id = "eu-west-2:00000000-1111-2abc-3def-4444aaaa5555"
        with self.assertRaises(ResourceNotFoundException):
            pool_access.get_federated_credentials(id, id_token)


class TestScribeAuthGetSignatureForRequest(unittest.TestCase):
    def test_get_signature_for_request_successfully(self):
        id_token = generate_id_token_for_test()
        federated_id = pool_access.get_federated_id(id_token)
        federated_credentials = pool_access.get_federated_credentials(
            federated_id, id_token
        )
        request = AWSRequest("GET", url="http://google.com")
        signature = pool_access.get_signature_for_request(
            request=request, credentials=federated_credentials
        )
        self.assertTrue(signature)


def generate_refresh_token_for_test():
    tokens_or_challenge = access.get_tokens(username=username, password=password)
    if "refresh_token" in tokens_or_challenge:
        return tokens_or_challenge.get("refresh_token")
    raise Exception("Could not get refresh_token")


def generate_id_token_for_test():
    tokens_or_challenge = access.get_tokens(username=username, password=password)
    if "id_token" in tokens_or_challenge:
        return tokens_or_challenge.get("id_token")
    raise Exception("Could not get id_token")


def generate_refresh_token_for_test_with_mfa():
    challenge = access.get_tokens(username=username2, password=password)
    return access.respond_to_auth_challenge_mfa(
        username=username2, session=challenge.get("session", ""), code=otp.now()
    ).get("refresh_token")


def assert_tokens(self, user_tokens):
    self.assertIsNone(user_tokens.get("challenge_name"))
    self.assertIsNotNone(user_tokens.get("refresh_token"))
    self.assertIsNotNone(user_tokens.get("access_token"))
    self.assertIsNotNone(user_tokens.get("id_token"))
    self.assertNotEqual(
        user_tokens.get("refresh_token"), user_tokens.get("access_token")
    )
    self.assertNotEqual(user_tokens.get("refresh_token"), user_tokens.get("id_token"))
    self.assertNotEqual(user_tokens.get("id_token"), user_tokens.get("access_token"))
