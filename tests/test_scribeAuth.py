import unittest
from scribeAuth import ScribeAuth
from scribeAuth import Tokens
import os
from dotenv import load_dotenv

load_dotenv()

clientId: str = os.environ.get("CLIENT_ID")
username: str = os.environ.get("USER")
password: str = os.environ.get("PASSWORD")
access = ScribeAuth(clientId)

class TestScribeAuthGetTokens(unittest.TestCase):

    def test_get_tokens_username_password_successfully(self):
        userTokens: Tokens = access.get_tokens(username=username, password=password)
        assert_tokens(self, userTokens)

    def test_get_tokens_wrong_username_fails(self):
        with self.assertRaises(Exception):
            self.assertRaises(access.get_tokens(username='username', password=password))

    def test_get_tokens_wrong_password_fails(self):
        with self.assertRaises(Exception):
            self.assertRaises(access.get_tokens(username=username, password='password'))

    def test_get_tokens_empty_username_fails(self):
        with self.assertRaises(Exception):
            self.assertRaises(access.get_tokens(password=password))
            
    def test_get_tokens_empty_password_fails(self):            
        with self.assertRaises(Exception):
            self.assertRaises(access.get_tokens(username=username))

    def test_get_tokens_empty_username_and_password_fails(self):
        with self.assertRaises(Exception):
            self.assertRaises(access.get_tokens())

    def test_get_tokens_refresh_token_successfully(self):
        refreshToken = generate_refresh_token_for_test()
        userTokens: Tokens = access.get_tokens(refreshToken=refreshToken)
        assert_tokens(self, userTokens)
        self.assertEqual(refreshToken, userTokens.get('refreshToken'))

    def test_get_tokens_refresh_token_fails(self):
        with self.assertRaises(Exception):
            self.assertRaises(access.get_tokens(refreshToken='refreshToken'))

    def test_get_tokens_refresh_token_multiple_params_successfully(self):
        refreshToken = generate_refresh_token_for_test()
        userTokens: Tokens = access.get_tokens(**{'refreshToken': refreshToken})
        assert_tokens(self, userTokens)
        self.assertEqual(refreshToken, userTokens.get('refreshToken'))

    def test_get_tokens_refresh_token_multiple_params_fails(self):
        with self.assertRaises(Exception):
            self.assertRaises(access.get_tokens(**{'refreshToken': 'refreshToken'}))


class TestScribeAuthRevokeRefreshTokens(unittest.TestCase):

    def test_revoke_refresh_token_successfully(self):
        refreshToken = generate_refresh_token_for_test()
        self.assertTrue(access.revoke_refresh_token(refreshToken))
        
    def test_revoke_refresh_token_unexistent_successfully(self):
        self.assertTrue(access.revoke_refresh_token('refreshToken'))

    def test_revoke_refresh_token_and_use_old_refresh_token_fails(self):
        refreshToken = generate_refresh_token_for_test()
        self.assertTrue(access.revoke_refresh_token(refreshToken))
        with self.assertRaises(Exception):
            self.assertRaises(access.get_tokens(refreshToken=refreshToken))

    def test_revoke_refresh_token_invalid_and_use_valid_refresh_token_successfully(self):
        refreshToken = generate_refresh_token_for_test()
        self.assertTrue(access.revoke_refresh_token('refreshToken'))
        userTokens: Tokens = access.get_tokens(refreshToken=refreshToken)
        assert_tokens(self, userTokens)
        self.assertEqual(refreshToken, userTokens.get('refreshToken'))


def generate_refresh_token_for_test():
    return access.get_tokens(username=username, password=password).get('refreshToken')

def assert_tokens(self, userTokens):
    self.assertIsNotNone(userTokens.get('refreshToken'))
    self.assertIsNotNone(userTokens.get('accessToken'))
    self.assertIsNotNone(userTokens.get('idToken'))
    self.assertNotEqual(userTokens.get('refreshToken'), userTokens.get('accessToken'))
    self.assertNotEqual(userTokens.get('refreshToken'), userTokens.get('idToken'))
    self.assertNotEqual(userTokens.get('idToken'), userTokens.get('accessToken'))
