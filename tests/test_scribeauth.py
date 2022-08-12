import unittest
from scribeauth import ScribeAuth, Tokens
from scribeauth.scribeauth import UnauthorizedException
import os
from dotenv import load_dotenv

load_dotenv()

client_id: str = os.environ.get("CLIENT_ID")
username: str = os.environ.get("USER")
password: str = os.environ.get("PASSWORD")
access = ScribeAuth(client_id)

class TestScribeAuthGetTokens(unittest.TestCase):

    def test_get_tokens_username_password_successfully(self):
        user_tokens: Tokens = access.get_tokens(username=username, password=password)
        assert_tokens(self, user_tokens)

    def test_get_tokens_wrong_username_fails(self):
        with self.assertRaises(UnauthorizedException):
            self.assertRaises(access.get_tokens(username='username', password=password))

    def test_get_tokens_wrong_password_fails(self):
        with self.assertRaises(UnauthorizedException):
            self.assertRaises(access.get_tokens(username=username, password='password'))

    def test_get_tokens_empty_username_fails(self):
        with self.assertRaises(UnauthorizedException):
            self.assertRaises(access.get_tokens(password=password))
            
    def test_get_tokens_empty_password_fails(self):            
        with self.assertRaises(UnauthorizedException):
            self.assertRaises(access.get_tokens(username=username))

    def test_get_tokens_empty_username_and_password_fails(self):
        with self.assertRaises(UnauthorizedException):
            self.assertRaises(access.get_tokens())

    def test_get_tokens_refresh_token_successfully(self):
        refresh_token = generate_refresh_token_for_test()
        user_tokens: Tokens = access.get_tokens(refresh_token=refresh_token)
        assert_tokens(self, user_tokens)
        self.assertEqual(refresh_token, user_tokens.get('refresh_token'))

    def test_get_tokens_refresh_token_fails(self):
        with self.assertRaises(UnauthorizedException):
            self.assertRaises(access.get_tokens(refresh_token='refresh_token'))

    def test_get_tokens_refresh_token_multiple_params_successfully(self):
        refresh_token = generate_refresh_token_for_test()
        user_tokens: Tokens = access.get_tokens(**{'refresh_token': refresh_token})
        assert_tokens(self, user_tokens)
        self.assertEqual(refresh_token, user_tokens.get('refresh_token'))

    def test_get_tokens_refresh_token_multiple_params_fails(self):
        with self.assertRaises(UnauthorizedException):
            self.assertRaises(access.get_tokens(**{'refresh_token': 'refresh_token'}))


class TestScribeAuthRevokeRefreshTokens(unittest.TestCase):

    def test_revoke_refresh_token_successfully(self):
        refresh_token = generate_refresh_token_for_test()
        self.assertTrue(access.revoke_refresh_token(refresh_token))
        
    def test_revoke_refresh_token_unexistent_successfully(self):
        self.assertTrue(access.revoke_refresh_token('refresh_token'))

    def test_revoke_refresh_token_and_use_old_refresh_token_fails(self):
        refresh_token = generate_refresh_token_for_test()
        self.assertTrue(access.revoke_refresh_token(refresh_token))
        with self.assertRaises(UnauthorizedException):
            self.assertRaises(access.get_tokens(refresh_token=refresh_token))

    def test_revoke_refresh_token_invalid_and_use_valid_refresh_token_successfully(self):
        refresh_token = generate_refresh_token_for_test()
        self.assertTrue(access.revoke_refresh_token('refresh_token'))
        user_tokens: Tokens = access.get_tokens(refresh_token=refresh_token)
        assert_tokens(self, user_tokens)
        self.assertEqual(refresh_token, user_tokens.get('refresh_token'))


def generate_refresh_token_for_test():
    return access.get_tokens(username=username, password=password).get('refresh_token')

def assert_tokens(self, user_tokens):
    self.assertIsNotNone(user_tokens.get('refresh_token'))
    self.assertIsNotNone(user_tokens.get('access_token'))
    self.assertIsNotNone(user_tokens.get('id_token'))
    self.assertNotEqual(user_tokens.get('refresh_token'), user_tokens.get('access_token'))
    self.assertNotEqual(user_tokens.get('refresh_token'), user_tokens.get('id_token'))
    self.assertNotEqual(user_tokens.get('id_token'), user_tokens.get('access_token'))
