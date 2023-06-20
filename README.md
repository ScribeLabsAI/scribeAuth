# Scribe Auth

Most calls to Scribe's API require authentication and authorization. This library simplifies this process.

You first need a Scribe account and a client ID. Both can be requested at support[atsign]scribelabs[dotsign]ai or through Intercom on https://platform.scribelabs.ai if you already have a Scribe account.

This library interacts directly with our authentication provider [AWS Cognito](https://aws.amazon.com/cognito/) meaning that your username and password never transit through our servers.

## Installation

```bash
pip install scribeauth
```

This library requires Python >= 3.10 that supports typing.

## Methods

### 1. Changing password

```python
from scribeauth import ScribeAuth
access = ScribeAuth(client_id)
access.change_password('username', 'password', 'new_password')
```

### 2. Recovering an account in case of forgotten password

```python
from scribeauth import ScribeAuth
access = ScribeAuth(client_id)
access.forgot_password('username', 'password', 'confirmation_code')
```

### 3. Get or generate tokens

##### With username and password

```python
from scribeauth import ScribeAuth
access = ScribeAuth(client_id)
access.get_tokens(username='username', password='password')
```

##### With refresh token

```python
from scribeauth import ScribeAuth
access = ScribeAuth(client_id)
access.get_tokens(refresh_token='refresh_token')
```

### 4. Revoking a refresh token

```python
from scribeauth import ScribeAuth
access = ScribeAuth(client_id)
access.revoke_refresh_token('refresh_token')
```

### 5. Getting federated id

```python
from scribeauth import ScribeAuth
access = ScribeAuth({'client_id': your_client_id, 'user_pool_id': your_user_pool_id, 'identity_pool_id': your_identity_pool_id})
access.get_federated_id('your_id_token')
```

### 6. Getting federated credentials

```python
from scribeauth import ScribeAuth
access = ScribeAuth({'client_id': your_client_id, 'user_pool_id': your_user_pool_id, 'identity_pool_id': your_identity_pool_id})
access.get_federated_credentials('your_federated_id', 'your_id_token')
```

### 7. Getting signature for request

```python
from scribeauth import ScribeAuth
access = ScribeAuth({'client_id': your_client_id, 'user_pool_id': your_user_pool_id, 'identity_pool_id': your_identity_pool_id})
access.get_signature_for_request(request='your_request', credentials='your_federated_credentials')
```

## Flow

- If you never have accessed your Scribe account, it probably still contains the temporary password we generated for you. You can change it directly on the [platform](https://platform.scribelabs.ai) or with the `change_password` method. You won't be able to access anything else until the temporary password has been changed.

- Once the account is up and running, you can request new tokens with `get_tokens`. You will initially have to provide your username and password. The access and id tokens are valid for up to 30 minutes. The refresh token is valid for 30 days.

- While you have a valid refresh token, you can request fresh access and id tokens with `get_tokens` but using the refresh token this time, so you're not sending your username and password over the wire anymore.

- In case you suspect that your refresh token has been leaked, you can revoke it with `revoke_token`. This will also invalidate any access/id token that has been issued with it. In order to get a new one, you'll need to use your username and password again.

- You can get your federated id by using `get_federated_id` and providing your id token. The federated id will allow you to use `get_federated_credentials` to get an access key id, secret key and session token.

- Every API call to be made to Scribe's API Gateway needs to have a signature. You can get the signature for your request by using `get_signature_for_request`. Provide the request you'll be using and your credentials (use `get_federated_credentials` to get them).

## Command line

You can also use the package as follows for quick access to tokens:

```bash
python -m scribeauth --client_id clientid --user_pool_id user_pool_id --username username --password password
```

---

To flag an issue, open a ticket on [Github](https://github.com/ScribeLabsAI/ScribeAuth/issues) and contact us on Intercom through the platform.
