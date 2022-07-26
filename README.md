# Scribe Auth

Most calls to Scribe's API require authentication and authorization. This library simplifies this process.

You first need a Scribe account and a client ID. Both can be requested at support[atsign]scribelabs[dotsign]ai or through Intercom on https://platform.scribelabs.ai if you already have a Scribe account.

This library interacts directly with our authentication provider [AWS Cognito](https://aws.amazon.com/cognito/) meaning that your username and password never transit through our servers.

## Installation

```bash
pip install scribe-auth
```

This library requires Python >= 3.10 that supports typings.

## Methods

### 1. Changing password

```python
from scribeAuth import ScribeAuth
access = ScribeAuth(clientId)
access.change_password('username', 'password', 'newPassword')
```

### 2. Recovering an account in case of forgotten password

```python
from scribeAuth import ScribeAuth
access = ScribeAuth(clientId)
access.forgot_password('username', 'password', 'confirmationCode')
```

### 3. Get or generate tokens

##### With username and password

```python
from scribeAuth import ScribeAuth
access = ScribeAuth(clientId)
access.get_tokens(username='username', password='password')
```

##### With refresh token

```python
from scribeAuth import ScribeAuth
access = ScribeAuth(clientId)
access.get_tokens(refreshToken='refreshToken')
```

### 4. Revoking a refresh token

```python
from scribeAuth import ScribeAuth
access = ScribeAuth(clientId)
access.revoke_refresh_token('refreshToken')
```

## Flow

- If you never have accessed your Scribe account, it probably still contains the temporary password we generated for you. You can change it directly on the [platform](https://platform.scribelabs.ai) or with the `change_password` method. You won't be able to access anything else until the temporary password has been changed.

- Once the account is up and running, you can request new tokens with `get_tokens`. You will initially have to provide your username and password. The access and id tokens are valid for up to 30 minutes. The refresh token is valid for 30 days. 

- While you have a valid refresh token, you can request fresh access and id tokens with `get_tokens` but using the refresh token this time, so you're not sending your username and password over the wire anymore.

- In case you suspect that your refresh token has been leaked, you can revoke it with `revoke_token`. This will also invalidate any access/id token that has been issued with it. In order to get a new one, you'll need to use your username and password again.

---

To flag an issue, open a ticket on [Github](https://github.com/ScribeLabsAI/scribeAuth/issues) and contact us on Intercom through the platform.
