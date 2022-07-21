# Scribe Auth

##### Library to connect to Scribe's platform.

---

Most calls to Scribe's api on [https://api.scribelabs.ai](https://api.scribelabs.ai/) require a [AWS](https://aws.amazon.com/) for authentication and authorization. This library simplifies this process.

You first need a Scribe account and an api key. Both can be requested at support[atsign]scribelabs[dotsign]ai.

---

This library requires a version of Python 3 that supports typings.

### Installation

```bash
pip install scribe-auth
```

---

_CLIENT_ID is necessary to create a ScribeAuth instance_

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

### 3. Get or generate tokens: (REFRESH_TOKEN, ACCESS_TOKEN, ID_TOKEN)

##### With USERNAME and PASSWORD

```python
from scribeAuth import ScribeAuth
access = ScribeAuth(clientId)
access.get_tokens(username='username', password='password')
```

##### With REFRESH_TOKEN

```python
from scribeAuth import ScribeAuth
access = ScribeAuth(clientId)
access.get_tokens(refreshToken='refreshToken')
```

### 4. Revoking a REFRESH_TOKEN

```python
from scribeAuth import ScribeAuth
access = ScribeAuth(clientId)
access.revoke_refresh_token('refreshToken')
```

---

To flag an issue, open a ticket on [Github](https://github.com/scribelabsai/authpy/issues).
