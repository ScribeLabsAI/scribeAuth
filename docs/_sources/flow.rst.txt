Flow
====

-  If you never have accessed your Scribe account, it probably still
   contains the temporary password we generated for you. You can change
   it directly on the `platform <https://platform.scribelabs.ai>`__ or
   with the ``change_password`` method. You won't be able to access
   anything else until the temporary password has been changed.

-  Once the account is up and running, you can request new tokens with
   ``get_tokens``. You will initially have to provide your username and
   password. The access and id tokens are valid for up to 30 minutes.
   The refresh token is valid for 30 days.

-  While you have a valid refresh token, you can request fresh access
   and id tokens with ``get_tokens`` but using the refresh token this
   time, so you're not sending your username and password over the wire
   anymore.

-  In case you suspect that your refresh token has been leaked, you can
   revoke it with ``revoke_token``. This will also invalidate any
   access/id token that has been issued with it. In order to get a new
   one, you'll need to use your username and password again.