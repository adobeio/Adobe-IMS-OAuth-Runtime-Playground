# Adobe-IMS-OAuth-Runtime-Playground
A simple app deployed on Adobe I/O Runtime platform based on passport-adobe-oauth2 strategy. Helps retrieve the access and refresh token for client created on Adobe I/O Console.


1. [Setup](#Setup)
1. [Run It!](#Run)

# <a name="Setup">Setup</a>

Clone the repository.
Add a unique secret password for serverside encryption/decryption in callback.js Line 4862
https://github.com/adobeio/Adobe-IMS-OAuth-Runtime-Playground/blob/master/callback.js#L4862

To set up the playground execute the following commands:

  ```sh
  $ wsk package create adobe-oauth-playground
  $ wsk action create adobe-oauth-playground/oauth oauth.js --web true
  $ wsk action create adobe-oauth-playground/callback callback.js --web true

Retrieve action urls:

  $ wsk action get adobe-oauth-playground/oauth --url
  $ wsk action get adobe-oauth-playground/callback --url
  
Update action parameters with above urls:

  $ wsk action update adobe-oauth-playground/oauth --param oauth_url <COPY_OAUTH_ACTION_URL> --param callback_url <COPY_CALLBACK_ACTION_URL>

e.g.[wsk action update adobe-oauth-playground/oauth --param oauth_url https://runtime.adobe.io/api/v1/web/io-solutions/adobe-oauth-playground/oauth --param callback_url https://runtime.adobe.io/api/v1/web/io-solutions/adobe-oauth-playground/callback]

  $ wsk action update adobe-oauth-playground/callback --param oauth_url <COPY_OAUTH_ACTION_URL> --param callback_url <COPY_CALLBACK_ACTION_URL>

e.g. [wsk action update adobe-oauth-playground/callback --param oauth_url https://runtime.adobe.io/api/v1/web/io-solutions/adobe-oauth-playground/oauth --param callback_url https://runtime.adobe.io/api/v1/web/io-solutions/adobe-oauth-playground/callback]

  ```

Create an integration on the [Adobe I/O Console](https://console.adobe.io/integrations).

- Create an integration-> Select Access an API-> Select services you wish to integrate with (e.g. Adobe Stock->OAuth Integration)
- Provide the Default redirect URI as Callback action URL generated using command: 
```sh
wsk action get adobe-oauth-playground/callback --url 
```
(e.g. https://runtime.adobe.io/api/v1/web/io-solutions/adobe-oauth-playground/callback)

# <a name="Run">Run It!</a>


Browse to Oauth action URL generated using command: 
```sh
wsk action get adobe-oauth-playground/oauth --url 
```
(e.g. https://runtime.adobe.io/api/v1/web/io-solutions/adobe-oauth-playground/oauth.html)
Paste your credentials (which can be found in your I/O integration), and you are ready to start!

Note: Do not forget to append ".html" at the end of Oauth Action URL.

# Author
- Hiren Shah [@hirenshah111](https://github.com/hirenshah111).

# License
[MIT](LICENSE)
