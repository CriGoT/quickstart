# OAuth2 Test

## Summary
This is a toy project to test and learn `oauth2rize` and `flowstate`. The project provides a very simple Authorization server that allows users to authorize access to their profile info.

## Requirements
In order to run the server you will need

- NodeJS >= 10
- MongoDB >= 4

## Installation

1. Clone this repo and then run `yarn install`
1. Set the configuration using environment variables as described in the next section
1. Run the server using `node server.js`

## Configuration

All the configuration is passed via environment variables. The following are required variables to work:

- *MONGODB_URL*: The Url used to connect to the MongoDB instance where the information will be stored.
- *COOKIE_SECRET*: The phrase used to sign the session cookie.
- *PRIVATE_KEY_FILE*: The path to the private key that will be used to sign the ID tokens.

If you want to test authentication with other providers you will have to provide the following configuration:

- Google
  - *GOOGLE_CLIENT_ID*
  - *GOOGLE_CLIENT_SECRET*
- GitHub
  - *GITHUB_CLIENT_ID*
  - *GITHUB_CLIENT_SECRET*

Some additional optional configuration available:

- Configuration related to the password hashing for users stored in the DB:
  - *PASSSWORD_ITERATIONS*: Number of iterations used by PBKDF2. Default: `10000`.
  - *PASSWORD_DIGEST*: the digest algorithm used by PBKDF2. It has to be a digest algorithm supported by your version of NodeJS. Deatul: `sha512`.
  - *PASSWORD_SALT_LENGTH*: The length of the random salt that will be created and passed to the PBKDF2 function. Default: `32`.
  - *PASSWORD_KEY_LENGTH*: The length of the key passwed to the PBKDF2 function. Default: `64`.
- Token Configuration:
  - *TOKEN_LIFETIME*: The number of milliseconds that the issued tokens will be valid. Default: 1day.
