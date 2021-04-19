# Session and Token based AuthN implementation along with Google Login using Flask and Sqlite

## Configuration

If your are going to test Google Login, you should have a [project](https://developers.google.com/identity/sign-in/web/sign-in#before_you_begin) in google, you should generate [OAuth Client](https://console.cloud.google.com/apis/credentials) ID and Secret from there.

```bash
# Google login creds
export GOOGLE_CLIENT_ID=<YOU_GOOGLE_CLIENT_ID>
export GOOGLE_CLIENT_SECRET=<GOOGLE_CLIENT_SECRET>

# Default will be generated if not configured for below configs.
# Flask secret Key
export SECRET_KEY=<SECRET_KEY>

# Extra secrets for JWT based
export JWT_SECRET_KEY=<JWT_SECRET_KEY>
export SQLALCHEMY_DATABASE_URI=<SQLALCHEMY_DATABASE_URI>
export SQLALCHEMY_TRACK_MODIFICATIONS=<SQLALCHEMY_TRACK_MODIFICATIONS>
```

## Running the App

```bash
# For session based --> checkout to session branch
git checkout session-based

# Or, for jwt based --> checkout to jwt branch
git checkout jwt-based


# Make sure you are inside a virtualenv
# I am using python3
pip install -r requirements.txt
FLASK_APP=app.py FLASK_DEBUG=1 flask run --cert=adhoc
```

## Usage

### Session based

It has views which works on browser so you can navigate to [http://localhost:5000/](http://localhost:5000/)

### JWT based

It doesn't have any views, below are the details of exposed APIs

* [Users Password Flow](#User-Password-Flow)
  
  * [Register](#1-register)
  * [Login](#2-login)
  * [Get Profile](#3-get-profile)

* [Google Login](#Google-Login-Flow)
  * [Get Google Login URL](#1-Get-Google-Login-URL)
  * [Get tokens](#2-Get-JWT)
  * [Get Profile](#3-get-profile)

--------

## User Password Flow

User account management related APIs

### 1. Register

Creates a new user

***Endpoint:***

```bash
Method: POST
Type: RAW
URL: http://localhost:5000/auth/register
```

***Body:***

```js
{
    "username": "harshit9715@gmail.com", // email is not validated any unique string will work
    "password": "ThisIsTooEasyToGuess"
}
```

### 2. Login

Login a user with email and password

***Endpoint:***

```bash
Method: POST
Type: RAW
URL: http://localhost:5000/auth/login
```

***Body:***

```js
{
    "username": "harshit9715@gmail.com", // email is not validated any unique string will work
    "password": "ThisIsTooEasyToGuess"
}
```

### 3. Get Profile

Get current user's profile.

***Endpoint:***

```bash
Method: GET
Type: None
URL: http://localhost:5000/auth/status
Header: Authorization Bearer <TOKEN>
```

## Google Login Flow

### 1. Get Google Login URL

Get the URL that will redirect the user to google login page

***Endpoint:***

```bash
Method: GET
Type: None
URL: http://localhost:5000/auth/google
```

### 2. Get JWT

Get the JWT tokens in exchange of google tokens

***Endpoint:***

```bash
Method: POST
Type: RAW
URL: http://localhost:5000/auth/google
```

***Body:***

```js
{
    "url": "<URL_TO_WHICH_GOOGLE_REDIRECTED_AFTER_LOGIN>"
}
```
