# Authentication Module Documentation

## Overview

The Authentication Module is responsible for handling user authentication, account activation, Google authentication, and password-related functionalities in a NestJS application.

## Table of Contents

1. [Installation](#installation)
2. [Endpoints](#endpoints)
   - [Signup](#signup)
   - [Activate Account](#activate-account)
   - [Send Back Mail Confirmation](#send-back-mail-confirmation)
   - [Sign In](#sign-in)
   - [Get User](#get-user)
   - [Sign Out](#sign-out)
   - [Forgot Password](#forgot-password)
   - [Reset Password](#reset-password)

## Installation
- **nodemailer / @nestjs-modules/mailer:** Provides mail sending capabilities for sending activation and password reset emails.
- **@nestjs/jwt:** Handles JSON Web Token (JWT) creation and verification for user authentication.
- **@nestjs/passport:** Passport module for authentication in NestJS applications.
- **bcrypt:** Library for hashing passwords securely.
- **prisma / @prisma/client:** Prisma client for database interaction.
- **passport-google-oauth20:** Google OAuth2.0 authentication strategy for Passport.
- **cookie-parser:** Middleware for parsing cookies in Express.
- **class-validator:** Validation library for TypeScript and JavaScript.
- **class-transformer:** Library for transforming plain to class instances and vice versa.
- **uuid:** Library for generating UUIDs.



## Endpoints

### Signup

**Endpoint:** `POST /auth/signup`

**Description:**
Creates a new user account. Checks if the user already exists, hashes the password, generates an activation token, and sends an activation email.

**Request:**
```json
{
  "email": "user@example.com",
  "name": "John Doe",
  "password": "securePassword"
}
``` 

**Response:**
```json
{
    "message": "User created. Activation email sent."
}
```

### Activate Account

**Endpoint:** `POST /auth/activate/:token`

**Description:**
Activates a user account using the activation token sent via email. Handles token expiration and invalid token scenarios.

**Response:**
```json
{
   "message": "Account activated successfully."

}
```
### Send Back Mail Confirmation

**Endpoint:** `POST /auth/sendBackMailConfirmation`

**Description:**
Re-sends the activation email to the user for account confirmation.

**Request:**
```json
{
  "email": "user@example.com"
}
```

**Response:**
```json
{
  "message": "Activation email sent successfully."
}
```

### Sign In

**Endpoint:** `POST /auth/signin`

**Description:**
Handles user login. Validates credentials, checks account activation status, and returns a JWT token.

**Request:**
```json
{
  "email": "user@example.com",
  "password": "securePassword"

}
```
**Response:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```
### Get User

**Endpoint:** `POST /auth/user`

**Description:**
Verifies the JWT token and returns user information if authenticated.

**Response:**
```json
{
  "message": "Hello Mayssa, you are logged in."
}
```
### Sign Out

**Endpoint:** `POST /auth/signout`

**Description:**
Clears the authentication token and logs the user out.


**Response:**
```json
{
  "message": "Logged out successfully."
}
```

### Forgot Password

**Endpoint:** `POST /auth/forgotPassword`

**Description:**
Sends a reset password email to the user.

**Request:**
```json
{
  "email": "user@example.com"
}
```
**Response:**
```json
{
  "message": "Mail sent successfully."
}
```

### Reset Password

**Endpoint:** `POST /auth/resetPassword/:token`

**Description:**
Resets the user's password using the provided token.

**Request:**
```json
{
  "password": "newSecurePassword"
}
```
**Response:**
```json
{
  "message": "Your password has been reset successfully."
}
```

