# Authentication Service Documentation

## Overview

The Authentication Service is responsible for handling user authentication, account activation, Google authentication, and password-related functionalities in a NestJS application.

## Table of Contents

1. [Dependencies](#dependencies)
2. [Modules](#modules)
   - [AuthModule](#authmodule)
3. [Controllers](#controllers)
   - [AuthController](#authcontroller)
4. [Services](#services)
   - [AuthService](#authservice)
5. [Endpoints](#endpoints)
   - [Signup](#signup)
   - [Activate Account](#activate-account)
   - [Send Back Mail Confirmation](#send-back-mail-confirmation)
   - [Google Authentication](#google-authentication)
   - [Sign In](#sign-in)
   - [Get User](#get-user)
   - [Sign Out](#sign-out)
   - [Forgot Password](#forgot-password)
   - [Reset Password](#reset-password)

## Dependencies

- **PrismaService**: Database service for interacting with the underlying database.
- **JwtService**: Service for handling JSON Web Tokens (JWT) creation and verification.
- **MailerService**: Service for sending email notifications.

## Modules

### AuthModule

**Description:**
The AuthModule encapsulates the authentication-related components, including controllers, services, and any required modules.

**Dependencies:**
- JwtModule: Handles JSON Web Token creation and verification.
- AuthController: Handles incoming HTTP requests related to authentication.
- AuthService: Implements the business logic for authentication.

## Controllers

### AuthController

**Description:**
The AuthController handles incoming HTTP requests related to user authentication, account activation, Google authentication, and password-related functionalities.

**Dependencies:**
- AuthService: Injects the AuthService to delegate business logic.

## Services

### AuthService

**Description:**
The AuthService contains the business logic for user authentication, account activation, Google authentication, and password-related functionalities.

**Dependencies:**
- PrismaService: Manages interactions with the database.
- JwtService: Handles JSON Web Token creation and verification.
- MailerService: Sends email notifications.

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
