# NestJS Authentication Starter

This project provides a robust authentication starter kit built with NestJS, designed to streamline the implementation of secure user authentication in your applications. It includes features for Super Admin, Admin and Customer roles with Email/Password login, OTP verification, password reset flows, Google OAuth and user activity logging.

## Features and Functionality

-   **Multi-Role Support**: Authentication flows tailored for Super Admin, Admin and Customer roles.
-   **Email/Password Login**: Secure authentication using email and password with OTP verification.
-   **Google OAuth**: Seamless integration with Google OAuth for customer authentication.
-   **OTP Verification**: Enhanced security with OTP verification for registration and login.
-   **Password Reset Flows**: Comprehensive password reset functionality, including forgot password and reset password endpoints.
-   **JWT Authentication**: Secure authentication using JWT (JSON Web Tokens) for access and refresh tokens.
-   **Refresh Token Rotation**: Implementation of refresh token rotation for enhanced security.
-   **User Activity Logging**: Detailed logging of user activities for auditing and security monitoring.
-   **Email Integration**: Uses Resend for sending OTPs and other email notifications.
-   **Prisma ORM**: Database interactions managed using Prisma ORM for type safety and ease of use.
-   **Configuration**: Uses NestJS ConfigModule for managing environment variables and application configuration.
-   **Validation**: Utilizes class-validator for request body validation.
-   **Swagger API Documentation**: Automatically generated API documentation using Swagger.
-   **CORS**: Configured CORS to allow requests from specified origins.
-   **CSRF Protection**: CSRF protection middleware is implemented.
-   **Cron Jobs**: Scheduled tasks for OTP cleanup and account maintenance.

## Technology Stack

-   [NestJS](https://nestjs.com/): A progressive Node.js framework for building efficient, reliable, and scalable server-side applications.
-   [Prisma](https://www.prisma.io/): Next-generation ORM for Node.js and TypeScript.
-   [Passport](http://www.passportjs.org/): Authentication middleware for Node.js.
-   [JSON Web Token (JWT)](https://jwt.io/): An open standard for securely transmitting information as a JSON object.
-   [Resend](https://resend.com/): Email API for sending transactional emails.
-   [class-validator](https://github.com/typestack/class-validator):  for request body validation.
-   [Swagger](https://swagger.io/):  for API documentation.
-   [bcrypt](https://www.npmjs.com/package/bcrypt):  for password hashing.
-   [js-yaml](https://www.npmjs.com/package/js-yaml):  for writing documentation to YAML files.

## Prerequisites

Before you begin, ensure you have met the following requirements:

-   [Node.js](https://nodejs.org/en/download/) (>= 16.0)
-   [npm](https://www.npmjs.com/get-npm) (>= 7.0) or [yarn](https://yarnpkg.com/)
-   [PostgreSQL](https://www.postgresql.org/)
-   [Resend API Key](https://resend.com/):  for sending emails.
-   [Google OAuth Credentials](https://console.cloud.google.com/apis/credentials): Required for Google OAuth login.

## Installation Instructions

1.  **Clone the repository:**

    ```bash
    git clone https://github.com/bali-yoga-center/nestjs-auth-starter.git
    cd nestjs-auth-starter/2. Customer with Google & Email Login (Includes Super Admin)/server
    ```

2.  **Install dependencies:**

    ```bash
    npm install
    # or
    yarn install
    ```

3.  **Set up environment variables:**

    Create a `.env` file in the root directory of the project and add the following environment variables:

    ```env
    PORT=3336
    API_URL=http://localhost:3336/xam
    NODE_ENV=development
    LOG_SLOW_QUERIES=false
    API_DOC_URL=api-docs

    DATABASE_URL="postgresql://user:password@host:port/database?schema=public"

    ALLOWED_ORIGINS=http://localhost:3000,http://localhost:3336

    JWT_SECRET=your_jwt_secret
    RT_SECRET=your_refresh_token_secret

    TEST_OTP_PRODUCTION=false

    RESEND_API_KEY=your_resend_api_key
    MAIN_EMAIL_ADDRESS=your_email@example.com

    GOOGLE_CLIENT_ID=your_google_client_id
    GOOGLE_CLIENT_SECRET=your_google_client_secret
    GOOGLE_CALLBACK_URL=http://localhost:3336/xam/auth/customer/google/callback

    FRONTEND_URL=http://localhost:3000
    ```

4.  **Run database migrations:**

    ```bash
    npx prisma migrate dev
    # or
    yarn prisma migrate dev
    ```

5.  **Start the application:**

    ```bash
    npm run start:dev
    # or
    yarn start:dev
    ```

## Usage Guide

1.  **Access the API documentation:**

    Open your browser and navigate to `http://localhost:3336/xam/api-docs` to access the Swagger API documentation.  Note that your port and prefix might be different based on .env config.

2.  **Register a Super Admin:**

    Send a POST request to `/auth/super-admin/register` with the following payload:

    ```json
    {
      "email": "superadmin@example.com",
      "password": "SuperAdmin@123",
      "firstName": "John",
      "lastName": "Doe"
    }
    ```

3.  **Verify Super Admin OTP:**

    Send a POST request to `/auth/super-admin/register-verify-otp` with the OTP sent to your email:

    ```json
    {
      "email": "superadmin@example.com",
      "otp": "123456"
    }
    ```

4.  **Login Super Admin:**

    Send a POST request to `/auth/super-admin/login` with the following payload:

    ```json
    {
      "email": "superadmin@example.com",
      "password": "SuperAdmin@123"
    }
    ```

5.  **Verify Login OTP:**

     Send a POST request to `/auth/super-admin/verify-otp` with the OTP sent to your email:

    ```json
    {
      "email": "superadmin@example.com",
      "otp": "123456"
    }
    ```

6.  **Access Protected Routes:**

    Use the access token obtained during login to access protected routes by including it in the `Authorization` header as a Bearer token.

    ```
    Authorization: Bearer <access_token>
    ```

7.  **Using The Client App**

    In the `client(nextjs)` directory, you need to make an `.env` file and specify the API URL. Run `npm install` and `npm run dev`.

## API Documentation

The API documentation is generated using Swagger and is available at `/xam/api-docs` (e.g., `http://localhost:3336/xam/api-docs`). The documentation includes endpoints for:

-   Super Admin Authentication
-   Admin Authentication
-   Customer Authentication
-   User Activity Logging
-   Email Templates
-   Test Emails

## Contributing Guidelines

Contributions are welcome! To contribute:

1.  Fork the repository.
2.  Create a new branch for your feature or bug fix.
3.  Commit your changes.
4.  Push to the branch.
5.  Submit a pull request.

## License Information

This project has no specified license. All rights are reserved.

## Contact/Support Information

For questions or support, please contact:

-   Name: SUBHAM MAITY
-   Email: maitysubham4041@gmail.com
-   GitHub: [https://github.com/Subham-Maity](https://github.com/Subham-Maity)