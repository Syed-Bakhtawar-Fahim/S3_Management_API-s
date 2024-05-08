# S3 File Management API

This API provides functionalities to manage files in an AWS S3 bucket, including user authentication using Amazon Cognito.

## Features

- **File Upload**: Upload files to an S3 bucket.
- **File Listing**: Retrieve a list of buckets and their contents.
- **File Retrieval**: Retrieve a specific file from an S3 bucket.
- **File Deletion**: Delete a file from an S3 bucket.
- **User Authentication**: Sign up, login, confirm email, and logout functionalities using Amazon Cognito.

## Prerequisites

Before running the application, ensure you have:

- Python 3.x installed
- Flask installed
- boto3 library installed
- Amazon Cognito User Pool configured
- AWS IAM user with appropriate permissions

## Setup

1. `Clone the repository`:

    ```
    git clone https://github.com/your/repository.git
    ```

2. `Install dependencies:`

    ```
    pip install -r requirements.txt
    ```

3. `Set up environment variables:`

    Create a `.env` file in the project root directory and add the following variables:

    ```
    AWS_ACCESS_KEY_ID=<Your AWS Access Key ID>
    AWS_SECRET_ACCESS_KEY=<Your AWS Secret Access Key>
    AWS_REGION=<Your AWS Region>
    COGNITO_CLIENT_ID=<Your Cognito Client ID>
    COGNITO_CLIENT_SECRET_ID=<Your Cognito Client Secret ID>
    ```

4. `Run the application:`

    ```
    python app.py
    ```

## API Endpoints

- **POST /signup**: Sign up a new user.
- **POST /login**: Log in an existing user.
- **POST /user/confirm**: Confirm user's email after sign up.
- **GET /buckets**: Retrieve a list of buckets.
- **GET /buckets/files/<bucket>/<file>**: Retrieve a specific file from a bucket.
- **POST /upload**: Upload a file to S3.
- **DELETE /bucketsfile/delete/<bucket>/<file>/<VersionId>**: Delete a file from S3 with a specific version ID.
- **GET /logout**: Log out the user.

## Usage

1. Sign up a new user using the `/signup` endpoint.
2. Log in with the new user credentials using the `/login` endpoint.
3. Upload files using the `/upload` endpoint.
4. Manage files using the provided endpoints (`/buckets`, `/buckets/files/<bucket>/<file>`, `/bucketsfile/delete/<bucket>/<file>/<VersionId>`).
5. Log out using the `/logout` endpoint.

## Contributors

- [Syed Bakhtawar Fahim](https://github.com/Syed-Bakhtawar-Fahim)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
