from flask import Flask, request, jsonify
app = Flask(__name__)
import os
import boto3
import os
from pathlib import Path
from dotenv import load_dotenv, dotenv_values
from boto3.session import Session
import json
import hmac
import hashlib
import base64
import pyotp




# from app import app
config = dotenv_values(".env")  


# Upload File to S3 Bucket
AWS_ACCESS_KEY_ID = config['AWS_ACCESS_KEY_ID']
AWS_SECRET_ACCESS_KEY = config['AWS_SECRET_ACCESS_KEY']
AWS_BUCKET_NAME = config['AWS_BUCKET_NAME']

# AWS Cognito Configuration
AWS_REGION = config['AWS_REGION']
COGNITO_USER_POOL_ID = config['COGNITO_USER_POOL_ID']
COGNITO_CLIENT_ID = config['COGNITO_CLIENT_ID']
COGNITO_CLIENT_SECRET_ID = config['COGNITO_CLIENT_SECRET_ID']

s3 = boto3.client('s3', aws_access_key_id=AWS_ACCESS_KEY_ID, aws_secret_access_key=AWS_SECRET_ACCESS_KEY)


# Upload to S3

def upload_file(self, file):
    if 'file' not in request.files:
            return jsonify({'error': 'No file part'})

        file = request.files['file']

        if file.filename == '':
            return jsonify({'error': 'No selected file'})

        # Save the file to a temporary directory
        file_path = os.path.join('./uploads', file.filename)
        file.save(file_path)

        # Upload the file to S3
        try:
            # self.s3.upload_file(file_path, config['AWS_BUCKET_NAME'], file.filename)
            self.s3.upload_file(file_path, os.getenv(AWS_BUCKET_NAME), file.filename)
        except Exception as e:
            return jsonify({'error': str(e)})
        finally:
            # Remove the temporary file
            os.remove(file_path)

        return jsonify({'message': 'File uploaded successfully'})

# GET ALL BUCKETS
@app.route("/buckets", methods = ["GET"])
def list_files():
    try: 
        if 'Authorization' not in request.headers:
            return jsonify({'error': 'Authorization header missing'}), 401

        token = request.headers['Authorization'].split(' ')[1]
        if token:
            s3 = boto3.client('s3', aws_access_key_id=AWS_ACCESS_KEY_ID, aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
            response = s3.list_buckets()
            return jsonify(response['Buckets'][0]['Name'])
    except Exception as e:
        print("Error:", e)
        return []

# Get Single File/Object from specific bucket    
@app.route("/buckets/files/<bucket>/<file>", methods = ["GET"])
def bucket_objects(bucket, file):
    try: 
        if 'Authorization' not in request.headers:
            return jsonify({'error': 'Authorization header missing'}), 401

        token = request.headers['Authorization'].split(' ')[1]
        if token:
            s3 = boto3.client('s3', aws_access_key_id=AWS_ACCESS_KEY_ID, aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
            
            response = s3.get_object(Bucket = bucket, Key = file)
            data = response['Body'].read()
            file_content_decoded = data.decode('utf-8', errors='replace') if data else ''
            return jsonify(json.dumps({'file_content': file_content_decoded}))
    except Exception as e:
        print("Error:", e)
        return []



# Delete Files/Object from S3 Bucket with given versionId    
@app.route("/bucketsfile/delete/<bucket>/<file>/<VersionId>", methods = ["DELETE"])
def delete_bucket_objects(bucket, file, VersionId):
    try: 
        if 'Authorization' not in request.headers:
            return jsonify({'error': 'Authorization header missing'}), 401

        token = request.headers['Authorization'].split(' ')[1]
        if token:
            s3 = boto3.client('s3', aws_access_key_id=AWS_ACCESS_KEY_ID,                aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
        response = s3.delete_object(Bucket = bucket, Key = file, VersionId = VersionId)
        # print(response)
        # print("delete successfully")
        return jsonify({"Response": response})
    except Exception as e:
        print("Error:", e)
        return []
    


@app.route('/login', methods=['POST'])
def login():
    try:
        client = boto3.client('cognito-idp', region_name=AWS_REGION)
        data = request.get_json()
        username = data['username']
        password = data['password']

        # Calculate SECRET_HASH
        client_secret = COGNITO_CLIENT_SECRET_ID
        secret_hash = hmac.new(
            bytes(client_secret, 'utf-8'),
            msg=bytes(username + COGNITO_CLIENT_ID, 'utf-8'),
            digestmod=hashlib.sha256
        ).digest()
        secret_hash = base64.b64encode(secret_hash).decode('utf-8')

        # Authenticate user with Cognito
        response = client.initiate_auth(
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': username,
                'PASSWORD': password,
                'SECRET_HASH': secret_hash
            },
            ClientId=COGNITO_CLIENT_ID
        )

        print(response)  # Print the response for debugging

        # Check if MFA is required
        if response.get('ChallengeName') == 'SOFTWARE_TOKEN_MFA':
            # Generate TOTP code
            totp = pyotp.TOTP(COGNITO_CLIENT_SECRET_ID)  # Replace with your secret key
            mfa_code = totp.now()

            # Send OTP code via email
            send_otp_email(username, mfa_code)

            # Prompt user to enter OTP code
            return jsonify({'message': 'OTP code sent to your email. Please enter the code.'}), 200

        # Extract authentication result
        authentication_result = response.get('AuthenticationResult')
        if authentication_result:
            access_token = authentication_result.get('AccessToken')
            id_token = authentication_result.get('IdToken')
            refresh_token = authentication_result.get('RefreshToken')

            # Return tokens
            return jsonify({
                'access_token': access_token,
                'id_token': id_token,
                'refresh_token': refresh_token
            }), 200
        else:
            return jsonify({'error': 'No AuthenticationResult found in response'}), 400

    except Exception as e:
        return jsonify({'error': str(e)}), 400

def send_otp_email(username, otp_code):
    # Compose the email message
    subject = 'Your OTP Code for Login'
    body_text = f'Your OTP code for login is: {otp_code}'
    sender = username
    recipient = username  # Assuming username is the user's email address

    # Send the email using Amazon SES
    try:
        ses_client = boto3.client('ses', region_name=AWS_REGION)
        response = ses_client.send_email(
            Source=sender,
            Destination={
                'ToAddresses': [
                    recipient,
                ],
            },
            Message={
                'Subject': {
                    'Data': subject,
                },
                'Body': {
                    'Text': {
                        'Data': body_text,
                    },
                },
            }
        )
        print(f'OTP code sent to {recipient} successfully.')
        return True
    except Exception as e:
        print(f'Failed to send OTP code to {recipient}: {str(e)}')
        return False

# Example usage:


@app.route('/signup', methods=['POST'])
def signup():
    try:
        client = boto3.client('cognito-idp', region_name=AWS_REGION)
        data = request.get_json()
        username = data['username']
        email = data['email']
        password = data['password']

        client_secret = COGNITO_CLIENT_SECRET_ID
        secret_hash = hmac.new(
            bytes(client_secret, 'utf-8'),
            msg=bytes(username + COGNITO_CLIENT_ID, 'utf-8'),
            digestmod=hashlib.sha256
        ).digest()
        secret_hash = base64.b64encode(secret_hash).decode('utf-8')
        
        
        # Sign up user with Cognito
        response = client.sign_up(
            ClientId=COGNITO_CLIENT_ID,
            Username=username,
            Password=password,
            SecretHash=secret_hash,
            UserAttributes=[
                {'Name': 'email', 'Value': email},
            ]
        )

        # If successful, Cognito requires confirmation code to complete sign up.
        return jsonify({'message': 'User sign up successfull. Confirmation code send to given email.'}), 200
    except client.exceptions.UsernameExistsException:
        return jsonify({'error': 'Username already exists'}), 400
    except client.exceptions.InvalidParameterException as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@app.route('/user/confirm', methods=['POST'])
def confirm():
    try:
        client = boto3.client('cognito-idp', region_name=AWS_REGION)
        data = request.get_json()
        username = data['username']
        confirmation_code = data['confirmation_code']

        client_secret = COGNITO_CLIENT_SECRET_ID
        secret_hash = hmac.new(
            bytes(client_secret, 'utf-8'),
            msg=bytes(username + COGNITO_CLIENT_ID, 'utf-8'),
            digestmod=hashlib.sha256
        ).digest()
        secret_hash = base64.b64encode(secret_hash).decode('utf-8')

        # Confirm user's email using the verification code
        response = client.confirm_sign_up(
            ClientId=COGNITO_CLIENT_ID,
            Username=username,
            ConfirmationCode=confirmation_code,
            SecretHash=secret_hash,
        )
        return jsonify({'message': 'User email confirmed successfully.'}), 200
    except client.exceptions.CodeMismatchException:
        return jsonify({'error': 'Confirmation code does not match'}), 400
    except client.exceptions.UserNotFoundException:
        return jsonify({'error': 'User not found'}), 400
    except client.exceptions.InvalidParameterException as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 400



@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'})

    file = request.files['file']

    if file.filename == '':
        return jsonify({'error': 'No selected file'})

    file_path = os.path.join('./uploads', file.filename)  # Save the file to a temporary directory
    file.save(file_path)

    # Upload the file to S3
    try:
        if 'Authorization' not in request.headers:
            return jsonify({'error': 'Authorization header missing'}), 401

        token = request.headers['Authorization'].split(' ')[1]
        # print(token)
        if token:
            s3.upload_file(file_path, config['AWS_BUCKET_NAME'], file.filename)
            # return jsonify({"message": "Please login to upload file"}), 401
        else:
            return jsonify({"message":"File not uploaded"})
    except Exception as e:
        return jsonify({'error': str(e)})
    finally:
        os.remove(file_path)  # Remove the temporary file
    return jsonify({'message': 'File uploaded successfully'})




@app.route('/logout', methods=['GET'])
def logout():
    try:
        client = boto3.client('cognito-idp', region_name=AWS_REGION)
        data = request.get_json()
        print(data)
        refresh_token = data.get('refresh_token')
        if not refresh_token:
            return jsonify({'error': 'Refresh token is missing'}), 400

        # Perform global sign out
        response = client.global_sign_out(
            AccessToken=refresh_token
        )

        return jsonify({'message': 'User successfully logged out.'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400
         
try:
    from Controllers import *
except Exception as e:
    print(e)