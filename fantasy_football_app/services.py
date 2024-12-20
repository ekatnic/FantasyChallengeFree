from django.conf import settings
from django.shortcuts import redirect
from django.core.exceptions import ValidationError
from django.contrib.auth import get_user_model
from urllib.parse import urlencode
import requests
import base64
import json

User = get_user_model()

AWS_COGNITO_TOKEN_URL = f"{settings.AWS_COGNITO_DOMAIN}/oauth2/token"
AWS_COGNITO_USER_INFO_URL = f"{settings.AWS_COGNITO_DOMAIN}/oauth2/userInfo"

def cognito_get_access_token(code: str, redirect_uri: str) -> str:
    data = {
        'grant_type': 'authorization_code',
        'client_id': settings.AWS_COGNITO_CLIENT_ID,
        'client_secret': settings.AWS_COGNITO_CLIENT_SECRET,
        'code': code,
        'redirect_uri': redirect_uri,
    }

    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
    }

    response = requests.post(AWS_COGNITO_TOKEN_URL, data=data, headers=headers)
    if not response.ok:
        raise ValidationError('Could not get access token from Cognito.')

    return response.json()['access_token']

def cognito_get_user_info(access_token: str):
    headers = {
        'Authorization': f'Bearer {access_token}',
    }

    response = requests.get(AWS_COGNITO_USER_INFO_URL, headers=headers)
    if not response.ok:
        raise ValidationError('Could not get user info from Cognito.')

    return response.json()

def get_user_data(validated_data):
    redirect_uri = f"{settings.BASE_API_URL}/auth/api/login/cognito/"

    code = validated_data.get('code')
    error = validated_data.get('error')

    if error or not code:
        return redirect(f"{settings.BASE_APP_URL}/error?error={error}")

    access_token = cognito_get_access_token(code=code, redirect_uri=redirect_uri)
    user_data = cognito_get_user_info(access_token)

    # Create user in DB if not exist
    User.objects.get_or_create(
        username=user_data['email'],
        email=user_data['email'],
        first_name=user_data.get('given_name'),
        last_name=user_data.get('family_name'),
    )

    return user_data
