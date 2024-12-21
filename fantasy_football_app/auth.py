from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.core.exceptions import PermissionDenied
from django.http import HttpResponse

import jwt
from jwt.exceptions import InvalidTokenError
from jose import JWTError, jwt

import requests
from django.conf import settings
# from .models import User
from django.contrib.auth import get_user_model

class CognitoAuthentication(BaseAuthentication):
    def get_jwks(self):
        jwks_url = f"https://cognito-idp.{settings.AWS_COGNITO_REGION}.amazonaws.com/{settings.AWS_COGNITO_USER_POOL_ID}/.well-known/jwks.json"
        response = requests.get(jwks_url)
        return response.json()

    def decode_jwt(self, token):
        jwks = self.get_jwks()
        unverified_header = jwt.get_unverified_header(token)
        rsa_key = {}
        
        for key in jwks['keys']:
            if key['kid'] == unverified_header['kid']:
                rsa_key = {
                    'kty': key['kty'],
                    'kid': key['kid'],
                    'use': key['use'],
                    'n': key['n'],
                    'e': key['e'],
                }
        
        if not rsa_key:
            raise AuthenticationFailed('Unable to find appropriate key')

        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=["RS256"],
                audience=settings.AWS_COGNITO_CLIENT_ID,
                options={"verify_aud": True}
            )
            return payload
        except jwt.JWTError:
            raise AuthenticationFailed('Invalid token')

    def authenticate(self, request):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return None

        try:
            token = auth_header.split(' ')[1]
            payload = self.decode_jwt(token)
            user_sub = payload.get('username')
            
            if not user_sub:
                raise AuthenticationFailed('Invalid token payload')

            user = get_user_model().objects.get(user_sub=user_sub)
            # user = User.objects.get(user_sub=user_sub)
            return (user, token)
        except (IndexError, user.DoesNotExist):
            raise AuthenticationFailed('Invalid token or user not found')
            
def get_jwks():
    """Fetches the JSON Web Key Set (JWKS) from Cognito."""
    jwks_url = f"https://cognito-idp.{settings.AWS_COGNITO_REGION}.amazonaws.com/{settings.AWS_COGNITO_USER_POOL_ID}/.well-known/jwks.json"
    response = requests.get(jwks_url)
    return response.json()

def decode_jwt(token: str):
    """Decode JWT and validate the claims."""
    print(f"Decoding JWT token:\n > '{token}'")
    jwks = get_jwks()
    unverified_header = jwt.get_unverified_header(token)
    rsa_key = {}
    
    for key in jwks['keys']:
        if key['kid'] == unverified_header['kid']:
            rsa_key = {
                'kty': key['kty'],
                'kid': key['kid'],
                'use': key['use'],
                'n': key['n'],
                'e': key['e'],
            }
    
    if not rsa_key:
        raise PermissionDenied("Unable to find appropriate key to decode JWT token")

    try:
        payload = jwt.decode(
            token,
            rsa_key,
            algorithms=["RS256"],
            audience=settings.AWS_COGNITO_CLIENT_ID,
            options={"verify_aud": True}
        )
        return payload
    except JWTError:
        raise PermissionDenied("Invalid token")


def get_user_sub_from_token(token):
    """Get the current user from the token."""

    # token = request.headers.get('Authorization')
    if not token:
        return HttpResponse({'detail': 'Token is missing'}, status=401)

    # Remove 'Bearer ' part from token (if present)
    token = token.split(' ')[1] if token.startswith('Bearer ') else token

    print("-----------------------------------")
    print("--- get_user_sub_from_token() ---")
    print(f"Token:\n > '{token}'\n")

    # Decode the JWT token and extract payload
    payload = decode_jwt(token)
    user_sub = payload.get("username")

    print("Payload: ", payload, "\nUsername: ", user_sub)
    print("-----------------------------------")

    # If no user_sub is found, raise authentication failure
    if user_sub is None:
        raise AuthenticationFailed("Could not validate credentials")
    
    return user_sub


def get_current_user(token):
    """Get the current user from the token."""

    # token = request.headers.get('Authorization')
    if not token:
        return HttpResponse({'detail': 'Token is missing'}, status=401)

    # Remove 'Bearer ' part from token (if present)
    token = token.split(' ')[1] if token.startswith('Bearer ') else token

    try:
        print("-----------------------------------")
        print("--- get_current_user() ---")
        print(f"Token:\n > '{token}'\n")

        # Decode the JWT token and extract payload
        payload = decode_jwt(token)
        user_sub = payload.get("username")

        print("Payload: ", payload, "\nUsername: ", user_sub)
        print("-----------------------------------")

        # If no user_sub is found, raise authentication failure
        if user_sub is None:
            raise AuthenticationFailed("Could not validate credentials")

        # Retrieve the user from the database
        user = get_user_model().objects.get(username=user_sub)

        if not user:
            raise AuthenticationFailed("User not found or insufficient permissions")

    except jwt.ExpiredSignatureError:
        raise AuthenticationFailed("Token has expired")
    except jwt.JWTError:
        raise AuthenticationFailed("Invalid token")
    except get_user_model().DoesNotExist:
        raise AuthenticationFailed("User not found")

    return user