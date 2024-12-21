# authentication/backends.py
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
import jwt
import requests
from django.conf import settings

import jwt
from jwt.exceptions import InvalidTokenError
from jose import JWTError, jwt
from django.conf import settings
from django.http import HttpRequest, HttpResponse
from django.core.exceptions import PermissionDenied
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import BaseBackend
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

import jwt
from jwt.exceptions import InvalidTokenError
from jose import JWTError, jwt

import json
import logging
import time
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

class CognitoCaseInsensitiveModelBackend(ModelBackend):
    def get_jwks(self):
        """Fetches the JSON Web Key Set (JWKS) from Cognito."""
        jwks_url = f"https://cognito-idp.{settings.AWS_COGNITO_REGION}.amazonaws.com/{settings.AWS_COGNITO_USER_POOL_ID}/.well-known/jwks.json"
        response = requests.get(jwks_url)
        return response.json()

    def decode_cognito_token(self, token):
        """Decode and verify the Cognito JWT token."""
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
        
        if rsa_key:
            try:
                return jwt.decode(
                    token,
                    rsa_key,
                    algorithms=["RS256"],
                    audience=settings.AWS_COGNITO_CLIENT_ID,
                    options={"verify_aud": True}
                )
            except jwt.JWTError:
                return None
        return None

    def authenticate(self, request, username=None, password=None, token=None, **kwargs):
        UserModel = get_user_model()
        
        try:
            # If token is provided, authenticate using Cognito JWT
            if token:
                payload = self.decode_cognito_token(token)
                if payload:
                    cognito_sub = payload.get('sub')
                    try:
                        user = UserModel.objects.get(username=cognito_sub)
                        return user
                    except UserModel.DoesNotExist:
                        return None
            
            # Fall back to username/password authentication
            if username and password:
                try:
                    # Use case-insensitive lookup
                    user = UserModel.objects.get(username__iexact=username)
                    if user.check_password(password):
                        return user
                except UserModel.DoesNotExist:
                    return None
                
        except UserModel.DoesNotExist:
            return None

    def get_user(self, user_id):
        UserModel = get_user_model()
        try:
            return UserModel.objects.get(pk=user_id)
        except UserModel.DoesNotExist:
            return None


# User = get_user_model()

# class CognitoJWTAuthentication(BaseAuthentication):
#     def __init__(self):
#         self.region = settings.AWS_COGNITO_REGION
#         self.user_pool_id = settings.AWS_COGNITO_USER_POOL_ID
#         self.app_client_id = settings.AWS_COGNITO_CLIENT_ID
#         self._jwks = None
#         self._jwks_url = f"https://cognito-idp.{self.region}.amazonaws.com/{self.user_pool_id}/.well-known/jwks.json"

#     def _get_jwks(self):
#         """Fetch the JWK keys from Cognito"""
#         if self._jwks is None:
#             response = requests.get(self._jwks_url)
#             self._jwks = response.json()["keys"]
#         return self._jwks

#     def _get_public_key(self, kid: str):
#         """Get the public key that matches the kid from the JWT token"""
#         jwks = self._get_jwks()
#         key_data = next((key for key in jwks if key["kid"] == kid), None)
#         if not key_data:
#             raise AuthenticationFailed("No matching key found")
#         return jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key_data))

#     def _validate_token(self, token: str) -> Tuple[dict, bool]:
#         """Validate the JWT token"""
#         try:
#             # Decode the token header to get the kid
#             header = jwt.get_unverified_header(token)
#             kid = header["kid"]

#             # Get the public key
#             public_key = self._get_public_key(kid)

#             # Verify and decode the token
#             claims = jwt.decode(
#                 token,
#                 public_key,
#                 algorithms=["RS256"],
#                 audience=self.app_client_id,
#                 issuer=f"https://cognito-idp.{self.region}.amazonaws.com/{self.user_pool_id}",
#             )

#             # Check if token is expired
#             if time.time() > claims["exp"]:
#                 raise AuthenticationFailed("Token has expired")

#             return claims, True

#         except jwt.ExpiredSignatureError:
#             raise AuthenticationFailed("Token has expired")
#         except jwt.InvalidTokenError as e:
#             raise AuthenticationFailed(f"Invalid token: {str(e)}")
#         except Exception as e:
#             logger.error(f"Token validation error: {str(e)}")
#             raise AuthenticationFailed("Token validation failed")

#     def authenticate(self, request) -> Optional[Tuple[User, dict]]:
#         """
#         Django REST Framework authentication method
#         Returns a tuple of (user, token_claims) if successful
#         """
#         auth_header = request.headers.get("Authorization")
#         if not auth_header:
#             return None

#         try:
#             # Check if it's a Bearer token
#             auth_parts = auth_header.split()
#             if len(auth_parts) != 2 or auth_parts[0].lower() != "bearer":
#                 raise AuthenticationFailed("Invalid authorization header")

#             token = auth_parts[1]
#             claims, verified = self._validate_token(token)

#             if not verified:
#                 raise AuthenticationFailed("Token validation failed")

#             # Get or create user based on Cognito user sub
#             user, created = User.objects.get_or_create(
#                 username=claims["sub"],
#                 defaults={
#                     "email": claims.get("email", ""),
#                     "is_active": True,
#                 }
#             )

#             return (user, claims)

#         except Exception as e:
#             logger.error(f"Authentication error: {str(e)}")
#             raise AuthenticationFailed(str(e))

#     def authenticate_header(self, request):
#         """
#         Return the authentication header format expected
#         """
#         return "Bearer"