# # cognito_auth.py
# import json
# import logging
# import time
# from typing import Optional, Tuple

# import jwt
# import requests
# from django.conf import settings
# from django.contrib.auth import get_user_model
# from django.contrib.auth.backends import BaseBackend
# from rest_framework.authentication import BaseAuthentication
# from rest_framework.exceptions import AuthenticationFailed

# logger = logging.getLogger(__name__)
# User = get_user_model()

# class CognitoJWTAuthentication(BaseAuthentication):
#     def __init__(self):
#         self.region = settings.AWS_COGNITO_REGION
#         self.user_pool_id = settings.AWS_COGNITO_USER_POOL_ID
#         self.app_client_id = settings.AWS_COGNITO_APP_CLIENT_ID
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