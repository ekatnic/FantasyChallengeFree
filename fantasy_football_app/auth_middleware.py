# from django.contrib.auth import authenticate, login
# from django.http import JsonResponse
# from django.conf import settings

# import boto3

# import jwt
# from datetime import datetime

# # from .cognito_idp import CognitoIdentityProvider
# from .cognito_idp import cognito_service
# # Initialize Cognito client (ensure these are imported from your constants)
# # cognito_client = boto3.client('cognito-idp', 
# #                               region_name=settings.AWS_COGNITO_REGION,
# #                                 aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
# #                                 aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY
# #                               )
# # cognito_service = CognitoIdentityProvider(
# #     cognito_idp_client=cognito_client, 
# #     user_pool_id=settings.AWS_COGNITO_USER_POOL_ID,
# #     client_id=settings.AWS_COGNITO_CLIENT_ID,
# #     client_secret=settings.AWS_COGNITO_CLIENT_SECRET
# # )

# class CognitoAuthenticationMiddleware:
#     def __init__(self, get_response):
#         self.get_response = get_response

#     def __call__(self, request):
#         # Check for Cognito token in Authorization header
#         auth_header = request.headers.get('Authorization')
#         if auth_header and auth_header.startswith('Bearer '):
#             token = auth_header.split(' ')[1]
#             user = authenticate(request, token=token)
#             if user:
#                 login(request, user)

#         response = self.get_response(request)
#         return response


# class TokenRefreshMiddleware:
#     def __init__(self, get_response):
#         self.get_response = get_response

#     def __call__(self, request):
#         # Skip middleware for refresh token endpoint to avoid infinite loop
#         if request.path == '/refresh_token/':
#             return self.get_response(request)
            
#         access_token = request.COOKIES.get('access_token')
#         refresh_token = request.COOKIES.get('refresh_token')
        
#         if access_token:
#             try:
#                 # Try to decode the token to check if it's expired
#                 jwt.decode(access_token, options={"verify_signature": False})
#             except jwt.ExpiredSignatureError:
#                 # Token is expired, try to refresh
#                 if refresh_token:
#                     try:
#                         refresh_response = cognito_service.refresh_auth_tokens(refresh_token)
#                         new_access_token = refresh_response['AuthenticationResult']['AccessToken']
                        
#                         # Get the original response
#                         response = self.get_response(request)
                        
#                         # Set the new access token in cookie
#                         response.set_cookie(
#                             'access_token',
#                             new_access_token,
#                             httponly=True,
#                             secure=settings.COOKIE_SECURE,
#                             samesite='Lax',
#                             max_age=3600
#                         )
                        
#                         return response
#                     except Exception as e:
#                         return JsonResponse(
#                             {'detail': 'Error refreshing token'},
#                             status=401
#                         )
                        
#         return self.get_response(request)