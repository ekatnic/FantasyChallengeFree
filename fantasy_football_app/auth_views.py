# Update views.py to use the new forms and backend
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth import login, authenticate
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required, user_passes_test

import boto3

from .auth_forms import CognitoAuthenticationForm
from .auth_serializers import SignUpRequestSerializer, CognitoAuthenticationSerializer, ConfirmSignUpRequestSerializer, ChangePasswordRequestSerializer
from .cognito_idp import CognitoIdentityProvider
from .auth import get_current_user, get_user_sub_from_token

# Initialize Cognito client (ensure these are imported from your constants)
cognito_client = boto3.client('cognito-idp', 
                              region_name=settings.AWS_COGNITO_REGION,
                                aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                                aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY
                              )
cognito_service = CognitoIdentityProvider(
    cognito_idp_client=cognito_client, 
    user_pool_id=settings.AWS_COGNITO_USER_POOL_ID,
    client_id=settings.AWS_COGNITO_CLIENT_ID,
    client_secret=settings.AWS_COGNITO_CLIENT_SECRET
)

# --------------------------------------------------------      
# ---- Login endpoint ----
# --------------------------------------------------------      

@api_view(['POST'])
def login_view(request):
    print(f"--- Login view ---")
    print(f"Login view request: {request}")
    print(f"Login view request data: {request.data}")
    
    serializer = CognitoAuthenticationSerializer(data=request.data)

    if serializer.is_valid():
        username = serializer.validated_data['username']
        password = serializer.validated_data['password']
        print(f"Username: {username}")
        print(f"Password: {password}") 
        # Authenticate with Cognito
        try:
            login_response = cognito_service.start_sign_in(
                user_name=username,
                password=password
            )
            print(f"Login response: {login_response}")
            print(f"Login response keys: {login_response.keys()}")
            if 'AuthenticationResult' in login_response:
                # token = login_response['AuthenticationResult']['AccessToken']
                auth_result = login_response['AuthenticationResult']
                access_token = auth_result['AccessToken']
                refresh_token = auth_result['RefreshToken']
                id_token = auth_result['IdToken']

                user_sub = get_user_sub_from_token(access_token)
                # user = serializer.validated_data['user']  # Retrieve the Django user instance
                print(f"User sub: {user_sub}")
                
                User = get_user_model()
                # Get or create the user based on the user_sub
                user, created = User.objects.get_or_create(
                    username=user_sub,  # You could also use email or another unique field if applicable
                    defaults={
                        'email': serializer.validated_data.get('email', ''),
                        'first_name': serializer.validated_data.get('first_name', ''),
                              'last_name': serializer.validated_data.get('last_name', '')}
                )
                print(f"User created: {created}, User: {user}")
                
                # Log in the user *only after* successful Cognito authentication
                login(request, user, backend='django.contrib.auth.backends.CognitoCaseInsensitiveModelBackend')
                print(f"Authenticated user: {user}")
                
                # Create response with tokens
                response = Response({
                    'access_token': access_token,
                    'id_token': id_token,
                    'token_type': 'bearer',
                    'user': {
                        'username': user.username,
                        'email': user.email,
                        'first_name': user.first_name,
                        'last_name': user.last_name
                    }
                })

                # Set access token cookie
                response.set_cookie(
                    'access_token',
                    access_token,
                    httponly=True,
                    secure=settings.COOKIE_SECURE,  # True in production
                    samesite='Lax',
                    max_age=3600,  # 1 hour
                    path='/'
                )

                # Set refresh token cookie
                response.set_cookie(
                    'refresh_token',
                    refresh_token,
                    httponly=True,
                    secure=settings.COOKIE_SECURE,
                    samesite='Lax',
                    max_age=7 * 24 * 3600,  # 7 days
                    path='/'
                )

                # Set ID token cookie
                response.set_cookie(
                    'id_token',
                    id_token,
                    httponly=True,
                    secure=settings.COOKIE_SECURE,
                    samesite='Lax',
                    max_age=3600,  # 1 hour
                    path='/'
                )

                return response

                # return Response({
                #     'access_token': access_token,
                #     'token_type': 'bearer'
                # })
                
        except Exception as e:
            return Response(
                {'detail': str(e)},
                status=status.HTTP_401_UNAUTHORIZED
            )
    return Response(serializer.errors, status=status.HTTP_401_UNAUTHORIZED)

# --------------------------------------------------------      
# ---- Sign up endpoint ----
# --------------------------------------------------------      


@api_view(['POST'])
def signup_view(request):
    print(f"--- signup_view ---")
    print(f"Signup view request: {request}")
    print(f"Signup view request data: {request.data}")
    serializer = SignUpRequestSerializer(data=request.data)
    if serializer.is_valid():
        email = serializer.validated_data['email']
        password = serializer.validated_data['password']
        print(f"Email: {email}")
        print(f"Password: {password}")
        try:
            is_confirmed = cognito_service.sign_up_user(
                user_name=email,
                password=password,
                user_email=email
            )
            if is_confirmed:
                return Response(
                    {'detail': 'User already exists and is confirmed'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            return Response(
                {'detail': 'User signup successful. Please check your email for confirmation code.'}
            )
        except Exception as e:
            return Response(
                {'detail': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )
    else:
        return Response(
            serializer.errors,
            status=status.HTTP_400_BAD_REQUEST
        )
# --------------------------------------------------------      
# ---- Confirm Sign up endpoint ----
# --------------------------------------------------------      

@api_view(['POST'])
def confirm_signup_view(request):
    print(f"--- confirm_signup_view ---")
    print(f"Confirm signup view request: {request}")
    print(f"Confirm signup view request data: {request.data}")
    serializer = ConfirmSignUpRequestSerializer(data=request.data)
    if serializer.is_valid():
        email = serializer.validated_data['email']
        confirmation_code = serializer.validated_data['confirmation_code']
        print(f"Email: {email}")
        print(f"Confirmation code: {confirmation_code}")
        try:
            confirmed = cognito_service.confirm_user_sign_up(
                user_name=email,
                confirmation_code=confirmation_code
            )
            if not confirmed:
                return Response(
                    {'detail': 'Invalid confirmation token'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            registered_user = cognito_service.get_user_by_username(email)
            user_attrs = {attr.get('Name'): attr.get('Value') for attr in registered_user.get('UserAttributes')}
            print(f"User attributes: {user_attrs}")
            User = get_user_model()
            new_user = User.objects.create_user(
                username=user_attrs.get('sub'),
                email=user_attrs.get('email'),
                first_name=user_attrs.get('given_name', ''),
                last_name=user_attrs.get('family_name', '')
            )
            return Response(
                {'detail': 'User confirmed successfully.'}
            )
        except Exception as e:
            return Response(
                {'detail': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )
    else:
        return Response(
            serializer.errors,
            status=status.HTTP_400_BAD_REQUEST
       )

# --------------------------------------------------------      
# ---- Change password endpoints ----
# --------------------------------------------------------   

# TODO: Add permission_classes([IsAuthenticated]) to require authentication (right now the user has to just send the access_token with the request to get results)
# @api_view(['POST'])
# @permission_classes([IsAuthenticated])
@api_view(['POST'])
def change_password_view(request):
    print(f"--- change_password ---")
    print(f"Change password request: {request}")
    print(f"Change password request data: {request.data}")
    serializer = ChangePasswordRequestSerializer(data=request.data)
    if serializer.is_valid():
        email = serializer.validated_data['email']
        old_password = serializer.validated_data['old_password']
        new_password = serializer.validated_data['new_password']
        access_token = serializer.validated_data['access_token']
        # access_token = request.headers.get('Authorization')

        print(f"Email: {email}")
        print(f"Old password: {old_password}")
        print(f"New password: {new_password}")
        print(f"Acess token: {access_token}") 
        print(f"request.headers: {request.headers}")
        print(f"request.headers.get('Authorization'): {request.headers.get('Authorization')}")
        
        try:
            change_resp = cognito_service.change_password(
                user_name=email,
                old_password=old_password,
                new_password=new_password,
                access_token=access_token
            )
            print(f"Change password response: {change_resp}")
            return Response(
                {'detail': change_resp}
            )
        except Exception as e:
            return Response(
                {'detail': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )
    else:
        return Response(
            serializer.errors,
            status=status.HTTP_400_BAD_REQUEST
        )  

# --------------------------------------------------------      
# ---- Forgot password / confirmation endpoints ----
# --------------------------------------------------------      

@api_view(['POST'])
def forgot_password_view(request):
    print(f"--- forgot_password ---")
    print(f"Forgot password request: {request}")
    print(f"Forgot password request data: {request.data}")
    email = request.data.get('email')
    print(f"Email: {email}")
    try:
        forgot_resp = cognito_service.forgot_password(user_name=email)
        print(f"Forgot password response: {forgot_resp}")
        return Response(
            {'detail': 'Password reset code sent to verified email or device'}
        )
    except Exception as e:
        return Response(
            {'detail': str(e)},
            status=status.HTTP_400_BAD_REQUEST
        )
    
@api_view(['POST'])
def confirm_forgot_password_view(request):
    print(f"--- confirm_forgot_password ---")
    print(f"Confirm forgot password request: {request}")
    print(f"Confirm forgot password request data: {request.data}")
    email = request.data.get('email')
    confirmation_code = request.data.get('confirmation_code')
    password = request.data.get('password')
    print(f"Email: {email}")
    print(f"Confirmation code: {confirmation_code}")
    print(f"Password: {password}")
    try:
        confirm_resp = cognito_service.confirm_forgot_password(
            user_name=email,
            confirmation_code=confirmation_code,
            password=password
        )
        print(f"Confirm forgot password response: {confirm_resp}")
        return Response(
            {'detail': confirm_resp}
        )
    except Exception as e:
        return Response(
            {'detail': str(e)},
            status=status.HTTP_400_BAD_REQUEST
        )

# --------------------------------------------------------      
# ---- Logout endpoint ----
# --------------------------------------------------------      

@api_view(['POST'])
def logout_view(request):
    print(f"--- logout ---")
    print(f"Logout request: {request}")
    print(f"Logout request data: {request.data}")
    access_token = request.data.get('access_token')
    print(f"Access token: {access_token}")
    try:
        logout_resp = cognito_service.sign_out(access_token=access_token)
        print(f"Logout response: {logout_resp}")
        return Response(
            {'detail': logout_resp}
        )
    except Exception as e:
        return Response(
            {'detail': str(e)},
            status=status.HTTP_400_BAD_REQUEST
        )


# --------------------------------------------------------      
# ---- Refresh cookies endpoint ----
# --------------------------------------------------------      

@api_view(['POST'])
def refresh_token_view(request):
    """
    Endpoint to refresh an expired access token using a refresh token
    """
    print("--- refresh_token_view ---")
    refresh_token = request.data.get('refresh_token')
    
    if not refresh_token:
        return Response(
            {'detail': 'Refresh token is required'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    try:
        # Use Cognito to get new tokens
        refresh_response = cognito_service.refresh_auth_tokens(refresh_token)
        
        new_access_token = refresh_response['AuthenticationResult']['AccessToken']
        new_refresh_token = refresh_response['AuthenticationResult'].get('RefreshToken', refresh_token)
        
        # Set tokens in cookies
        response = Response({
            'detail': 'Tokens refreshed successfully',
            'access_token': new_access_token
        })
        
        # Set httponly cookies
        response.set_cookie(
            'access_token',
            new_access_token,
            httponly=True,
            secure=settings.COOKIE_SECURE,  # True in production
            samesite='Lax',
            max_age=3600  # 1 hour
        )
        
        response.set_cookie(
            'refresh_token',
            new_refresh_token,
            httponly=True,
            secure=settings.COOKIE_SECURE,
            samesite='Lax',
            max_age=7 * 24 * 3600  # 7 days
        )
        
        return response
        
    except Exception as e:
        return Response(
            {'detail': str(e)},
            status=status.HTTP_401_UNAUTHORIZED
        )
