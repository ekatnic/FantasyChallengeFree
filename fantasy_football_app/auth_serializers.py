# # authentication/serializers.py
# from rest_framework.decorators import api_view
# from rest_framework.response import Response
# from rest_framework import serializers, status
# from django.contrib.auth import authenticate, login
# # from .models import User

# class CognitoAuthenticationSerializer(serializers.Serializer):
#     username = serializers.CharField()
#     password = serializers.CharField(write_only=True)
#     # token = serializers.CharField(required=False, write_only=True)

#     # def validate(self, data):
#     #     username = data.get('username', '').lower()
#     #     password = data.get('password')
#     #     token = data.get('token')

#     #     # Authenticate with token if provided
#     #     if token:
#     #         user = authenticate(self.context['request'], token=token)
#     #         if not user:
#     #             raise serializers.ValidationError("Invalid token")
#     #         data['user'] = user
#     #         return data

#     #     # Otherwise authenticate with username and password
#     #     user = authenticate(username=username, password=password)
#     #     if not user:
#     #         raise serializers.ValidationError("Invalid credentials")
        
#     #     data['user'] = user
#     #     return data

# class SignUpRequestSerializer(serializers.Serializer):
#     email = serializers.EmailField()
#     password = serializers.CharField(write_only=True)
#     # birthdate = serializers.DateField(required=False)

# class ConfirmSignUpRequestSerializer(serializers.Serializer):
#     email = serializers.EmailField()
#     confirmation_code = serializers.CharField()

# class ConfirmSignUpResponseSerializer(serializers.Serializer):
#     status = serializers.CharField()
#     message = serializers.CharField()
#     user_sub = serializers.CharField()
#     email = serializers.EmailField()
#     confirmation_token = serializers.CharField()

# class LoginResponseSerializer(serializers.Serializer):
#     access_token = serializers.CharField()
#     token_type = serializers.CharField()

# class ChangePasswordRequestSerializer(serializers.Serializer):
#     email = serializers.EmailField()
#     old_password = serializers.CharField(write_only=True)
#     new_password = serializers.CharField(write_only=True)
#     access_token = serializers.CharField()

# class ForgotPasswordRequestSerializer(serializers.Serializer):
#     email = serializers.EmailField()

# class ConfirmForgotPasswordRequestSerializer(serializers.Serializer):
#     email = serializers.EmailField()
#     confirmation_code = serializers.CharField()
#     password = serializers.CharField(write_only=True)