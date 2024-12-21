# from django import forms
# from django.contrib.auth.forms import AuthenticationForm, UsernameField
# from django.contrib.auth import authenticate

# class CognitoAuthenticationForm(AuthenticationForm):
#     password = forms.CharField(label="Password", strip=False)
#     # token = forms.CharField(required=False, widget=forms.HiddenInput())
    
#     def clean(self):
#         cleaned_data = super().clean()
#         username = cleaned_data.get('username')
#         password = cleaned_data.get('password')
#         # token = cleaned_data.get('token')
        
#         if username:
#             cleaned_data['username'] = username.lower()
            
#         # # If token is provided, try to authenticate with it
#         # if token:
#         #     user = authenticate(self.request, token=token)
#         #     if user:
#         #         cleaned_data['user'] = user
#         #         return cleaned_data
                
#         return cleaned_data
