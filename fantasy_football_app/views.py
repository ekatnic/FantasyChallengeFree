from django import forms  # Import Django's built-in forms module
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, get_user_model, login, logout
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm
from django.contrib.auth.models import User
from django.core.cache import cache
from django.forms.models import model_to_dict
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.utils.safestring import mark_safe
from django.http import HttpResponseRedirect

from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.views import TokenRefreshView
from authlib.integrations.requests_client import OAuth2Session

import json
import uuid

from waffle import flag_is_active

from .tank_api.api_request import TankAPIClient
from .constants import (DEFENSE_STATS_NAMES, POSITION_ORDER,
                        SKILL_POS_STATS_NAMES, WEEK_CHOICES)
from .forms import EntryForm  
from .models import (
    Entry, 
    Player,
    RosteredPlayers,
    WeeklyStats
)
from .utils import (
    get_all_entry_score_dicts, get_entry_list_score_dict,
    get_entry_score_dict, get_entry_total_dict,
    get_summarized_players, update_and_return
)

from .jwt import decode_and_verify_token


# class RegistrationForm(UserCreationForm):
#     email = forms.EmailField(required=True)
#     first_name = forms.CharField(max_length=30)
#     last_name = forms.CharField(max_length=30)

#     class Meta:
#         model = User
#         fields = ("first_name", "last_name", "username", "email", "password1", "password2")

#     def save(self, commit=True):
#         user = super(RegistrationForm, self).save(commit=False)
#         user.first_name = self.cleaned_data["first_name"]
#         user.last_name = self.cleaned_data["last_name"]
#         user.email = self.cleaned_data["email"]
#         if commit:
#             user.save()
#         return user

# def register(request):
#     if request.method == 'POST':
#         form = RegistrationForm(request.POST)
#         if form.is_valid():
#             user = form.save()  # This will handle the first_name, last_name, email, and password fields
#             username = form.cleaned_data.get('username').lower()
#             messages.success(request, f'Account created for {username}!')
#             login(request, user)  # Log the user in
#             return redirect('create_entry')
#     else:
#         form = RegistrationForm()
#     return render(request, 'fantasy_football_app/register.html', {'form': form})

# def index(request):
#     if request.user.is_authenticated:
#         return redirect('user_home')
#     return render(request, 'fantasy_football_app/index.html')



# class CaseInsensitiveModelBackend(ModelBackend):
#     def authenticate(self, request, username=None, password=None, **kwargs):
#         UserModel = get_user_model()
#         try:
#             user = UserModel.objects.get(username__iexact=username)
#             if user.check_password(password):
#                 return user
#         except UserModel.DoesNotExist:
#             return None

#     def get_user(self, user_id):
#         UserModel = get_user_model()
#         try:
#             return UserModel.objects.get(pk=user_id)
#         except UserModel.DoesNotExist:
#             return None

# class CustomAuthenticationForm(AuthenticationForm):
#     def clean(self):
#         cleaned_data = super().clean()
#         username = cleaned_data.get('username')
#         if username:
#             cleaned_data['username'] = username.lower()
#         return cleaned_data

# def sign_in(request):
#     if request.method == 'POST':
#         form = CustomAuthenticationForm(request, data=request.POST)
#         if form.is_valid():
#             username = form.cleaned_data.get('username')
#             password = form.cleaned_data.get('password')
#             user = authenticate(request, username=username, password=password)
#             if user is not None:
#                 login(request, user)
#                 messages.info(request, f"You are now logged in as {username}.")
#                 return redirect('user_home')
#             else:
#                 messages.error(request,"Invalid username or password.")

#     form = CustomAuthenticationForm()
#     return render(request = request, template_name = "fantasy_football_app/sign_in.html", context={"form":form})

User = get_user_model()

class CognitoAuthManager:
    def __init__(self):
        self.client = OAuth2Session(
            client_id=settings.AWS_COGNITO['CLIENT_ID'],
            client_secret=settings.AWS_COGNITO['CLIENT_SECRET'],
            scope=settings.AWS_COGNITO['SCOPES'],
        )
        self.token_url = f"{settings.COGNITO_USER_POOL_URL}oauth2/token"
        self.userinfo_url = f"{settings.COGNITO_USER_POOL_URL}oauth2/userInfo"

    def get_login_url(self, state):
        return (
            f"{settings.COGNITO_USER_POOL_URL}/login"
            f"?response_type=code"
            f"&client_id={settings.AWS_COGNITO['CLIENT_ID']}"
            f"&redirect_uri={settings.AWS_COGNITO['REDIRECT_URI']}"
            f"&scope={settings.AWS_COGNITO['SCOPES']}"
            f"&state={state}"
        )

    def exchange_code_for_tokens(self, code):
        return self.client.fetch_token(
            self.token_url,
            code=code,
            grant_type="authorization_code",
            redirect_uri=settings.AWS_COGNITO['REDIRECT_URI']
        )

    def get_user_info(self):
        return self.client.get(self.userinfo_url).json()

class LoginView(APIView):
    def get(self, request):
        state = str(uuid.uuid4())
        request.session['oauth_state'] = state
         
        # Store the 'next' parameter in session
        next_url = request.GET.get('next')
        if next_url:
            request.session['next_url'] = next_url
        
        auth_manager = CognitoAuthManager()
        login_url = auth_manager.get_login_url(state)
        return redirect(login_url)

class AuthorizeView(APIView):
    def get(self, request):
        code = request.GET.get('code')
        state = request.GET.get('state')
        
        if not code or not state:
            return Response(
                {'error': 'Invalid request parameters'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # stored_state = request.session.get('oauth_state')
        # if state != stored_state:
        #     return Response(
        #         {'error': 'Invalid state parameter'},
        #         status=status.HTTP_400_BAD_REQUEST
        #     )

        auth_manager = CognitoAuthManager()
        
        try:
            # Get tokens from Cognito
            cognito_tokens = auth_manager.exchange_code_for_tokens(code)
            print(f"Cognito Tokens: {cognito_tokens}")
            # Get user info
            user_info = auth_manager.get_user_info()
            
            print(f"User Info: {user_info}")

            # # Decode and verify the access token
            # access_token = cognito_tokens.get('access_token')
            # decoded_token = decode_and_verify_token(access_token)

            # # Log decoded token or use it as needed
            # print(f"Decoded Token: {decoded_token}")

            # Find or create the user in the database
            user, created = User.objects.get_or_create(
                cognito_sub=user_info['sub'], 
                defaults={
                'email': user_info.get('email'),
                'username': user_info.get('username'),
            })

            print(f"User: {user}")
            print(f"Created: {created}")
            # Generate JWT tokens
            refresh = RefreshToken.for_user(user)
            tokens = {
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            }
            
            request.session['tokens_json'] = json.dumps(tokens)

            # Store Cognito refresh token in user model or secure storage
            user.cognito_refresh_token = cognito_tokens.get('refresh_token')
            user.save()

            # Login user
            login(request, user)

            resp = {
                'tokens': tokens,
                'user': {
                    'id': user.id,
                    'email': user.email,
                    'username': user.username
                }
            }
            print(f"Response: {resp}")

            # Convert tokens to JSON and mark as safe for template rendering
            tokens_json = mark_safe(json.dumps(tokens))

            print(f"Tokens JSON: {tokens_json}")
            # Render template with tokens
            context = {
                'tokens_json': tokens_json
            }
            print(f"Context: {context}")
      
            # Check for stored next_url in session
            next_url = request.session.pop('next_url', None)
            if next_url:
                return redirect(next_url)
                
            # return render(request, 'auth_test.html', context=context)
            return redirect('/auth-test/')

        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )

class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        print("LogoutView Post Method")
        print(f"Request: {request}")
        try:

            refresh_token = request.data.get('refresh')
            token = RefreshToken(refresh_token)
            print(f"Refresh Token: {refresh_token}")
            print(f"Token: {token}")
            token.blacklist()
            
            # Clear session
            request.session.flush()
            logout(request) 

            # redirect to home/ page
            return redirect('/home/')
            # return Response(
            #     {"message": "Logout successful."},
            #     status=status.HTTP_200_OK,
            # )
            # return HttpResponseRedirect('/')  # Redirecting to the home page

        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )

# New Protected Views
class ProtectedResourceView(APIView):
    permission_classes = [IsAuthenticated]  # This makes the route protected
    def get(self, request):
        """
        Example protected endpoint that returns user data
        """

        return Response({
            'user_id': request.user.id,
            'email': request.user.email,
            'username': request.user.username,
            'message': 'You have access to this protected resource!'
        })
    
    def post(self, request):
        """
        Example protected endpoint that processes data
        """
        data = request.data
        # Process the data here...
        return Response({
            'message': 'Data processed successfully',
            'received_data': data
        })

# Example of another protected view with custom logic
class UserProfileView(APIView):
    permission_classes = [IsAuthenticated]
    print(f"UserProfileView Perrmission Classes: {permission_classes}")

    def get(self, request):
        """
        Retrieve user profile data
        """
        user = request.user

        print(f"User: {user}")
        print(f"Request: {request}")

        profile_data = {
            'id': user.id,
            'email': user.email,
            'username': user.username,
            # Add any other user fields you want to expose
        }
        return Response(profile_data)
    
    def put(self, request):
        """
        Update user profile data
        """
        user = request.user
        # Example of updating username
        new_username = request.data.get('username')
        if new_username:
            user.username = new_username
            user.save()
            return Response({'message': 'Profile updated successfully'})
        return Response(
            {'error': 'No data provided'}, 
            status=status.HTTP_400_BAD_REQUEST
        )

def auth_test_view(request):
    print(f"Auth_Test_View\nRequest: {request}")

    tokens_json = request.session.pop('tokens_json', None)  # Retrieve and remove from session
    
    print(f"Auth_Test_View Tokens JSON: {tokens_json}")
    print(f"Is Authenticated: {request.user.is_authenticated}")
    if not tokens_json:
        return redirect('/authorize/')  # Redirect if tokens are missing
    
    context = {
        'tokens_json': tokens_json
    }
    print(f"Auth_Test_View Context:\n > '{context}'")

    return render(request, 'fantasy_football_app/auth_test.html', context=context)

def home_test_view(request):
    print(f"Start test view\nRequest: {request}")

    return render(request, 'fantasy_football_app/home.html')

# def user_home(request):
#     print(f"Index View\nRequest: {request}")
#     print(f"Is Authenticated: {request.user.is_authenticated}")
#     if request.user.is_authenticated:
#         return redirect('/auth-test/')
#     return render(request, 'user_home.html')


@login_required
def create_entry(request):
    if flag_is_active(request, 'entry_lock'):
        messages.error(request, "Entry Creation is Locked")
        return redirect('user_home')
    
    if request.method == 'POST':
        form = EntryForm(request.POST)
        if form.is_valid():
            entry = form.save(commit=True, user=request.user)
            entry.save()

            player_fields = ['quarterback', 'running_back1', 'running_back2', 'wide_receiver1', 'wide_receiver2', 'tight_end', 'flex1', 'flex2', 'flex3', 'flex4', 'scaled_flex', 'defense']

            messages.success(request, 'Entry submitted successfully.')
            cache.delete('ranked_entries_dict')
            return redirect('user_home')
        else:
            messages.error(request, 'Error submitting entry. Please check the form.')
    else:
        form = EntryForm()

    context = {'form': form}
    return render(request, 'fantasy_football_app/create_entry.html', context)

@login_required
def user_home(request):
    all_entries_dict = get_all_entry_score_dicts()
    # filter for only entries by that user
    user_entries_dict = {entry: scoring_dict for entry, scoring_dict in all_entries_dict.items() if entry.user.id == request.user.id}
    context = {'entries': user_entries_dict}
    return render(request, 'fantasy_football_app/user_home.html', context)

@login_required
def delete_entry(request, entry_id):
    if flag_is_active(request, 'entry_lock'):
        messages.error(request, "Entry Deleting is Locked")
        return redirect('user_home')

    entry = get_object_or_404(Entry, id=entry_id, user=request.user)
    entry.delete()
    messages.success(request, 'Entry deleted successfully.')
    cache.delete('ranked_entries_dict')
    return redirect('user_home')

@login_required
def edit_entry(request, entry_id):
    if flag_is_active(request, 'entry_lock'):
        messages.error(request, "Entry Editing is Locked")
        return redirect('user_home')

    entry = get_object_or_404(Entry.objects.select_related('user'), id=entry_id)

    player_fields = ['quarterback', 'running_back1', 'running_back2', 'wide_receiver1', 'wide_receiver2', 'tight_end', 'flex1', 'flex2', 'flex3', 'flex4', 'scaled_flex', 'defense']

    if entry.user.id is not request.user.id:
        messages.error(request, 'You do not have permission to edit this entry.')
        return redirect('user_home')
    if request.method != 'POST':
        # Get the rostered players
        rostered_players = RosteredPlayers.objects.filter(entry=entry).order_by('id')

        # Create a dictionary to pre-populate the form fields
        initial_data = {field_name: rp.player for field_name, rp in zip(player_fields, rostered_players)}
        initial_data.update({f'captain_{field_name}': rp.is_captain for field_name, rp in zip(player_fields, rostered_players)})

        form = EntryForm(instance=entry, initial=initial_data)  # Pass instance to EntryForm
    else:
        form = EntryForm(instance=entry, data=request.POST)  # Pass instance to EntryForm
        if form.is_valid():
            RosteredPlayers.objects.filter(entry=entry).delete()
            form.save()
            cache.delete('ranked_entries_dict')
            return redirect('user_home')  # Redirect to user_home after successfully submitting the form

    context = {'entry': entry, 'form': form}
    return render(request, 'fantasy_football_app/edit_entry.html', context)

@login_required
def standings(request):
    all_entries_dict = get_all_entry_score_dicts()
    return render(request, 'fantasy_football_app/standings.html', {'entries': all_entries_dict})

@login_required
def view_entry(request, entry_id):
    entry = get_object_or_404(Entry.objects.prefetch_related('rosteredplayers_set__player__weeklystats_set'), id=entry_id)
    if not flag_is_active(request, 'entry_lock') and entry.user.id is not request.user.id:
        messages.error(request, 'You do not have permission to view this entry.')
        return redirect('user_home')
    player_total_dict = get_entry_score_dict(entry)
    entry_total_dict = get_entry_total_dict(player_total_dict) 
    zipped_player_list = zip(POSITION_ORDER, player_total_dict.items())
    context = {
        "player_list": zipped_player_list,
        "entry_total": entry_total_dict['total'],
    }
    return render(request, 'fantasy_football_app/view_entry.html', context) 

# def sign_out(request):
#     logout(request)
#     return redirect('index')


def players_view(request):
    players_scoring_dict = cache.get('players_scoring_dict')
    if not players_scoring_dict:
        # Get a QuerySet of Players, annotated with the count of related RosteredPlayer instances
        players_scoring_dict = get_summarized_players()
        cache.set('players_scoring_dict', players_scoring_dict, 60 * 30)  # Cache for 30 minutes
    context = {
        'players_scoring_dict': players_scoring_dict,
    }
    return render(request, 'fantasy_football_app/players.html', {'players_scoring_dict': players_scoring_dict})

@login_required
def rules(request):
    return render(request, 'fantasy_football_app/rules.html')
  
def player_stats_view(request, player_id):
    player = get_object_or_404(Player.objects.prefetch_related('weeklystats_set'), id=player_id)
    weekly_stats = player.weeklystats_set.all().order_by('id')
    weekly_stats_dicts = [update_and_return(model_to_dict(stat), {'week_score': stat.week_score}) for stat in weekly_stats]
    context = {
        'player': player,
        'weekly_stats': weekly_stats_dicts,
        'field_name_mapping': DEFENSE_STATS_NAMES if player.position == 'DEF' else SKILL_POS_STATS_NAMES,
    }
    return render(request, 'fantasy_football_app/player_stats.html', context)

def entry_list_view(request):
    rostered_player_id = request.GET.get('rostered_player','')
    scaled_flex_id = request.GET.get('scaled_flex','')
    captain_id = request.GET.get('captain','')
    player_id = rostered_player_id or scaled_flex_id or captain_id
    player = get_object_or_404(Player, id=player_id)
    if rostered_player_id:
        filter_condition={'player_id':rostered_player_id}
        filter_message=f'Entries where {player.name} is rostered'
    elif scaled_flex_id:
        filter_condition={'player_id':scaled_flex_id, 'is_scaled_flex':True}
        filter_message=f'Entries where {player.name} is scaled flex'
    elif captain_id:
        filter_condition={'player_id':captain_id, 'is_captain':True}
        filter_message=f'Entries where {player.name} is captain'
    else:
        return redirect('players')
    rostered_player_set = RosteredPlayers.objects.filter(**filter_condition)
    entry_id_list = rostered_player_set.values_list('entry', flat=True)
    all_entries_dict = get_all_entry_score_dicts()
    entries_list = {entry: scoring for entry, scoring in all_entries_dict.items() if entry.id in entry_id_list}
    context = {
        'entries': entries_list,
        'filter_message': filter_message,
        }
    return render(request, 'fantasy_football_app/entry_list.html', context)

@user_passes_test(lambda u: u.is_superuser)
def load_players_api_view(request):
    result = None
    if request.method == 'POST':
        week = request.POST.get('week')
        game_date = request.POST.get('game_date')
        cache.delete('ranked_entries_dict')
        cache.delete('players_scoring_dict')
        client = TankAPIClient()
        result = client.process_player_stats_for_date(game_date, week)
        result.sort()

    # Default date to today in 'YYYYMMDD' format
    default_date = timezone.now().strftime('%Y%m%d')

    context = {
        'week_choices': WEEK_CHOICES,
        'default_date': default_date,
        'result': result,
    }
    return render(request, 'fantasy_football_app/load_players_api.html', context)

def react_view(request):
    return render(request, 'index.html')