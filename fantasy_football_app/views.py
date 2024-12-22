from django import forms  # Import Django's built-in forms module
from django.contrib import messages
from django.contrib.auth import authenticate, get_user_model

from django.contrib.auth import login as django_login
from django.contrib.auth import logout as django_logout
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm
from django.contrib.auth.models import User
from django.core.cache import cache
from django.forms.models import model_to_dict
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone

from django.http import JsonResponse
from django.views.decorators.csrf import ensure_csrf_cookie, csrf_protect
from django.views.decorators.http import require_http_methods
from django.middleware.csrf import get_token
from django.http import HttpResponse

from waffle import flag_is_active

import json

from .tank_api.api_request import TankAPIClient
from .constants import (DEFENSE_STATS_NAMES, POSITION_ORDER,
                        SKILL_POS_STATS_NAMES, WEEK_CHOICES)
from .forms import EntryForm, RegistrationForm, CustomAuthenticationForm 
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

from .cognito_idp import cognito_service

# -------------------------------------------------------------------------
# ----- Authentication backend -----
# TODO: Move to a backends.py file
# -------------------------------------------------------------------------

class CaseInsensitiveModelBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        UserModel = get_user_model()
        try:
            user = UserModel.objects.get(username__iexact=username)
            if user.check_password(password):
                return user
        except UserModel.DoesNotExist:
            return None

    def get_user(self, user_id):
        UserModel = get_user_model()
        try:
            return UserModel.objects.get(pk=user_id)
        except UserModel.DoesNotExist:
            return None

# -------------------------------------------------------------------------
# ----- index.html (/) -----
# -------------------------------------------------------------------------
def index(request):
    print(f"INDEX view is handling request:\n > '{request}'")
    # print(f"Index vars{request}: {vars(request)}")
    # req = vars(request)
    # for key in req.items():
    #     print(f"Key: '{key}'\n >'")
    #     print()

    print(f"Is requested user authenticated? {request.user.is_authenticated:}")

    if request.user.is_authenticated:
        return redirect('user_home')
    return render(request, 'fantasy_football_app/index.html')

# -------------------------------------------------------------------------
# ----- Auth endpoints -----
# -------------------------------------------------------------------------

@ensure_csrf_cookie
def get_csrf_token(request):
    """
    Endpoint to get CSRF token - needed for non-GET requests
    """
    return JsonResponse({'csrfToken': get_token(request)})

@require_http_methods(["POST"])
@csrf_protect
def signup_view(request):
    try:
        data = json.loads(request.body)
        form = RegistrationForm(data)
        
        if form.is_valid():
            user = form.save(commit=False)
            username = form.cleaned_data.get('username').lower()
            email = form.cleaned_data.get('email')
            password = form.cleaned_data.get('password1')
            
            try:
                # Register in Cognito
                response = cognito_service.sign_up_user(
                    user_name=email,
                    password=password,
                    user_email=email
                )
                
                confirmation = cognito_service.admin_confirm_user_sign_up(user_name=email)
                
                # Save user in Django DB
                user.save()
                
                return JsonResponse({
                    'success': True,
                    'message': 'Account created successfully',
                    'user': {
                        'username': username,
                        'email': email,
                        'firstName': user.first_name,
                        'lastName': user.last_name
                    }
                })
                
            except cognito_service.cognito_idp_client.exceptions.UsernameExistsException:
                return JsonResponse({
                    'success': False,
                    'errors': {'username': ['Username already exists']}
                }, status=400)
            except Exception as e:
                return JsonResponse({
                    'success': False,
                    'errors': {'server': [str(e)]}
                }, status=500)
        
        return JsonResponse({
            'success': False,
            'errors': form.errors
        }, status=400)
        
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'errors': {'server': ['Invalid JSON payload']}
        }, status=400)

# --------------------------------------------------------      
# ---- Login view API endpoint ----
# --------------------------------------------------------      

@require_http_methods(["POST"])
@csrf_protect
def login_view(request):
    try:
        data = json.loads(request.body)
        username = data.get('username', '').lower()
        password = data.get('password', '')
        
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            try:
                # Authenticate with Cognito
                response = cognito_service.start_sign_in(username, password)
                
                if response.get("ChallengeName") == "NEW_PASSWORD_REQUIRED":
                    return JsonResponse({
                        'success': False,
                        'requiresPasswordReset': True,
                        'message': 'Password reset required'
                    }, status=401)
                
                django_login(request, user)
                
                return JsonResponse({
                    'success': True,
                    'user': {
                        'username': user.username,
                        'email': user.email,
                        'firstName': user.first_name,
                        'lastName': user.last_name
                    }
                })
                
            except Exception as e:
                return JsonResponse({
                    'success': False,
                    'errors': {'server': [str(e)]}
                }, status=500)
        
        return JsonResponse({
            'success': False,
            'errors': {'credentials': ['Invalid username or password']}
        }, status=401)
        
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'errors': {'server': ['Invalid JSON payload']}
        }, status=400)

# --------------------------------------------------------      
# ---- Logout API endpoint ----
# --------------------------------------------------------      

@require_http_methods(["POST"])
@csrf_protect
def logout_view(request):
    user = request.user 
    django_logout(request)
    logout_resp = cognito_service.admin_sign_out(user_name=user)

    return JsonResponse({
        'success': True,
        'message': 'Successfully logged out'
    })

# --------------------------------------------------------      
# ---- check_auth_status API endpoint ----
# --------------------------------------------------------      

@require_http_methods(["GET"])
def check_auth_status(request):
    if request.user.is_authenticated:
        return JsonResponse({
            'isAuthenticated': True,
            'user': {
                'username': request.user.username,
                'email': request.user.email,
                'firstName': request.user.first_name,
                'lastName': request.user.last_name
            }
        })
    return JsonResponse({'isAuthenticated': False})

# -------------------------------------------------------------------------
# ----- Django REST endpoints -----
# -------------------------------------------------------------------------

from rest_framework import status, generics
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.views import APIView
from django.contrib.auth import login, logout, authenticate
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth import update_session_auth_hash
from django.views.decorators.csrf import ensure_csrf_cookie
from django.utils.decorators import method_decorator

from .serializers import (
    UserSerializer, 
    SignupSerializer, 
    LoginSerializer, 
    ForgotPasswordSerializer, 
    ConfirmForgotPasswordSerializer,
    ChangePasswordSerializer
    )

@method_decorator(ensure_csrf_cookie, name = "post")
class SignupView(generics.CreateAPIView):
    serializer_class = SignupSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            try:
                # Register with Cognito
                cognito_service.sign_up_user(
                    user_name=serializer.validated_data['email'],
                    password=serializer.validated_data['password1'],
                    user_email=serializer.validated_data['email']
                )
                
                # Confirm the user in Cognito
                cognito_service.admin_confirm_user_sign_up(
                    user_name=serializer.validated_data['email']
                )
                
                # Create Django user
                user = serializer.save()
                
                return Response({
                    'success': True,
                    'message': 'Account created successfully',
                    'user': UserSerializer(user).data
                }, status=status.HTTP_201_CREATED)
                
            except cognito_service.cognito_idp_client.exceptions.UsernameExistsException:
                return Response({
                    'success': False,
                    'errors': {'username': ['Username already exists in Cognito']}
                }, status=status.HTTP_400_BAD_REQUEST)
            except Exception as e:
                return Response({
                    'success': False,
                    'errors': {'server': [str(e)]}
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        return Response({
            'success': False,
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

@method_decorator(ensure_csrf_cookie, name = "post")
class LoginView(APIView):
    permission_classes = [AllowAny]
    serializer_class = LoginSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            username = serializer.validated_data['username']
            password = serializer.validated_data['password']
            
            print(f"Authing {username} w/ pass: {password}")
            user = authenticate(request, username=username, password=password)
            
            if user:
                try:
                    # Authenticate with Cognito
                    response = cognito_service.start_sign_in(username, password)
                    print(f"Response from cognito: {response}")
                    if response.get("ChallengeName") == "NEW_PASSWORD_REQUIRED":
                        return Response({
                            'success': False,
                            'requiresPasswordReset': True,
                            'message': 'Password reset required'
                        }, status=status.HTTP_401_UNAUTHORIZED)
                    
                    django_login(request, user)
                    
                    return Response({
                        'success': True,
                        'user': UserSerializer(user).data
                    })
                    
                except Exception as e:
                    return Response({
                        'success': False,
                        'errors': {'server': [str(e)]}
                    }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            return Response({
                'success': False,
                'errors': {'credentials': ['Invalid username or password']}
            }, status=status.HTTP_401_UNAUTHORIZED)
        
        return Response({
            'success': False,
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

@method_decorator(ensure_csrf_cookie, name = "post")
class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # user = request.user 
        # Get the actual username string from the user object
        username = str(request.user)
        # django_logout(request)
        print(f"username: {username}")

        logout_resp = cognito_service.admin_sign_out(user_name=username)
        print(f"logout_resp: {logout_resp}")
        
        django_logout(request)
        return Response({
            'success': True,
            'message': 'Successfully logged out'
        })

class ForgotPasswordView(APIView):
    permission_classes = [AllowAny]
    serializer_class = ForgotPasswordSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        
        if serializer.is_valid():
            email = serializer.validated_data['email']
            
            try:
                # Verify user exists in Django DB
                User.objects.get(email=email)
                
                # Initiate Cognito forgot password flow
                forgot_resp = cognito_service.forgot_password(user_name=email)
                
                return Response({
                    'success': True,
                    'message': 'Password reset code sent to your email',
                    'details': forgot_resp
                })
                
            except User.DoesNotExist:
                return Response({
                    'success': False,
                    'errors': {'email': ['No account found with this email address']}
                }, status=status.HTTP_404_NOT_FOUND)
                
            except Exception as e:
                return Response({
                    'success': False,
                    'errors': {'server': [str(e)]}
                }, status=status.HTTP_400_BAD_REQUEST)
        
        return Response({
            'success': False,
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)


class ConfirmForgotPasswordView(APIView):
    permission_classes = [AllowAny]
    serializer_class = ConfirmForgotPasswordSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        
        if serializer.is_valid():
            email = serializer.validated_data['email']
            confirmation_code = serializer.validated_data['confirmation_code']
            new_password = serializer.validated_data['password']
            
            try:
                # First confirm with Cognito
                confirm_resp = cognito_service.confirm_forgot_password(
                    user_name=email,
                    confirmation_code=confirmation_code,
                    password=new_password
                )
                
                # If Cognito confirms successfully, update Django user password
                try:
                    user = User.objects.get(email=email)
                    user.set_password(new_password)
                    user.save()
                    
                    return Response({
                        'success': True,
                        'message': 'Password reset successful',
                        'details': confirm_resp
                    })
                    
                except User.DoesNotExist:
                    # This shouldn't happen if the earlier flow worked correctly
                    return Response({
                        'success': False,
                        'errors': {'email': ['User not found in system']}
                    }, status=status.HTTP_404_NOT_FOUND)
                
            except Exception as e:
                return Response({
                    'success': False,
                    'errors': {'server': [str(e)]}
                }, status=status.HTTP_400_BAD_REQUEST)
        
        return Response({
            'success': False,
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)
    
class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]
    serializer_class = ChangePasswordSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        
        if serializer.is_valid():
            try:
                user = request.user
                new_password = serializer.validated_data['new_password']
                
                # Update password in Cognito
                cognito_response = cognito_service.admin_set_user_password(
                    user_name=user.email,  # Using email as username
                    password=new_password,
                    permanent=True
                )
                
                # If Cognito update successful, update Django password
                user.set_password(new_password)
                user.save()
                
                # Update session to prevent logout
                update_session_auth_hash(request, user)
                
                return Response({
                    'success': True,
                    'message': 'Password successfully changed',
                    'details': cognito_response
                })
                
            except Exception as e:
                return Response({
                    'success': False,
                    'errors': {'server': [str(e)]}
                }, status=status.HTTP_400_BAD_REQUEST)
        
        return Response({
            'success': False,
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

# @ensure_csrf_cookie
class AuthStatusView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        if request.user.is_authenticated:
            return Response({
                'isAuthenticated': True,
                'user': UserSerializer(request.user).data
            })
        return Response({'isAuthenticated': False})
    
# -------------------------------------------------------------------------
# ----- Auth template view endpoints -----
# -------------------------------------------------------------------------

def signup(request):
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        print(f"Signup form: {form}")
        if form.is_valid():
            user = form.save(commit=False)  # Save user locally but don't log them in
            username = form.cleaned_data.get('username').lower()
            email = form.cleaned_data.get('email')
            password = form.cleaned_data.get('password1')
            
            # Register the user in Cognito
            try:
                print(f"Trying to sign up user in cognito...")
                response = cognito_service.sign_up_user(
                        user_name=email,
                        password=password,
                        user_email=email
                    )
                
                print(f"Response: {response}")
                print(f"User after sign up in cognito... : {user}")
                print(f"Forcing confirmation of user: {user} ...")

                confirmation = cognito_service.admin_confirm_user_sign_up(user_name=email)
                print(f"Confirmation complete: '{confirmation}'")
                
                user.save()  # Save the user in the Django database
                
                messages.success(request, f'Account created for {username}! Please check your email to confirm registration.')
                
                # return redirect('confirm_signup', email=email)
                return redirect('create_entry')

            except cognito_service.cognito_idp_client.exceptions.UsernameExistsException:
                messages.error(request, 'Username already exists in Cognito. Try a different username.')
            except Exception as e:
                messages.error(request, f'Error occurred during registration with Cognito: {str(e)}')
    
    else:
        form = RegistrationForm()
    return render(request, 'fantasy_football_app/signup.html', {'form': form})

def confirm_signup(request, email):
    if request.method == 'POST':
        confirmation_code = request.POST.get('confirmation_code')
        
        try:
            response = cognito_service.confirm_user_sign_up(
                user_name = email,
                confirmation_code=confirmation_code
            )
               
            messages.success(request, 'Your account has been successfully confirmed!')
            return redirect('create_entry')

        except cognito_service.cognito_idp_client.exceptions.CodeMismatchException:
            messages.error(request, 'Invalid confirmation code. Please try again.')
        except cognito_service.cognito_idp_client.exceptions.ExpiredCodeException:
            messages.error(request, 'Confirmation code has expired. Please request a new one.')
        except Exception as e:
            messages.error(request, f'Error occurred during confirmation: {str(e)}')
    
    return render(request, 'fantasy_football_app/confirm_signup.html', {'email': email})

def login(request):
    if request.method == 'POST':
        form = CustomAuthenticationForm(request, data=request.POST)
        print(f"FORM FROM LOGIN(): {form}")
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(request, username=username, password=password)
            print(f"User: {user}")
            if user is not None:
                try:
                    # Step 2: Start sign-in process with Cognito
                    response = cognito_service.start_sign_in(username, password)
                    print(f"response from cognito: {response}")
                    if response.get("ChallengeName") == "NEW_PASSWORD_REQUIRED":
                        messages.info(request, "Password reset required. Please update your password.")
                        # Redirect to a password reset page if needed
                        return redirect('password_reset')
                    django_login(request, user)
                    messages.info(request, f"You are now logged in as {username}.")
                    return redirect('user_home')
                except Exception as e:
                    messages.error(request, f"Cognito sign-in failed: {str(e)}")
            else:
                messages.error(request,"Invalid username or password.")

    form = CustomAuthenticationForm()
    return render(request = request, template_name = "fantasy_football_app/login.html", context={"form":form})

# --------------------------------------------------------      
# ---- Logout endpoint ----
# --------------------------------------------------------      
from django.http import HttpResponse

def logout(request):
    print(f"--- logout ---")
    print(f"Logout request: {request}")
    # print(f"vars(request): {vars(request)}")
    print(f"Request keys: {vars(request).keys()}")
    print(f"Request user: {request.user}")

    try:
        user = request.user 
        # logout_resp = cognito_service.admin_sign_out(user_name=request.user)
        # print(f"Cognito logout response: {logout_resp}")
        django_logout(request)

        logout_resp = cognito_service.admin_sign_out(user_name=user)

        print(f"Cognito logout response: {logout_resp}")
        try:
            print(f"Is current requests user authenticated? {request.user.is_authenticated}")
        except:
            print(f"Checking if authenticated after logout threw an error")

        return redirect('index')
    except Exception as e:
        messages.error(request, "Failed logout")

    # return HttpResponse(content = "Successful signout", status = 200)
    return redirect('index')

# --------------------------------------------------------      
# ---- User / Business logic endpoints ----
# -------------------------------------------------------- 

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

def sign_out(request):
    django_logout(request)
    return redirect('index')


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