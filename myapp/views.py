# views.py

from django.shortcuts import render, redirect
from django.conf import settings
from keycloak import KeycloakOpenID
from django.contrib.auth.decorators import login_required

keycloak_openid = KeycloakOpenID(
    server_url=settings.KEYCLOAK_SERVER_URL,
    client_id=settings.KEYCLOAK_CLIENT_ID,
    realm_name=settings.KEYCLOAK_REALM,
    client_secret_key=settings.KEYCLOAK_CLIENT_SECRET,
)

def login(request):
    redirect_uri = request.build_absolute_uri('/callback/')
    auth_url = keycloak_openid.auth_url(redirect_uri=redirect_uri)
    return redirect(auth_url)

def callback(request):
    code = request.GET.get('code')
    redirect_uri = request.build_absolute_uri('/callback/')
    
    # دریافت توکن
    token = keycloak_openid.token(code=code, redirect_uri=redirect_uri)
    request.session['token'] = token
    return redirect('profile')

@login_required
def profile(request):
    token = request.session.get('token')
    if not token:
        return redirect('login')
    
    user_info = keycloak_openid.userinfo(token['access_token'])
    return render(request, 'profile.html', {'user_info': user_info})

def logout(request):
    request.session.pop('token', None)
    return redirect('home')

def home(request):
    return render(request, 'home.html')
