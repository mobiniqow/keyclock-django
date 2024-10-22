# views.py

from django.shortcuts import render, redirect
from django.conf import settings
from keycloak import KeycloakOpenID
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
import requests

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
    return redirect('verify_otp')

def verify_otp(request):
    if request.method == 'POST':
        otp_code = request.POST.get('otp_code')
        token = request.session.get('token')

        # ارسال OTP به Keycloak
        response = requests.post(
            f"{settings.KEYCLOAK_SERVER_URL}{settings.KEYCLOAK_REALM}/protocol/openid-connect/token",
            data={
                'grant_type': 'urn:ietf:params:oauth:grant-type:otp',
                'otp': otp_code,
                'client_id': settings.KEYCLOAK_CLIENT_ID,
                'client_secret': settings.KEYCLOAK_CLIENT_SECRET,
            },
        )

        if response.status_code == 200:
            # ذخیره توکن در سشن
            request.session['token'] = response.json()
            return redirect('profile')
        else:
            return render(request, 'verify_otp.html', {'error': 'Invalid OTP'})

    return render(request, 'verify_otp.html')

class ProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        token = request.session.get('token')
        user_info = keycloak_openid.userinfo(token['access_token'])
        return Response(user_info)

    def post(self, request):
        token = request.session.get('token')
        user_info = request.data
        
        # ارسال اطلاعات به Keycloak برای به‌روزرسانی پروفایل
        response = requests.put(
            f"{settings.KEYCLOAK_SERVER_URL}{settings.KEYCLOAK_REALM}/protocol/openid-connect/userinfo",
            headers={'Authorization': f'Bearer {token["access_token"]}'},
            json=user_info,
        )
        
        if response.status_code == 204:
            return Response({'message': 'Profile updated successfully.'})
        else:
            return Response({'error': 'Failed to update profile.'})

def logout(request):
    request.session.pop('token', None)
    return redirect('home')

def home(request):
    return render(request, 'home.html')
