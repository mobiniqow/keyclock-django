# urls.py

from django.urls import path
from .views import home, login, callback, verify_otp, ProfileView, logout

urlpatterns = [
    path('', home, name='home'),
    path('login/', login, name='login'),
    path('callback/', callback, name='callback'),
    path('verify_otp/', verify_otp, name='verify_otp'),
    path('api/profile/', ProfileView.as_view(), name='profile'),
    path('logout/', logout, name='logout'),
]
