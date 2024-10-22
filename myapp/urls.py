from django.urls import path
from .views import home, login, callback, profile, logout

urlpatterns = [
    path('', home, name='home'),
    path('login/', login, name='login'),
    path('callback/', callback, name='callback'),
    path('profile/', profile, name='profile'),
    path('logout/', logout, name='logout'),
]
