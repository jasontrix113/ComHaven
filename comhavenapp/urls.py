from django.urls import path
from django.conf.urls import url
from . import views as my_views

urlpatterns = [
    path('signup/', my_views.signup, name='signup')
    #path('login/', my_views.login, name='login')
]