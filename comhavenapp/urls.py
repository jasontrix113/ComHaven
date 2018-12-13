from django.urls import path
from django.conf.urls import url
from . import views as my_views

urlpatterns = [
    path('register/', my_views.register, name='register')

]