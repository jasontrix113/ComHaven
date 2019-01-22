from django.contrib import admin
from django.urls import path, include
from django.views.generic.base import TemplateView
from comhavenapp import views
from django.conf.urls import url
from django.contrib.auth.views import LoginView

urlpatterns = [
    # Core
    # path('admin/', admin.site.urls),
    path('accounts/', include('comhavenapp.urls')),
    path('accounts/', include('django.contrib.auth.urls')),

    # Page URLs #
    url(r'^$', views.index, name='home'),
    url(r'^accounts$', views.accounts, name='accounts'),
    url(r'^express-login/', views.expresslogins, name='express-login'),
    url(r'^access-control/', views.accesscontrol, name='access-control'),
    url(r'^security-challenges/', views.securitychallenges, name='security-challenges'),
    url(r'^sharedhaven/', views.sharedhaven, name='sharedhaven'),
    url(r'^generate-password/', views.generatepassword, name='generate-password'),

    # Authentication
    url('user_login/', views.user_login, name='user_login'),

    # Page CRUD URLs #
    url(r'^logins/new_login/$', views.new_login, name='new_login'),
    url(r'^logins/edit/(?P<login_id>\d+)/$', views.login_edit, name='edit'),
    url(r'^logins/delete/(?P<login_id>\d+)/$', views.login_destroy, name='delete'),

    # User Profile
    url(r'^users/user_profile/', views.user_profile, name='user_profile'),
    url(r'^users/user_profile_edit/', views.user_edit, name='user_profile_edit'),
    url(r'^users/user_profile_delete/', views.user_delete, name='user_delete'),
    url(r'^users/user_stats/', views.user_stats, name='user_stats'),

    # Account Recovery
    url(r'^password_reset/done/', views.pass_r_done, name='password_reset_done'),
    url(r'^password_reset/confirm/', views.pass_r_confirm, name='password_reset_confirm'),

    # Express Login
    url(r'^auto_login/(?P<login_id>\d+)', views.auto_login, name='auto_login'),

    # SharedHaven
    url(r'^send_email/(?P<login_id>\d+)', views.send_email, name='send_email'),
]