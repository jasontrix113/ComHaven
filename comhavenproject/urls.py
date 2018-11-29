from django.contrib import admin
from django.urls import path, include
from django.views.generic.base import TemplateView
from comhavenapp import views
from django.conf.urls import url
from django.contrib.auth.views import LoginView

urlpatterns = [
    #path('', TemplateView.as_view(template_name='home-accounts.html'), name='home'),

    path('admin/', admin.site.urls),
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

    url('user_login/', views.user_login, name='user_login'),

    # Page CRUD URLs #
    url(r'^logins/new_haven_folder/$', views.new_haven_folder, name='new_haven_folder'),
    url(r'^logins/new_login/$', views.new_login, name='new_login'),
    url(r'^logins/edit/(?P<login_id>\d+)/$', views.login_edit, name='edit'),
    url(r'^logins/delete/(?P<login_id>\d+)/$', views.login_destroy, name='delete'),

    url(r'^users/user_profile/$', views.user_profile, name='user_profile'),
    url(r'^users/profile_edit/(?P<user_id>\d+)/$', views.user_edit, name='profile_edit'),

    url(r'^auto_login/$', views.auto_login, name='auto_login'),

    #SharedHaven
    url('/send_email/', views.send_email, name='send_email'),
]