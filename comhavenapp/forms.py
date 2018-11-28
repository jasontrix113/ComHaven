from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from zxcvbn_password.fields import PasswordField, PasswordConfirmationField
from django.forms import ModelForm
from .models import HavenFolder, NewAccountLogin, NewHavenFolder, AccessList
from zxcvbn_password import zxcvbn



class SignUpForm(UserCreationForm):
    email = forms.EmailField(max_length=254, help_text='Required. Inform a valid email address.')

    class Meta:
        model = User
        #fields = ('username', 'first_name', 'last_name', 'email', 'password1', 'password2', )
        fields = ('username', 'email', 'password1', 'password2')

class NewAccountLoginForm(ModelForm):

    login_password = forms.CharField(widget = forms.PasswordInput)
    login_notes = forms.CharField(widget = forms.Textarea)

    class Meta:
        model = NewAccountLogin
        fields = ['login_target_url', 'login_name', 'login_haven_folder', 'login_username', 'login_password', 'login_notes']


class NewHavenFolderForm(ModelForm):
    class Meta:
        model = NewHavenFolder
        fields = ['new_haven_folder']

class HavenFolderForm(ModelForm):
    class Meta:
        model = HavenFolder
        fields = ['login_haven_folder']

class AccessListForm(ModelForm):
    class Meta:
        model = AccessList
        fields = ['device_Name']
