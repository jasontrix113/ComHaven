from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from zxcvbn_password.fields import PasswordField, PasswordConfirmationField
from django.forms import ModelForm
from .models import HavenFolder, NewAccountLogin, NewHavenFolder, UserProfile
from zxcvbn_password import zxcvbn

class UserProfileForm(UserCreationForm):

    class Meta:
        model = UserProfile
        fields = ('user', 'email', 'firstname', 'lastname', 'address', 'notes')

class SignUpForm(UserCreationForm):
    email = forms.EmailField(max_length=254, help_text='Required. Inform a valid email address.')

    class Meta:
        model = User
        #fields = ('username', 'first_name', 'last_name', 'email', 'password1', 'password2', )
        fields = ('username', 'email', 'password1', 'password2')

def clean_username(self):
    username = self.cleaned_data.get('username')
    if not username:
        raise forms.ValidationError('username does not exist.')
class NewAccountLoginForm(ModelForm):

    login_target_url = forms.CharField(max_length='200', required=False)
    login_name = forms.CharField(max_length='200', required=False)
    login_username = forms.CharField(required=False)
    login_password = forms.CharField(widget = forms.PasswordInput, required=False)
    login_notes = forms.CharField(widget = forms.Textarea, required=False)

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

class SharedHavenForm(forms.Form):
    from_email = forms.EmailField(required=True)
    to_email = forms.EmailField(required=True)
    subject = forms.CharField(required=True)
    message = forms.CharField(widget=forms.Textarea)
    # username = forms.CharField(required=True)
    # password = forms.CharField(widget=forms.PasswordInput)