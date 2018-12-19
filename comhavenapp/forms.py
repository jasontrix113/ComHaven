from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from zxcvbn_password.fields import PasswordField, PasswordConfirmationField
from django.forms import ModelForm
from .models import NewAccountLogin, UserProfile
from zxcvbn_password import zxcvbn

class UserProfileForm(UserCreationForm):
   
    firstname = forms.CharField(max_length='200', required=False)
    lastname = forms.CharField(required=False)
    address = forms.CharField(required=False)
    notes = forms.CharField(required=False)
    class Meta:
        model = UserProfile
        fields = ('firstname', 'lastname', 'address', 'notes')

class RegistrationForm(UserCreationForm):
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
    # user_id = forms.CharField(max_length='200', required=False)
    login_target_url = forms.CharField(max_length='200', required=False)
    login_name = forms.CharField(max_length='200', required=False)
    login_username = forms.CharField(required=False)
    login_password = forms.CharField(widget = forms.PasswordInput(), required=False)
    login_notes = forms.CharField(widget = forms.Textarea, required=False)


    class Meta:
        model = NewAccountLogin
        widgets = {
            'password': forms.PasswordInput(),
        }
        fields = ['login_target_url', 'login_name', 'login_username', 'login_password', 'login_notes']

# class NewHavenFolderForm(ModelForm):
#     class Meta:
#         model = NewHavenFolder
#         fields = ['new_haven_folder']

# class HavenFolderForm(ModelForm):
#     # login_haven_folder = forms.ChoiceField(required=False)
#     class Meta:
#         model = HavenFolder
#         fields = ['login_haven_folder']

class SharedHavenForm(forms.Form):
    from_email = forms.EmailField(required=True)
    to_email = forms.EmailField(required=True)
    subject = forms.CharField(required=True)
    message = forms.CharField(widget=forms.Textarea)
    # username = forms.CharField(required=True)
    # password = forms.CharField(widget=forms.PasswordInput)

# class UpdateProfile(forms.ModelForm):
#     username = forms.CharField(required=True)
#     email = forms.EmailField(required=True)
#     firstname = forms.CharField(required=False)
#     lastname = forms.CharField(required=False)
#
#     class Meta:
#         model = User
#         fields = ('username', 'email', 'firstname', 'lastname')
#
#     def clean_email(self):
#         username = self.cleaned_data.get('username')
#         email = self.cleaned_data.get('email')
#
#         if email and User.objects.filter(email=email).exclude(username=username).count():
#             raise forms.ValidationError('This email address is already in use. Please supply a different email address.')
#         return email
#
#     def save(self, commit=True):
#         user = super(RegistrationForm, self).save(commit=False)
#         user.email = self.cleaned_data['email']
#
#         if commit:
#             user.save()
#
#         return user