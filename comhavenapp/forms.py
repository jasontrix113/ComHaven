from django import forms
from django.contrib.auth.forms import UserCreationForm, UserChangeForm
from django.contrib.auth.models import User
from django.forms import ModelForm
from .models import NewAccountLogin, UserProfile, ExpressLoginsSites, PasswordGenerator
from django.core.validators import MinValueValidator
from zxcvbn_password import zxcvbn
from zxcvbn_password.fields import PasswordField, PasswordConfirmationField

class RegistrationForm(UserCreationForm):
    email = forms.EmailField(max_length=254, help_text='Required. Inform a valid email address.')
    # password1 = PasswordField()
    # password2 = PasswordConfirmationField(confirm_with='password1')

    # password1 =  PasswordField()
    # password2 =  PasswordConfirmationField(confirm_with='password1')

    class Media:
        js = ('zxcvbn-async.js')
    class Meta:
        model = User
        #fields = ('username', 'first_name', 'last_name', 'email', 'password1', 'password2', )
        fields = ('username', 'email', 'password1', 'password2')


def clean_username(self):
    username = self.cleaned_data.get('username')
    if not username:
        raise forms.ValidationError('username does not exist.')

def clean():
    password = self.cleaned_data.get('password1')

    if password:
        score = zxcvbn(password)['score']
        # score is between 0 and 4
        # raise forms.ValidationError if needed

    return self.cleaned_data

class UserProfileForm(ModelForm):
    email = forms.EmailField(max_length=200, required=False)
    firstname = forms.CharField(max_length=200, required=False)
    lastname = forms.CharField(required=False)
    notes = forms.CharField(required=False)
    class Meta:
        model = UserProfile
        fields = ('email', 'firstname', 'lastname', 'notes')

class NewAccountLoginForm(ModelForm):
    url_choices = (
        ('N/A', 'None'),
        ('https://www.facebook.com/', 'https://www.facebook.com/'),
        ('https://github.com/login', 'https://github.com/login'),
        ('https://www.instagram.com/accounts/login/', 'https://www.instagram.com/accounts/login/'),
        ('http://lms.uno-r.edu.ph/login/index.php', 'http://lms.uno-r.edu.ph/login/index.php'),
        ('https://www.netflix.com/ph/login', 'https://www.netflix.com/ph/login'),
        ('https://app.schoology.com/login', 'https://app.schoology.com/login'),
        ('https://accounts.spotify.com/en/login/', 'https://accounts.spotify.com/en/login/'),
        ('https://trello.com/login', 'https://trello.com/login'),
        ('https://twitter.com/login', 'https://twitter.com/login'),
        ('http://uis.uno-r.edu.ph/Student/Account/Login', 'http://uis.uno-r.edu.ph/Student/Account/Login'),

    )
    login_name_choices = (
        ('Facebook','Facebook'),
        ('GitHub', 'GitHub'),
        ('Instagram', 'Instagram'),
        ('LMS', 'LMS'),
        ('Netflix', 'Netflix'),
        ('Schoology', 'Schoology'),
        ('Spotify', 'Spotify'),
        ('Twitter', 'Twitter'),
        ('UIS', 'UIS'),
        ('Trello', 'Trello'),
    )
    # user_id = forms.CharField(max_length='200', required=False)
    login_target_url = forms.ChoiceField(choices=url_choices)
    login_name = forms.ChoiceField(choices=login_name_choices)
    login_username = forms.CharField(required=True)
    login_password = forms.CharField(widget = forms.PasswordInput(), required=False)
    login_notes = forms.CharField(widget = forms.Textarea, required=False)

    class Meta:
        model = NewAccountLogin
        widgets = {
            'password': forms.PasswordInput(),
        }
        fields = ['login_target_url', 'login_name', 'login_username', 'login_password', 'login_notes']

class SharedHavenForm(forms.Form):
    # from_email = forms.EmailField(required=True)
    to_email = forms.EmailField(required=True)
    subject = forms.CharField(required=True)
    message = forms.CharField(widget=forms.Textarea)
    # username = forms.CharField(required=True)
    # password = forms.CharField(widget=forms.PasswordInput)

class PasswordGeneratorForm(ModelForm):
    length_choices = [(i,i) for i in range(12,255)]
    pass_length = forms.ChoiceField(choices=length_choices)
    pass_anagram = forms.ChoiceField(label="Choose an anagram",
                               initial='0',
                               widget=forms.Select(),
                               required=False)
    pass_phrase = forms.CharField(max_length=200, required=True)
    pass_up_lo_case = forms.BooleanField(initial= False, required=False)
    pass_no_case = forms.BooleanField(initial=False, required=False)
    pass_ch_case = forms.BooleanField(initial=False, required=False)
    pass_result = forms.CharField(required=False)
    class Meta:
        model = PasswordGenerator
        fields = ['pass_length', 'pass_phrase', 'pass_up_lo_case','pass_no_case','pass_ch_case']





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