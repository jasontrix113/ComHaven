from django import forms
from django.contrib.auth.forms import UserCreationForm, UserChangeForm
from django.contrib.auth.models import User
from django.forms import ModelForm
from .models import NewAccountLogin, UserProfile, ExpressLoginsSites, PasswordGenerator
from django.core.validators import MinValueValidator
from zxcvbn_password import zxcvbn
from zxcvbn_password.fields import PasswordField, PasswordConfirmationField

from django.contrib.auth.forms import PasswordResetForm as BasePasswordResetForm
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_text
from django.contrib.auth.tokens import default_token_generator


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
        ('https://www.edmodo.com/', 'https://www.edmodo.com'),
        ('https://www.facebook.com/', 'https://www.facebook.com'),
        ('https://github.com/login', 'https://github.com'),
        # ('https://accounts.google.com/AccountChooser/identifier?service=mail&continue=https%3A%2F%2Fmail.google.com%2Fmail%2F&flowName=GlifWebSignIn&flowEntry=AccountChooser',
        # 'Gmail'),
        ('https://www.instagram.com/accounts/login/', 'https://www.instagram.com'),
        ('http://lms.uno-r.edu.ph/login/index.php', 'http://lms.uno-r.edu.ph'),
        ('https://www.netflix.com/ph/login', 'https://www.netflix.com'),
        ('https://app.schoology.com/login', 'https://app.schoology.com'),
        ('https://accounts.spotify.com/en/login/', 'https://accounts.spotify.com'),
        ('https://trello.com/login', 'https://trello.com'),
        ('https://twitter.com/login', 'https://twitter.com'),
        ('http://uis.uno-r.edu.ph/Student/Account/Login', 'http://uis.uno-r.edu.ph'),

    )
    login_name_choices = (
        ('Edmodo', 'Edmodo'),
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
    login_name = forms.CharField(max_length=200, required=True)
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
    length_choices = [(i,i) for i in range(6,255)]
    pass_length = forms.ChoiceField(choices=length_choices)
    pass_anagram = forms.ChoiceField(label="Choose an anagram",
                               initial='0',
                               widget=forms.Select(),
                               required=False)
    pass_phrase = forms.CharField(max_length=200, required=True)
    pass_up_lo_case = forms.BooleanField(initial= True, required=False)
    pass_no_case = forms.BooleanField(initial=True, required=False)
    pass_ch_case = forms.BooleanField(initial=True, required=False)
    pass_result = forms.CharField(required=False)
    class Meta:
        model = PasswordGenerator
        fields = ['pass_length', 'pass_phrase', 'pass_up_lo_case','pass_no_case','pass_ch_case']

# # noinspection PyClassHasNoInit
# class PasswordResetForm(BasePasswordResetForm):
#     """A self-reset form for users."""
#
#     def save(self, domain_override='comhaven.herokuapp.com', subject_template_name='registration/password_reset_subject.txt',
#              email_template_name='registration/password_reset_email.html', use_https=False,
#              token_generator=default_token_generator, from_email=None, request=None,
#              html_email_template_name=None,
#              extra_email_context=None):
#         """Override the default in order to return the UID and token for use in the view. This also differs from the
#         default behavior by working with one user at a time.
#         :rtype: list[str]
#         """
#
#         # Get the email. That's why we're here.
#         email = self.cleaned_data["email"]
#
#         # Find the user.
#         try:
#             user = User.objects.get(email=email)
#         except User.DoesNotExist:
#             return None, None
#
#         # Generate token and UID.
#         token = token_generator.make_token(user)
#         uid = urlsafe_base64_encode(force_bytes(user.pk))
#
#         # Get site info.
#         if domain_override:
#             site_title = domain = domain_override
#         else:
#             current_site = request.site
#             site_title = current_site.name
#             domain = current_site.domain
#         # Create the template context.
#         context = {
#             'domain': 'comhaven.herokuapp.com',
#             'email': email,
#             'protocol': 'https' if use_https else 'http',
#             'site_title': site_title,
#             'token': token,
#             'uid': uid,
#             'user': user,
#         }
#
#         if extra_email_context is not None:
#             context.update(extra_email_context)
#
#         # Send the email.
#         # noinspection PyUnusedLocal
#         try:
#             self.send_mail(
#                 subject_template_name,
#                 email_template_name,
#                 context,
#                 from_email,
#                 email
#             )
#         except (SMTPAuthenticationError, SocketError) as e:
#             # TODO: Need to deal with email errors.
#             pass
#
#         # Return the token and uid for use in the view.
#         return token, uid
#
#

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