from django.contrib.auth.forms import UserCreationForm
from django.urls import reverse_lazy
from django.views import generic
from django.contrib.auth import login, authenticate
from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from comhavenapp.forms import SignUpForm, UserProfileForm

from django.contrib.auth.decorators import login_required

from .models import HavenFolder, NewAccountLogin, PinaxPoints, UserProfile
from .forms import NewAccountLoginForm, SharedHavenForm
from django.contrib import messages
import os, string, random, hashlib, cpuinfo, json, uuid
from pathlib import Path
from autologin import AutoLogin

#Selenium#
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

#Pinax-Points#
from pinax.points.models import points_awarded

#DeviceDetector#
#from device_detector import DeviceDetector

#send Email
from django.core.mail import send_mail
from django.template import loader
from selenium.webdriver.common.keys import Keys


@login_required
def auto_login(request):
    new_login = NewAccountLogin.objects.all()
    context_login = {'new_login': new_login}

    usernameStr = 'jsnjocsin@gmail.com'
    passwordStr = 'Jpskrilljap11398'

    #express login function for schoology site
    browser = webdriver.Chrome(os.path.join(os.getcwd(),r'comhavenapp/chromedriver.exe'))
    browser.find_element_by_tag_name('body').send_keys(Keys.COMMAND + 't')
    #browser = webdriver.Chrome(executable_path='C:/path/to/chromedriver.exe')
    browser.get('https://app.schoology.com/login')
    #fill in username and hit the next button
    username = browser.find_element_by_id('edit-mail')
    username.send_keys(usernameStr)
    password = browser.find_element_by_id('edit-pass')
    password.send_keys(passwordStr)

    #signInButton = browser.find_element_by_id('edit-submit');
    #signInButton.click()

    return render(request, 'pages/express-logins.html', context_login)

def user_login(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(username=username, password=password)
        if user:
            # Is the account active? It could have been disabled.
            if user.is_active:
                if request.user_agent.is_pc == True:
                    path = os.getenv('LOCALAPPDATA')
                    filename = os.path.join(path, r"AccessID\cpuinfo.bin")
                    directory = os.path.dirname(filename)
                    path_exist = directory
                    if os.path.exists(path_exist):
                        login(request, user)
                        return redirect('home')
                    else:
                        return redirect('/accounts/login', messages.success(request, 'Cannot find access ID', 'alert-danger'))
        else:
            return redirect('/accounts/login', messages.error(request, 'username or password is incorrect.', 'alert-danger'))

def signup(request):
    if request.method == 'POST':
        form = SignUpForm(request.POST)
        if form.is_valid():
            if request.user_agent.is_pc == True:
                filename = os.path.expandvars(r"C:")
                if os.path.exists(filename):
                        path = os.getenv('LOCALAPPDATA')
                        filename = os.path.join(path, r"AccessID\cpuinfo.bin")
                        directory = os.path.dirname(filename)
                        path_exist = directory
                        if os.path.exists(path_exist):
                            try:
                                return redirect('/accounts/login', messages.success(request, 'Path Already exist.','alert-danger'))
                            except:
                                print("file exist")
                        else:
                            os.mkdir(directory)
                            with open(filename, "w") as f:
                                info = cpuinfo.get_cpu_info()
                                CPUINFO = {'CPUINFO': info}
                                f.write(json.dumps(CPUINFO))
                                form.save()
                                print("Success")
                                return redirect('/accounts/login', messages.success(request, 'Account created successfully.', 'alert-success'))
                else:
                    print("hello")
            elif request.user_agent.is_mobile == True:
                 form.save()
                 return redirect('/accounts/login',
                            messages.success(request, 'Account created successfully.', 'alert-success'))
        else:
            print("Sign Up Failed");
    else:
        form = SignUpForm()
    return render(request, 'registration/signup.html', {'form': form})

# Page Views #
@login_required
def index(request):
    new_login = NewAccountLogin.objects.all()
    context_login = {'new_login': new_login}
    return render(request, 'pages/home-accounts.html', context_login)
@login_required
def accounts(request):
    new_login = NewAccountLogin.objects.all()
    context_login = {'new_login': new_login}
    return render(request, 'pages/home-accounts.html', context_login)

@login_required
def haven_folder(request):
    haven_folder = HavenFolder.objects.all()
    context_folder = {'haven_folder': haven_folder}
    return render(request, 'pages/home-accounts.html',  context_folder)


@login_required
def expresslogins(request):
    new_login = NewAccountLogin.objects.all()
    context_login = {'new_login': new_login}
    return render(request, 'pages/express-logins.html', context_login)

@login_required
def accesscontrol(request):
    device_Name = AccessList.objects.all()
    context_AC = {'deviceName': device_Name}
    return render(request, 'pages/access-control.html', context_AC)

@login_required
def securitychallenges(request):

    return render(request, 'pages/security-challenges.html')

@login_required
def sharedhaven(request):
    new_login = NewAccountLogin.objects.all()
    context_login = {'new_login': new_login}


    return render(request, 'pages/sharedhaven.html', context_login)
@login_required
def generatepassword(request):
    return render(request, 'pages/generate-password.html')

##############END_OF_PAGE_VIEWS##############

@login_required
def new_login(request):
    if request.POST:
        form = NewAccountLoginForm(request.POST)
        if form.is_valid():
            if form.save():
                return redirect('/', messages.success(request, 'Account was successfully added.', 'alert-success'))
            else:
                return redirect('/', messages.error(request, 'Account is not saved', 'alert-danger'))
        else:
            return redirect('/', messages.error(request, 'data is invalid', 'alert-danger'))
    else:
        form = NewAccountLoginForm()
        return render(request, 'pages/new_login.html', {'form':form})

@login_required
def new_haven_folder(request):
    if request.POST:
        form = NewHavenFolderForm(request.POST)
        if form.is_valid():
            if form.save():
                return redirect('/', messages.success(request, 'Folder was successfully added.', 'alert-success'))
            else:
                return redirect('/', messages.error(request, 'Folder is not saved', 'alert-danger'))
        else:
            return redirect('/', messages.error(request, 'Folder is invalid', 'alert-danger'))
    else:
        form = NewHavenFolderForm()
        return render(request, 'pages/new_login.html', {'form':form})

@login_required
def login_edit(request, login_id):
    login = NewAccountLogin.objects.get(id=login_id)
    if request.POST:
        form = NewAccountLoginForm(request.POST, instance=login)
        if form.is_valid():
            if form.save():
                return redirect('/', messages.success(request, 'Account was successfully updated.', 'alert-success'))
            else:
                return redirect('/', messages.error(request, 'Data is not saved', 'alert-danger'))
        else:
            return redirect('/', messages.error(request, 'Form is not valid', 'alert-danger'))
    else:
        form = NewAccountLoginForm(instance=login)
        return render(request, 'pages/login_edit.html', {'form':form})

@login_required
def login_destroy(request, login_id):
    login = NewAccountLogin.objects.get(id=login_id)
    login.delete()
    return redirect('/', messages.success(request, 'Account was successfully deleted.', 'alert-success'))

@login_required
def user_profile(request):
    if request.POST:
        form = UserProfileForm(request.POST)
        if form.is_valid():
            if form.save():
                return redirect('/users/user_profile', messages.success(request, 'Folder was successfully added.', 'alert-success'))
            else:
                return redirect('/users/user_profile', messages.error(request, 'Folder is not saved', 'alert-danger'))
        else:
            return redirect('/users/user_profile', messages.error(request, 'Folder is invalid', 'alert-danger'))
    else:
        form = UserProfileForm()
        return render(request, 'pages/user_profile.html', {'form':form})

@login_required
def user_edit(request, profile_id):
    profile = UserProfile.objects.get(id=profile_id)
    if request.POST:
        form = UserProfileForm(request.POST, instance=profile)
        if form.is_valid():
            if form.save():
                return redirect('/users/user_profile', messages.success(request, 'Profile was successfully updated.', 'alert-success'))
            else:
                return redirect('/users/user_profile', messages.error(request, 'Profile is not saved', 'alert-danger'))
        else:
            return redirect('/users/user_profile', messages.error(request, 'Profile is not valid', 'alert-danger'))
    else:
        form = UserProfileForm(instance=profile)
        return render(request, 'pages/user_profile_edit.html', {'form': form})

@login_required
def send_email(request):
    if request.method == 'GET':
        form = SharedHavenForm()
    else:
        form = SharedHavenForm(request.POST)
        if form.is_valid():
            subject = form.cleaned_data['subject']
            from_email = form.cleaned_data['from_email']
            message = form.cleaned_data['message']
            to_email = [from_email, 'to_email']
            html_message = loader.render_to_string(
                'pages/html_email.html', {
                    'Username': 'jsnjocsin@gmail.com',
                    'Password': '***************',
                }
            )
            try:
                send_mail(subject, message, from_email, to_email, fail_silently=False, html_message=html_message)
            except BadHeaderError:
                return HttpResponse('Invalid header found.')
            return redirect('/sharedhaven', messages.success(request, 'Credential is shared', 'alert-success'))
    return render(request ,"pages/share_credentials.html", {'form': form})
