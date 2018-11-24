from django.contrib.auth.forms import UserCreationForm
from django.urls import reverse_lazy
from django.views import generic
from django.contrib.auth import login, authenticate
from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from comhavenapp.forms import SignUpForm

from django.contrib.auth.decorators import login_required

from .models import HavenFolder, NewAccountLogin
from .forms import NewAccountLoginForm
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

@login_required
def auto_login(request, login_id):
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

    usernameStr = 'jsnjocsin@gmail.com'
    passwordStr = 'Jpskrilljap11398'

    #express login function for schoology site
    browser = webdriver.Chrome("D:\Backup\Recent\ComHaven\comhavenapp\chromedriver.exe")
    browser.get('https://app.schoology.com/login')
    #fill in username and hit the next button
    username = browser.find_element_by_id('edit-mail')
    username.send_keys(usernameStr)
    #nextButton = browser.find_element_by_id('identifierNext')
    #nextButton.click()
    password = browser.find_element_by_id('edit-pass')
    password.send_keys(passwordStr)
    #Password Fill wait 10 seconds until animation finished
    #password = WebDriverWait(browser, 10).until(
    #   EC.presence_of_element_located((By.ID, 'Password')))
    #password.send_keys(passwordStr)

    #signInButton = browser.find_element_by_id('edit-submit');
    #signInButton.click()

    #express login function for edmodo site
    #browser = webdriver.Chrome("D:\Backup\Recent\ComHaven\comhavenapp\chromedriver.exe")
    #browser.get('https://www.edmodo.com/?simplified_landing_page=1&go2url=%2Flogin')
    # fill in username and hit the next button
    #username = browser.find_element_by_id('un')
    #username.send_keys(usernameStr)
    # nextButton = browser.find_element_by_id('identifierNext')
    # nextButton.click()
    #password = browser.find_element_by_id('pw')
    #password.send_keys(passwordStr)
    # Password Fill wait 10 seconds until animation finished
    # password = WebDriverWait(browser, 10).until(
    #   EC.presence_of_element_located((By.ID, 'Password')))
    # password.send_keys(passwordStr)

    return render(request, 'pages/home-accounts.html')

#@login_required
#def autologin(request):
#    if request.method == 'POST':
#        url = 'www.edmodo.com'
#        username = 'jsnjocsin@gmail.com'
#        password = 'Jpskrilljap11398'
#        al = AutoLogin()
#        cookies = al.auth_cookies_from_url(url, username, password)

def signup(request):
    if request.method == 'POST':
        form = SignUpForm(request.POST)
        if form.is_valid():
            filename = os.path.expandvars(r"C:")
            if os.path.exists(filename):
                filename = os.path.expandvars(r"C:\Users\jason\AppData\Local\AccessID\cpuinfo.bin")
                directory = os.path.dirname(filename)
                os.mkdir(directory)
                with open(filename, "w") as f:
                    info = cpuinfo.get_cpu_info()
                    CPUINFO = {'CPUINFO': info}
                    f.write(json.dumps(CPUINFO))
                    form.save()
                    print("Success")
                    return redirect('login')
            else:
                #dd = 'Mozilla/5.0 (Linux; Android 4.3; C5502 Build/10.4.1.B.0.101) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/33.0.1750.136 Mobile Safari/537.36'
                ## Parse UA string and load data to dict of 'os', 'client', 'device' keys
                #device = DeviceDetector(dd).parse()
                #dt = device.device_type()
                print("hello")
        else:
            print("Sign Up Failed");
    else:
        form = SignUpForm()
    return render(request, 'registration/signup.html', {'form': form})
#def login(request):
    #if request.method == 'POST':
    #    form = SignUpForm(request.POST)
    #    if form.is_valid():
    #        print("form is valid")
    #        username = form.cleaned_data.get('username')
    #        raw_password = form.cleaned_data.get('password1')
    #        print(raw_password)
    #        print(username)
    #        print("authenticate")
    #        user = authenticate(username=username, password=raw_password)
    #        login(request, user)
    #        return redirect('home')
    #    else:
    #        print("form is invalid")
    #        username = form.cleaned_data.get('username')
    #        raw_password = form.cleaned_data.get('password1')
    #        print(username)
    #        print(raw_password)
    #        user = authenticate(username=username, password=raw_password)
    #        login(user)
    #        return redirect('home')
    #dirName = Path("/Access_ID/access.txt")
    #if os.path.exists(dirName):
    #   print('directory found')
        #print('ready to authenticate')

    #else:
    #    print('directory does not exist')
    #    form = LoginForm()
    #    return render(request, 'registration/login.html', {'form': form})
    #else:
    #    form = SignUpForm()
    #return render(request, 'registration/login.html', {'form': form})
# Page Views #
@login_required
def index(request):
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
    return render(request, 'pages/express-logins.html')

@login_required
def accesscontrol(request):
    return render(request, 'pages/access-control.html')

@login_required
def securitychallenges(request):
    user = request.user
    points = points_awarded(user)
    return render(request, 'pages/security-challenges.html')

@login_required
def sharedhaven(request):
    return render(request, 'pages/sharedhaven.html')

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

#def user_profile(request):
#    return render(request, 'user_profile.html')

@login_required
def sent_mail(request):
    send_mail('Subject here', 'Here is the message.', 'jsnjocsin@gmail.com', ['jpskrilljap@gmail.com'], fail_silently=False)

    return render(request, 'pages/sharedhaven.html')


def pass_reset(request):

    send_mail('Subject here', 'Here is the message.', 'jsnjocsin@gmail.com', ['jpskrilljap@gmail.com'], fail_silently=False)

    return render(request, 'registration/password_reset_form.html')
