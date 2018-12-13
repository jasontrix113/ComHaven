from django.contrib.auth.forms import UserCreationForm
from django.urls import reverse_lazy
from django.views import generic
from django.contrib.auth import login, authenticate
from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from comhavenapp.forms import RegistrationForm, UserProfileForm

from django.contrib.auth.decorators import login_required

from .models import NewAccountLogin, PinaxPoints, UserProfile, TempAccounts, AccessListOfDevices, ExpressLoginsSites
from .forms import NewAccountLoginForm, SharedHavenForm
from django.contrib import messages
import os, string, random, hashlib, cpuinfo, json, uuid
from pathlib import Path

#Selenium#
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.keys import Keys

#Pinax-Points#
from pinax.points.models import points_awarded

#send Email
from django.core.mail import send_mail
from django.template import loader

#Password Hasher
import hashlib
from django.contrib.auth.hashers import make_password, check_password
from passlib.hash import pbkdf2_sha256

#Date Time
from datetime import datetime

@login_required
def auto_login(request, login_id):
    new_login = NewAccountLogin.objects.all()
    context_login = {'new_login': new_login}

    #express login function for schoology site

    #get instance ID
    login = NewAccountLogin.objects.get(id=login_id)
    # login_name1 = NewAccountLogin.objects.get(login_name='Schoology')
    # login_name2 = NewAccountLogin.objects.get(login_name='LMS')
    # login_name1 = NewAccountLogin.objects.get(login_name='Schoology')
    # login_name2 = NewAccountLogin.objects.get(login_name='LMS')
    form = NewAccountLoginForm(request.POST, instance=login)
    # if login_name1 == 'Schoology':
    #     try:
            # if request.user_agent.browser == 'Google Chrome':
            #     browser = webdriver.Chrome()
            #     browser.find_element_by_tag_name('body').send_keys(Keys.CONTROL + 't')
            #     browser.get('https://app.schoology.com/login')
            #     username = browser.find_element_by_id('edit-mail')
            #     username.send_keys("jsnjocsin@gmail.com")
            #     password = browser.find_element_by_id('edit-pass')
            #     password.send_keys("Jpskrilljap11398")
            #
            # if request.user_agent.browser == 'Firefox':
    try:
        browser = webdriver.Firefox()
        browser.find_element_by_tag_name('body').send_keys(Keys.CONTROL + 't')
        browser.get('https:/schoology.com/login')
        username = browser.find_element_by_id('edit-mail')
        username.send_keys("jsnjocsin@gmail.com")
        password = browser.find_element_by_id('edit-pass')
        password.send_keys("Jpskrilljap11398")
    except:
        return redirect('/express-login', messages.error(request, 'Network Error. Check your Internet Connection', 'alert-danger'))

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
                    form = AccessListOfDevices.objects.all()
                    if os.path.exists(path_exist):
                        login(request, user)
                        return redirect('home')
                    else:
                        return redirect('/accounts/login', messages.success(request, 'Cannot find access ID', 'alert-danger'))
                if request.user_agent.is_mobile == True:
                    return redirect('home')
        else:
            return redirect('/accounts/login', messages.error(request, 'username or password is incorrect.', 'alert-danger'))

def register(request):
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
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
                            form.save()
                            return redirect('/accounts/login', messages.success(request, 'Account created successfully.','alert-success'))
                        except:
                            print("file exist")
                    else:
                        os.mkdir(directory)
                        with open(filename, "w") as f:
                            info = cpuinfo.get_cpu_info()
                            CPUINFO = {'CPUINFO': info}
                            f.write(json.dumps(CPUINFO))
                            if request.method == 'POST':
                                user = request.POST['username']
                                device_model = request.user_agent.device
                                print(device_model)
                                # f.save()
                                form.save()
                                print("Success")
                                AccessListOfDevices.objects.create(
                                    acl_user = user,
                                    device_model=device_model,
                                    access_id_path=directory
                                )
                                return redirect('/accounts/login', messages.success(request, 'Account created successfully.', 'alert-success'))
            elif request.user_agent.is_mobile == True:
                 form.save()
                 return redirect('/accounts/login',messages.success(request, 'Account created successfully.', 'alert-success'))

            else:
                form.save()
                return redirect('/accounts/login', messages.success(request, 'Account created successfully.', 'alert-success'))
        else:
            return redirect('/accounts/register', messages.success(request, 'Registration Failed Form is Invalid.'))
    else:
        form = RegistrationForm()
    return render(request, 'registration/register.html', {'form': form})

# Page Views #
@login_required
def index(request):
    new_login = NewAccountLogin.objects.filter(login_user=request.user)
    context_login = {'new_login': new_login}
    return render(request, 'pages/dashboard.html', context_login)

@login_required
def accounts(request):
    new_login = NewAccountLogin.objects.filter(login_user=request.user)
    context_login = {'new_login': new_login}
    return render(request, 'pages/home-accounts.html', context_login)

@login_required
def haven_folder(request):
    haven_folder = HavenFolder.objects.all()
    context_folder = {'login_haven_folder': login_haven_folder}
    return render(request, 'pages/home-accounts.html',  context_folder)

@login_required
def expresslogins(request):
    new_login = NewAccountLogin.objects.filter(login_user=request.user)
    context_login = {'new_login': new_login}
    return render(request, 'pages/express-logins.html', context_login)

@login_required
def accesscontrol(request):
    ac_list = AccessListOfDevices.objects.filter(acl_user=request.user)
    context_AC = {'ac_list': ac_list}
    return render(request, 'pages/access-control.html', context_AC)

@login_required
def securitychallenges(request):
    return render(request, 'pages/security-challenges.html')

@login_required
def sharedhaven(request):
    new_login = NewAccountLogin.objects.filter(login_user=request.user)
    context_login = {'new_login': new_login}
    return render(request, 'pages/sharedhaven.html', context_login)
@login_required
def generatepassword(request):
    return render(request, 'pages/generate-password.html')

##############END_OF_PAGE_VIEWS##############

##############FUNCTION VIEWS##############

@login_required
def new_login(request):
    if request.POST:
        form = NewAccountLoginForm(request.POST)
        if request.method == 'POST':
            if form.is_valid():
                login_target_url = request.POST['login_target_url']
                login_name = request.POST['login_name']
                login_username = request.POST['login_username']
                login_password = request.POST['login_password']
                login_notes = request.POST['login_notes']
                # login_haven_folder = request.POST['login_haven_folder']
                # login_username.set_cookie('login_name', datetime.datetime.now())
                # login_password.set_cookie('login_username', datetime.datetime.now())
                # sp = request.session['login_password'] = login_password
                # su = request.session['login_username'] = login_username
                # login_haven_folder = request.POST['login_haven_folder']

                #Password Encryption with Salt#
                enc_password = pbkdf2_sha256.encrypt(login_password, rounds=100000, salt_size=32)
                user = request.user
                TempAccounts.objects.create(
                    temp_user = request.user,
                    temp_uname = login_username,
                    temp_pword = login_password,
                )
                NewAccountLogin.objects.create(
                    login_user = user,
                    # login_haven_folder = login_haven_folder,
                    login_target_url=login_target_url,
                    login_name=login_name,
                    login_username=login_username,
                    login_password=enc_password,
                    login_notes=login_notes,
                )
            if form.is_valid():
               return redirect('/', messages.success(request, 'Account was successfully added.', 'alert-success'))
            else:
                return redirect('/', messages.error(request, 'Account is not saved', 'alert-danger'))

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
        info = UserProfile.objects.all()
        if form.is_valid():
            return redirect('user_profile_edit')
    else:
        form = UserProfileForm()
        return render(request, 'pages/user_profile.html', {'form':form})

@login_required
def user_edit(request):
    if request.POST:
        form = UserProfileForm(request.POST)
        if request.method == 'POST':
            if form.is_valid():
                return redirect('user_profile_save')
    else:
        form = UserProfileForm(instance=request.user)
        return render(request, 'pages/user_profile_edit.html', {'form': form})
@login_required
def user_save(request):
    if request.POST:
        form = UserProfileForm(request.POST)
        if request.method == 'POST':
            if form.is_valid():
                firstname = request.POST['firstname'];
                print(firstname)
                lastname = request.POST['lastname'];
                address = request.POST['address'];
                notes = request.POST['notes'];
                form.save(commit=False)
                userp = UserProfile.objects.all();
                print("hellod")
                return redirect('user_profile')
        else:
            print('hello')
            return none

@login_required
def send_email(request):
    if request.method == 'GET':
        form = SharedHavenForm()
    else:
        form = SharedHavenForm(request.POST)
        if form.is_valid():
            subject = form.cleaned_data['subject']
            print(subject)
            from_email = form.cleaned_data['from_email']
            message = form.cleaned_data['message']
            to_email = [from_email, 'to_email']
            html_message = loader.render_to_string(
                'pages/html_email.html', {
                    'Username': 'jsnjocsin@gmail.com',
                    'Password': 'samplepassword',
                }
            )
            # try:
            send_mail(subject, message, from_email, to_email, fail_silently=False, html_message=html_message)
            return redirect('/sharedhaven', messages.success(request, 'Credential is shared', 'alert-success'))
            # except BadHeaderError:
            # return HttpResponse('Invalid header found.')
    return render(request ,"pages/share_credentials.html", {'form': form})
