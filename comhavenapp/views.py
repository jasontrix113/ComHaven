from django.contrib.auth.forms import UserCreationForm
from django.urls import reverse_lazy
from django.views import generic
from django.contrib.auth import login, authenticate
from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from comhavenapp.forms import RegistrationForm, UserProfileForm, PasswordGeneratorForm
from django.contrib import auth

from django.contrib.auth.decorators import login_required

from .models import NewAccountLogin, UserProfile, TempAccounts, AccessListOfDevices, ExpressLoginsSites, Status, SecurityChallenges, PasswordGenerator, User_Stats
from .forms import NewAccountLoginForm, SharedHavenForm
from django.contrib import messages
import os, string, random, hashlib, cpuinfo, json, uuid
from pathlib import Path

#Selenium#
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver import ActionChains
from selenium.webdriver.common.keys import Keys

#send Email
from django.core.mail import send_mail
from django.template import loader

#Password Hasher
import hashlib
from django.contrib.auth.hashers import make_password, check_password
from passlib.hash import pbkdf2_sha256

#Date Time
from datetime import datetime

#Generate passwords
import itertools
from collections import defaultdict
from django.template import RequestContext
import csv

import platform
from zxcvbn import zxcvbn

@login_required
def auto_login(request, login_id):
    new_login = NewAccountLogin.objects.filter(login_user=request.user)
    context_login = {'new_login': new_login}
    #get instance ID
    login = NewAccountLogin.objects.get(id=login_id)
    temp_ac = TempAccounts.objects.get(id=login_id)
    sites = ExpressLoginsSites.objects.get(id=login_id)
    form = NewAccountLoginForm(request.POST, instance=login)
    if login:
        print(login.login_name)
        print(login.login_target_url)
        print(login.id)
        if login.login_name == 'Schoology':
            try:
                browser = webdriver.Chrome()
                browser.get(login.login_target_url)
                parent = browser.current_window_handle
                username = browser.find_element_by_id("edit-mail")
                username.send_keys(login.login_username)
                password = browser.find_element_by_id("edit-pass")
                password.send_keys(temp_ac.temp_pword)
                # url = browser.find_element_by_id('edit-submit')
                # url.click(parent)

            except:
                return redirect('/express-login', messages.error(request, 'Something is not right. Check your Internet Connection', 'alert-danger'))

                #signInButton = browser.find_element_by_id('edit-submit');
                #signInButton.click()
        elif login.login_name == 'LMS':
            try:
                browser = webdriver.Chrome()
                browser.get(login.login_target_url)
                body = driver.find_element_by_tag_name("body")
                body.send_keys(Keys.CONTROL + 't')
                username = browser.find_element_by_id('username')
                username.send_keys(login.login_username)
                password = browser.find_element_by_id('password')
                password.send_keys(temp_ac.temp_pword)

            except:
                return redirect('/express-login', messages.error(request, 'Something is not right. Check your Internet Connection', 'alert-danger'))

        elif login.login_name == 'Netflix':
            try:
                browser = webdriver.Chrome()
                browser.get(login.login_target_url)
                username = browser.find_element_by_id('id_userLoginId')
                username.send_keys(login.login_username)
                password = browser.find_element_by_id('id_password')
                password.send_keys(temp_ac.temp_pword)

            except:
                return redirect('/express-login', messages.error(request, 'Something is not right. Check your Internet Connection',
                                               'alert-danger'))

                    #signInButton = browser.find_element_by_id('edit-submit');
                    #signInButton.click()
                #signInButton = browser.find_element_by_id('edit-submit');
                #signInButton.click()

        elif login.login_name == 'Facebook':
            try:
                print("hello")
                browser = webdriver.Chrome()
                browser.get(login.login_target_url)
                print(login.login_target_url)
                username = browser.find_element_by_id('email')
                username.send_keys(login.login_username)
                password = browser.find_element_by_id('pass')
                password.send_keys(temp_ac.temp_pword)

            except:
                return redirect('/express-login', messages.error(request, 'Something is not right. Check your Internet Connection',
                                          'alert-danger'))

                    #signInButton = browser.find_element_by_id('edit-submit');
                    #signInButton.click()
                #signInButton = browser.find_element_by_id('edit-submit');
                #signInButton.click()

        elif login.login_name == 'UIS':
            try:
                browser = webdriver.Chrome()
                browser.get(login.login_target_url)
                username = browser.find_element_by_id('UserName')
                username.send_keys(login.login_username)
                password = browser.find_element_by_name('Password')
                password.send_keys(temp_ac.temp_pword)

            except:
                return redirect('/express-login', messages.error(request, 'Something is not right. Check your Internet Connection',
                                               'alert-danger'))

                # signInButton = browser.find_element_by_id('edit-submit');
                # signInButton.click()
                # signInButton = browser.find_element_by_id('edit-submit');
                # signInButton.click()
        elif login.login_name == 'Spotify':
            try:
                browser = webdriver.Chrome()
                browser.get(login.login_target_url)
                username = browser.find_element_by_id('login-username')
                username.send_keys(login.login_username)
                password = browser.find_element_by_id('login-password')
                password.send_keys(temp_ac.temp_pword)

            except:
                return redirect('/express-login', messages.error(request, 'Something is not right. Check your Internet Connection',
                                               'alert-danger'))

                # signInButton = browser.find_element_by_id('edit-submit');
                # signInButton.click()
                # signInButton = browser.find_element_by_id('edit-submit');
                # signInButton.click()
        elif login.login_name == 'Twitter':
            try:
                browser = webdriver.Chrome()
                browser.get(login.login_target_url)
                username = browser.find_element_by_name('session[username_or_email]')
                username.send_keys(login.login_username)
                password = browser.find_element_by_name('session[password]')
                password.send_keys(temp_ac.temp_pword)

            except:
                return redirect('/express-login', messages.error(request, 'Something is not right. Check your Internet Connection',
                                               'alert-danger'))

                # signInButton = browser.find_element_by_id('edit-submit');
                # signInButton.click()
                # signInButton = browser.find_element_by_id('edit-submit');
                # signInButton.click()

        elif login.login_name == 'GitHub':
            try:
                browser = webdriver.Chrome()
                browser.get(login.login_target_url)
                username = browser.find_element_by_id('login_field')
                username.send_keys(login.login_username)
                password = browser.find_element_by_id('password')
                password.send_keys(temp_ac.temp_pword)

            except:
                return redirect('/express-login', messages.error(request, 'Something is not right. Check your Internet Connection',
                                               'alert-danger'))

                # signInButton = browser.find_element_by_id('edit-submit');
                # signInButton.click()
                # signInButton = browser.find_element_by_id('edit-submit');
                # signInButton.click()
        elif login.login_name == 'Instagram':
            try:
                browser = webdriver.Chrome()
                browser.get(login.login_target_url)
                username = browser.find_element_by_id('f33d3bc34c83252')
                username.send_keys(login.login_username)
                password = browser.find_element_by_id('fef35d0b7dedbc')
                password.send_keys(temp_ac.temp_pword)

            except:
                return redirect('/express-login', messages.error(request, 'Something is not right. Check your Internet Connection',
                                               'alert-danger'))

                # signInButton = browser.find_element_by_id('edit-submit');
                # signInButton.click()
                # signInButton = browser.find_element_by_id('edit-submit');
                # signInButton.click()
        elif login.login_name == 'Trello':
            try:
                browser = webdriver.Chrome()
                browser.get(login.login_target_url)
                username = browser.find_element_by_id('user')
                username.send_keys(login.login_username)
                password = browser.find_element_by_id('password')
                password.send_keys(temp_ac.temp_pword)

            except:
                return redirect('/express-login',
                                messages.error(request, 'Something is not right. Check your Internet Connection',
                                               'alert-danger'))

                # signInButton = browser.find_element_by_id('edit-submit');
                # signInButton.click()
                # signInButton = browser.find_element_by_id('edit-submit');
                # signInButton.click()
        else:
            return redirect('/express-login', messages.error(request, 'Something is not right. Check your Internet Connection',
                                           'alert-danger'))
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
                    # path = os.getenv('LOCALAPPDATA')
                    # filename = os.path.join(path, r"AccessID\cpuinfo.bin")
                    # directory = os.path.dirname(filename)
                    # path_exist = directory
                    # form = AccessListOfDevices.objects.all()
                    # if os.path.exists(path_exist):
                    login(request, user)
                    return redirect('home')
                    # else:
                    #     return redirect('/accounts/login', messages.error(request, 'Cannot find access ID', 'alert-danger'))
                if request.user_agent.is_mobile == True:
                    login(request, user)
                    return redirect('home')
                else:
                    login(request, user)
                    return redirect('home')
        else:
            return redirect('/accounts/login', messages.error(request, 'username or password is incorrect.', 'alert-danger'))

def register(request):
    if request.method == 'POST':
        form = RegistrationForm(request.POST)

        # if len(pass1) < 12:
        #     return redirect('/accounts/register',
        #                     messages.error(request, 'Password must be in 12 characters', 'alert-danger'))

        # duplicate_email = User.objects.filter(email=email_data)
        # if duplicate_email.exists():
        #     return redirect('/accounts/register', messages.error(request, 'Email has already taken', 'alert-danger'))
        if form.is_valid():
            if request.user_agent.is_pc == True:
                filename = os.path.expandvars(r"C:")
                if os.path.exists(filename):
                    path = os.getenv('LOCALAPPDATA')
                    filename = os.path.join(path, r"AccessID\cpuinfo.bin")
                    directory = os.path.dirname(filename)
                    path_exist = directory
                    if os.path.exists(path_exist):
                        print("file exist")
                        form.save()
                        return redirect('/accounts/login',
                                messages.success(request, 'Account created successfully.', 'alert-success'))
                    else:
                        os.mkdir(directory)
                        with open(filename, "w") as f:
                            info = cpuinfo.get_cpu_info()
                            CPUINFO = {'CPUINFO': info}
                            f.write(json.dumps(CPUINFO))
                            if request.method == 'POST':
                                user = request.POST['username']
                                device_model = request.user_agent.device
                                device_platform = platform.system()
                                print(device_model)
                                # f.save()
                                create = form.save(commit=False)
                                create.password = form.cleaned_data['password1']
                                create.save()
                                print("Success")
                                AccessListOfDevices.objects.create(
                                    acl_user = user,
                                    device_model=device_model,
                                    access_id_path=directory,
                                    device_platform = device_platform
                                )
                                return redirect('/accounts/login', messages.success(request, 'Account created successfully.', 'alert-success'))
                else:
                    form.save()
                    return redirect('/accounts/login',
                                    messages.success(request, 'Account created successfully.', 'alert-success'))
            elif request.user_agent.is_mobile == True:
                 form.save()
                 return redirect('/accounts/login',messages.success(request, 'Account created successfully.', 'alert-success'))

            else:
                form.save()
                return redirect('/accounts/login', messages.success(request, 'Account created successfully.', 'alert-success'))
        else:
            return redirect('/accounts/register', messages.error(request, 'Registration Failed Form is Invalid.', 'alert-danger'))
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
    user = request.user
    sc = SecurityChallenges.objects.all()
    us = User_Stats.objects.all()
    context_us_sc = {'sc':sc, 'us':us}

    return render(request, 'pages/security-challenges.html', context_us_sc)

@login_required
def sharedhaven(request):
    new_login = NewAccountLogin.objects.filter(login_user=request.user)
    context_login = {'new_login': new_login}
    return render(request, 'pages/sharedhaven.html', context_login)

@login_required
def generatepassword(request):
    try:
        del request.session['result']
    except:
        print('session not found.')
    if request.POST:
        form = PasswordGeneratorForm(request.POST)
        if request.method == "POST":
            if form.is_valid():
                pass_length = request.POST['pass_length']
                length = int(pass_length)
                pass_phrase = request.POST['pass_phrase']

                try:
                    pass_up_lo = request.POST['pass_up_lo_case']
                    print(pass_up_lo)
                except:
                    print('except')
                    pass_up_lo = False
                try:
                    pass_no = request.POST['pass_no_case']
                    print(pass_no)
                except:
                    print('except2')
                    pass_no = False
                    print(pass_no)
                try:
                    pass_ch = request.POST['pass_ch_case']
                    print(pass_ch)
                except:
                    print('except3')
                    pass_ch = False

                # leetspeak converter
                getchar = lambda c: chars[c] if c in chars else c
                chars = {"a":"4","e":"3","l":"1","o":"0","s":"5","t":"7"}
                leet = ''.join(getchar(c) for c in pass_phrase)
                print('Leet Equivalent: '+ leet)
                chars1 = ''

                # pseudo-random string
                if pass_no == False and  pass_no == False and pass_ch == False:
                    chars1 = chars1 + string.ascii_letters
                    print('ok')
                if pass_up_lo == 'on':
                    chars1 = chars1 + string.ascii_uppercase + string.ascii_lowercase
                    print('uppercase and lowercase')
                if pass_no == 'on':
                    chars1 = chars1 + string.digits
                    print('numbers')
                if pass_ch == 'on':
                    chars1 = chars1 + string.punctuation
                    print('characters')

                res1 = ''.join(random.choice(chars1+leet) for x in range(length))
                res = ''.join(random.choice(chars1) for x in range(length))
                f_rest = ''.join(random.choice(res1+res) for x in range(length))

                # create session and store password result in session
                request.session['result'] = res1

                results = zxcvbn(res1)
                score = results['score']
                print(results)
                results['calc_time']
                cracktime = results['crack_times_display']



        else:
            del request.session['result']
        # pr = PasswordGenerator.objects.all().update(pass_result=res1)
        # pr_res = PasswordGenerator.objects.all()
        # pr.pass_result = res1
        # res_pr = pr.save()


        # pr1 = pr.pass_result
        # context_pr =  {'pass_result': res1}
        # print(pr)
        # pass_res = request.POST['pass_result']
        # form.pass_result = res1
        # print(form.pass_result+'hello')

    form = PasswordGeneratorForm()
    try:
        return render(request, 'pages/generate-password.html', {'form': form, 'score':score, 'cracktime':cracktime})
    except:
        return render(request, 'pages/generate-password.html', {'form': form})

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

                #Password Encryption with Salt#
                enc_password = pbkdf2_sha256.encrypt(login_password, rounds=10000, salt=bytes(32))
                user = request.user
                TempAccounts.objects.create(
                    temp_uname = login_username,
                    temp_pword = login_password,
                )
                NewAccountLogin.objects.create(
                    login_user = user,
                    login_target_url=login_target_url,
                    login_name=login_name,
                    login_username=login_username,
                    login_password=enc_password,
                    login_notes=login_notes,
                )
            if form.is_valid():
               return redirect('/accounts', messages.success(request, 'Account was successfully added.', 'alert-success'))
            else:
                return redirect('/accounts', messages.error(request, 'Account is not saved', 'alert-danger'))
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
    temp = TempAccounts.objects.get(id=login_id)
    print(temp.temp_pword)
    if request.POST:
        form = NewAccountLoginForm(request.POST, instance=login)
        init = form.save(commit=False)
        init.login_password = temp.temp_pword
        init.save()
        print(temp.temp_pword)
        if form.is_valid():
            init = form.save(commit=False)
            init.login_password = temp.temp_pword
            init.save()
            if form.save():
                return redirect('/', messages.success(request, 'Account was successfully updated.', 'alert-success'))
            else:
                return redirect('/', messages.error(request, 'Data is not saved', 'alert-danger'))
        else:
            return redirect('/', messages.error(request, 'Form is not valid', 'alert-danger'))
    else:
        form = NewAccountLoginForm(instance=login)
        return render(request, 'pages/login_edit.html', {'form':form}, {'temp':temp})

@login_required
def login_destroy(request, login_id):
    temp_ac = TempAccounts.objects.get(id=login_id)
    temp_ac.delete()
    login = NewAccountLogin.objects.get(id=login_id)
    login.delete()
    return redirect('/', messages.success(request, 'Account was successfully deleted.', 'alert-success'))

@login_required
def user_profile(request):
    userprofile = User.objects.all()
    context_up = {'userprofile': userprofile}
    return render(request, 'pages/user_profile.html', context_up)

@login_required
def user_edit(request):
    if request.method == 'POST':
        # instance = UserProfile.objects.get(id=login_id)
        form = UserProfileForm(request.POST, instance=request.user.userprofile)
        print(form)
        if request.method == 'POST':
            if form.is_valid():
                form.save()
                if form.save():
                    return redirect('/users/user_profile/', messages.success(request, 'Account was successfully updated.', 'alert-success'))
                else:
                    return redirect('/users/user_profile/', messages.error(request, 'Data is not saved', 'alert-danger'))
            else:
                return redirect('/users/user_profile/', messages.error(request, 'Form is invalid', 'alert-danger'))
    else:
        profile = request.user.userprofile
        form = UserProfileForm(instance=profile)
        return render(request, 'pages/user_profile_edit.html', {'form': form})

@login_required
def user_delete(request):
    current_user = request.user
    print(current_user)
    user_profile = UserProfile.objects.get(user=current_user)
    user_profile.delete()
    user = User.objects.get(username=current_user)
    user.delete()
    return redirect('/accounts/login', messages.success(request, 'Account was successfully deleted.', 'alert-success'))

@login_required
def user_stats(request):
    return render(request, 'pages/user_stats.html')

@login_required
def send_email(request, login_id):
    temp = TempAccounts.objects.get(id=login_id)
    if request.method == 'GET':
        form = SharedHavenForm()
    else:
        form = SharedHavenForm(request.POST)
        if form.is_valid():
            subject = form.cleaned_data['subject']
            # from_email = form.cleaned_data['from_email']
            from_email = form.cleaned_data['to_email']
            message = form.cleaned_data['message']
            to_email = [from_email, 'to_email']
            html_message = "Username: " + temp.temp_uname + '\n' + 'Password: ' + temp.temp_pword
            # try:
            send_mail(subject, message, from_email, to_email, fail_silently=False, html_message=html_message)
            return redirect('/sharedhaven', messages.success(request, 'Credential is shared', 'alert-success'))
            # except BadHeaderError:
            # return HttpResponse('Invalid header found.')
    return render(request ,"pages/share_credentials.html", {'form': form})


def pass_r_done(request):
    return redirect('/accounts/password_reset', messages.success(request, 'Email sent successfully!', 'alert-success'))

def pass_r_confirm(request):
    return redirect('/accounts/password_reset/done', messages.success(request, 'Email sent successfully!', 'alert-success'))