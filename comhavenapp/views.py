from django.contrib.auth.forms import UserCreationForm
from django.urls import reverse_lazy
from django.views import generic
from django.contrib.auth import login, authenticate
from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from comhavenapp.forms import RegistrationForm, UserProfileForm, PasswordGeneratorForm
from django.contrib import auth

from django.contrib.auth.decorators import login_required


from .models import NewAccountLogin, UserProfile, AccessListOfDevices, ExpressLoginsSites, Status, SecurityChallenges, PasswordGenerator, User_Stats, Tasks, PerformedTasks, WeakPasswords, Rewards, CompromisedPasswords, OldPasswords, DuplicatePasswords
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
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from email import encoders
from email.mime.base import MIMEBase

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
from django.db.models import Count
from django.template.loader import render_to_string, get_template
from django.core.mail import EmailMultiAlternatives
from django.utils.html import strip_tags

from django.conf import settings

# confirmation email imports
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import force_bytes, force_text
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from .tokens import account_activation_token
from django.http import HttpResponse


@login_required
def auto_login(request, login_id):
    new_login = NewAccountLogin.objects.filter(login_user=request.user)
    context_login = {'new_login': new_login}
    #get instance ID
    login = NewAccountLogin.objects.get(id=login_id)
    # sites = ExpressLoginsSites.objects.get(id=login_id)
    form = NewAccountLoginForm(request.POST, instance=login)

    if login:
        if login.login_name == 'Schoology':
            try:
                browser = webdriver.Chrome()
                browser.get(login.login_target_url)
                username = browser.find_element_by_id("edit-mail")
                username.send_keys(login.login_username)
                password = browser.find_element_by_id("edit-pass")
                password.send_keys(login.login_tp)
                signInButton = browser.find_element_by_id('edit-submit');
                signInButton.click()
            except:
                return redirect('/express-login', messages.error(request, 'Something is not right. Check your Internet Connection', 'alert-danger'))

        elif login.login_name == 'LMS':
            try:
                browser = webdriver.Chrome()
                browser.get(login.login_target_url)
                username = browser.find_element_by_name('username')
                username.send_keys(login.login_username)
                password = browser.find_element_by_name('password')
                password.send_keys(login.login_tp)
                signInButton = browser.find_element_by_id('loginbtn');
                signInButton.click()

            except:
                return redirect('/express-login', messages.error(request, 'Something is not right. Check your Internet Connection', 'alert-danger'))

        elif login.login_name == 'Netflix':
            try:
                browser = webdriver.Chrome()
                browser.get(login.login_target_url)
                username = browser.find_element_by_id('id_userLoginId')
                username.send_keys(login.login_username)
                password = browser.find_element_by_id('id_password')
                password.send_keys(login.login_tp)
                signInButton = browser.find_element_by_class_name('login-button')
                signInButton.click()

            except:
                return redirect('/express-login', messages.error(request, 'Something is not right. Check your Internet Connection','alert-danger'))

        elif login.login_name == 'Facebook':
            try:
                print("hello")
                browser = webdriver.Chrome()
                browser.get(login.login_target_url)
                print(login.login_target_url)
                username = browser.find_element_by_id('email')
                username.send_keys(login.login_username)
                password = browser.find_element_by_id('pass')
                password.send_keys(login.login_tp)
                signInButton = browser.find_element_by_id('loginbutton');
                signInButton.click()

            except:
                return redirect('/express-login', messages.error(request, 'Something is not right. Check your Internet Connection',
                                          'alert-danger'))

        elif login.login_name == 'UIS':
            try:
                browser = webdriver.Chrome()
                browser.get(login.login_target_url)
                username = browser.find_element_by_id('UserName')
                username.send_keys(login.login_username)
                password = browser.find_element_by_name('Password')
                password.send_keys(login.login_tp)
                signInButton = browser.find_element_by_id('');
                signInButton.click()

            except:
                return redirect('/express-login', messages.error(request, 'Something is not right. Check your Internet Connection',
                                               'alert-danger'))
        elif login.login_name == 'Spotify':
            try:
                browser = webdriver.Chrome()
                browser.get(login.login_target_url)
                username = browser.find_element_by_id('login-username')
                username.send_keys(login.login_username)
                password = browser.find_element_by_id('login-password')
                password.send_keys(login.login_tp)
                signInButton = browser.find_element_by_id('login-button');
                signInButton.click()

            except:
                return redirect('/express-login', messages.error(request, 'Something is not right. Check your Internet Connection',
                                               'alert-danger'))
        elif login.login_name == 'Twitter':
            try:
                browser = webdriver.Chrome()
                browser.get(login.login_target_url)
                username = browser.find_element_by_name('session[username_or_email]')
                username.send_keys(login.login_username)
                password = browser.find_element_by_name('session[password]')
                password.send_keys(login.login_tp)
                signInButton = browser.find_element_by_id('');
                signInButton.click()
            except:
                return redirect('/express-login', messages.error(request, 'Something is not right. Check your Internet Connection',
                                               'alert-danger'))
        elif login.login_name == 'GitHub':
            try:
                browser = webdriver.Chrome()
                browser.get(login.login_target_url)
                username = browser.find_element_by_id('login_field')
                username.send_keys(login.login_username)
                password = browser.find_element_by_id('password')
                password.send_keys(login.login_tp)
                signInButton = browser.find_element_by_name('commit');
                signInButton.click()
            except:
                return redirect('/express-login', messages.error(request, 'Something is not right. Check your Internet Connection',
                                               'alert-danger'))
        elif login.login_name == 'Instagram':
            try:
                browser = webdriver.Chrome()
                browser.get(login.login_target_url)
                username = browser.find_element_by_name('username')
                username.send_keys(login.login_username)
                password = browser.find_element_by_name('password')
                password.send_keys(login.login_tp)
                signInButton = browser.find_element_by_id('');
                signInButton.click()
            except:
                return redirect('/express-login', messages.error(request, 'Something is not right. Check your Internet Connection',
                                               'alert-danger'))
        elif login.login_name == 'Trello':
            try:
                browser = webdriver.Chrome()
                browser.get(login.login_target_url)
                username = browser.find_element_by_id('user')
                username.send_keys(login.login_username)
                password = browser.find_element_by_id('password')
                password.send_keys(login.login_tp)
                signInButton = browser.find_element_by_id('');
                signInButton.click()
            except:
                return redirect('/express-login',
                                messages.error(request, 'Something is not right. Check your Internet Connection',
                                               'alert-danger'))
        elif login.login_name == 'Edmodo':
            try:
                browser = webdriver.Chrome()
                browser.get(login.login_target_url)
                loginBtn = browser.find_element_by_id('qa-test-top-login-button')
                loginBtn.click()
                username = browser.find_element_by_id('un')
                username.send_keys(login.login_username)
                password = browser.find_element_by_id('pw')
                password.send_keys(login.login_tp)
                signInButton = browser.find_element_by_id('qa-test-lightbox-login');
                signInButton.click()
            except:
                return redirect('/express-login',
                                messages.error(request, 'Something is not right. Check your Internet Connection',
                                                'alert-danger'))
        # elif login.login_name == 'Gmail':
        #     try:
        #         browser = webdriver.Chrome()
        #         browser.get(login.login_target_url)
        #         username = browser.find_element_by_id('identifierId')
        #         username.send_keys(login.login_username)
        #         nextBtn = browser.find_element_by_id('identifierNext')
        #         nextBtn.click()
        #         password = WebDriverWait(browser, 10).until(
        #             EC.presence_of_element_located((By.ID, 'password')))
        #         password1 = browser.find_element_by_class_name('whsOnd')
        #         password1.send_keys(temp_ac.temp_pword)
        #         signInButton = browser.find_element_by_id('passwordNext');
        #         signInButton.click()
        #     except:
        #         return redirect('/express-login',
        #                         messages.error(request, 'Something is not right. Check your Internet Connection',
        #                                        'alert-danger'))

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
                # if request.user_agent.is_pc == True:
                #     path = os.getenv('LOCALAPPDATA')
                #     filename = os.path.join(path, r"AccessID\cpuinfo.bin")
                #     directory = os.path.dirname(filename)
                #     path_exist = directory
                #     form = AccessListOfDevices.objects.all()
                #     if os.path.exists(path_exist):
                #         login(request, user)
                #         return redirect('home')
                #     else:
                #
                #         # the application will send an email confirming that the user wants to register a new device
                #         user_email = User.objects.filter(username=username).values_list('email', flat=True).first()
                #         subject = 'Register a New Device'
                #         from_email = 'comhaven.test.mail@gmail.com'
                #         to_email = [from_email, user_email]
                #
                #         # Generate a random token
                #
                #         html_message = render_to_string('pages/register_device_email_template.html')
                #         plain_message = strip_tags(html_message)
                #         try:
                #             send_mail(subject, plain_message, from_email, to_email, fail_silently=False,
                #                       html_message=html_message)
                #             # return redirect('/sharedhaven',
                #             #                 messages.success(request, 'Credential is shared', 'alert-success'))
                #         except:
                #              print('failed')
                #
                #         return redirect('/accounts/login', messages.error(request, 'Cannot find access ID.' + "<br>" + 'Please check your email address.', 'alert-danger'))

                if request.user_agent.is_mobile == True:
                    login(request, user)
                    return redirect('home')
                elif request.user_agent.is_pc == True:
                    login(request, user)
                    return redirect('home')
        else:
            return redirect('/accounts/login', messages.error(request, 'username or password is incorrect.', 'alert-danger'))
    else:
        return redirect('/accounts/login')
def register(request):
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        username = request.POST['username']
        email  = request.POST['email']
        password = request.POST['password1']
        pass_length = len(password)
        print(pass_length)
        email_db = UserProfile.objects.all()
        print(email_db)
        print(email)

        for x in email_db:
            print(x)
            if email == x.email:
                return redirect('/accounts/register',
                                messages.error(request, 'Email has already taken.', 'alert-danger'))
            if username == str(x.user):
                return redirect('/accounts/register',
                                messages.error(request, 'Username has already taken.', 'alert-danger'))
            if int(pass_length) <= 7:
                print(True)
                return redirect('/accounts/register',
                            messages.error(request, 'Password must be at least 8 characters', 'alert-danger'))
        if form.is_valid():
            # FOR HEROKU TEST #
            if request.user_agent.is_pc == True:
                user = request.POST['username']
                directory = r"C:\Users\%user%\AppData\Local\AccessID"
                device_model = request.user_agent.device
                # device_platform = platform.system

                AccessListOfDevices.objects.create(
                    acl_user=user,
                    device_name='Android',
                    device_model='Android',
                    access_id_path=directory,
                    device_platform='Android'
                )
                User_Stats.objects.create(
                    user=user,
                    overall_points=0,
                    count=10
                )
                # email verification upon registration
                from_email = 'comhaven.test.mail@gmail.com'
                to_email = [from_email, email]

                user = form.save(commit=False)
                user.is_active = False
                user.save()
                current_site = get_current_site(request)
                subject = 'Activate your ComHaven Account'

                html_message = render_to_string(
                    'registration/activate_acc_email.html', {
                        'user': user,
                        'domain': current_site.domain,
                        'uid': urlsafe_base64_encode(force_bytes(user.pk)).decode(),
                        'token': account_activation_token.make_token(user)

                    }
                )
                plain_message = strip_tags(html_message)
                try:
                    send_mail(subject, plain_message, from_email, to_email, fail_silently=False,
                              html_message=html_message)
                    # return redirect('/sharedhaven',
                    #                 messages.success(request, 'Credential is shared', 'alert-success'))
                except:
                    print('failed')

                return redirect('/accounts/login',
                                messages.success(request, 'Account Verification Sent. Check your email.',
                                                 'alert-success'))
            # if request.user_agent.is_pc == True:
            #     filename = os.path.expandvars(r"C:")
            #     if os.path.exists(filename): # checks if access id already exists
            #         path = os.getenv('LOCALAPPDATA')
            #         filename = os.path.join(path, r"AccessID\cpuinfo.bin")
            #         directory = os.path.dirname(filename)
            #         path_exist = directory
            #         if os.path.exists(path_exist):
            #             # form.save()
            #             user = request.POST['username']
            #             User_Stats.objects.create(
            #                 user=user,
            #                 overall_points=0,
            #                 count = 10
            #             )
            #             # email verification upon registration
            #             from_email = 'comhaven.test.mail@gmail.com'
            #             to_email = [from_email, email]
            #
            #             user = form.save(commit=False)
            #             user.is_active = False
            #             user.save()
            #             current_site = get_current_site(request)
            #             subject = 'Activate your ComHaven Account'
            #
            #             html_message = render_to_string(
            #                 'registration/activate_acc_email.html', {
            #                     'user': user,
            #                     'domain': current_site.domain,
            #                     'uid': urlsafe_base64_encode(force_bytes(user.pk)).decode(),
            #                     'token': account_activation_token.make_token(user)
            #
            #                 }
            #             )
            #             plain_message = strip_tags(html_message)
            #             try:
            #                 send_mail(subject, plain_message, from_email, to_email, fail_silently=False,
            #                           html_message=html_message)
            #                 # return redirect('/sharedhaven',
            #                 #                 messages.success(request, 'Credential is shared', 'alert-success'))
            #             except:
            #                 print('failed')
            #
            #             return redirect('/accounts/login',
            #                     messages.success(request, 'Account Verification Sent. Check your email.', 'alert-success'))
            #         else:
            #             # email verification upon registration
            #             user_email = User.objects.filter(username=username).values_list('email', flat=True).first()
            #             from_email = 'comhaven.test.mail@gmail.com'
            #             to_email = [from_email, user_email]
            #
            #             user = form.save(commit=False)
            #             user.is_active = False
            #             user.save()
            #             current_site = get_current_site(request)
            #             subject = 'Activate your ComHaven Account'
            #
            #             html_message = render_to_string(
            #                 'registration/activate_acc_email.html',{
            #                  'user': user,
            #                  'domain': current_site.domain,
            #                  'uid': urlsafe_base64_encode(force_bytes(user.pk)).decode(),
            #                  'token': account_activation_token.make_token(user)
            #
            #                 }
            #             )
            #             plain_message = strip_tags(html_message)
            #             try:
            #                 send_mail(subject, plain_message, from_email, to_email, fail_silently=False,
            #                           html_message=html_message)
            #                 # return redirect('/sharedhaven',
            #                 #                 messages.success(request, 'Credential is shared', 'alert-success'))
            #             except:
            #                 print('failed')
            #
            #
            #             os.mkdir(directory)
            #             with open(filename, "w") as f:
            #                 info = cpuinfo.get_cpu_info()
            #                 CPUINFO = {'CPUINFO': info}
            #                 f.write(json.dumps(CPUINFO))
            #                 if request.method == 'POST':
            #                     user = request.POST['username']
            #                     device_model = request.user_agent.device
            #                     device_platform = platform.system()
            #                     device_name = os.name
            #                     print(device_model)
            #                     # f.save()
            #                     # form.save()
            #                     print("Success")
            #                     AccessListOfDevices.objects.create(
            #                         acl_user = user,
            #                         device_name = 'Windows-PC',
            #                         device_model=device_model,
            #                         access_id_path=directory,
            #                         device_platform = 'Windows 10'
            #                     )
            #                     User_Stats.objects.create(
            #                         user=user,
            #                         overall_points=0,
            #                         count = 10
            #                     )
            #                     return redirect('/accounts/login', messages.success(request, 'Account Verification Sent. Check your email.', 'alert-success'))
                # else:
                #     form.save()
                #     user = request.POST['username']
                #     directory = 'path'
                #     device_model = request.user_agent.device
                #     device_name = os.uname()
                #     device_platform = platform.system
                #     AccessListOfDevices.objects.create(
                #         acl_user=user,
                #         device_name = 'Windows-PC',
                #         device_model=device_model,
                #         access_id_path=directory,
                #         device_platform='Windows 10'
                #     )
                #     User_Stats.objects.create(
                #         user=user,
                #         overall_points=0,
                #         count = 10
                #     )
                #     return redirect('/accounts/login',
                #                     messages.success(request, 'Account created successfully.', 'alert-success'))
            elif request.user_agent.is_mobile == True:
                 form.save()
                 user = request.POST['username']
                 directory = r"C:\Users\jason\AppData\Local\AccessID"
                 device_model = request.user_agent.device
                 # device_platform = platform.system

                 AccessListOfDevices.objects.create(
                     acl_user=user,
                     device_name = 'Android',
                     device_model='Android',
                     access_id_path=directory,
                     device_platform='Android'
                 )
                 User_Stats.objects.create(
                     user=user,
                     overall_points=0,
                     count = 10,
                 )
                 return redirect('/accounts/login',messages.success(request, 'Account created successfully.', 'alert-success'))

            # else:
            #     user = request.POST['username']
            #     directory = 'path'
            #     device_name = os.uname()
            #     device_model = request.user_agent.device
            #     device_platform = platform.system()
            #     AccessListOfDevices.objects.create(
            #         acl_user=user,
            #         device_name = device_name,
            #         device_model=device_model,
            #         access_id_path=directory,
            #         device_platform=device_platform
            #     )
            #     User_Stats.objects.create(
            #         user=user,
            #         overall_points=0,
            #         count = 0
            #     )
            #     form.save()
            #     return redirect('/accounts/login', messages.success(request, 'Account created successfully.', 'alert-success'))
        else:
            return redirect('/accounts/register', messages.error(request, 'Registration Failed Form is Invalid.', 'alert-danger'))
    else:
        form = RegistrationForm()
    return render(request, 'registration/register.html', {'form': form})

# activate account
def activate(request, uidb64, token):
    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user is not None and account_activation_token.check_token(user, token):
        user.is_active = True
        user.save()
        login(request, user)
        # return redirect('home')
        return redirect('/accounts/login', messages.success(request, 'Account Activated successfully.', 'alert-success'))
    else:
        return HttpResponse('Activation link is invalid!')

# Page Views #
@login_required
def index(request):
    new_login = NewAccountLogin.objects.filter(login_user=request.user)

    sc_count = SecurityChallenges.objects.filter(user=request.user).count()
    context_login = {'new_login': new_login, 'sc_count':sc_count}
    user = request.user
    return render(request, 'pages/dashboard.html', context_login)

@login_required
def accounts(request):
    el_image = ExpressLoginsSites.objects.all()
    sample = NewAccountLogin.objects.values_list('login_name', flat=True)

    new_login = NewAccountLogin.objects.filter(login_user=request.user)
    sc_count = SecurityChallenges.objects.filter(user=request.user).count()

    s_icon = "fa fa-"
    print(s_icon)


    context_login = {'new_login': new_login, 's_icon': s_icon, 'sc_count':sc_count}
    return render(request, 'pages/home-accounts.html', context_login)

@login_required
def expresslogins(request):
    new_login = NewAccountLogin.objects.filter(login_user=request.user)
    sc_count = SecurityChallenges.objects.filter(user=request.user).count()
    context_login = {'new_login': new_login, 'sc_count':sc_count}
    return render(request, 'pages/express-logins.html', context_login)

@login_required
def accesscontrol(request):
    ac_list = AccessListOfDevices.objects.filter(acl_user=request.user)
    sc_count = SecurityChallenges.objects.filter(user=request.user).count()
    context_AC = {'ac_list': ac_list, 'sc_count':sc_count}
    return render(request, 'pages/access-control.html', context_AC)

@login_required
def securitychallenges(request):
    # create context for instances
    sc_count = SecurityChallenges.objects.filter(user=request.user).count()
    sc = SecurityChallenges.objects.filter(user=request.user)
    us = User_Stats.objects.filter(user=request.user)
    context_us_sc = {'sc': sc, 'us': us, 'sc_count': sc_count}

    ##########################OLD PASSWORDS ############################
    login_user = request.user
    login_date = NewAccountLogin.objects.filter(login_user=login_user)

    for date in login_date: # get the day format of the date inserted
        date_f = str(date.date_inserted) # get DATE_TIME
        # print(date_f)
        last_date = str(date_f[:10]) # get YY:MM:DD
        # print(last_date)
        l_date = str(last_date[-2:]) # get the DD
        # print(l_date)
        day = int(l_date) # int DD

        # get current date


        # if(day+10<25):
        #     print('ISSUE')


    return render(request, 'pages/security-challenges.html', context_us_sc)

@login_required
def sharedhaven(request):
    new_login = NewAccountLogin.objects.filter(login_user=request.user)
    sc_count = SecurityChallenges.objects.filter(user=request.user).count()
    context_login = {'new_login': new_login, 'sc_count': sc_count}
    return render(request, 'pages/sharedhaven.html', context_login)

def sharedhaven_token(request, uidb64, token):
    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user is not None and account_activation_token.check_token(user, token):
        new_login = NewAccountLogin.objects.filter(login_user=request.user)
        context_login = {'new_login': new_login}
        return render(request, 'pages/home-accounts.html', context_login)
    else:
        return HttpResponse('Activation link is invalid!')

@login_required
def test_password(request):
    if request.POST:
        form = PasswordGeneratorForm(request.POST)
        if request.method == "POST":
            password = request.POST['pass_result']
            print(password)
            res = zxcvbn(password)
            score = res['score']
            # print(res)
            cracktime = res['crack_times_display']
            guesses = res['guesses']
            feedback = res['feedback']
            # print(feedback)

            if score == 0:
                strength = "Very Weak"
            elif score == 1:
                strength = "Weak"
            elif score == 2:
                strength = "Medium"
            elif score == 3:
                strength = "Strong"
            elif score == 4:
                strength = "Very Strong"
    form = PasswordGeneratorForm(request.POST)
    try:
        return render(request, 'pages/generate-password.html',
                      {'form': form, 'score': score, 'cracktime': cracktime, 'strength': strength, 'guesses': guesses,
                       'suggestions': suggestions})
    except:
        return render(request, 'pages/generate-password.html', {'form': form})


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

                #store generated passwords in the database
                user = request.user
                pwds = PasswordGenerator.objects.create(
                    user = user,
                    identifier = 1,
                    pass_result = res1
                )

                # export generated passwords in the csv
                # header = ['passwords']
                # with open('password.csv', 'wb') as out:
                #     writer = csv.DictWriter(out, header, extrasaction='ignore')
                #     writer.writeheader()
                #     for line in reader:
                #         writer.writerow(line)

                # password evaluation based on generated passwords
                results = zxcvbn(res1)
                score = results['score']
                # print(results)
                cracktime = results['crack_times_display']
                guesses = results['guesses']
                feedback = results['feedback']
                suggestions = feedback['suggestions']
                print(feedback)
                if score == 0:
                    strength = "Very Weak"
                elif score == 1:
                    strength = "Weak"
                elif score == 2:
                    strength = "Medium"
                elif score == 3:
                    strength = "Strong"
                elif score == 4:
                    strength = "Very Strong"

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

    sc_count = SecurityChallenges.objects.filter(user=request.user).count()

    form = PasswordGeneratorForm()
    try:
        return render(request, 'pages/generate-password.html', {'form': form, 'score':score, 'cracktime':cracktime, 'strength':strength, 'guesses':guesses, 'suggestions':suggestions, 'sc_count': sc_count})
    except:
        return render(request, 'pages/generate-password.html', {'form': form, 'sc_count': sc_count })

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
                count = NewAccountLogin.objects.filter(login_user=request.user).count()
                user_count = User_Stats.objects.get(user=request.user)
                us_count = int(user_count.count)

                count = count + 1
                print(count)
                if count <= us_count:
                    #Password Encryption with Salt#
                    enc_password = pbkdf2_sha256.encrypt(login_password, rounds=10000, salt=bytes(32))
                    user = request.user
                    NewAccountLogin.objects.create(
                        login_user = user,
                        login_target_url=login_target_url,
                        login_name=login_name,
                        login_username=login_username,
                        login_password=enc_password,
                        login_tp = login_password,
                        login_notes=login_notes,
                    )


                    # check if the account of the user has an issue
                    user = request.user
                    sc = SecurityChallenges.objects.filter(user=request.user)

                    ##################### DUPLICATE PASSWORD ############################
                    # check for the duplication of password
                    dups = NewAccountLogin.objects.values('login_tp').annotate(
                        dup_pword_count=Count('login_tp')).filter(dup_pword_count__gt=1, login_user=request.user)
                    cnt_dups = dups.count()

                    # display the id's of duplicate passwords
                    dups_record = NewAccountLogin.objects.filter(login_tp__in=[item['login_tp'] for item in dups])
                    dups_id = [item.id for item in dups_record]

                    # filter the id of duplicate passwords
                    record = NewAccountLogin.objects.filter(id__in=dups_id)
                    # cnt = DuplicatePasswords.objects.filter(user=request.user).count()

                    # store the accounts with duplicate
                    if cnt_dups > 0 and not DuplicatePasswords.objects.exists():
                        for id in record:
                            stored_dup_acc = DuplicatePasswords.objects.create(
                                user=user,
                                account_id=id.id
                            )
                            nl = NewAccountLogin.objects.filter(login_user=user).get(id=id.id)
                            nl.issue_flag = True
                            nl.save()
                    else:
                        for id in dups_record:
                            nl = NewAccountLogin.objects.filter(login_user=user).get(id=id.id)
                            nl.issue_flag = True
                            nl.save()

                    ############################ WEAK PASSWORD ######################################
                    try:
                        tp_init = NewAccountLogin.objects.filter(login_user=request.user)

                        # evaluates the password in the new login model
                        for t in tp_init:
                            pass_results = zxcvbn(t.login_tp)
                        res = pass_results['score']
                        count_wp = WeakPasswords.objects.filter(user=request.user).count()
                        if res == 0 or res == 1:
                            try:
                                if count_wp == 0:
                                    user = request.user
                                    WeakPasswords.objects.create(
                                        user=user,
                                        login_account=t.login_name,
                                        login_password=t.login_tp,
                                        login_score='0 or 1',
                                        login_strength='Weak'
                                    )
                                elif not count_wp == 0:
                                    user = request.user
                                    WeakPasswords.objects.create(
                                        user=user,
                                        login_account=t.login_name,
                                        login_password=t.login_tp,
                                        login_score='0 or 1',
                                        login_strength='Weak'
                                    )
                            except:
                                print(t.id)
                                x = 'Weak Password'
                    except:
                        print('itrt')








                    # Initialize object values for security challenge
                    user = request.user
                    tasks = Tasks.objects.get(tasks='Duplicate Passwords')
                    status = Status.objects.get(status='Unfinished')
                    status2 = Status.objects.get(status='Completed')

                    count_sc = SecurityChallenges.objects.filter(user=request.user).count()
                    try:
                        if dups_id and count_sc == 0:
                            SecurityChallenges.objects.create(
                                user=user,
                                tasks=tasks,
                                points=4,
                                date_completed='',
                                date_initiated='',
                                status=status
                            )
                            update_status = NewAccountLogin.objects.filter(login_user=request.user).all()
                            for x in update_status:
                                x.issue_flag=True
                                x.save()
                                print("dadada")
                        elif dups_id == record and not count_sc == 0:
                            SecurityChallenges.objects.create(
                                user=user,
                                tasks=tasks,
                                points=4,
                                date_completed='',
                                date_initiated='',
                                status=status
                            )
                            nl_acc = NewAccountLogin.objects.filter(login_user=user).all()
                            for x in nl_acc:
                                x.issue_flag = True
                                x.save()
                        elif not dups and NewAccountLogin.objects.get(changed_flag=True):
                            update = SecurityChallenges.objects.get(status=status)
                            update.status = status2
                            update.save()
                            update_status = NewAccountLogin.objects.get(changed_flag=False)
                            update_status.changed_flag = False
                            update_status.save()
                    except:
                        print('i try')




                    if form.is_valid():
                       return redirect('/accounts', messages.success(request, 'Account was successfully added.', 'alert-success'))
                    else:
                        return redirect('/accounts', messages.error(request, 'Account is not saved', 'alert-danger'))
                else:
                    return redirect('/accounts', messages.error(request, 'You have reach the maximum number of accounts for free user! Consider Redeeming a Reward.', 'alert-danger'))
    else:
        form = NewAccountLoginForm()
        sc_count = SecurityChallenges.objects.filter(user=request.user).count()
        return render(request, 'pages/new_login.html', {'form':form, 'sc_count': sc_count})

@login_required
def login_edit(request, login_id):
    login = NewAccountLogin.objects.get(id=login_id)
    login_tp = NewAccountLogin.objects.filter(login_user = request.user)
    form = NewAccountLoginForm(request.POST)
    if request.method == 'POST':
        if form.is_valid():
            # update account in the database
            issue_flag = True
            update=True
            temp_pass = request.POST['login_password3']
            login_url = request.POST['login_target_url']
            login_name = request.POST['login_name']
            login_username = request.POST['login_username']
            login_notes = request.POST['login_notes']
            enc_password = pbkdf2_sha256.encrypt(temp_pass, rounds=10000, salt=bytes(32))
            user = request.user
            init = NewAccountLogin.objects.get(id=login_id)
            init.login_user = user
            init.login_name = login_name
            init.login_username = login_username
            init.login_notes = login_notes
            init.login_target_url = login_url
            init.login_password = enc_password
            init.login_tp = temp_pass
            print(init.login_tp)
            init.changed_flag=update
            init.issue_flag = False
            init.save()
            flag = NewAccountLogin.objects.filter(login_user=request.user)
            for x in flag:
                x.issue_flag = False
                x.save()
            # update the secret model
            ch_flag = True






            # check if issue has been solved during the update of accounts
            # verify if that there is no duplication issue raised
            # get passwords with duplication
            dups = NewAccountLogin.objects.values('login_tp').annotate(dup_pword_count=Count('login_tp')).filter(
                dup_pword_count__gt=1, login_user=request.user)
            cnt_dup = dups.count
            # get the duplication of passwords instance
            dup_acc = DuplicatePasswords.objects.filter(user = request.user).all()

            # get all of the account instance in New Account login
            nl_acc = NewAccountLogin.objects.filter(login_user=user).all()

            for d in nl_acc:
                if d.issue_flag == True and d.changed_flag == True and not dups:
                    d.issue_flag = False
                    d.save()
                    print('Problem Solved!!!')
                    dp = DuplicatePasswords.objects.filter(user=request.user).delete()
                    cnt_dp = DuplicatePasswords.objects.filter(user=request.user).count()
                    tasks = Tasks.objects.get(tasks='Duplicate Passwords')
                    status = Status.objects.get(status='Unfinished')
                    status2 = Status.objects.get(status='Completed')
                    try:
                        if cnt_dp == 0:
                            update_score = User_Stats.objects.get(user=request.user)
                            update_score.overall_points = int(update_score.overall_points) + 4
                            update_score.save()
                            sc_status = SecurityChallenges.objects.get(user=request.user)
                            sc_status.status = status2
                            sc_status.save()
                            break
                    except:
                        print('no challenge yet')

            return redirect('/', messages.success(request, 'Account was successfully updated.', 'alert-success'))
        else:
            return redirect('/', messages.error(request, 'Form is not valid', 'alert-danger'))

    form = NewAccountLoginForm(instance=login)
    sc_count = SecurityChallenges.objects.filter(user=request.user).count()
    return render(request, 'pages/login_edit.html', {'form':form, 'login_tp':login_tp, 'login':login, 'sc_count': sc_count })

@login_required
def login_destroy(request, login_id):
    login = NewAccountLogin.objects.get(id=login_id)
    login.delete()
    # sc = SecurityChallenges.objects.get(user=request.user)
    # sc.delete()
    sc_count = SecurityChallenges.objects.filter(user=request.user).count()
    context_temp = {'login':login, 'sc_count': sc_count }
    # weak_pass = WeakPasswords.objects.filter(user=request.user).get(id=login_id)
    # weak_pass.delete()
    # print(weak_pass)
    #
    # old_pass = OldPasswords.objects.filter(user=request.user).get(id=login_id)
    # old_pass.delete()
    # print(old_pass)
    #
    # com_pass = CompromisedPasswords.objects.filter(user=request.user).get(id=login_id)
    # com_pass.delete()
    # print(com_pass)

    return redirect('/', messages.success(request, 'Account was successfully deleted.', 'alert-success'), context_temp)

@login_required
def user_profile(request):
    userprofile = User.objects.filter(username=request.user)
    overall_points = User_Stats.objects.filter(user=request.user)
    rewards = Rewards.objects.all()
    sc_count = SecurityChallenges.objects.filter(user=request.user).count()
    context_up = {'userprofile': userprofile, 'overall_points':overall_points, 'rewards':rewards, 'sc_count': sc_count}
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
        sc_count = SecurityChallenges.objects.filter(user=request.user).count()
        form = UserProfileForm(instance=profile)
        return render(request, 'pages/user_profile_edit.html', {'form': form, 'sc_count': sc_count })

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

    # CHECKING FOR DUPLICATE PASSWORDS
    # get NewAccountLogin Model instance
    tp = NewAccountLogin.objects.values_list('login_tp', flat=True)
    context_dups = {'tp': tp}

    # get passwords with duplication
    dups = NewAccountLogin.objects.values('login_tp').annotate(dup_pword_count=Count('login_tp')).filter(dup_pword_count__gt=1, login_user = request.user)
    print(dups)
    # display the id's of duplicate passwords
    dups_record = NewAccountLogin.objects.filter(login_tp__in=[item['login_tp'] for item in dups], login_user=request.user)
    dups_id = [item.id for item in dups_record]
    print(dups_record)

    # get Weak Password instance
    wp = WeakPasswords.objects.filter(user=request.user)
    print(wp)

    # count the number of weak passwords
    count_wp = WeakPasswords.objects.filter(user=request.user).count()
    print(count_wp)

    # count the number of compromised passwords
    count_cp = CompromisedPasswords.objects.filter(user=request.user).count()
    print(count_cp)

    # count the number of old passwords
    count_op = OldPasswords.objects.filter(user=request.user).count()
    print(count_op)


    # login_id = NewAccountLogin.objects.values_list('id', flat=True)



    duplicate_account = NewAccountLogin.objects.filter(id__in = dups_id, login_user= request.user).all()
    da_count = duplicate_account.count()
    print(da_count)
    # duplicate_id = NewAccountLogin.objects.filter(id__in=dups_id).values_list('id', flat=True)
    # duplicate_password = NewAccountLogin.objects.filter(id__in = dups_id).values_list('login_password', flat=True)




    # CHECKING FOR COMPROMISED PASSWORDS
    # archive the generated passwords and used passwords
    # checked if used again then trigger the compromise password issue

    sc_count = SecurityChallenges.objects.filter(user=request.user).count()


    context_dups = {'duplicate_account': duplicate_account, 'dups':dups, 'wp':wp, 'count_wp':count_wp, 'count_cp':count_cp, 'count_op':count_op, 'da_count':da_count, 'sc_count':sc_count}
    return render(request, 'pages/user_stats.html', context_dups)



@login_required
def send_email(request, login_id):
    temp = NewAccountLogin.objects.filter(id=login_id).all()
    if request.method == 'GET':
        form = SharedHavenForm()
    else:
        form = SharedHavenForm(request.POST)
        if form.is_valid():
            email = request.POST['to_email']
            subject = request.POST['subject']
            # send credentials
            from_email = 'comhaven.test.mail@gmail.com'
            to_email = [from_email, email]
            user = request.user
            current_site = get_current_site(request)
            # subject = 'Access Sharedhaven'

            html_message = render_to_string(
                'pages/share_credentials_template.html', {
                    'user': user,
                    'domain': current_site.domain,
                    'uid': urlsafe_base64_encode(force_bytes(user.pk)).decode(),
                    'token': account_activation_token.make_token(user)

                }
            )
            plain_message = strip_tags(html_message)
            try:
                send_mail(subject, plain_message, from_email, to_email, fail_silently=False,
                          html_message=html_message)
                return redirect('/sharedhaven',
                                messages.success(request, 'Credential is shared', 'alert-success'))
            except:
                print('failed')



            # subject = form.cleaned_data['subject']
            # # from_email = form.cleaned_data['from_email']
            # from_email = form.cleaned_data['to_email']
            # message = form.cleaned_data['message']
            # to_email = [from_email, 'to_email']
            #
            # html = render(request, "pages/html_email.html")
            #
            # # create txt file attachment to email
            #
            # # url = 'http://127.0.0.1:8000/logins/edit/7/'
            # # token = RequestToken.objects.create_token(scope="foo")
            # # html_message = "Username: " + temp.temp_uname + '\n' + 'Password: ' + temp.temp_pword
            # html_message = render_to_string('pages/html_email.html', {'temp': temp})
            # plain_message = strip_tags(html_message)
            #
            #
            # try:
            #     send_mail(subject, plain_message, from_email, to_email, fail_silently=False, html_message=html_message)
            #     return redirect('/sharedhaven', messages.success(request, 'Credential is shared', 'alert-success'))
            # except:
            #     return redirect('/sharedhaven', messages.error(request, 'Something is not right. Check your Internet Connection', 'alert-danger'))
    sc_count = SecurityChallenges.objects.filter(user=request.user).count()
    return render(request ,"pages/share_credentials.html", {'form': form, 'temp':temp, 'sc_count': sc_count })

def pass_r_done(request):
    return redirect('/accounts/password_reset', messages.success(request, 'Email sent successfully!', 'alert-success'))

def pass_r_confirm(request):
    return redirect('/accounts/password_reset/done', messages.success(request, 'Email sent successfully!', 'alert-success'))

def password_reset(request):

    form = PasswordResetForm(request.POST)
    if form.is_valid():
        domain = 'comhaven.herokuapp.com'
        form.save(domain_override=domain, email_template_name='registration/password_reset_email.html')
        return redirect('/accounts/password_reset',
                        messages.success(request, 'Email sent successfully!', 'alert-success'))
    return render(request, 'registration/password_reset_form.html', {'form': form})

def redeem_rewards(request):
    userprofile = UserProfile.objects.filter(user=request.user)
    rewards = Rewards.objects.all()
    user_stats = User_Stats.objects.filter(user=request.user).values_list('overall_points', flat=True).first()
    print(user_stats)
    overall_points = User_Stats.objects.filter(user=request.user)
    rewards = Rewards.objects.all()
    sc_count = SecurityChallenges.objects.filter(user=request.user).count()
    context_up = {'userprofile': userprofile, 'overall_points': overall_points, 'rewards': rewards, 'sc_count': sc_count }

    # get the number of account logins of the user
    nl_count = NewAccountLogin.objects.filter(login_user=request.user).count()
    # get the current count in the user stats model, user overall points
    userpt = User_Stats.objects.get(user=request.user)
    userpt.overall_points = int(userpt.overall_points)

    print(userpt.overall_points)
    # check if the points of the user reach the required points for rewards
    p1 = 25
    p2 = 50
    p3 = 75
    p4 = 100
    if(userpt.overall_points >= 25):
        userpt.count = userpt.count + 15
        userpt.overall_points = userpt.overall_points - 25
        userpt.save()
        # return redirect('/redeem_rewards',
        #                  messages.success(request, 'Rewards Redeemed Successfully!', 'alert-success'))
    elif (userpt.overall_points >= 50):
        userpt.count = userpt.count + 20
        userpt.overall_points = userpt.overall_points - 50
        userpt.save()
    elif (userpt.overall_points >= 75):
        userpt.count = userpt.count + 25
        userpt.overall_points = userpt.overall_points - 75
        userpt.save()
    elif (userpt.overall_points >= 100):
        userpt.count = userpt.count + 30
        userpt.overall_points = userpt.overall_points - 100
        userpt.save()
    # else:
    #     return redirect('/redeem_rewards',
    #                          messages.error(request, 'You don not have enough points to redeem a reward.', 'alert-danger'))

    # if(userpt.overall_points == 25):
    #     return redirect('users/user_profile/',
    #                 messages.success(request, 'Rewards Redeemed Successfully!', 'alert-success'))
    # else:
    #     return redirect('users/user_profile/',
    #                     messages.error(request, 'You don not have enough points to redeem a reward.', 'alert-danger'))

    return render(request, 'pages/user_profile.html', context_up)

def register_device(request):
    try:
        path = os.getenv('LOCALAPPDATA')
        filename = os.path.join(path, r"AccessID\cpuinfo.bin")
        directory = os.path.dirname(filename)
        os.mkdir(directory)
        with open(filename, "w") as f:
            info = cpuinfo.get_cpu_info()
            CPUINFO = {'CPUINFO': info}
        f.write(json.dumps(CPUINFO))
    except:
        print('exist')
    return render(request, 'pages/register_device.html')



