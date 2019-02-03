from django.contrib.auth.forms import UserCreationForm
from django.urls import reverse_lazy
from django.views import generic
from django.contrib.auth import login, authenticate
from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from comhavenapp.forms import RegistrationForm, UserProfileForm, PasswordGeneratorForm, PasswordResetForm
from django.contrib import auth

from django.contrib.auth.decorators import login_required

from .models import NewAccountLogin, UserProfile, TempAccounts, AccessListOfDevices, ExpressLoginsSites, Status, SecurityChallenges, PasswordGenerator, User_Stats, Tasks, PerformedTasks, WeakPasswords, Rewards, CompromisedPasswords, OldPasswords, DuplicatePasswords
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
        if login.login_name == 'Schoology':

            browser = webdriver.Chrome()
            browser.get(login.login_target_url)
            username = browser.find_element_by_id("edit-mail")
            username.send_keys(login.login_username)
            password = browser.find_element_by_id("edit-pass")
            password.send_keys(temp_ac.temp_pword)
            signInButton = browser.find_element_by_id('edit-submit');
            signInButton.click()

            # except:
            #     return redirect('/express-login', messages.error(request, 'Something is not right. Check your Internet Connection', 'alert-danger'))


        elif login.login_name == 'LMS':
            try:
                browser = webdriver.Chrome()
                browser.get(login.login_target_url)
                username = browser.find_element_by_name('username')
                username.send_keys(login.login_username)
                password = browser.find_element_by_name('password')
                password.send_keys(temp_ac.temp_pword)
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
                password.send_keys(temp_ac.temp_pword)
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
                password.send_keys(temp_ac.temp_pword)
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
                password.send_keys(temp_ac.temp_pword)
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
                password.send_keys(temp_ac.temp_pword)
                signInButton = browser.find_element_by_id('');
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
                password.send_keys(temp_ac.temp_pword)
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
                password.send_keys(temp_ac.temp_pword)
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
                password.send_keys(temp_ac.temp_pword)
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
                password.send_keys(temp_ac.temp_pword)
                signInButton = browser.find_element_by_id('');
                signInButton.click()
            except:
                return redirect('/express-login',
                                messages.error(request, 'Something is not right. Check your Internet Connection',
                                               'alert-danger'))
        elif login.login_name == 'Edmodo':

            browser = webdriver.Chrome()
            browser.get(login.login_target_url)
            loginBtn = browser.find_element_by_id('qa-test-top-login-button')
            loginBtn.click()
            username = browser.find_element_by_id('un')
            username.send_keys(login.login_username)
            password = browser.find_element_by_id('pw')
            password.send_keys(temp_ac.temp_pword)
            signInButton = browser.find_element_by_id('qa-test-lightbox-login');
            signInButton.click()

                # return redirect('/express-login',
                #                 messages.error(request, 'Something is not right. Check your Internet Connection',
                #                                'alert-danger'))
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
            print(user)
            if user.is_active:
                if request.user_agent.is_pc == True:
                    # path = os.environ.get('LOCALAPPDATA')
                    # filename = os.path.join(path, r"AccessID\cpuinfo.bin")
                    # directory = os.path.dirname(filename)
                    # path_exist = directory
                    # form = AccessListOfDevices.objects.all()
                    # if os.path.exists(path_exist):
                    #     login(request, user)
                    #     return redirect('home')
                    # else:
                    #     return redirect('/accounts/login', messages.error(request, 'Cannot find access ID', 'alert-danger'))
                    login(request,user)
                    return redirect('home')
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
        if form.is_valid():
            if request.user_agent.is_pc == True:
                filename = os.path.expandvars(r"C:")
                if os.path.exists(filename):
                    path = os.environ('LOCALAPPDATA')
                    filename = os.path.join(path, r"AccessID\cpuinfo.bin")
                    directory = os.path.dirname(filename)
                    path_exist = directory
                    if os.path.exists(path_exist):
                        print("file exist")
                        form.save()
                        user = request.POST['username']
                        User_Stats.objects.create(
                            user=user,
                            overall_points=0,
                        )
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
                                form.save()
                                print("Success")
                                AccessListOfDevices.objects.create(
                                    acl_user = user,
                                    device_model=device_model,
                                    access_id_path=directory,
                                    device_platform = device_platform
                                )
                                User_Stats.objects.create(
                                    user=user,
                                    overall_points=0,
                                )
                                return redirect('/accounts/login', messages.success(request, 'Account created successfully.', 'alert-success'))
                else:
                    form.save()
                    user = request.POST['username']
                    directory = 'path'
                    device_model = request.user_agent.device
                    device_platform = platform.system()
                    AccessListOfDevices.objects.create(
                        acl_user=user,
                        device_model=device_model,
                        access_id_path=directory,
                        device_platform=device_platform
                    )
                    User_Stats.objects.create(
                        user=user,
                        overall_points=0,
                    )
                    return redirect('/accounts/login',
                                    messages.success(request, 'Account created successfully.', 'alert-success'))
            elif request.user_agent.is_mobile == True:
                 form.save()
                 user = request.POST['username']
                 directory = 'path'
                 device_model = request.user_agent.device
                 device_platform = platform.system()
                 AccessListOfDevices.objects.create(
                     acl_user=user,
                     device_model=device_model,
                     access_id_path=directory,
                     device_platform=device_platform
                 )
                 User_Stats.objects.create(
                     user=user,
                     overall_points=0,
                 )
                 return redirect('/accounts/login',messages.success(request, 'Account created successfully.', 'alert-success'))

            else:
                user = request.POST['username']
                directory = 'path'
                device_model = request.user_agent.device
                device_platform = platform.system()
                AccessListOfDevices.objects.create(
                    acl_user=user,
                    device_model=device_model,
                    access_id_path=directory,
                    device_platform=device_platform
                )
                User_Stats.objects.create(
                    user=user,
                    overall_points=0,
                )
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
    user = request.user
    return render(request, 'pages/dashboard.html', context_login)

@login_required
def accounts(request):
    el_image = ExpressLoginsSites.objects.all()
    new_login = NewAccountLogin.objects.filter(login_user=request.user)


    s_icon = "fa fa-"


    context_login = {'new_login': new_login, 's_icon': s_icon}
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
    #get user instance
    user = request.user
    #get Security challenge model instance
    sc = SecurityChallenges.objects.filter(user=request.user)
    dups = TempAccounts.objects.values('temp_pword').annotate(dup_pword_count=Count('temp_pword')).filter(dup_pword_count__gt=1)

    cnt_dups = dups.count()

    # display the id's of duplicate passwords
    dups_record = TempAccounts.objects.filter(temp_pword__in=[item['temp_pword'] for item in dups])
    dups_id = [item.id for item in dups_record]

    record = TempAccounts.objects.filter(id__in=dups_id)
    print(record)
    cnt = DuplicatePasswords.objects.filter(user=request.user).count()


    # store the accounts with duplicate

    if cnt_dups > 0 and not DuplicatePasswords.objects.exists():
        for id in record:
            stored_dup_acc = DuplicatePasswords.objects.create(
                user = user,
                account_id = id.id
            )
            nl = NewAccountLogin.objects.filter(login_user=user).get(id=id.id)
            nl.issue_flag = True
            nl.save()


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
                points = 4,
                date_completed='',
                date_initiated='',
                status=status
            )
        elif dups_id == record and not count_sc == 0:
            SecurityChallenges.objects.create(
                user=user,
                tasks=tasks,
                points = 4,
                date_completed='',
                date_initiated='',
                status=status
            )
        elif not dups and NewAccountLogin.objects.get(updated=True):
            update = SecurityChallenges.objects.get(status=status)
            update.status = status2
            update.save()
            update_status = NewAccountLogin.objects.get(updated=True)
            update_status.updated = False
            update_status.save()
    except:
        print('i try')
    #get User Stats instance
    us = User_Stats.objects.filter(user=request.user)



    # get instance of accounts
    acc_init = NewAccountLogin.objects.values_list('id', flat=True)
    temp_init = TempAccounts.objects.filter(user=request.user)
    print(temp_init)

    for t in temp_init:
        pass_results = zxcvbn(t.temp_pword)
        res = pass_results['score']
        count_wp = WeakPasswords.objects.filter(user=request.user).count()
        if res == 0 or res == 1:
            try:
                if count_wp == 0:
                    user = request.user
                    WeakPasswords.objects.create(
                        user=user,
                        login_account= t.temp_uname,
                        login_password= t.temp_pword,
                        login_score='0 or 1',
                        login_strength='Weak'
                    )
                elif not count_wp == 0:
                    user = request.user
                    WeakPasswords.objects.create(
                        user = user,
                        login_account = t.temp_name,
                        login_password = t.temp_pword,
                        login_score = '0 or 1',
                        login_strength= 'Weak'
                    )
            except:
                print(t.id)
                x = 'Weak Password'



    # create context for instances
    context_us_sc = {'sc': sc, 'us': us}

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
                cracktime = results['crack_times_display']
                guesses = results['guesses']
                feedback = results['feedback']
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

    form = PasswordGeneratorForm()
    try:
        return render(request, 'pages/generate-password.html', {'form': form, 'score':score, 'cracktime':cracktime, 'strength':strength, 'guesses':guesses, 'feedback':feedback})
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
                count = NewAccountLogin.objects.filter(login_user=request.user).count()
                if count <= 9:
                    #Password Encryption with Salt#
                    enc_password = pbkdf2_sha256.encrypt(login_password, rounds=10000, salt=bytes(32))
                    user = request.user
                    TempAccounts.objects.create(
                        user = user,
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
                    return redirect('/accounts', messages.error(request, 'You have reach the maximum number of accounts for free user! Consider Redeeming a Reward.', 'alert-danger'))
    else:
        form = NewAccountLoginForm()
        return render(request, 'pages/new_login.html', {'form':form})

@login_required
def login_edit(request, login_id):
    login = NewAccountLogin.objects.get(id=login_id)
    temp = TempAccounts.objects.filter(id=login_id)
    temp_pword = TempAccounts.objects.values_list('temp_pword').get(id=login_id)
    form = NewAccountLoginForm(request.POST)
    if request.method == 'POST':
        if form.is_valid():
            #get POST data
            # temp_login_name = request.POST['login_name']
            # temp_login_username = request.POST['login_username']
            # temp_login_url = request.POST['login_target_url']
            # temp_pass = request.POST['login_password3']
            # temp_notes = request.POST['login_notes']
            # updated = True
            # init = NewAccountLogin.objects.get(id=login_id)
            # init.login_password = temp_pass
            # init.login_name = temp_login_name
            # init.login_target_url = temp_login_url
            # init.login_username = temp_login_username
            # init.login_notes = temp_notes
            # init.updated = updated
            # init.save()
            # temp_init = TempAccounts.objects.get(id=login_id)
            # temp_init.temp_pword = temp_pass
            # temp_init.save()

            # get accounts with duplication

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
            init.changed_flag=update
            init.save()
            # update the secret model
            ch_flag = True
            init2 = TempAccounts.objects.get(id=login_id)
            init2.user = user
            init2.temp_pword = temp_pass
            init2.save()

            # check if issue has been solved during the update of accounts
            # verify if that there is no duplication issue raised
            # get passwords with duplication
            dups = TempAccounts.objects.values('temp_pword').annotate(dup_pword_count=Count('temp_pword')).filter(
                dup_pword_count__gt=1)
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






            # # display the id's of duplicate passwords
            # dups_record = TempAccounts.objects.filter(temp_pword__in=[item['temp_pword'] for item in dups])
            # dups_id = [item.id for item in dups_record]


            return redirect('/', messages.success(request, 'Account was successfully updated.', 'alert-success'))
        else:
            return redirect('/', messages.error(request, 'Form is not valid', 'alert-danger'))

    form = NewAccountLoginForm(instance=login)
    return render(request, 'pages/login_edit.html', {'form':form, 'temp':temp})

@login_required
def login_destroy(request, login_id):
    login = NewAccountLogin.objects.get(id=login_id).all()
    login.delete()
    temp = TempAccounts.objects.filter(id=login_id).all()
    temp.delete()
    context_temp = { 'temp': temp, 'login':login}
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
    context_up = {'userprofile': userprofile, 'overall_points':overall_points, 'rewards':rewards}
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

    # CHECKING FOR DUPLICATE PASSWORDS
    # get TempAccounts Model instance
    temp = TempAccounts.objects.values_list('temp_pword', flat=True)
    print(temp)
    context_dups = {'temp': temp}

    # get passwords with duplication
    dups = TempAccounts.objects.values('temp_pword').annotate(dup_pword_count=Count('temp_pword')).filter(dup_pword_count__gt=1)
    print(dups)
    # display the id's of duplicate passwords
    dups_record = TempAccounts.objects.filter(temp_pword__in=[item['temp_pword'] for item in dups])
    dups_id = [item.id for item in dups_record]

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

    temp_id = TempAccounts.objects.values_list('id', flat=True)
    login_id = NewAccountLogin.objects.values_list('id', flat=True)



    duplicate_account = NewAccountLogin.objects.filter(id__in = dups_id).all()
    duplicate_password = TempAccounts.objects.filter(id__in = dups_id).all()
    # duplicate_id = NewAccountLogin.objects.filter(id__in=dups_id).values_list('id', flat=True)
    # duplicate_password = NewAccountLogin.objects.filter(id__in = dups_id).values_list('login_password', flat=True)




    # CHECKING FOR COMPROMISED PASSWORDS
    # archive the generated passwords and used passwords
    # checked if used again then trigger the compromise password issue


    context_dups = {'duplicate_account': duplicate_account, 'dups':dups, 'duplicate_password':duplicate_password, 'wp':wp, 'count_wp':count_wp, 'count_cp':count_cp, 'count_op':count_op}
    return render(request, 'pages/user_stats.html', context_dups)

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

            html = render(request, "pages/html_email.html")

            # create txt file attachment to email


            # html_message = "Username: " + temp.temp_uname + '\n' + 'Password: ' + temp.temp_pword
            html_message = render_to_string('pages/html_email.html', {'username':temp.temp_uname, 'password':temp.temp_pword})
            plain_message = strip_tags(html_message)


            try:

                send_mail(subject, plain_message, from_email, to_email, fail_silently=False, html_message=html_message)
                return redirect('/sharedhaven', messages.success(request, 'Credential is shared', 'alert-success'))
            except:
                return redirect('/sharedhaven', messages.error(request, 'Something is not right. Check your Internet Connection', 'alert-danger'))
    return render(request ,"pages/share_credentials.html", {'form': form, 'temp':temp})

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
