from django.contrib.auth.forms import UserCreationForm
from django.urls import reverse_lazy
from django.views import generic
from django.contrib.auth import login, authenticate
from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from comhavenapp.forms import SignUpForm

from django.contrib.auth.decorators import login_required

from .models import HavenFolder, NewAccountLogin, PinaxPoints, AccessList
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




