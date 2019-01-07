from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver
from datetime import date


# Create your models here.
class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete='CASCADE', default="")
    email = models.CharField(max_length=100, default='')
    firstname = models.CharField(max_length=100, default='')
    lastname = models.CharField(max_length = 100, default='')
    address = models.CharField(max_length = 100, default='')
    notes = models.CharField(max_length=200, default='')

    USERNAME_FIELD = 'username'
    def __str__(self):
        return self.user.username

def create_profile(sender, **kwargs):
    if kwargs['created']:
        user_profile = UserProfile.objects.create(user=kwargs['instance'])

post_save.connect(create_profile, sender=User)

# class NewHavenFolder (models.Model):
#     new_haven_folder = models.CharField(max_length=200, unique=True)
#
#     def __str__(self):
#         return self.new_haven_folder
#
# class HavenFolder (models.Model):
#     login_haven_folder = models.CharField(max_length=200, unique=True,)
#
#     def __str__(self):
#         return self.login_haven_folder
class ExpressLoginsSites(models.Model):
    s_user = models.ForeignKey(User, on_delete=models.CASCADE, to_field="username", default='')
    site_name = models.CharField(max_length=50)
    site_url = models.CharField(max_length=100, default='')
    site_uid = models.CharField(max_length=50, default='')
    site_pid = models.CharField(max_length=50, default='')
    def __str__(self):
        return self.site_name;


class NewAccountLogin (models.Model):
    login_user = models.ForeignKey(User, on_delete=models.CASCADE, to_field="username", default="user")
    login_target_url = models.CharField(max_length=200)
    login_name = models.CharField(max_length=200)
    # site_url = models.ForeignKey(ExpressLoginsSites, on_delete=models.CASCADE, to_field='site_url', default='https:/')
    # login_haven_folder = models.ForeignKey(HavenFolder, on_delete=models.CASCADE, to_field="login_haven_folder", default="folder")
    login_username = models.CharField(max_length=200)
    login_password = models.CharField(max_length=200)
    login_notes = models.CharField(max_length=200)

    def __str__(self):
        return self.login_user.username

class Tasks(models.Model):
    tasks = models.CharField(max_length=200)
    def __str__(self):
        return self.tasks

class PinaxPoints (models.Model):
    pinax_user = models.ForeignKey(User, on_delete=models.CASCADE, to_field="username", default="user")
    pinax_task = models.ForeignKey(Tasks, on_delete=models.CASCADE, default='')
    point_values = models.IntegerField(default='0')

    def __str__(self):
        return self.pinax_user.username
class Status(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, to_field="username", default='')
    status = models.CharField(max_length=50)
    def __str__(self):
        return self.user.username

class SecurityChallenges(models.Model):
    # user = models.ForeignKey(User, on_delete=models.CASCADE, to_field="username", default='')
    tasks = models.ForeignKey(Tasks, on_delete=models.CASCADE, default='')
    date_completed = models.DateTimeField(auto_now_add=False)
    date_initiated = models.DateTimeField(auto_now_add=False)
    status = models.ForeignKey(Status, on_delete=models.CASCADE, default='')
    award_point_values = models.ForeignKey(PinaxPoints, on_delete=models.CASCADE, default='')

    def __str__(self):
        return self.user.username
class AccessListOfDevices(models.Model):
    acl_user = models.CharField(max_length=30)
    device_model = models.CharField(max_length=30, default='')
    access_id_path = models.CharField(max_length=30, default='')
    def __str__(self):
        return self.acl_user

class TempAccounts(models.Model):
    temp_uname = models.CharField(max_length=30)
    temp_pword = models.CharField(max_length=200)

    def __str__(self):
        return self.temp_uname

class PasswordGenerator(models.Model):
    # user  = models.ForeignKey(User, on_delete=models.CASCADE, to_field='username', default='')
    pass_length = models.IntegerField(default=0)
    pass_anagram = models.CharField(max_length=200)
    pass_phrase = models.CharField(max_length=200)
    pass_result = models.CharField(max_length=200, default='res')

    def __str__(self):
        return self.pass_result

