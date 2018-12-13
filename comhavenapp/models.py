from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save

# Create your models here.
class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete='CASCADE', default="")
    email = models.CharField(max_length=100)
    firstname = models.CharField(max_length=100)
    lastname = models.CharField(max_length = 100)
    address = models.CharField(max_length = 100)
    notes = models.CharField(max_length=200)

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

class NewAccountLogin (models.Model):
    login_user = models.ForeignKey(User, on_delete=models.CASCADE, to_field="username", default="user")
    login_target_url = models.CharField(max_length=200)
    login_name = models.CharField(max_length=200)
    # login_haven_folder = models.ForeignKey(HavenFolder, on_delete=models.CASCADE, to_field="login_haven_folder", default="folder")
    login_username = models.CharField(max_length=200)
    login_password = models.CharField(max_length=200)
    login_notes = models.CharField(max_length=200)

    def __str__(self):
        return self.login_user

class PinaxPoints (models.Model):
    award_point_values = models.CharField(max_length=200)
    point_values = models.CharField(max_length=200)

    def __str__(self):
        return self.award_point_values

class Tasks(models.Model):
    tasks = models.CharField(max_length=200)

    def __str__(self):
        return self.tasks

class AccessListOfDevices(models.Model):
    acl_user = models.CharField(max_length=30)
    device_model = models.CharField(max_length=30, default='')
    access_id_path = models.CharField(max_length=30, default='')
    def __str__(self):
        return self.acl_user

class TempAccounts(models.Model):
    temp_user = models.ForeignKey(User, on_delete=models.CASCADE, to_field = "username",default='')
    temp_uname = models.CharField(max_length=20)
    temp_pword = models.CharField(max_length=200)

    def __str__(self):
        return self.temp_user

class ExpressLoginsSites(models.Model):
    site_name = models.CharField(max_length=20)
    site_url = models.CharField(max_length=40, default='')
    def __str__(self):
        return self.site_name