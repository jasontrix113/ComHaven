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
    notes = models.CharField(max_length=200, default='')

    USERNAME_FIELD = 'username'
    def __str__(self):
        return self.user.username

def create_profile(sender, **kwargs):
    if kwargs['created']:
        user_profile = UserProfile.objects.create(user=kwargs['instance'])

post_save.connect(create_profile, sender=User)

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
    login_username = models.CharField(max_length=200)
    login_password = models.CharField(max_length=200, blank=False)
    login_notes = models.CharField(max_length=200)
    # date_inserted = models.DateTimeField(auto_now=False,null=True)

    def __str__(self):
        return self.login_user.username

class Points(models.Model):
    points = models.IntegerField(unique=True)
    def __str__(self):
        return str(self.points)

class Tasks(models.Model):
    tasks = models.CharField(max_length=200, unique=True, default='')
    def __str__(self):
        return str(self.tasks)

class Status(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, to_field="username", default='')
    status = models.CharField(max_length=50)
    def __str__(self):
        return self.status

class SecurityChallenges(models.Model):
    tasks = models.ForeignKey(Tasks, on_delete=models.CASCADE, default='', to_field='tasks')
    points = models.ForeignKey(Points, on_delete=models.CASCADE, default='', to_field='points')
    date_completed = models.DateTimeField(auto_now_add=False)
    date_initiated = models.DateTimeField(auto_now_add=False)
    status = models.ForeignKey(Status, on_delete=models.CASCADE, default='')
    def __str__(self):
        return str(self.status)

class AccessListOfDevices(models.Model):
    acl_user = models.CharField(max_length=30)
    device_model = models.CharField(max_length=30, default='')
    access_id_path = models.CharField(max_length=30, default='')
    device_platform = models.CharField(max_length=30, default='')
    def __str__(self):
        return self.acl_user

class TempAccounts(models.Model):
    # user = models.ForeignKey(User, on_delete=models.CASCADE, to_field='username', default='')
    temp_uname = models.CharField(max_length=30)
    temp_pword = models.CharField(max_length=200)
    def __str__(self):
        return self.temp_uname

class PasswordGenerator(models.Model):
    user  = models.ForeignKey(User, on_delete=models.CASCADE, to_field='username', default='')
    identifier = models.IntegerField()
    pass_result = models.CharField(max_length=200, default='res')
    def __str__(self):
        return self.pass_result

class User_Stats(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, to_field='username', default='')
    # points_awarded = models.IntegerField()
    overall_points = models.CharField(max_length=200, default='')
    def __str__(self):
        return self.user.username

class Rewards(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, to_field='username', default='')
    reward = models.CharField(max_length=200, default='')
    points_required = models.IntegerField()
    def __str__(self):
        return self.user.username