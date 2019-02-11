from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver
from datetime import date

# Create your models here.
class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete='CASCADE')
    email = models.CharField(max_length=100, default='')
    firstname = models.CharField(max_length=100, default='')
    lastname = models.CharField(max_length = 100, default='')
    notes = models.CharField(max_length=200, default='')

    def __str__(self):
        return str(self.user)
@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.create(user=instance)
@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    instance.userprofile.save()

class ExpressLoginsSites(models.Model):
    site_name = models.CharField(max_length=50)
    image_path = models.CharField(max_length=200, default='')
    # site_url = models.CharField(max_length=100, default='')
    def __str__(self):
        return self.site_name;

class NewAccountLogin (models.Model):
    login_user = models.ForeignKey(User, on_delete=models.CASCADE, to_field="username", default="user")
    login_target_url = models.CharField(max_length=200)
    login_name = models.CharField(max_length=200)
    login_username = models.CharField(max_length=200)
    login_password = models.CharField(max_length=200, blank=False)
    login_notes = models.CharField(max_length=200)
    date_inserted = models.DateTimeField(auto_now=True)
    changed_flag = models.BooleanField(default=False)
    issue_flag = models.BooleanField(default=False)
    def __str__(self):
        return self.login_user.username

class Tasks(models.Model):
    tasks = models.CharField(max_length=200, unique=True, default='')
    def __str__(self):
        return str(self.tasks)

class Status(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, to_field="username", default='')
    status = models.CharField(max_length=50)
    def __str__(self):
        return str(self.status)

class SecurityChallenges(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, default='', to_field='username')
    tasks = models.ForeignKey(Tasks, on_delete=models.CASCADE, default='', to_field='tasks')
    points = models.IntegerField(default=0)
    date_completed = models.DateTimeField(auto_now_add=True)
    date_initiated = models.DateTimeField(auto_now_add=True)
    status = models.ForeignKey(Status, on_delete=models.CASCADE, default='')
    def __str__(self):
        return str(self.user)

class AccessListOfDevices(models.Model):
    acl_user = models.CharField(max_length=30)
    device_name = models.CharField(max_length=30, default='Windows-PC')
    device_model = models.CharField(max_length=30, default='')
    access_id_path = models.CharField(max_length=30, default='')
    device_platform = models.CharField(max_length=30, default='Windows')
    def __str__(self):
        return self.acl_user

class TempAccounts(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, to_field='username', default='')
    temp_uname = models.CharField(max_length=30)
    temp_pword = models.CharField(max_length=200)
    ch_flag = models.BooleanField(default=False)
    def __str__(self):
        return str(self.user)

class PasswordGenerator(models.Model):
    user  = models.ForeignKey(User, on_delete=models.CASCADE, to_field='username', default='')
    identifier = models.IntegerField()
    pass_result = models.CharField(max_length=200, default='res')
    def __str__(self):
        return self.pass_result

class User_Stats(models.Model):
    user = models.CharField(max_length=30)
    # points_awarded = models.IntegerField()
    overall_points = models.CharField(max_length=200, default=0)
    count = models.IntegerField(default=10)
    def __str__(self):
        return str(self.user)

class Rewards(models.Model):
    reward = models.CharField(max_length=200, default='')
    points_required = models.IntegerField()
    def __str__(self):
        return str(self.reward)

class PerformedTasks(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, to_field='username', default='')
    accounts = models.CharField(max_length=200, default='')
    status = models.CharField(max_length=20, default='')
    def __str__(self):
        return str(self.user)

class WeakPasswords(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, to_field="username", default='')
    login_account = models.CharField(max_length=200, default='')
    login_password = models.CharField(max_length=200, default='')
    login_score = models.CharField(max_length=20, default=0)
    login_strength = models.CharField(max_length=200, default='')
    def __str__(self):
        return str(self.user)

class DuplicatePasswords(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, to_field="username", default='')
    account_id = models.IntegerField(default=0)
    def __str__(self):
        return str(self.user)

class CompromisedPasswords(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, to_field="username", default='')
    login_account = models.CharField(max_length=200, default='')
    login_password = models.CharField(max_length=200, default='')
    def __str__(self):
        return str(self.user)

class OldPasswords(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, to_field="username", default='')
    login_account = models.CharField(max_length=200, default='')
    login_password = models.CharField(max_length=200, default='')
    date_last_inserted = models.DateTimeField(auto_now=True)
    def __str__(self):
        return str(self.user)