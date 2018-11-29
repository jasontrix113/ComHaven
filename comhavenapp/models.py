from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from pgcrypto_expressions.fields import EncryptedTextField
# Create your models here.
class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete='CASCADE')
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

class NewHavenFolder (models.Model):
    new_haven_folder = models.CharField(max_length=200, unique=True)

    def __str__(self):
        return self.new_haven_folder

class HavenFolder (models.Model):
    login_haven_folder = models.CharField(max_length=200, unique=True, default='Folder')

    def __str__(self):
        return self.login_haven_folder

class NewAccountLogin (models.Model):

    login_target_url = models.CharField(max_length=200)
    login_name = models.CharField(max_length=200)
    login_haven_folder = models.ForeignKey(HavenFolder, on_delete=models.CASCADE, to_field="login_haven_folder")
    login_username = models.CharField(max_length=200)
    login_password = models.CharField(max_length=200)
    login_notes = models.CharField(max_length=200)

    def __str__(self):
        return self.login_name

class PinaxPoints (models.Model):
    award_point_values = models.CharField(max_length=200)
    point_values = models.CharField(max_length=200)

    def __str__(self):
        return self.award_point_values

