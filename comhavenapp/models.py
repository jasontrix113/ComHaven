from django.db import models
from django.contrib.auth.models import User

# Create your models here.
class NewHavenFolder (models.Model):
    new_haven_folder = models.CharField(max_length=200, unique=True)

    def __str__(self):
        return self.new_haven_folder

class HavenFolder (models.Model):
    login_haven_folder = models.CharField(max_length=200, unique=True)

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
