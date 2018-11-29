from django.contrib import admin
from .models import NewAccountLogin, HavenFolder, UserProfile, PinaxPoints


admin.site.register(NewAccountLogin)
admin.site.register(HavenFolder)
admin.site.register(UserProfile)
admin.site.register(PinaxPoints)