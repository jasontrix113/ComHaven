from django.contrib import admin
from .models import NewAccountLogin, UserProfile, PinaxPoints, Tasks


admin.site.register(NewAccountLogin)
# admin.site.register(HavenFolder)
admin.site.register(UserProfile)
admin.site.register(PinaxPoints)
admin.site.register(Tasks)