from django.contrib import admin
from .models import NewAccountLogin, UserProfile, PinaxPoints, Tasks, TempAccounts, AccessListOfDevices, ExpressLoginsSites


admin.site.register(NewAccountLogin)
# admin.site.register(HavenFolder)
admin.site.register(UserProfile)
admin.site.register(PinaxPoints)
admin.site.register(Tasks)
admin.site.register(TempAccounts)
admin.site.register(AccessListOfDevices)
admin.site.register(ExpressLoginsSites)