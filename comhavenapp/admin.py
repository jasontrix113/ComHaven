from django.contrib import admin
from .models import NewAccountLogin, UserProfile, PinaxPoints, Tasks, TempAccounts, AccessListOfDevices, ExpressLoginsSites, SecurityChallenges, Status, PasswordGenerator


admin.site.register(NewAccountLogin)
# admin.site.register(HavenFolder)
admin.site.register(UserProfile)
admin.site.register(PinaxPoints)
admin.site.register(Tasks)
admin.site.register(TempAccounts)
admin.site.register(AccessListOfDevices)
admin.site.register(ExpressLoginsSites)
admin.site.register(SecurityChallenges)
admin.site.register(Status)
admin.site.register(PasswordGenerator)