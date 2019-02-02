from django.contrib import admin
from .models import NewAccountLogin, UserProfile, Tasks, TempAccounts, AccessListOfDevices, ExpressLoginsSites, SecurityChallenges, Status, PasswordGenerator, User_Stats, Rewards, PerformedTasks, WeakPasswords, CompromisedPasswords, OldPasswords, DuplicatePasswords


admin.site.register(NewAccountLogin)
admin.site.register(UserProfile)
admin.site.register(Tasks)
admin.site.register(TempAccounts)
admin.site.register(AccessListOfDevices)
admin.site.register(ExpressLoginsSites)
admin.site.register(SecurityChallenges)
admin.site.register(Status)
admin.site.register(PasswordGenerator)
admin.site.register(User_Stats)
admin.site.register(Rewards)
admin.site.register(PerformedTasks)
admin.site.register(WeakPasswords)
admin.site.register(CompromisedPasswords)
admin.site.register(OldPasswords)
admin.site.register(DuplicatePasswords)