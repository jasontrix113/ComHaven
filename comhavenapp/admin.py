from django.contrib import admin
from .models import NewAccountLogin, UserProfile, Tasks, AccessListOfDevices, ExpressLoginsSites, SecurityChallenges, Status, PasswordGenerator, User_Stats, Rewards, PerformedTasks, WeakPasswords, CompromisedPasswords, OldPasswords, DuplicatePasswords


class NewAccountLoginAdmin(admin.ModelAdmin):
    fields =('login_user', 'login_target_url', 'login_name', 'login_name', 'login_username', 'login_password', 'date_inserted', 'changed_flag', 'issue_flag')
class NewAccountLoginAdmin(admin.ModelAdmin ):
    exclude = ('login_tp',)

admin.site.register(NewAccountLogin, NewAccountLoginAdmin)

# admin.site.register(NewAccountLogin)
admin.site.register(UserProfile)
admin.site.register(Tasks)
admin.site.register(AccessListOfDevices)
admin.site.register(ExpressLoginsSites)
admin.site.register(SecurityChallenges)
admin.site.register(Status)
admin.site.register(PasswordGenerator)
admin.site.register(User_Stats)
admin.site.register(Rewards)
# admin.site.register(PerformedTasks)
# admin.site.register(WeakPasswords)
# admin.site.register(CompromisedPasswords)
# admin.site.register(OldPasswords)
# admin.site.register(DuplicatePasswords)