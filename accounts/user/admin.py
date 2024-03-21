from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

#from .forms import UserCreationForm, UserChangeForm
from accounts.user.models import User


class UserAdmin(UserAdmin):
    #add_form = UserCreationForm
    #form = UserChangeForm
    model = User
    list_display = [
        "email",
        "mobile",
        "username",
      
        "is_staff",
    ]
    fieldsets = UserAdmin.fieldsets + ((None, {"fields": ("user_bio",)}),)
    add_fieldsets = UserAdmin.add_fieldsets + ((None, {"fields": ("user_bio","mobile")}),)


admin.site.register(User, UserAdmin)
