from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser
from .models import *

class CustomUserAdmin(UserAdmin):
    model = CustomUser
    list_display = ['username', 'email', 'phone_no', 'role', 'approval_status', 'visible_password', 'is_staff']
    fieldsets = UserAdmin.fieldsets + (
        ('Custom Info', {'fields': ('role', 'phone_no', 'approval_status', 'visible_password')}),
    )
    add_fieldsets = UserAdmin.add_fieldsets + (
        ('Custom Info', {'fields': ('role', 'phone_no', 'approval_status', 'visible_password')}),
    )

admin.site.register(CustomUser, CustomUserAdmin)
admin.site.register(Document)
admin.site.register(DocumentPermission)