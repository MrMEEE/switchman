from django.contrib import admin

from .models import SwitchDevice


@admin.register(SwitchDevice)
class SwitchDeviceAdmin(admin.ModelAdmin):
	list_display = ("name", "management_ip", "platform", "username", "is_active", "updated_at")
	search_fields = ("name", "management_ip", "username")
	list_filter = ("platform", "is_active")
