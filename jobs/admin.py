from django.contrib import admin

from .models import CommandJob


@admin.register(CommandJob)
class CommandJobAdmin(admin.ModelAdmin):
	list_display = ("device", "action", "status", "created_at", "completed_at")
	search_fields = ("device__name", "action", "command")
	list_filter = ("status", "action")
