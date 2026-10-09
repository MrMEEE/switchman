from django.db import models


class SwitchDevice(models.Model):
	PLATFORM_JUNIPER_EX3300 = "juniper_ex3300"
	COMMIT_MODE_VALIDATE_ONLY = "validate_only"
	COMMIT_MODE_VALIDATE_AND_COMMIT = "validate_and_commit"

	PLATFORM_CHOICES = [
		(PLATFORM_JUNIPER_EX3300, "Juniper EX3300"),
	]
	COMMIT_MODE_CHOICES = [
		(COMMIT_MODE_VALIDATE_ONLY, "Validate configuration changes"),
		(COMMIT_MODE_VALIDATE_AND_COMMIT, "Validate and commit configuration changes"),
	]

	name = models.CharField(max_length=100, unique=True)
	management_ip = models.GenericIPAddressField(unique=True)
	platform = models.CharField(
		max_length=40,
		choices=PLATFORM_CHOICES,
		default=PLATFORM_JUNIPER_EX3300,
	)
	ssh_port = models.PositiveIntegerField(default=22)
	username = models.CharField(max_length=64)
	password = models.CharField(max_length=256)
	snmp_enabled = models.BooleanField(default=False)
	snmp_community = models.CharField(max_length=128, default="public")
	snmp_port = models.PositiveIntegerField(default=161)
	snmp_timeout = models.FloatField(default=1.0)
	port_layout = models.JSONField(default=dict, blank=True)
	commit_mode = models.CharField(
		max_length=24,
		choices=COMMIT_MODE_CHOICES,
		default=COMMIT_MODE_VALIDATE_ONLY,
	)
	notes = models.TextField(blank=True)
	is_active = models.BooleanField(default=True)
	created_at = models.DateTimeField(auto_now_add=True)
	updated_at = models.DateTimeField(auto_now=True)

	class Meta:
		ordering = ["name"]
		permissions = [
			("access_dashboard", "Can access dashboard"),
			("run_operational_commands", "Can run operational commands"),
			("manage_system_settings", "Can manage system settings"),
			("manage_vlans", "Can manage VLANs"),
			("manage_interfaces", "Can manage interfaces"),
			("manage_routing", "Can manage routing"),
			("run_manual_commands", "Can run manual edge-case commands"),
			("view_cached_config", "Can view cached switch config"),
			("sync_cached_config", "Can sync cached switch config"),
			("stage_config_changes", "Can stage switch configuration changes"),
			("commit_staged_changes", "Can commit staged configuration changes"),
			("discard_staged_changes", "Can discard staged configuration changes"),
			("compare_staged_changes", "Can compare staged configuration changes"),
			("manage_commit_preference", "Can manage commit preference"),
			("view_live_snmp_status", "Can view live SNMP interface status"),
			("manage_port_layout", "Can calibrate switch port layout"),
			("manage_gemini_api_key", "Can manage Gemini API key"),
		]

	def __str__(self):
		return f"{self.name} ({self.management_ip})"


class GeminiApiCredential(models.Model):
	provider = models.CharField(max_length=32, default="gemini", unique=True)
	api_key = models.CharField(max_length=512)
	updated_at = models.DateTimeField(auto_now=True)

	def masked_key(self) -> str:
		if len(self.api_key) <= 8:
			return "********"
		return f"{self.api_key[:4]}...{self.api_key[-4:]}"

	def __str__(self):
		return self.provider


class SwitchConfigSnapshot(models.Model):
	device = models.OneToOneField(
		SwitchDevice,
		on_delete=models.CASCADE,
		related_name="config_snapshot",
	)
	config_version = models.CharField(max_length=256, blank=True)
	config_hash = models.CharField(max_length=64, blank=True)
	# Dashboard panels
	system_info = models.JSONField(default=dict, blank=True)
	health_info = models.JSONField(default=dict, blank=True)
	alarms = models.JSONField(default=dict, blank=True)
	# Raw show outputs
	interfaces = models.JSONField(default=dict, blank=True)
	vlans = models.JSONField(default=dict, blank=True)
	routing = models.JSONField(default=dict, blank=True)
	security = models.JSONField(default=dict, blank=True)
	services = models.JSONField(default=dict, blank=True)
	# Extended monitor outputs
	monitor = models.JSONField(default=dict, blank=True)
	raw_config = models.TextField(blank=True)
	synced_at = models.DateTimeField(auto_now=True)
	# Celery task ID for the most recent in-flight or completed sync
	sync_task_id = models.CharField(max_length=64, blank=True)

class PendingConfigChange(models.Model):
	STATUS_PENDING = "pending"
	STATUS_COMMITTED = "committed"
	STATUS_DISCARDED = "discarded"

	STATUS_CHOICES = [
		(STATUS_PENDING, "Pending"),
		(STATUS_COMMITTED, "Committed"),
		(STATUS_DISCARDED, "Discarded"),
	]

	device = models.ForeignKey(
		SwitchDevice,
		on_delete=models.CASCADE,
		related_name="pending_changes",
	)
	created_by = models.ForeignKey(
		"auth.User",
		on_delete=models.SET_NULL,
		null=True,
		blank=True,
		related_name="staged_switch_changes",
	)
	action = models.CharField(max_length=64)
	summary = models.CharField(max_length=255)
	commands = models.TextField()
	status = models.CharField(max_length=16, choices=STATUS_CHOICES, default=STATUS_PENDING)
	created_at = models.DateTimeField(auto_now_add=True)
	updated_at = models.DateTimeField(auto_now=True)

	class Meta:
		ordering = ["created_at"]

	def __str__(self):
		return f"{self.device.name} {self.action} ({self.status})"
