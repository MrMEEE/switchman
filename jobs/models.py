from django.db import models

from devices.models import SwitchDevice


class CommandJob(models.Model):
	STATUS_PENDING = "pending"
	STATUS_SUCCESS = "success"
	STATUS_ERROR = "error"

	STATUS_CHOICES = [
		(STATUS_PENDING, "Pending"),
		(STATUS_SUCCESS, "Success"),
		(STATUS_ERROR, "Error"),
	]

	device = models.ForeignKey(SwitchDevice, on_delete=models.CASCADE, related_name="jobs")
	action = models.CharField(max_length=120)
	command = models.TextField()
	status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_PENDING)
	output = models.TextField(blank=True)
	created_at = models.DateTimeField(auto_now_add=True)
	completed_at = models.DateTimeField(null=True, blank=True)

	class Meta:
		ordering = ["-created_at"]

	def __str__(self):
		return f"{self.device.name} - {self.action} ({self.status})"
