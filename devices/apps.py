from django.apps import AppConfig


class DevicesConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "devices"

    def ready(self) -> None:
        from django.db.models.signals import post_migrate

        post_migrate.connect(_register_periodic_sync, sender=self)


def _register_periodic_sync(sender, **kwargs) -> None:
    """
    Ensure a Celery Beat PeriodicTask exists for syncing all active devices.
    Runs after each `migrate` so it's safe to access ORM models.
    """
    try:
        from django.conf import settings
        from django_celery_beat.models import IntervalSchedule, PeriodicTask

        interval_seconds = getattr(settings, "JWEB_SYNC_INTERVAL_SECONDS", 300)
        schedule, _ = IntervalSchedule.objects.get_or_create(
            every=interval_seconds,
            period=IntervalSchedule.SECONDS,
        )
        PeriodicTask.objects.update_or_create(
            name="Auto-sync all active devices",
            defaults={
                "task": "devices.sync_all_active_devices",
                "interval": schedule,
                "enabled": True,
            },
        )
    except Exception:
        # Silently ignore when tables don't exist yet (first run before migrate)
        pass
