from __future__ import annotations

import logging

from celery import shared_task
from django.utils import timezone

logger = logging.getLogger(__name__)


@shared_task(
    bind=True,
    name="devices.sync_device_cache",
    max_retries=2,
    default_retry_delay=30,
    track_started=True,
)
def sync_device_cache(self, device_id: int) -> dict:
    """
    Background task: run a full cached-config sync for a single device.
    Uses at most 2 SSH connections via the optimised get_full_snapshot() path.
    """
    # Local imports to avoid circular-import issues with views.py
    from integrations.services.juniper_ssh import JuniperSSHError

    from .models import SwitchConfigSnapshot, SwitchDevice
    from .views import _sync_config_cache

    try:
        device = SwitchDevice.objects.get(pk=device_id)
    except SwitchDevice.DoesNotExist:
        logger.error("sync_device_cache: device %s not found", device_id)
        return {"status": "error", "error": "Device not found", "device_id": device_id}

    # Record that a sync is in flight so the UI can show a spinner
    SwitchConfigSnapshot.objects.filter(device=device).update(sync_task_id=self.request.id)

    try:
        snapshot, changed = _sync_config_cache(device)
        logger.info(
            "sync_device_cache: device=%s changed=%s task=%s",
            device_id, changed, self.request.id,
        )
        return {
            "status": "ok",
            "changed": changed,
            "device_id": device_id,
            "synced_at": snapshot.synced_at.isoformat(),
        }
    except JuniperSSHError as exc:
        logger.warning("sync_device_cache: SSH error for device %s: %s", device_id, exc)
        raise self.retry(exc=exc) from exc
    except Exception as exc:
        logger.exception("sync_device_cache: unexpected error for device %s", device_id)
        raise


@shared_task(name="devices.sync_all_active_devices")
def sync_all_active_devices() -> dict:
    """Celery-Beat task: dispatch a per-device sync for every active device."""
    from .models import SwitchDevice

    devices = SwitchDevice.objects.filter(is_active=True).values_list("id", flat=True)
    for device_id in devices:
        sync_device_cache.delay(device_id)
    return {"dispatched": list(devices)}
