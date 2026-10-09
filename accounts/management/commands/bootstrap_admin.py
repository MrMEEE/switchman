from django.core.management.base import BaseCommand
from django.contrib.auth.models import Permission, User


ADMIN_PERMISSIONS = [
    "access_dashboard",
    "run_operational_commands",
    "manage_system_settings",
    "manage_vlans",
    "manage_interfaces",
    "manage_routing",
    "run_manual_commands",
    "view_cached_config",
    "sync_cached_config",
    "stage_config_changes",
    "commit_staged_changes",
    "discard_staged_changes",
    "compare_staged_changes",
    "manage_commit_preference",
    "view_live_snmp_status",
    "manage_port_layout",
    "manage_gemini_api_key",
    "add_switchdevice",
    "change_switchdevice",
    "delete_switchdevice",
    "view_switchdevice",
]


class Command(BaseCommand):
    help = "Bootstrap a super admin user with all switch management permissions"

    def add_arguments(self, parser):
        parser.add_argument("--username", default="admin", help="Admin username (default: admin)")
        parser.add_argument("--password", help="Admin password (prompted if not provided)")

    def handle(self, *args, **options):
        username = options["username"]
        password = options.get("password")

        if not password:
            import getpass
            password = getpass.getpass(f"Password for {username}: ")

        if User.objects.filter(username=username).exists():
            self.stdout.write(self.style.WARNING(f"User {username} already exists."))
            return

        user = User.objects.create_superuser(username=username, email="", password=password)
        perms = Permission.objects.filter(
            content_type__app_label="devices",
            codename__in=ADMIN_PERMISSIONS,
        )
        user.user_permissions.set(perms)

        self.stdout.write(
            self.style.SUCCESS(
                f"✓ Super admin {username} created with all switch management permissions."
            )
        )
