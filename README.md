# Switch Control Center (Django)

Central web configuration tool for network switches, currently focused on Juniper EX3300 over SSH.

## Security Model

- All routes require login by default.
- Every switch function is protected by dedicated permissions.
- Manual commands are treated as edge-case operations and require a stricter permission.
- User and permission management is done in the app UI (`/accounts/users/`), not Django admin.

## Permission Codenames

- `access_dashboard`
- `run_operational_commands`
- `manage_system_settings`
- `manage_vlans`
- `manage_interfaces`
- `manage_routing`
- `run_manual_commands`
- `view_cached_config`
- `sync_cached_config`
- `stage_config_changes`
- `commit_staged_changes`
- `discard_staged_changes`
- `compare_staged_changes`
- `manage_commit_preference`

## Quick Start

### First Run (Auto-Setup)
Simply run the control script—it will auto-create the virtual environment, install dependencies, and apply migrations:

```bash
./scripts/start.sh start
```

This automatically creates `.venv`, installs from `requirements.txt`, and runs migrations on the first invocation.

### Create an Admin Account
```bash
./scripts/start.sh createsuperuser admin admin123
```

Or manually:
```bash
. .venv/bin/activate
python manage.py bootstrap_admin --username <username> --password <password>
```

### Running the Server

```bash
./scripts/start.sh start        # Start on port 8000 (default)
./scripts/start.sh start 8080   # Start on port 8080
./scripts/start.sh stop         # Stop the running server
./scripts/start.sh restart      # Restart the server
./scripts/start.sh restart 8080 # Restart on port 8080
```

Or manually:
```bash
. .venv/bin/activate
python manage.py runserver
```

### Default Credentials

If you run `bootstrap_admin` with `admin` / `admin123`, access:

- Login: `http://127.0.0.1:8000/accounts/login/`
- **Username:** `admin`
- **Password:** `admin123`
- User management: `http://127.0.0.1:8000/accounts/users/`
- Devices: `http://127.0.0.1:8000/devices/`

Create additional users in-app at `/accounts/users/` and assign granular permissions.

## Configuration Workflow

1. Open a device and click **Sync Cache** to pull current switch state.
2. Make changes in the web UI sections (Interfaces, Switching, System, Troubleshoot manual set).
3. Changes are staged and listed as **Pending Changes**.
4. Click **Compare** to view a human-readable pending configuration list.
5. Click **Commit** to push staged commands, or **Discard** to remove all pending changes.
6. Use **Preference** to choose commit mode:
	- Validate configuration changes (single accumulated commit; default)
	- Validate and commit configuration changes (immediate commit after each change)
7. Commit automatically attempts a cache refresh so view data reflects the latest state.

## Notes

- Django admin URL is not exposed by default.
- SSH execution is handled by Paramiko integration.
- Optional Ansible-based integration scaffold is available for Junos.
