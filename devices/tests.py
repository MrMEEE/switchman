import json

from django.contrib.auth.models import Permission, User
from django.test import TestCase
from django.urls import reverse
from unittest.mock import Mock, patch

from .models import GeminiApiCredential, SwitchConfigSnapshot, SwitchDevice
from .faceplates import get_faceplate
from integrations.services.snmp import _collect_interface_status
from .views import (
	GEMINI_PORT_DETECTION_PROMPT,
	_extract_json_payload,
	_parse_capacity,
	_parse_health,
	_sanitize_detected_port_candidates,
	_snapshot_has_operational_dashboard_data,
	_visual_ports_for_device,
)


class AuthorizationTests(TestCase):
	def setUp(self):
		self.device = SwitchDevice.objects.create(
			name="ex3300-lab",
			management_ip="192.0.2.10",
			username="netops",
			password="secret",
		)

	def test_requires_login(self):
		response = self.client.get(reverse("dashboard"))
		self.assertEqual(response.status_code, 302)
		self.assertIn("/accounts/login/", response.url)

	def test_dashboard_requires_permission(self):
		user = User.objects.create_user(username="reader", password="testpass123")
		self.client.login(username="reader", password="testpass123")

		response = self.client.get(reverse("dashboard"))
		self.assertEqual(response.status_code, 403)

		perm = Permission.objects.get(codename="access_dashboard")
		user.user_permissions.add(perm)
		response = self.client.get(reverse("dashboard"))
		self.assertEqual(response.status_code, 302)
		self.assertEqual(response.url, reverse("devices:detail", args=[self.device.id]))

	def test_dashboard_redirects_to_last_accessed_switch(self):
		second_device = SwitchDevice.objects.create(
			name="edge-switch",
			management_ip="192.0.2.11",
			username="netops",
			password="secret",
		)
		user = User.objects.create_user(username="operator", password="testpass123")
		user.user_permissions.add(
			Permission.objects.get(codename="access_dashboard"),
			Permission.objects.get(codename="view_switchdevice"),
		)
		self.client.login(username="operator", password="testpass123")

		response = self.client.get(reverse("dashboard"))
		self.assertEqual(response.status_code, 302)
		self.assertEqual(response.url, reverse("devices:detail", args=[self.device.id]))

		self.client.get(reverse("devices:detail", args=[second_device.id]))
		response = self.client.get(reverse("dashboard"))
		self.assertEqual(response.status_code, 302)
		self.assertEqual(response.url, reverse("devices:detail", args=[second_device.id]))

	def test_vlan_endpoint_requires_vlan_permission(self):
		user = User.objects.create_user(username="operator", password="testpass123")
		dashboard_perm = Permission.objects.get(codename="access_dashboard")
		user.user_permissions.add(dashboard_perm)
		self.client.login(username="operator", password="testpass123")

		response = self.client.post(
			reverse("devices:apply_vlan", args=[self.device.id]),
			{
				"vlan_id": 100,
				"vlan_name": "CLIENTS",
			},
		)
		self.assertEqual(response.status_code, 403)

	def test_device_detail_includes_sidebar_switch_picker_and_user_nav(self):
		SwitchDevice.objects.create(
			name="edge-switch",
			management_ip="192.0.2.11",
			username="netops",
			password="secret",
			is_active=False,
		)
		user = User.objects.create_user(username="admin", password="testpass123")
		user.user_permissions.add(
			Permission.objects.get(codename="view_switchdevice"),
			Permission.objects.get(codename="view_user"),
		)
		self.client.login(username="admin", password="testpass123")

		response = self.client.get(reverse("devices:detail", args=[self.device.id]))

		self.assertEqual(response.status_code, 200)
		self.assertContains(response, 'id="device-switcher"')
		self.assertContains(response, "ex3300-lab (192.0.2.10)")
		self.assertContains(response, "edge-switch (192.0.2.11)")
		self.assertContains(response, 'href="/accounts/users/"')
		self.assertContains(response, 'href="/accounts/logout/"')
		self.assertNotContains(response, 'href="/devices/"')
		self.assertNotContains(response, "Manage switch")
		self.assertNotContains(response, "jweb-topbar")

	def test_device_detail_includes_switch_management_modal_for_permitted_user(self):
		user = User.objects.create_user(username="admin", password="testpass123")
		user.user_permissions.add(
			Permission.objects.get(codename="view_switchdevice"),
			Permission.objects.get(codename="add_switchdevice"),
			Permission.objects.get(codename="change_switchdevice"),
			Permission.objects.get(codename="delete_switchdevice"),
		)
		self.client.login(username="admin", password="testpass123")

		response = self.client.get(reverse("devices:detail", args=[self.device.id]))

		self.assertEqual(response.status_code, 200)
		self.assertContains(response, "Switches...")
		self.assertContains(response, reverse("devices:create_modal"))
		self.assertContains(response, reverse("devices:update_modal", args=[self.device.id]))
		self.assertContains(response, reverse("devices:delete_modal", args=[self.device.id]))

	def test_detection_buttons_are_always_available_to_calibrators(self):
		user = User.objects.create_user(username="calibrator", password="testpass123")
		user.user_permissions.add(
			Permission.objects.get(codename="view_switchdevice"),
			Permission.objects.get(codename="manage_port_layout"),
		)
		self.client.login(username="calibrator", password="testpass123")

		response = self.client.get(reverse("devices:detail", args=[self.device.id]))
		self.assertContains(response, "Local Detect")
		self.assertContains(response, "Gemini Detect")

		self.device.port_layout = {"ge-0/0/0": {"left": 43.35, "top": 34.35, "width": 2.45, "height": 7.9}}
		self.device.save(update_fields=["port_layout"])
		response = self.client.get(reverse("devices:detail", args=[self.device.id]))
		self.assertContains(response, "Local Detect")
		self.assertContains(response, "Gemini Detect")

	def test_switch_modal_create_update_delete_actions(self):
		user = User.objects.create_user(username="admin", password="testpass123")
		user.user_permissions.add(
			Permission.objects.get(codename="access_dashboard"),
			Permission.objects.get(codename="view_switchdevice"),
			Permission.objects.get(codename="add_switchdevice"),
			Permission.objects.get(codename="change_switchdevice"),
			Permission.objects.get(codename="delete_switchdevice"),
		)
		self.client.login(username="admin", password="testpass123")

		response = self.client.post(
			reverse("devices:create_modal"),
			{
				"add-name": "edge-switch",
				"add-management_ip": "192.0.2.11",
				"add-platform": SwitchDevice.PLATFORM_JUNIPER_EX3300,
				"add-ssh_port": 22,
				"add-username": "netops",
				"add-password": "secret",
				"add-snmp_enabled": "on",
				"add-snmp_community": "public",
				"add-snmp_port": 161,
				"add-snmp_timeout": 1.0,
				"add-notes": "",
				"add-is_active": "on",
			},
		)
		new_device = SwitchDevice.objects.get(name="edge-switch")
		self.assertEqual(response.status_code, 302)
		self.assertEqual(response.url, reverse("devices:detail", args=[new_device.id]))

		response = self.client.post(
			reverse("devices:update_modal", args=[new_device.id]),
			{
				"edit-name": "edge-switch-renamed",
				"edit-management_ip": "192.0.2.12",
				"edit-platform": SwitchDevice.PLATFORM_JUNIPER_EX3300,
				"edit-ssh_port": 2222,
				"edit-username": "netops2",
				"edit-password": "secret2",
				"edit-snmp_community": "private",
				"edit-snmp_port": 1161,
				"edit-snmp_timeout": 2.0,
				"edit-notes": "updated",
				"edit-is_active": "on",
			},
		)
		new_device.refresh_from_db()
		self.assertEqual(response.status_code, 302)
		self.assertEqual(new_device.name, "edge-switch-renamed")
		self.assertEqual(new_device.ssh_port, 2222)
		self.assertFalse(new_device.snmp_enabled)

		response = self.client.post(reverse("devices:delete_modal", args=[new_device.id]))
		self.assertEqual(response.status_code, 302)
		self.assertFalse(SwitchDevice.objects.filter(pk=new_device.id).exists())

	def test_switch_modal_reopens_with_errors_for_invalid_add(self):
		user = User.objects.create_user(username="admin", password="testpass123")
		user.user_permissions.add(
			Permission.objects.get(codename="view_switchdevice"),
			Permission.objects.get(codename="add_switchdevice"),
		)
		self.client.login(username="admin", password="testpass123")

		response = self.client.post(
			reverse("devices:create_modal"),
			{
				"add-name": "",
				"add-management_ip": "not-an-ip",
				"add-platform": SwitchDevice.PLATFORM_JUNIPER_EX3300,
				"add-ssh_port": 22,
				"add-username": "netops",
				"add-password": "secret",
				"add-snmp_community": "public",
				"add-snmp_port": 161,
				"add-snmp_timeout": 1.0,
				"add-notes": "",
			},
		)

		self.assertEqual(response.status_code, 200)
		self.assertContains(response, 'id="switch-modal"')
		self.assertContains(response, "display:flex")
		self.assertContains(response, "This field is required")

	def test_switch_modal_reopens_with_errors_for_invalid_edit(self):
		user = User.objects.create_user(username="admin", password="testpass123")
		user.user_permissions.add(
			Permission.objects.get(codename="view_switchdevice"),
			Permission.objects.get(codename="change_switchdevice"),
		)
		self.client.login(username="admin", password="testpass123")

		response = self.client.post(
			reverse("devices:update_modal", args=[self.device.id]),
			{
				"edit-name": "",
				"edit-management_ip": "192.0.2.10",
				"edit-platform": SwitchDevice.PLATFORM_JUNIPER_EX3300,
				"edit-ssh_port": 22,
				"edit-username": "netops",
				"edit-password": "secret",
				"edit-snmp_community": "public",
				"edit-snmp_port": 161,
				"edit-snmp_timeout": 1.0,
				"edit-notes": "",
			},
		)

		self.assertEqual(response.status_code, 200)
		self.assertContains(response, 'data-switch-panel="edit"')
		self.assertContains(response, "display:flex")
		self.assertContains(response, "This field is required")

	def test_live_interface_status_requires_dedicated_permission(self):
		user = User.objects.create_user(username="operator", password="testpass123")
		user.user_permissions.add(Permission.objects.get(codename="view_switchdevice"))
		self.client.login(username="operator", password="testpass123")

		response = self.client.get(reverse("devices:live_interface_status", args=[self.device.id]))

		self.assertEqual(response.status_code, 403)

	def test_live_interface_status_returns_disabled_without_polling(self):
		user = User.objects.create_user(username="operator", password="testpass123")
		user.user_permissions.add(
			Permission.objects.get(codename="view_switchdevice"),
			Permission.objects.get(codename="view_live_snmp_status"),
		)
		self.client.login(username="operator", password="testpass123")

		response = self.client.get(reverse("devices:live_interface_status", args=[self.device.id]))

		self.assertEqual(response.status_code, 200)
		self.assertEqual(response.json(), {"enabled": False, "interfaces": []})

	def test_live_interface_status_returns_snmp_interfaces(self):
		self.device.snmp_enabled = True
		self.device.save(update_fields=["snmp_enabled"])
		user = User.objects.create_user(username="operator", password="testpass123")
		user.user_permissions.add(
			Permission.objects.get(codename="view_switchdevice"),
			Permission.objects.get(codename="view_live_snmp_status"),
		)
		self.client.login(username="operator", password="testpass123")

		class FakeInterface:
			def as_dict(self):
				return {
					"name": "ge-0/0/1",
					"admin": "up",
					"link": "up",
					"in_octets": 100,
					"out_octets": 200,
					"total_octets": 300,
				}

		with patch("integrations.services.snmp.collect_interface_status", return_value=[FakeInterface()]):
			response = self.client.get(reverse("devices:live_interface_status", args=[self.device.id]))

		self.assertEqual(response.status_code, 200)
		self.assertEqual(response.json()["interfaces"][0]["name"], "ge-0/0/1")
		self.assertEqual(response.json()["interfaces"][0]["total_octets"], 300)

	def test_empty_operational_snapshot_is_not_considered_complete(self):
		snapshot = SwitchConfigSnapshot.objects.create(
			device=self.device,
			config_version="0 2026-05-09 02:21:44 CEST by root",
			config_hash="abc123",
			system_info={"hostname": "", "model": "", "junos_version": "", "uptime": ""},
			health_info={"memory_pct": None, "cpu_load": None, "temp_c": None},
			interfaces={"terse": "", "ports_diagram": []},
		)

		self.assertFalse(_snapshot_has_operational_dashboard_data(snapshot))

	def test_populated_operational_snapshot_is_considered_complete(self):
		snapshot = SwitchConfigSnapshot.objects.create(
			device=self.device,
			config_version="0 2026-05-09 02:21:44 CEST by root",
			config_hash="abc123",
			system_info={"hostname": "boba", "model": "ex3300", "junos_version": "12.3R12", "uptime": "1 day"},
			health_info={"memory_pct": 22, "cpu_load": 4, "temp_c": 35},
			interfaces={"terse": "ge-0/0/0 up down", "ports_diagram": [{"name": "ge-0/0/0", "admin": "up", "link": "down"}]},
		)

		self.assertTrue(_snapshot_has_operational_dashboard_data(snapshot))

	def test_snapshot_without_cpu_load_is_not_considered_complete(self):
		snapshot = SwitchConfigSnapshot.objects.create(
			device=self.device,
			config_version="0 2026-05-09 02:21:44 CEST by root",
			config_hash="abc123",
			system_info={"hostname": "boba", "model": "ex3300", "junos_version": "12.3R12", "uptime": "1 day"},
			health_info={"memory_pct": 22, "cpu_load": None, "temp_c": 35},
			interfaces={"terse": "ge-0/0/0 up down", "ports_diagram": [{"name": "ge-0/0/0", "admin": "up", "link": "down"}]},
		)

		self.assertFalse(_snapshot_has_operational_dashboard_data(snapshot))

	def test_parse_health_derives_cpu_from_idle_percentage(self):
		health = _parse_health(
			"""
			Routing Engine status:
			  Memory utilization          46 percent
			  5 sec CPU utilization:
			    User                      19 percent
			    Kernel                    28 percent
			    Idle                      53 percent
			  Temperature                 55 degrees C / 131 degrees F
			""",
			"Fan Tray 0 OK",
		)

		self.assertEqual(health["memory_pct"], 46)
		self.assertEqual(health["cpu_load"], 47)
		self.assertEqual(health["temp_c"], 55)
		self.assertEqual(health["fan_status"], "OK")

	def test_parse_capacity_counts_only_physical_ports(self):
		capacity = _parse_capacity(
			"""
			Interface               Admin Link Proto
			ge-0/0/0                up    down
			ge-0/0/0.0              up    down eth-switch
			ge-0/0/1                up    up
			ge-0/0/1.0              up    up eth-switch
			""",
			"",
			"",
		)

		self.assertEqual(capacity["active_ports"], 1)
		self.assertEqual(capacity["total_ports"], 2)

	def test_ports_are_not_invented_without_switch_data(self):
		ports = _visual_ports_for_device(self.device, None)

		self.assertEqual(ports, [])

	def test_faceplate_variant_is_selected_from_reported_model(self):
		self.assertEqual(get_faceplate("ex3300-24p")["image"], "img/juniper-ex3300-photo.png")
		self.assertEqual(get_faceplate("ex3300-48p")["image"], "img/ex3300-48p-front-high.jpg")
		self.assertEqual(get_faceplate("unknown-model")["image"], "img/juniper-ex3300-photo.png")

	def test_48p_visual_ports_use_48p_geometry(self):
		snapshot = SwitchConfigSnapshot.objects.create(
			device=self.device,
			system_info={"model": "ex3300-48p"},
			interfaces={
				"ports_diagram": [
					{"name": "ge-0/0/0", "admin": "up", "link": "up"},
					{"name": "ge-0/0/47", "admin": "up", "link": "down"},
				]
			},
		)

		ports = _visual_ports_for_device(self.device, snapshot)

		self.assertEqual(len(ports), 2)
		self.assertEqual(ports[0]["label"], "1")
		self.assertEqual(ports[1]["label"], "48")
		self.assertGreater(ports[1]["left"], ports[0]["left"])
		self.assertAlmostEqual(ports[0]["left"], 2.363, places=2)
		self.assertAlmostEqual(ports[0]["top"], 30.727, places=2)
		self.assertAlmostEqual(ports[1]["top"], 60.086, places=2)

	def test_48p_detail_uses_variant_image_and_collected_port_count(self):
		ports = [
			{"name": f"ge-0/0/{index}", "admin": "up", "link": "down"}
			for index in range(48)
		]
		ports.append({"name": "xe-0/1/0", "admin": "up", "link": "down"})
		SwitchConfigSnapshot.objects.create(
			device=self.device,
			system_info={"model": "ex3300-48p"},
			interfaces={"ports_diagram": ports},
		)
		user = User.objects.create_user(username="viewer", password="testpass123")
		user.user_permissions.add(Permission.objects.get(codename="view_switchdevice"))
		self.client.login(username="viewer", password="testpass123")

		response = self.client.get(reverse("devices:detail", args=[self.device.id]))

		self.assertEqual(response.status_code, 200)
		self.assertContains(response, "/static/img/ex3300-48p-front-high.jpg")
		self.assertEqual(response.content.decode().count("data-port-name="), 49)

	def test_saved_port_layout_overrides_default_mapping(self):
		snapshot = SwitchConfigSnapshot.objects.create(
			device=self.device,
			interfaces={"ports_diagram": [{"name": "ge-0/0/0", "admin": "up", "link": "up"}]},
		)
		self.device.port_layout = {"ge-0/0/0": {"left": 10, "top": 11, "width": 12, "height": 13}}
		self.device.save(update_fields=["port_layout"])

		ports = _visual_ports_for_device(self.device, snapshot)

		self.assertEqual(ports[0]["left"], 10)
		self.assertEqual(ports[0]["top"], 11)
		self.assertEqual(ports[0]["width"], 12)
		self.assertEqual(ports[0]["height"], 13)
		self.assertAlmostEqual(ports[0]["default_left"], 46.15, places=2)

	def test_saved_port_layout_overrides_port_orientation(self):
		snapshot = SwitchConfigSnapshot.objects.create(
			device=self.device,
			interfaces={"ports_diagram": [{"name": "ge-0/0/0", "admin": "up", "link": "up"}]},
		)
		self.device.port_layout = {"ge-0/0/0": {"inverted": True}}
		self.device.save(update_fields=["port_layout"])

		ports = _visual_ports_for_device(self.device, snapshot)

		self.assertTrue(ports[0]["inverted"])

	def test_save_port_layout_requires_dedicated_permission(self):
		user = User.objects.create_user(username="operator", password="testpass123")
		user.user_permissions.add(Permission.objects.get(codename="view_switchdevice"))
		self.client.login(username="operator", password="testpass123")

		response = self.client.post(
			reverse("devices:save_port_layout", args=[self.device.id]),
			data=json.dumps({"ports": {"ge-0/0/0": {"left": 10, "top": 11, "width": 12, "height": 13}}}),
			content_type="application/json",
		)

		self.assertEqual(response.status_code, 403)

	def test_save_port_layout_persists_sanitized_coordinates(self):
		snapshot = SwitchConfigSnapshot.objects.create(
			device=self.device,
			interfaces={"ports_diagram": [{"name": "ge-0/0/0", "admin": "up", "link": "up"}]},
		)
		user = User.objects.create_user(username="operator", password="testpass123")
		user.user_permissions.add(
			Permission.objects.get(codename="view_switchdevice"),
			Permission.objects.get(codename="manage_port_layout"),
		)
		self.client.login(username="operator", password="testpass123")

		response = self.client.post(
			reverse("devices:save_port_layout", args=[self.device.id]),
			data=json.dumps(
				{
					"ports": {
						"ge-0/0/0": {"left": -10, "top": 101, "width": 2.2222, "height": 3.3333},
						"not-a-port": {"left": 1, "top": 1, "width": 1, "height": 1},
					}
				}
			),
			content_type="application/json",
		)

		self.assertEqual(response.status_code, 200)
		self.device.refresh_from_db()
		self.assertEqual(set(self.device.port_layout.keys()), {"ge-0/0/0"})
		self.assertEqual(self.device.port_layout["ge-0/0/0"]["left"], 0.0)
		self.assertEqual(self.device.port_layout["ge-0/0/0"]["top"], 96.667)
		self.assertEqual(self.device.port_layout["ge-0/0/0"]["width"], 2.222)

	def test_gemini_api_key_requires_dedicated_permission(self):
		user = User.objects.create_user(username="operator", password="testpass123")
		user.user_permissions.add(Permission.objects.get(codename="view_switchdevice"))
		self.client.login(username="operator", password="testpass123")

		response = self.client.get(reverse("devices:gemini_api_key", args=[self.device.id]))

		self.assertEqual(response.status_code, 403)

	def test_gemini_api_key_can_be_saved_masked_and_removed(self):
		user = User.objects.create_user(username="operator", password="testpass123")
		user.user_permissions.add(
			Permission.objects.get(codename="view_switchdevice"),
			Permission.objects.get(codename="manage_gemini_api_key"),
		)
		self.client.login(username="operator", password="testpass123")

		response = self.client.post(
			reverse("devices:gemini_api_key", args=[self.device.id]),
			data=json.dumps({"api_key": "abcd1234efgh5678"}),
			content_type="application/json",
		)

		self.assertEqual(response.status_code, 200)
		self.assertTrue(response.json()["has_key"])
		self.assertEqual(response.json()["source"], "webui")
		self.assertEqual(response.json()["masked_key"], "abcd...5678")
		self.assertEqual(GeminiApiCredential.objects.get(provider="gemini").api_key, "abcd1234efgh5678")

		response = self.client.post(
			reverse("devices:gemini_api_key", args=[self.device.id]),
			data=json.dumps({"delete": True}),
			content_type="application/json",
		)

		self.assertEqual(response.status_code, 200)
		self.assertFalse(response.json()["has_key"])
		self.assertFalse(GeminiApiCredential.objects.exists())

	def test_gemini_detect_uses_saved_webui_key(self):
		GeminiApiCredential.objects.create(provider="gemini", api_key="abcd1234efgh5678")
		user = User.objects.create_user(username="operator", password="testpass123")
		user.user_permissions.add(
			Permission.objects.get(codename="view_switchdevice"),
			Permission.objects.get(codename="manage_port_layout"),
		)
		self.client.login(username="operator", password="testpass123")

		class FakeResponse:
			def __enter__(self):
				return self

			def __exit__(self, exc_type, exc, traceback):
				return False

			def read(self):
				return json.dumps(
					{
						"candidates": [
							{
								"content": {
									"parts": [
										{"text": '{"ports":[{"left":10,"top":20,"width":3,"height":4}]}'},
									]
								}
							}
						]
					}
				).encode("utf-8")

		with patch.dict("os.environ", {}, clear=True), patch("urllib.request.urlopen", return_value=FakeResponse()) as urlopen:
			response = self.client.post(reverse("devices:gemini_detect_port_layout", args=[self.device.id]))

		self.assertEqual(response.status_code, 200)
		self.assertEqual(response.json()["count"], 1)
		self.assertIn("abcd1234efgh5678", urlopen.call_args.args[0].full_url)
		self.assertIn("gemini-3.6-flash", urlopen.call_args.args[0].full_url)

	def test_gemini_detect_sends_simple_port_detection_prompt(self):
		GeminiApiCredential.objects.create(provider="gemini", api_key="abcd1234efgh5678")
		user = User.objects.create_user(username="operator", password="testpass123")
		user.user_permissions.add(
			Permission.objects.get(codename="view_switchdevice"),
			Permission.objects.get(codename="manage_port_layout"),
		)
		self.client.login(username="operator", password="testpass123")

		class FakeResponse:
			def __enter__(self):
				return self

			def __exit__(self, exc_type, exc, traceback):
				return False

			def read(self):
				return b'{"candidates":[{"content":{"parts":[{"text":"{\\"ports\\":[]}"}]}}]}'

		with patch.dict("os.environ", {}, clear=True), patch("urllib.request.urlopen", return_value=FakeResponse()) as urlopen:
			response = self.client.post(reverse("devices:gemini_detect_port_layout", args=[self.device.id]))

		request_payload = json.loads(urlopen.call_args.args[0].data.decode("utf-8"))
		prompt = request_payload["contents"][0]["parts"][0]["text"]
		self.assertEqual(response.status_code, 200)
		self.assertEqual(prompt, GEMINI_PORT_DETECTION_PROMPT)
		self.assertIn("Do not group ports together", prompt)
		self.assertIn("one rectangle per physical port", prompt)

	def test_gemini_candidate_helpers_extract_and_sanitize_json(self):
		payload = _extract_json_payload('```json\n{"ports":[{"left":-2,"top":98,"width":3.3333,"height":4.4444}]}\n```')
		ports = _sanitize_detected_port_candidates(payload)

		self.assertEqual(ports, [{"left": 0.0, "top": 95.556, "width": 3.333, "height": 4.444}])

	def test_snmp_led_data_excludes_internal_and_logical_interfaces(self):
		async def fake_walk(host, community, port, timeout, oid, max_rows=128):
			if oid.endswith("31.1.1.1.1") or oid.endswith("2.2.1.2"):
				return {"1": "lo0", "2": "ge-0/0/0", "3": "ge-0/0/0.0", "4": "xe-0/1/0"}
			return {"1": "1", "2": "1", "3": "1", "4": "1"}

		with patch("integrations.services.snmp._safe_walk", side_effect=fake_walk):
			import asyncio
			result = asyncio.run(_collect_interface_status("192.0.2.1", "public", 161, 1.0))

		self.assertEqual([interface.name for interface in result], ["ge-0/0/0", "xe-0/1/0"])

	def test_gemini_candidate_helpers_normalize_fraction_and_pixel_coordinates(self):
		fraction_ports = _sanitize_detected_port_candidates(
			{"ports": [{"left": 0.1, "top": 0.2, "width": 0.03, "height": 0.04}]}
		)
		pixel_ports = _sanitize_detected_port_candidates(
			{"ports": [{"left": 150, "top": 90, "width": 45, "height": 35}]},
			1500,
			452,
		)

		self.assertEqual(fraction_ports, [{"left": 10.0, "top": 20.0, "width": 3.0, "height": 4.0}])
		self.assertEqual(pixel_ports, [{"left": 10.0, "top": 19.912, "width": 3.0, "height": 7.743}])

	def test_sync_updates_operational_data_when_config_hash_is_unchanged_but_snapshot_is_incomplete(self):
		from .views import _sync_config_cache

		SwitchConfigSnapshot.objects.create(
			device=self.device,
			config_version="0 2026-05-09 02:21:44 CEST by root",
			config_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			system_info={"hostname": "", "model": "", "junos_version": "", "uptime": ""},
			health_info={"memory_pct": None, "cpu_load": None, "temp_c": None},
			interfaces={"terse": "", "ports_diagram": []},
		)
		client = Mock()
		client.get_configuration_version.return_value = "0 2026-05-09 02:21:44 CEST by root"
		client.get_full_snapshot.return_value = (
			"0 2026-05-09 02:21:44 CEST by root",
			"",
			{
				"system_info": "Hostname: boba\nModel: ex3300-24p\nJunos: 12.3R12",
				"uptime": "System booted: now (1 day ago)",
				"health": "Memory utilization 46 percent\nIdle 53 percent\nTemperature 55 degrees C",
				"chassis_env": "Fan Tray 0 OK",
				"interfaces": "ge-0/0/0 up down",
			},
		)

		with patch("devices.views._client", return_value=client):
			snapshot, changed = _sync_config_cache(self.device)

		self.assertTrue(changed)
		self.assertEqual(snapshot.system_info["hostname"], "boba")
		self.assertEqual(snapshot.health_info["cpu_load"], 47)
		self.assertEqual(len(snapshot.interfaces["ports_diagram"]), 1)
