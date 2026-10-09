from django.urls import path

from . import views

app_name = "devices"

urlpatterns = [
    path("", views.device_list, name="list"),
    path("new/", views.device_create, name="create"),
    path("modal/create/", views.device_create_modal, name="create_modal"),
    path("<int:device_id>/", views.device_detail, name="detail"),
    path("<int:device_id>/modal/update/", views.device_update_modal, name="update_modal"),
    path("<int:device_id>/modal/delete/", views.device_delete_modal, name="delete_modal"),
    # Cache / commit flow
    path("<int:device_id>/compare/", views.compare_staged_changes, name="compare_staged"),
    path("<int:device_id>/commit-preference/", views.set_commit_preference, name="set_commit_preference"),
    path("<int:device_id>/sync-cache/", views.sync_config_cache, name="sync_cache"),
    path("<int:device_id>/sync-status/", views.sync_status, name="sync_status"),
    path("<int:device_id>/snmp/live-interfaces/", views.live_interface_status, name="live_interface_status"),
    path("<int:device_id>/port-layout/", views.save_port_layout, name="save_port_layout"),
    path("<int:device_id>/port-layout/gemini-detect/", views.gemini_detect_port_layout, name="gemini_detect_port_layout"),
    path("<int:device_id>/gemini-api-key/", views.gemini_api_key, name="gemini_api_key"),
    path("<int:device_id>/commit/", views.commit_staged_changes, name="commit_staged"),
    path("<int:device_id>/discard/", views.discard_staged_changes, name="discard_staged"),
    # Configure tab
    path("<int:device_id>/refresh/", views.refresh_status, name="refresh"),
    path("<int:device_id>/system/", views.apply_system_settings, name="apply_system"),
    path("<int:device_id>/vlan/", views.apply_vlan, name="apply_vlan"),
    path("<int:device_id>/vlan/delete/", views.delete_vlan, name="delete_vlan"),
    path("<int:device_id>/vlan/remove-member/", views.remove_vlan_member, name="remove_vlan_member"),
    path("<int:device_id>/interface/", views.apply_interface, name="apply_interface"),
    path("<int:device_id>/interface/disable/", views.disable_port, name="disable_port"),
    path("<int:device_id>/lag/", views.apply_lag, name="apply_lag"),
    path("<int:device_id>/lag/delete/", views.delete_lag, name="delete_lag"),
    path("<int:device_id>/lag/device-count/", views.set_lag_device_count, name="set_lag_device_count"),
    path("<int:device_id>/static-route/", views.apply_static_route, name="apply_static_route"),
    path("<int:device_id>/static-route/delete/", views.delete_static_route, name="delete_static_route"),
    path("<int:device_id>/ntp/", views.apply_ntp_server, name="apply_ntp"),
    path("<int:device_id>/ntp/delete/", views.delete_ntp_server, name="delete_ntp"),
    path("<int:device_id>/snmp/", views.apply_snmp_community, name="apply_snmp"),
    path("<int:device_id>/snmp/delete/", views.delete_snmp_community, name="delete_snmp"),
    # Maintain tab
    path("<int:device_id>/ping/", views.run_ping, name="run_ping"),
    path("<int:device_id>/traceroute/", views.run_traceroute, name="run_traceroute"),
    # Troubleshoot tab
    path("<int:device_id>/manual-show/", views.manual_show_command, name="manual_show"),
    path("<int:device_id>/manual-set/", views.manual_set_commands, name="manual_set"),
]
