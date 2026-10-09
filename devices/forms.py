from django import forms

from .models import SwitchDevice


class SwitchDeviceForm(forms.ModelForm):
    class Meta:
        model = SwitchDevice
        fields = [
            "name",
            "management_ip",
            "platform",
            "ssh_port",
            "username",
            "password",
            "snmp_enabled",
            "snmp_community",
            "snmp_port",
            "snmp_timeout",
            "notes",
            "is_active",
        ]
        widgets = {
            "password": forms.PasswordInput(render_value=True),
            "snmp_community": forms.PasswordInput(render_value=True),
            "notes": forms.Textarea(attrs={"rows": 3}),
        }


class SystemSettingsForm(forms.Form):
    hostname = forms.CharField(max_length=63)
    domain_name = forms.CharField(max_length=128, required=False)
    name_server = forms.GenericIPAddressField(required=False)
    ntp_server = forms.GenericIPAddressField(required=False)
    timezone = forms.CharField(max_length=64, required=False, initial="UTC")


class VlanConfigForm(forms.Form):
    vlan_name = forms.CharField(max_length=64)
    edit_mode = forms.ChoiceField(choices=[("add", "Add"), ("edit", "Edit")], required=False)
    original_vlan_name = forms.CharField(max_length=64, required=False)
    # ID or Range (one must be provided)
    id_type = forms.ChoiceField(choices=[("id", "VLAN ID"), ("range", "VLAN Range")], required=False, initial="id")
    vlan_id = forms.IntegerField(min_value=1, max_value=4094, required=False)
    vlan_range = forms.CharField(max_length=128, required=False, help_text="e.g. 100-200 or 10,20,30")
    description = forms.CharField(max_length=128, required=False)
    mac_aging = forms.IntegerField(min_value=60, max_value=1000000, required=False)
    filter_in = forms.CharField(max_length=64, required=False)
    filter_out = forms.CharField(max_length=64, required=False)
    # L3 Interface tab
    l3_interface = forms.CharField(max_length=32, required=False, help_text="e.g. irb.10")
    l3_inet = forms.CharField(max_length=64, required=False, help_text="e.g. 192.168.10.1/24")
    l3_inet6 = forms.CharField(max_length=64, required=False, help_text="e.g. 2001:db8::1/64")
    # Ports tab (single interface assignment)
    interface_name = forms.CharField(max_length=32, required=False)
    interface_mode = forms.ChoiceField(
        choices=[("access", "Access"), ("trunk", "Trunk")],
        required=False,
        initial="access",
    )


class InterfaceConfigForm(forms.Form):
    interface_name = forms.CharField(
        max_length=32,
        help_text="E.g. ge-0/0/4",
    )
    description = forms.CharField(max_length=128, required=False)
    enabled = forms.BooleanField(required=False, initial=True)
    mtu = forms.IntegerField(min_value=256, max_value=9216, required=False)
    port_mode = forms.ChoiceField(
        choices=[("none", "— No change —"), ("access", "Access"), ("trunk", "Trunk")],
        required=False,
        initial="none",
    )
    access_vlan = forms.CharField(max_length=64, required=False, help_text="Single VLAN name for access mode")
    trunk_vlans = forms.CharField(
        max_length=512,
        required=False,
        help_text="Comma-separated VLAN names for trunk mode (e.g. vlan100, mgmt)",
    )
    modal_type = forms.CharField(max_length=32, required=False)
    native_vlan = forms.CharField(max_length=64, required=False)
    vlan_members = forms.CharField(max_length=512, required=False)
    speed = forms.ChoiceField(
        choices=[("", "Auto-Negotiation"), ("10m", "10Mbps"), ("100m", "100Mbps"), ("1g", "1Gbps"), ("10g", "10Gbps")],
        required=False,
    )
    duplex = forms.ChoiceField(
        choices=[("", "Automatic"), ("half", "Half"), ("full", "Full")],
        required=False,
    )
    flow_control = forms.BooleanField(required=False)
    l3_inet = forms.CharField(max_length=64, required=False)
    l3_inet6 = forms.CharField(max_length=64, required=False)


class ManualShowForm(forms.Form):
    show_command = forms.CharField(
        max_length=200,
        help_text="Runs through 'cli -c ...'. Example: show chassis hardware",
    )
    reason = forms.CharField(
        max_length=200,
        required=False,
        help_text="Optional: why GUI action was not enough.",
    )


class ManualSetForm(forms.Form):
    set_commands = forms.CharField(
        widget=forms.Textarea(attrs={"rows": 6}),
        help_text="One 'set' or 'delete' command per line.",
    )
    reason = forms.CharField(
        max_length=200,
        required=False,
        help_text="Optional: why GUI action was not enough.",
    )
    confirm_edge_case = forms.BooleanField(
        required=True,
        label="I confirm this is an edge-case/manual override",
    )


class CommitPreferenceForm(forms.Form):
    commit_mode = forms.ChoiceField(
        choices=SwitchDevice.COMMIT_MODE_CHOICES,
        help_text="Single commit queues changes. Immediate mode commits each change after validation.",
    )


class PingForm(forms.Form):
    host = forms.CharField(max_length=255, label="Host / IP")
    count = forms.IntegerField(initial=5, min_value=1, max_value=100, required=False, label="Count")


class LagConfigForm(forms.Form):
    lag_name = forms.RegexField(
        regex=r"^ae\d+$",
        max_length=8,
        label="LAG Interface",
        help_text="e.g. ae0, ae1",
        error_messages={"invalid": "Must be ae0, ae1, ae2, …"},
    )
    description = forms.CharField(max_length=128, required=False, label="Description")
    lacp_mode = forms.ChoiceField(
        choices=[("off", "No LACP (static)"), ("active", "LACP Active"), ("passive", "LACP Passive")],
        initial="active",
        label="LACP Mode",
    )
    min_links = forms.IntegerField(
        min_value=1, max_value=8, required=False,
        label="Minimum Links",
        help_text="Minimum active member links before LAG goes down.",
    )
    member_interfaces = forms.CharField(
        max_length=512,
        required=False,
        label="Member Interfaces",
        help_text="Comma-separated, e.g. ge-0/0/0, ge-0/0/1",
    )


class StaticRouteForm(forms.Form):
    prefix = forms.CharField(
        max_length=64,
        label="Prefix",
        help_text="e.g. 0.0.0.0/0 or 10.0.0.0/8",
    )
    next_hop = forms.CharField(
        max_length=64,
        label="Next Hop",
        help_text="IP address of next hop",
    )


class NtpServerForm(forms.Form):
    ntp_server = forms.GenericIPAddressField(label="NTP Server IP")
    prefer = forms.BooleanField(required=False, label="Preferred server")


class SnmpCommunityForm(forms.Form):
    community = forms.RegexField(
        regex=r"^[\w\-]+$",
        max_length=64,
        label="Community String",
        error_messages={"invalid": "Letters, digits, hyphens and underscores only."},
    )
    authorization = forms.ChoiceField(
        choices=[("read-only", "Read-only"), ("read-write", "Read-write")],
        initial="read-only",
        label="Authorization",
    )
