from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import Permission, User


FUNCTION_PERMISSION_CODES = [
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


class UserCreateForm(UserCreationForm):
    email = forms.EmailField(required=False)
    permissions = forms.ModelMultipleChoiceField(
        queryset=Permission.objects.none(),
        required=False,
        widget=forms.CheckboxSelectMultiple,
    )

    class Meta:
        model = User
        fields = ("username", "email", "is_active", "password1", "password2", "permissions")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        permissions_field = self.fields["permissions"]
        if isinstance(permissions_field, forms.ModelMultipleChoiceField):
            permissions_field.queryset = Permission.objects.filter(
                content_type__app_label="devices",
                codename__in=FUNCTION_PERMISSION_CODES,
            ).order_by("codename")

    def save(self, commit=True):
        user = super().save(commit=False)
        user.email = self.cleaned_data.get("email", "")
        user.is_active = self.cleaned_data.get("is_active", True)
        if commit:
            user.save()
            user.user_permissions.set(self.cleaned_data.get("permissions", []))
        return user


class UserUpdateForm(forms.ModelForm):
    new_password = forms.CharField(
        required=False,
        widget=forms.PasswordInput,
        help_text="Leave blank to keep current password.",
    )
    permissions = forms.ModelMultipleChoiceField(
        queryset=Permission.objects.none(),
        required=False,
        widget=forms.CheckboxSelectMultiple,
    )

    class Meta:
        model = User
        fields = ("username", "email", "is_active", "permissions", "new_password")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        permissions_field = self.fields["permissions"]
        if isinstance(permissions_field, forms.ModelMultipleChoiceField):
            permissions_field.queryset = Permission.objects.filter(
                content_type__app_label="devices",
                codename__in=FUNCTION_PERMISSION_CODES,
            ).order_by("codename")
            permissions_field.initial = self.instance.user_permissions.filter(
                content_type__app_label="devices",
                codename__in=FUNCTION_PERMISSION_CODES,
            )

    def save(self, commit=True):
        user = super().save(commit=False)
        if commit:
            user.save()
            user.user_permissions.set(self.cleaned_data.get("permissions", []))
            new_password = self.cleaned_data.get("new_password")
            if new_password:
                user.set_password(new_password)
                user.save(update_fields=["password"])
        return user
