from django.contrib import messages
from django.contrib.auth.decorators import permission_required
from django.contrib.auth.models import User
from django.shortcuts import get_object_or_404, redirect, render

from .forms import UserCreateForm, UserUpdateForm


@permission_required("auth.view_user", raise_exception=True)
def user_list(request):
	users = User.objects.all().order_by("username")
	return render(request, "accounts/user_list.html", {"users": users})


@permission_required("auth.add_user", raise_exception=True)
def user_create(request):
	if request.method == "POST":
		form = UserCreateForm(request.POST)
		if form.is_valid():
			form.save()
			messages.success(request, "User created.")
			return redirect("accounts:user_list")
	else:
		form = UserCreateForm(initial={"is_active": True})
	return render(request, "accounts/user_form.html", {"form": form, "title": "Create User"})


@permission_required("auth.change_user", raise_exception=True)
def user_edit(request, user_id: int):
	user_obj = get_object_or_404(User, pk=user_id)
	if request.method == "POST":
		form = UserUpdateForm(request.POST, instance=user_obj)
		if form.is_valid():
			form.save()
			messages.success(request, "User updated.")
			return redirect("accounts:user_list")
	else:
		form = UserUpdateForm(instance=user_obj)
	return render(
		request,
		"accounts/user_form.html",
		{"form": form, "title": f"Edit User: {user_obj.username}"},
	)
