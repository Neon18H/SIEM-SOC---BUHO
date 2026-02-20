from django.conf import settings
from django.contrib import messages
from django.contrib.auth import login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth import get_user_model
from django.shortcuts import redirect, render
from django.views.decorators.http import require_http_methods

from soc.models import Organization, UserProfile

from .forms import LoginForm, RegisterForm

User = get_user_model()


@require_http_methods(['GET'])
def root_redirect(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    return redirect('login')


@require_http_methods(['GET', 'POST'])
def login_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')

    form = LoginForm(request.POST or None)
    if request.method == 'POST' and form.is_valid():
        login(request, form.user)
        messages.success(request, 'Bienvenido de nuevo al SOC.')
        return redirect('dashboard')

    return render(request, 'accounts/login.html', {'form': form})


@require_http_methods(['GET', 'POST'])
def register_view(request):
    signup_allowed = getattr(settings, 'ALLOW_PUBLIC_SIGNUP', True)
    form = RegisterForm(request.POST or None)

    if request.method == 'POST' and not signup_allowed:
        messages.error(request, 'Registro deshabilitado. Contacta al administrador.')
        return redirect('register')

    if request.method == 'POST' and form.is_valid() and signup_allowed:
        names = form.cleaned_data['full_name'].strip().split()
        first_name = names[0] if names else ''
        last_name = ' '.join(names[1:]) if len(names) > 1 else ''

        user = User.objects.create_user(
            username=form.cleaned_data['username'],
            email=form.cleaned_data['email'],
            password=form.cleaned_data['password1'],
            first_name=first_name,
            last_name=last_name,
        )

        org = Organization.objects.order_by('id').first()
        if org is None:
            org = Organization.objects.create(name='Default Org')

        default_role = getattr(settings, 'DEFAULT_SIGNUP_ROLE', UserProfile.ROLE_VIEWER)
        if default_role not in dict(UserProfile.ROLE_CHOICES):
            default_role = UserProfile.ROLE_VIEWER

        UserProfile.objects.create(user=user, organization=org, role=default_role)
        login(request, user)
        messages.success(request, 'Cuenta creada correctamente. Bienvenido a Agente Nocturno.')
        return redirect('dashboard')

    return render(
        request,
        'accounts/register.html',
        {'form': form, 'signup_allowed': signup_allowed},
    )


@login_required
@require_http_methods(['POST'])
def logout_view(request):
    logout(request)
    messages.info(request, 'Sesión cerrada correctamente.')
    return redirect('login')
