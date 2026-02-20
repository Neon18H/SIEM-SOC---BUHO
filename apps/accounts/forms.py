from django import forms
from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError

User = get_user_model()


class LoginForm(forms.Form):
    username = forms.CharField(label='Usuario o email', max_length=150)
    password = forms.CharField(label='Contraseña', widget=forms.PasswordInput)

    def clean(self):
        cleaned = super().clean()
        username = cleaned.get('username')
        password = cleaned.get('password')
        if not username or not password:
            return cleaned

        user = authenticate(username=username, password=password)
        if user is None:
            try:
                account = User.objects.get(email__iexact=username)
                user = authenticate(username=account.get_username(), password=password)
            except User.DoesNotExist:
                user = None

        if user is None:
            raise ValidationError('Credenciales inválidas.')

        self.user = user
        return cleaned


class RegisterForm(forms.Form):
    full_name = forms.CharField(label='Nombre completo', max_length=150)
    username = forms.CharField(label='Usuario', max_length=150)
    email = forms.EmailField(label='Correo electrónico')
    password1 = forms.CharField(label='Contraseña', widget=forms.PasswordInput)
    password2 = forms.CharField(label='Confirmar contraseña', widget=forms.PasswordInput)

    def clean_username(self):
        username = self.cleaned_data['username']
        if User.objects.filter(username__iexact=username).exists():
            raise ValidationError('Este nombre de usuario ya está en uso.')
        return username

    def clean_email(self):
        email = self.cleaned_data['email'].lower()
        if User.objects.filter(email__iexact=email).exists():
            raise ValidationError('Este correo ya está registrado.')
        return email

    def clean(self):
        cleaned = super().clean()
        p1 = cleaned.get('password1')
        p2 = cleaned.get('password2')
        if p1 and p2 and p1 != p2:
            self.add_error('password2', 'Las contraseñas no coinciden.')

        if p1:
            candidate = User(
                username=cleaned.get('username', ''),
                email=cleaned.get('email', ''),
                first_name=cleaned.get('full_name', '').split(' ')[0],
            )
            try:
                validate_password(p1, candidate)
            except ValidationError as exc:
                self.add_error('password1', exc)
        return cleaned
