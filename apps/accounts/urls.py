from django.urls import path

from .views import login_view, logout_view, register_view, root_redirect

urlpatterns = [
    path('', root_redirect, name='root_redirect'),
    path('login', login_view, name='login'),
    path('register', register_view, name='register'),
    path('logout', logout_view, name='logout'),
]
