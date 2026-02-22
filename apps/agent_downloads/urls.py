from django.urls import path

from .views import download_bundle, download_installer, downloads_page

app_name = 'agent_downloads'

urlpatterns = [
    path('downloads/', downloads_page, name='downloads'),
    path('downloads/installer/<str:platform>/', download_installer, name='download_installer'),
    path('downloads/bundle/<str:platform>/', download_bundle, name='download_bundle'),
]
