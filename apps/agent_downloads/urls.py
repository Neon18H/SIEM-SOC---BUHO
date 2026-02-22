from django.urls import path

from .views import (
    download_bundle,
    download_installer,
    downloads_page,
    release_activate,
    release_delete,
    releases_admin,
)

app_name = 'agent_downloads'

urlpatterns = [
    path('downloads/', downloads_page, name='downloads'),
    path('downloads/installer/<str:platform>/', download_installer, name='download_installer'),
    path('downloads/bundle/<str:platform>/', download_bundle, name='download_bundle'),
    path('releases/', releases_admin, name='releases_admin'),
    path('releases/<int:release_id>/delete/', release_delete, name='release_delete'),
    path('releases/<int:release_id>/activate/', release_activate, name='release_activate'),
]
