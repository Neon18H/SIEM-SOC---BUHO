from django.urls import path

from .views import (
    download_bundle,
    download_installer,
    downloads_page,
    generate_install_command,
    install_agent_linux_tar,
    install_agent_windows_zip,
    install_linux_script,
    install_windows_script,
    release_activate,
    release_delete,
    releases_admin,
)

app_name = 'agent_downloads'

urlpatterns = [
    path('downloads/', downloads_page, name='downloads'),
    path('downloads/command/<str:platform>/', generate_install_command, name='generate_install_command'),
    path('downloads/installer/<str:platform>/', download_installer, name='download_installer'),
    path('downloads/bundle/<str:platform>/', download_bundle, name='download_bundle'),
    path('releases/', releases_admin, name='releases_admin'),
    path('releases/<int:release_id>/delete/', release_delete, name='release_delete'),
    path('releases/<int:release_id>/activate/', release_activate, name='release_activate'),
    path('install/windows.ps1', install_windows_script, name='install_windows_script'),
    path('install/linux.sh', install_linux_script, name='install_linux_script'),
    path('install/agent/windows.zip', install_agent_windows_zip, name='install_agent_windows_zip'),
    path('install/agent/linux.tar.gz', install_agent_linux_tar, name='install_agent_linux_tar'),
]
