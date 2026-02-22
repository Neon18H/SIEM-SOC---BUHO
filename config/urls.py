from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import include, path
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from apps.agent_downloads import views as agent_install_views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('apps.accounts.urls')),
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('agents/', include('apps.agent_downloads.urls')),
    path('install/windows.ps1', agent_install_views.install_windows_script, name='install_windows_script_public'),
    path('install/linux.sh', agent_install_views.install_linux_script, name='install_linux_script_public'),
    path('install/agent/windows.zip', agent_install_views.install_agent_windows_zip, name='install_agent_windows_zip_public'),
    path('install/agent/linux.tar.gz', agent_install_views.install_agent_linux_tar, name='install_agent_linux_tar_public'),
    path('', include('soc.urls')),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
