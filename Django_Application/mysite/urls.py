from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path('', include('maindash.urls')),
    path('admin/', admin.site.urls),
]
