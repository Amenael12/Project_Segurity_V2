from django.urls import path
from .views import (
    UploadedFolderListCreateView, 
    UploadedFolderDetailView, 
    ScanFolderView, 
    VulnerabilityListView, 
    ScanResultView,
    ScanStatusView,
    RegisterView,
    LoginView,
    LogoutView,
    UserProfileView,
    FolderUploadView
)

urlpatterns = [
    path('folders/', UploadedFolderListCreateView.as_view(), name='folder-list-create'),
    path('folders/<int:pk>/', UploadedFolderDetailView.as_view(), name='folder-detail'),
    path('scan/', ScanFolderView.as_view(), name='scan-folder'),
    path('vulnerabilities/<int:folder_id>/', VulnerabilityListView.as_view(), name='vulnerability-list'),
    path('scan-results/<int:pk>/', ScanResultView.as_view(), name='scan-result'),
    path('scan-status/<str:task_id>/', ScanStatusView.as_view(), name='scan-status'),
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('profile/', UserProfileView.as_view(), name='user-profile'),
    path('upload-folder/', FolderUploadView.as_view(), name='upload-folder'),
]
urlpatterns = urlpatterns