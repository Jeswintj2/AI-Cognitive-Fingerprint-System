"""
URL configuration for file_sharing project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from myapp.views import (
    home, login_view, register_view, logout_view, admin_dashboard, 
    user_dashboard, admin_manage_users, admin_update_user_status, 
    user_upload_document, user_my_documents, admin_process_pending_documents, 
    user_verify_document, user_tamper_report, user_audit_logs,
    admin_security_alerts, admin_mark_alert_read,
    admin_documents, admin_document_permissions, admin_remove_permission,
    secure_download_document, user_request_retrieval,
    admin_retrieval_requests, admin_review_retrieval,
    user_share_document, admin_share_requests, admin_review_share,
    user_shared_with_me, view_shared_document, user_reupload_document,
    admin_audit_logs, user_delete_document, user_modify_document,verify_and_download
)

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', home, name='home'),
    path('login/', login_view, name='login'),
    path('register/', register_view, name='register'),
    path('logout/', logout_view, name='logout'),
    path('admin-dashboard/process-pending/', admin_process_pending_documents, name='admin_process_pending_documents'),
    path('admin-dashboard/alerts/', admin_security_alerts, name='admin_security_alerts'),
    path('admin-dashboard/alerts/read/<int:alert_id>/', admin_mark_alert_read, name='admin_mark_alert_read'),
    path('admin-dashboard/documents/', admin_documents, name='admin_documents'),
    path('admin-dashboard/documents/<int:doc_id>/permissions/', admin_document_permissions, name='admin_document_permissions'),
    path('admin-dashboard/permissions/remove/<int:perm_id>/', admin_remove_permission, name='admin_remove_permission'),
    path('admin-dashboard/', admin_dashboard, name='admin_dashboard'),
    path('admin-dashboard/users/', admin_manage_users, name='admin_manage_users'),
    path('admin-dashboard/users/action/<int:user_id>/<str:action>/', admin_update_user_status, name='admin_update_user_status'),
    path('dashboard/', user_dashboard, name='user_dashboard'),
    path('dashboard/my-documents/', user_my_documents, name='user_my_documents'),
    path('dashboard/verify/<int:doc_id>/', user_verify_document, name='user_verify_document'),
    path('dashboard/tamper-report/<int:doc_id>/', user_tamper_report, name='user_tamper_report'),
    path('dashboard/audit-logs/', user_audit_logs, name='user_audit_logs'),
    path('dashboard/upload/', user_upload_document, name='user_upload_document'),
    # path('dashboard/download/<int:doc_id>/', secure_download_document, name='secure_download_document'),
    path('dashboard/request-retrieval/<int:doc_id>/', user_request_retrieval, name='user_request_retrieval'),
    path('admin-dashboard/retrieval-requests/', admin_retrieval_requests, name='admin_retrieval_requests'),
    path('admin-dashboard/retrieval-requests/<int:request_id>/<str:action>/', admin_review_retrieval, name='admin_review_retrieval'),
    path('dashboard/share/<int:doc_id>/', user_share_document, name='user_share_document'),
    path('admin-dashboard/share-requests/', admin_share_requests, name='admin_share_requests'),
    path('admin-dashboard/share-requests/<int:share_id>/<str:action>/', admin_review_share, name='admin_review_share'),
    path('dashboard/shared-with-me/', user_shared_with_me, name='user_shared_with_me'),
    path('dashboard/view-shared/<int:doc_id>/', view_shared_document, name='view_shared_document'),
    path('dashboard/reupload/<int:doc_id>/', user_reupload_document, name='user_reupload_document'),
    path('admin-dashboard/audit-logs/', admin_audit_logs, name='admin_audit_logs'),
    path('dashboard/delete/<int:doc_id>/', user_delete_document, name='user_delete_document'),
    path('dashboard/modify/<int:doc_id>/', user_modify_document, name='user_modify_document'),
     path('download-hash/<int:doc_id>/', secure_download_document, name='secure_download_document'),
    path('verify-download/<int:doc_id>/', verify_and_download, name='verify_and_download'),

]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
