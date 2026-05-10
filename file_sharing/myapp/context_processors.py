from .models import SecurityAlert, RetrievalRequest, ShareRequest

def security_alerts_context(request):
    if request.user.is_authenticated and request.user.role == 'admin':
        return {
            'unread_alerts_count': SecurityAlert.objects.filter(is_read=False).count(),
            'pending_retrieval_count': RetrievalRequest.objects.filter(status='Pending').count(),
            'pending_share_count': ShareRequest.objects.filter(status='Pending').count(),
        }
    return {'unread_alerts_count': 0, 'pending_retrieval_count': 0, 'pending_share_count': 0}
