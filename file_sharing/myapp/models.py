from django.db import models
from django.contrib.auth.models import AbstractUser

class CustomUser(AbstractUser):
    ROLE_CHOICES = (
        ('admin', 'Admin'),
        ('user', 'User'),
    )
    STATUS_CHOICES = (
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('blocked', 'Blocked'),
    )
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='user')
    approval_status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')
    phone_no = models.CharField(max_length=15, blank=True, null=True)
    visible_password = models.CharField(max_length=255, blank=True, null=True)

    def __str__(self):
        return self.username

class AuditLog(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, null=True, blank=True, related_name='audit_logs')
    admin_user = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True, related_name='admin_actions')
    document = models.ForeignKey('Document', on_delete=models.SET_NULL, null=True, blank=True, related_name='audit_logs')
    action = models.CharField(max_length=255)
    action_type = models.CharField(max_length=100, null=True, blank=True) # Upload, Fingerprint, Integrity Check, etc.
    document_name = models.CharField(max_length=255, null=True, blank=True)
    status = models.CharField(max_length=50, null=True, blank=True) # Success, Tampered, Verified, etc.
    similarity_score = models.FloatField(null=True, blank=True)
    target_user = models.CharField(max_length=255, null=True, blank=True) # Kept for backward compatibility
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username if self.user else 'System'} - {self.action} - {self.timestamp}"

class Document(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='documents')
    title = models.CharField(max_length=255)
    file = models.FileField(upload_to='documents/')
    file_type = models.CharField(max_length=50) # To store extension like .pdf, .docx
    file_size = models.BigIntegerField() # Storing size in bytes for limits
    sha256_hash = models.CharField(max_length=64)
    cognitive_fingerprint = models.TextField(null=True, blank=True) # Global fingerprint
    section_fingerprints = models.TextField(null=True, blank=True) # JSON list of section-level fingerprints
    tamper_report = models.TextField(null=True, blank=True) # JSON details of last verification result
    status = models.CharField(max_length=50, default='Secure') # Secure, Processed, Tampered, Verified, etc
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title

class SecurityAlert(models.Model):
    document = models.ForeignKey(Document, on_delete=models.CASCADE, related_name='security_alerts')
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='notifications')
    similarity_score = models.FloatField()
    is_read = models.BooleanField(default=False)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Tamper Alert: {self.document.title} ({self.similarity_score}%)"

class DocumentPermission(models.Model):
    document = models.ForeignKey(Document, on_delete=models.CASCADE, related_name='permissions')
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='document_permissions')
    can_view = models.BooleanField(default=False)
    can_download = models.BooleanField(default=False)
    can_edit = models.BooleanField(default=False)
    can_share = models.BooleanField(default=False)
    granted_by = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True, related_name='granted_permissions')
    granted_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('document', 'user')

    def __str__(self):
        return f"{self.user.username} -> {self.document.title}"

class RetrievalRequest(models.Model):
    STATUS_CHOICES = (
        ('Pending', 'Pending'),
        ('Approved', 'Approved'),
        ('Rejected', 'Rejected'),
    )
    document = models.ForeignKey(Document, on_delete=models.CASCADE, related_name='retrieval_requests')
    requested_by = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='retrieval_requests')
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='Pending')
    requested_at = models.DateTimeField(auto_now_add=True)
    reviewed_by = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True, blank=True, related_name='reviewed_requests')
    reviewed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-requested_at']

    def __str__(self):
        return f"{self.requested_by.username} -> {self.document.title} [{self.status}]"

class ShareRequest(models.Model):
    STATUS_CHOICES = (
        ('Pending', 'Pending'),
        ('Approved', 'Approved'),
        ('Rejected', 'Rejected'),
    )
    document = models.ForeignKey(Document, on_delete=models.CASCADE, related_name='share_requests')
    requested_by = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='share_requests_made')
    target_user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='share_requests_received')
    can_view = models.BooleanField(default=False)
    can_download = models.BooleanField(default=False)
    can_edit = models.BooleanField(default=False)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='Pending')
    requested_at = models.DateTimeField(auto_now_add=True)
    reviewed_by = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True, blank=True, related_name='reviewed_share_requests')
    reviewed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-requested_at']

    def __str__(self):
        return f"{self.requested_by.username} shares {self.document.title} with {self.target_user.username} [{self.status}]"
