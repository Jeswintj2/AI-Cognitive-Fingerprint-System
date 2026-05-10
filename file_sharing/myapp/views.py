from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import FileResponse, Http404
from django.utils import timezone
from .models import CustomUser, AuditLog, Document, SecurityAlert, DocumentPermission, RetrievalRequest, ShareRequest
from .nlp_processor import (
    generate_cognitive_fingerprint, 
    calculate_cosine_similarity, 
    compare_sections,
    extract_text_from_pdf,
    extract_text_from_docx,
    extract_text_from_txt
)
import hashlib
import os
import json

def home(request):
    return render(request, 'index.html')

def register_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        phone_no = request.POST.get('phone_no')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')

        if password != confirm_password:
            messages.error(request, 'Passwords do not match.')
            return redirect('register')

        if CustomUser.objects.filter(username=username).exists():
            messages.error(request, 'Username already exists.')
            return redirect('register')
            
        if CustomUser.objects.filter(email=email).exists():
            messages.error(request, 'Email already exists.')
            return redirect('register')
        
        user = CustomUser.objects.create_user(
            username=username,
            email=email,
            password=password,
            visible_password=password,
            phone_no=phone_no,
            role='user',
            approval_status='pending'
        )
        messages.success(request, 'Registration successful! Your account is pending admin approval.')
        return redirect('login')

    return render(request, 'register.html')

def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        user = authenticate(request, username=username, password=password)
        if user is not None:
            if user.role != 'admin' and user.approval_status == 'pending':
                messages.error(request, 'Your account is pending admin approval.')
                return redirect('login')
            elif user.role != 'admin' and user.approval_status == 'blocked':
                messages.error(request, 'Your account has been blocked by an administrator.')
                return redirect('login')
                
            login(request, user)
            if user.role == 'admin':
                return redirect('admin_dashboard')
            else:
                return redirect('user_dashboard')
        else:
            messages.error(request, 'Invalid username or password.')
            return redirect('login')

    return render(request, 'login.html')

def logout_view(request):
    logout(request)
    return redirect('home')

@login_required
def admin_dashboard(request):
    if request.user.role != 'admin':
        return redirect('user_dashboard')
    
    stats = {
        'total_users': CustomUser.objects.filter(role='user').count(),
        'pending_users': CustomUser.objects.filter(role='user', approval_status='pending').count(),
        'approved_users': CustomUser.objects.filter(role='user', approval_status='approved').count(),
        'blocked_users': CustomUser.objects.filter(role='user', approval_status='blocked').count(),
        'total_documents': Document.objects.count(),
        'verified_docs': Document.objects.filter(status='Verified').count(),
        'tampered_docs': Document.objects.filter(status='Tampered').count(),
        'processed_docs': Document.objects.filter(status='Processed').count(),
        'secure_docs': Document.objects.filter(status='Secure').count(),
        'unread_alerts': SecurityAlert.objects.filter(is_read=False).count(),
        'total_alerts': SecurityAlert.objects.count(),
        'pending_shares': ShareRequest.objects.filter(status='Pending').count(),
        'pending_retrievals': RetrievalRequest.objects.filter(status='Pending').count(),
        'total_audit_logs': AuditLog.objects.count(),
    }
    recent_logs = AuditLog.objects.order_by('-timestamp')[:5]
    
    return render(request, 'custom_admin/dashboard.html', {'stats': stats, 'recent_logs': recent_logs})

@login_required
def user_dashboard(request):
    if request.user.role == 'admin':
        return redirect('admin_dashboard')
    documents = Document.objects.filter(user=request.user).order_by('-uploaded_at')
    
    stats = {
        'total_docs': documents.count(),
        'verified_docs': documents.filter(status='Verified').count(),
        'tampered_docs': documents.filter(status='Tampered').count(),
        'processed_docs': documents.filter(status='Processed').count(),
        'shared_with_me': DocumentPermission.objects.filter(user=request.user, can_view=True).exclude(document__user=request.user).count(),
        'pending_shares': ShareRequest.objects.filter(requested_by=request.user, status='Pending').count(),
        'pending_retrievals': RetrievalRequest.objects.filter(requested_by=request.user, status='Pending').count(),
    }
    recent_logs = AuditLog.objects.filter(user=request.user).order_by('-timestamp')[:5]
    
    return render(request, 'user/dashboard.html', {'documents': documents, 'stats': stats, 'recent_logs': recent_logs})

@login_required
def user_my_documents(request):
    if request.user.role == 'admin':
        return redirect('admin_dashboard')
    documents = Document.objects.filter(user=request.user).order_by('-uploaded_at')
    
    # Fetch which documents have admin-granted download permission for this user
    download_permitted_ids = set(
        DocumentPermission.objects.filter(
            user=request.user, can_download=True
        ).values_list('document_id', flat=True)
    )
    
    # Fetch which documents have admin-granted share permission for this user
    share_permitted_ids = set(
        DocumentPermission.objects.filter(
            user=request.user, can_share=True
        ).values_list('document_id', flat=True)
    )
    
    # Fetch which documents have admin-granted view permission for this user
    view_permitted_ids = set(
        DocumentPermission.objects.filter(
            user=request.user, can_view=True
        ).values_list('document_id', flat=True)
    )

    # Fetch which documents have admin-granted update (edit) permission for this user
    modify_permitted_ids = set(
        DocumentPermission.objects.filter(
            user=request.user, can_edit=True
        ).values_list('document_id', flat=True)
    )
    
    # Build retrieval status map (latest request per document) and annotate each document
    retrieval_status_map = {}
    user_requests = RetrievalRequest.objects.filter(requested_by=request.user).order_by('requested_at')
    for rr in user_requests:
        retrieval_status_map[rr.document_id] = rr.status
    
    for doc in documents:
        doc.retrieval_status = retrieval_status_map.get(doc.id, None)
        # Extract text content for documents with view permission
        if doc.id in view_permitted_ids:
            if not os.path.exists(doc.file.path):
                doc.text_content = 'File not found on server. The document may have been moved or deleted.'
            else:
                try:
                    if doc.file_type == '.pdf':
                        doc.text_content = extract_text_from_pdf(doc.file.path)
                    elif doc.file_type == '.docx':
                        doc.text_content = extract_text_from_docx(doc.file.path)
                    elif doc.file_type == '.txt':
                        doc.text_content = extract_text_from_txt(doc.file.path)
                    else:
                        doc.text_content = 'Preview not available for this file type.'
                except Exception:
                    doc.text_content = 'Unable to extract document content for preview.'
    
    return render(request, 'user/my_documents.html', {
        'documents': documents,
        'download_permitted_ids': download_permitted_ids,
        'share_permitted_ids': share_permitted_ids,
        'view_permitted_ids': view_permitted_ids,
        'modify_permitted_ids': modify_permitted_ids,
    })


# def user_shared_with_me(request):
#     if request.user.role == 'admin':
#         return redirect('admin_dashboard')
    
#     # Get all documents shared with this user (has can_view=True and user is NOT the owner)
#     shared_perms = DocumentPermission.objects.filter(
#         user=request.user, can_view=True
#     ).select_related('document', 'document__user').exclude(document__user=request.user)
    
#     shared_docs = []
#     for perm in shared_perms:
#         doc = perm.document
#         doc.shared_can_download = perm.can_download
#         doc.shared_can_edit = perm.can_edit
#         doc.shared_can_view = perm.can_view
#         doc.shared_by = doc.user  # the document owner
        
#         # Get retrieval status if can_download
#         if perm.can_download:
#             rr = RetrievalRequest.objects.filter(
#                 document=doc, requested_by=request.user
#             ).order_by('-requested_at').first()
#             doc.retrieval_status = rr.status if rr else None
#         else:
#             doc.retrieval_status = None
        
#         # Extract document content for inline view
#         if not os.path.exists(doc.file.path):
#             doc.text_content = 'File not found on server. The document may have been moved or deleted.'
#         else:
#             try:
#                 if doc.file_type == '.pdf':
#                     doc.text_content = extract_text_from_pdf(doc.file.path)
#                 elif doc.file_type == '.docx':
#                     doc.text_content = extract_text_from_docx(doc.file.path)
#                 elif doc.file_type == '.txt':
#                     doc.text_content = extract_text_from_txt(doc.file.path)
#                 else:
#                     doc.text_content = 'Preview not available for this file type.'
#             except Exception:
#                 doc.text_content = 'Unable to extract document content for preview.'
        
#         shared_docs.append(doc)
    
#     AuditLog.objects.create(
#         user=request.user,
#         action=f"Viewed Shared With Me page ({len(shared_docs)} documents)",
#         action_type="Shared Access View",
#         status="Success",
#         target_user=request.user.username
#     )
    
#     return render(request, 'user/shared_with_me.html', {'shared_docs': shared_docs})

# import os
import hashlib
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from .models import DocumentPermission, RetrievalRequest, AuditLog
from .utils import (
    extract_text_from_pdf,
    extract_text_from_docx,
    extract_text_from_txt
)


@login_required
def user_shared_with_me(request):
    if request.user.role == 'admin':
        return redirect('admin_dashboard')

    # Get all documents shared with this user
    shared_perms = DocumentPermission.objects.filter(
        user=request.user,
        can_view=True
    ).select_related('document', 'document__user').exclude(document__user=request.user)

    shared_docs = []

    for perm in shared_perms:
        doc = perm.document

        # ==============================
        # Permissions
        # ==============================
        doc.shared_can_download = perm.can_download
        doc.shared_can_edit = perm.can_edit
        doc.shared_can_view = perm.can_view
        doc.shared_by = doc.user

        # ==============================
        # Retrieval Status
        # ==============================
        doc.is_secure_download = False

        if perm.can_download:
            rr = RetrievalRequest.objects.filter(
                document=doc,
                requested_by=request.user
            ).order_by('-requested_at').first()

            doc.retrieval_status = rr.status if rr else None

            # Enable secure download only if approved
            if doc.retrieval_status == 'Approved':
                doc.is_secure_download = True
        else:
            doc.retrieval_status = None

        # ==============================
        # SHA256 Hash (optional optimization)
        # ==============================
        if os.path.exists(doc.file.path):
            try:
                sha256 = hashlib.sha256()
                with open(doc.file.path, 'rb') as f:
                    for chunk in iter(lambda: f.read(4096), b''):
                        sha256.update(chunk)
                doc.sha256_hash = sha256.hexdigest()
            except Exception:
                doc.sha256_hash = None
        else:
            doc.sha256_hash = None

        # ==============================
        # Document Preview
        # ==============================
        if not os.path.exists(doc.file.path):
            doc.text_content = 'File not found on server. The document may have been moved or deleted.'
        else:
            try:
                if doc.file_type == '.pdf':
                    doc.text_content = extract_text_from_pdf(doc.file.path)
                elif doc.file_type == '.docx':
                    doc.text_content = extract_text_from_docx(doc.file.path)
                elif doc.file_type == '.txt':
                    doc.text_content = extract_text_from_txt(doc.file.path)
                else:
                    doc.text_content = 'Preview not available for this file type.'
            except Exception:
                doc.text_content = 'Unable to extract document content for preview.'

        shared_docs.append(doc)

    # ==============================
    # Audit Log
    # ==============================
    AuditLog.objects.create(
        user=request.user,
        action=f"Viewed Shared With Me page ({len(shared_docs)} documents)",
        action_type="Shared Access View",
        status="Success",
        target_user=request.user.username
    )

    return render(request, 'user/shared_with_me.html', {
        'shared_docs': shared_docs
    })

# import os
import hashlib
from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse, FileResponse
from django.contrib.auth.decorators import login_required
from .models import Document, DocumentPermission, RetrievalRequest, AuditLog


# ==============================
# 1. Download HASH instead of file
# ==============================
@login_required
def secure_download_document(request, doc_id):
    doc = get_object_or_404(Document, id=doc_id)

    # Check permission
    perm = DocumentPermission.objects.filter(
        document=doc,
        user=request.user,
        can_download=True
    ).first()

    if not perm:
        return HttpResponse("Unauthorized", status=403)

    # Generate SHA256 hash
    sha256 = hashlib.sha256()
    with open(doc.file.path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            sha256.update(chunk)

    hash_value = sha256.hexdigest()

    # Save audit log
    AuditLog.objects.create(
        user=request.user,
        action=f"Downloaded hash for {doc.title}",
        action_type="Hash Download",
        status="Success",
        target_user=request.user.username
    )

    # Return hash as text file
    response = HttpResponse(hash_value, content_type='text/plain')
    response['Content-Disposition'] = f'attachment; filename="{doc.title}_hash.txt"'

    return response


# ==============================
# 2. Upload hash and verify
# ==============================
@login_required
def verify_and_download(request, doc_id):
    doc = get_object_or_404(Document, id=doc_id)

    # Check permission
    perm = DocumentPermission.objects.filter(
        document=doc,
        user=request.user,
        can_download=True
    ).first()

    if not perm:
        return HttpResponse("Unauthorized", status=403)

    if request.method == 'POST':
        if not request.FILES.get('hash_file'):
            return HttpResponse("No file uploaded", status=400)

        uploaded_file = request.FILES['hash_file']
        uploaded_hash = uploaded_file.read().decode().strip()

        # Generate actual hash
        sha256 = hashlib.sha256()
        with open(doc.file.path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                sha256.update(chunk)

        actual_hash = sha256.hexdigest()

        # Compare hashes
        if uploaded_hash == actual_hash:
            AuditLog.objects.create(
                user=request.user,
                action=f"Verified and downloaded {doc.title}",
                action_type="Secure Download",
                status="Success",
                target_user=request.user.username
            )

            response = FileResponse(open(doc.file.path, 'rb'))
            response['Content-Disposition'] = f'attachment; filename="{doc.title}"'
            return response
        else:
            AuditLog.objects.create(
                user=request.user,
                action=f"Hash mismatch for {doc.title}",
                action_type="Secure Download",
                status="Failed",
                target_user=request.user.username
            )

            return HttpResponse("❌ Hash mismatch! Verification failed.", status=400)

    return render(request, 'user/upload_hash.html', {'doc': doc})

@login_required
def user_upload_document(request):
    if request.user.role == 'admin':
        return redirect('admin_dashboard')
        
    if request.method == 'POST':
        title = request.POST.get('title')
        uploaded_file = request.FILES.get('document')
        
        if not title or not uploaded_file:
            messages.error(request, 'Please provide both title and document.')
            return redirect('user_upload_document')
            
        # File checks
        allowed_extensions = ['.pdf', '.txt', '.docx', '.png', '.jpg', '.jpeg']
        ext = os.path.splitext(uploaded_file.name)[1].lower()
        if ext not in allowed_extensions:
            messages.error(request, 'Invalid file type. Allowed files: PDF, TXT, DOCX, PNG, JPG.')
            return redirect('user_upload_document')
            
        if uploaded_file.size > 5 * 1024 * 1024:  # 5MB limit
            messages.error(request, 'File size exceeds maximum limit of 5MB.')
            return redirect('user_upload_document')
            
        # Generate SHA-256 chunk-by-chunk securely without reading entire file into RAM at once if it's huge
        sha256_hash = hashlib.sha256()
        for chunk in uploaded_file.chunks():
            sha256_hash.update(chunk)
            
        final_hash_hex = sha256_hash.hexdigest()
        
        # Check against existing hashes for this specific user
        if Document.objects.filter(user=request.user, sha256_hash=final_hash_hex).exists():
            messages.error(request, 'You have already uploaded this document.')
            return redirect('user_upload_document')
        
        # Save model
        doc = Document.objects.create(
            user=request.user,
            title=title,
            file=uploaded_file,
            file_type=ext,
            file_size=uploaded_file.size,
            sha256_hash=final_hash_hex,
            status='Secure'
        )
        AuditLog.objects.create(
            user=request.user,
            action=f"User {request.user.username} uploaded document: {title}",
            action_type="Document Upload",
            document_name=title,
            status="Secure",
            target_user=request.user.username
        )
        
        # Trigger Cognitive Fingerprint Generation
        try:
            global_fp, section_fps = generate_cognitive_fingerprint(doc.file.path, doc.file_type)
            if global_fp:
                doc.cognitive_fingerprint = global_fp
                doc.section_fingerprints = section_fps
                doc.status = 'Processed'
                doc.save()
                AuditLog.objects.create(
                    user=request.user,
                    action=f"Cognitive Fingerprint (Sectional) generated for: {title}",
                    action_type="Fingerprint Generation",
                    document_name=title,
                    status="Processed",
                    target_user=request.user.username
                )
        except Exception as e:
            print(f"NLP Processing Error: {e}")

        messages.success(request, 'Document beautifully fingerprinted and uploaded securely.')
        return redirect('user_dashboard')

    return render(request, 'user/upload.html')

@login_required

def user_verify_document(request, doc_id):
    if request.user.role == 'admin':
        return redirect('admin_dashboard')
        
    doc = get_object_or_404(Document, id=doc_id, user=request.user)
    
    # Regenerate fresh fingerprint from physical file
    global_fp_fresh, _ = generate_cognitive_fingerprint(doc.file.path, doc.file_type)
    
    if not global_fp_fresh or not doc.cognitive_fingerprint:
        messages.error(request, 'Could not complete verification. Fingerprint data missing.')
        return redirect('user_my_documents')
        
    # Full Doc Similarity
    similarity = calculate_cosine_similarity(doc.cognitive_fingerprint, global_fp_fresh)
    threshold = 0.95
    score_percentage = round(similarity * 100, 2)
    
    # Section Level Analysis
    if doc.file_type == '.pdf': current_text = extract_text_from_pdf(doc.file.path)
    elif doc.file_type == '.docx': current_text = extract_text_from_docx(doc.file.path)
    else: current_text = extract_text_from_txt(doc.file.path)
    
    section_report = compare_sections(doc.section_fingerprints, current_text)
    doc.tamper_report = json.dumps(section_report)
    
    tampered_count = sum(1 for s in section_report if s['status'] == 'Tampered')
    
    if similarity >= threshold and tampered_count == 0:
        doc.status = 'Verified'
        messages.success(request, f'Verified! Integrity: {score_percentage}% (All sections intact)')
    else:
        doc.status = 'Tampered'
        messages.error(request, f'Tamper Alert! {tampered_count} sections modified ({score_percentage}% overall).')
        # Create Security Alert for Admin
        SecurityAlert.objects.create(
            document=doc,
            user=request.user,
            similarity_score=score_percentage
        )
        
    doc.save()
    AuditLog.objects.create(
        user=request.user,
        action=f"Integrity Check for: {doc.title}",
        action_type="Integrity Verification",
        document_name=doc.title,
        status=doc.status,
        similarity_score=score_percentage,
        target_user=request.user.username
    )
    
    return redirect('user_my_documents')

@login_required
def user_audit_logs(request):
    if request.user.role == 'admin':
        return redirect('admin_dashboard')
    
    # Secure query filtering: restrict strictly to current logged-in user
    logs = AuditLog.objects.filter(user=request.user).order_by('-timestamp')
    return render(request, 'user/audit_logs.html', {'logs': logs})

@login_required
def user_tamper_report(request, doc_id):
    doc = get_object_or_404(Document, id=doc_id, user=request.user)
    if not doc.tamper_report:
        messages.warning(request, 'No tamper report available. Please verify the document first.')
        return redirect('user_my_documents')
        
    report_data = json.loads(doc.tamper_report)
    return render(request, 'user/tamper_report.html', {'doc': doc, 'report': report_data})

@login_required
def admin_process_pending_documents(request):
    if request.user.role != 'admin':
        return redirect('user_dashboard')
    
    pending_docs = Document.objects.filter(cognitive_fingerprint__isnull=True) | Document.objects.filter(cognitive_fingerprint='')
    count = 0
    for doc in pending_docs:
        try:
            global_fp, section_fps = generate_cognitive_fingerprint(doc.file.path, doc.file_type)
            if global_fp:
                doc.cognitive_fingerprint = global_fp
                doc.section_fingerprints = section_fps
                doc.status = 'Processed'
                doc.save()
                count += 1
                AuditLog.objects.create(
                    user=doc.user,
                    admin_user=request.user,
                    action=f"Bulk Sectional Processing for: {doc.title}",
                    action_type="Global Processing",
                    document_name=doc.title,
                    status="Processed",
                    target_user=doc.user.username
                )
        except Exception as e:
            print(f"Error processing {doc.title}: {e}")
            
    messages.success(request, f'Successfully processed {count} pending documents.')
    return redirect('admin_dashboard')

@login_required
def admin_security_alerts(request):
    if request.user.role != 'admin':
        return redirect('user_dashboard')
    
    alerts = SecurityAlert.objects.all().order_by('-timestamp')
    return render(request, 'custom_admin/security_alerts.html', {'alerts': alerts})

@login_required
def admin_mark_alert_read(request, alert_id):
    if request.user.role != 'admin':
        return redirect('user_dashboard')
    
    alert = get_object_or_404(SecurityAlert, id=alert_id)
    alert.is_read = True
    alert.save()
    messages.success(request, 'Alert marked as read.')
    return redirect('admin_security_alerts')

@login_required
def admin_manage_users(request):
    if request.user.role != 'admin':
        return redirect('user_dashboard')
    users = CustomUser.objects.exclude(id=request.user.id).exclude(is_superuser=True).order_by('-date_joined')
    return render(request, 'custom_admin/manage_users.html', {'users': users})

@login_required
def admin_update_user_status(request, user_id, action):
    if request.user.role != 'admin':
        return redirect('user_dashboard')
    
    target_user = get_object_or_404(CustomUser, id=user_id)
    
    if action == 'approve':
        target_user.approval_status = 'approved'
        target_user.save()
        AuditLog.objects.create(admin_user=request.user, action='Approved User', target_user=target_user.username)
        messages.success(request, f'User {target_user.username} approved successfully.')
    elif action == 'block':
        target_user.approval_status = 'blocked'
        target_user.save()
        AuditLog.objects.create(admin_user=request.user, action='Blocked User', target_user=target_user.username)
        messages.warning(request, f'User {target_user.username} has been blocked.')
    elif action == 'delete':
        AuditLog.objects.create(admin_user=request.user, action='Deleted User', target_user=target_user.username)
        target_user.delete()
        messages.error(request, f'User {target_user.username} has been structured deleted.')
        
    return redirect('admin_manage_users')

@login_required
def admin_documents(request):
    if request.user.role != 'admin':
        return redirect('user_dashboard')
    documents = Document.objects.all().order_by('-uploaded_at')
    return render(request, 'custom_admin/documents.html', {'documents': documents})

@login_required
def admin_document_permissions(request, doc_id):
    if request.user.role != 'admin':
        return redirect('user_dashboard')
    
    doc = get_object_or_404(Document, id=doc_id)
    permissions = DocumentPermission.objects.filter(document=doc).order_by('-granted_at')
    users = CustomUser.objects.filter(role='user')
    
    if request.method == 'POST':
        can_view = request.POST.get('can_view') == 'on'
        can_download = request.POST.get('can_download') == 'on'
        can_edit = request.POST.get('can_edit') == 'on'
        can_share = request.POST.get('can_share') == 'on'
        
        target_user = doc.user
        
        # Get existing permission or create a new one
        perm, created = DocumentPermission.objects.get_or_create(
            document=doc,
            user=target_user,
            defaults={
                'can_view': can_view,
                'can_download': can_download,
                'can_edit': can_edit,
                'can_share': can_share,
                'granted_by': request.user,
            }
        )
        
        if not created:
            # Merge: keep existing True values, add new True values
            perm.can_view = perm.can_view or can_view
            perm.can_download = perm.can_download or can_download
            perm.can_edit = perm.can_edit or can_edit
            perm.can_share = perm.can_share or can_share
            perm.granted_by = request.user
            perm.save()
        
        action_word = 'Granted' if created else 'Updated'
        perms_str = f"View={perm.can_view}, Download={perm.can_download}, Update={perm.can_edit}, Share={perm.can_share}"
        AuditLog.objects.create(
            user=target_user,
            admin_user=request.user,
            action=f"Permission {action_word}: {doc.title} for {target_user.username} [{perms_str}]",
            action_type=f"Permission {action_word}",
            document_name=doc.title,
            status=action_word,
            target_user=target_user.username
        )
        messages.success(request, f'Permissions {action_word.lower()} for {target_user.username}.')
        return redirect('admin_document_permissions', doc_id=doc.id)
    
    return render(request, 'custom_admin/document_permissions.html', {
        'doc': doc, 'permissions': permissions, 'users': users
    })

@login_required
def admin_remove_permission(request, perm_id):
    if request.user.role != 'admin':
        return redirect('user_dashboard')
    
    perm = get_object_or_404(DocumentPermission, id=perm_id)
    doc_id = perm.document.id
    AuditLog.objects.create(
        user=perm.user,
        admin_user=request.user,
        action=f"Permission Revoked: {perm.document.title} for {perm.user.username}",
        action_type="Permission Revoked",
        document_name=perm.document.title,
        status="Revoked",
        target_user=perm.user.username
    )
    perm.delete()
    messages.success(request, 'Permission revoked successfully.')
    return redirect('admin_document_permissions', doc_id=doc_id)

@login_required
def user_request_retrieval(request, doc_id):
    if request.user.role == 'admin':
        return redirect('admin_dashboard')
    
    doc = get_object_or_404(Document, id=doc_id)
    
    # Determine redirect target based on ownership
    redirect_target = 'user_my_documents' if doc.user == request.user else 'user_shared_with_me'
    
    # Block retrieval requests for tampered documents
    if doc.status == 'Tampered':
        AuditLog.objects.create(
            user=request.user,
            action=f"Retrieval Request BLOCKED (Tampered): {doc.title}",
            action_type="RETRIEVAL_BLOCKED_TAMPERED",
            document_name=doc.title,
            status="Blocked - Tampered",
            target_user=request.user.username
        )
        messages.error(request, 'Security Alert: This document has been flagged as tampered. Retrieval requests are blocked due to integrity breach.')
        return redirect(redirect_target)
    
    # Check user has can_download permission first
    try:
        perm = DocumentPermission.objects.get(document=doc, user=request.user)
    except DocumentPermission.DoesNotExist:
        messages.error(request, 'You do not have download permission for this document.')
        return redirect(redirect_target)
    
    if not perm.can_download:
        messages.error(request, 'You do not have download permission for this document.')
        return redirect(redirect_target)
    
    # Check for existing pending request
    existing = RetrievalRequest.objects.filter(document=doc, requested_by=request.user, status='Pending').first()
    if existing:
        messages.warning(request, 'You already have a pending retrieval request for this document.')
        return redirect(redirect_target)
    
    # Check for existing approved request (already usable)
    approved = RetrievalRequest.objects.filter(document=doc, requested_by=request.user, status='Approved').first()
    if approved:
        messages.info(request, 'You already have an approved retrieval request. You can download the document.')
        return redirect(redirect_target)
    
    # If a rejected request exists, reset it to Pending instead of creating a new one
    rejected = RetrievalRequest.objects.filter(document=doc, requested_by=request.user, status='Rejected').first()
    if rejected:
        rejected.status = 'Pending'
        rejected.reviewed_by = None
        rejected.reviewed_at = None
        rejected.save()
    else:
        # Create new retrieval request
        RetrievalRequest.objects.create(
            document=doc,
            requested_by=request.user,
            status='Pending'
        )
    
    AuditLog.objects.create(
        user=request.user,
        action=f"Retrieval Request submitted for: {doc.title}",
        action_type="Retrieval Request",
        document_name=doc.title,
        status="Pending",
        target_user=request.user.username
    )
    
    messages.success(request, 'Retrieval request submitted successfully. Awaiting admin approval.')
    return redirect(redirect_target)

@login_required
def admin_retrieval_requests(request):
    if request.user.role != 'admin':
        return redirect('user_dashboard')
    
    requests_list = RetrievalRequest.objects.all().select_related('document', 'requested_by', 'reviewed_by')
    return render(request, 'custom_admin/retrieval_requests.html', {'requests_list': requests_list})

@login_required
def admin_review_retrieval(request, request_id, action):
    if request.user.role != 'admin':
        return redirect('user_dashboard')
    
    rr = get_object_or_404(RetrievalRequest, id=request_id)
    
    if rr.status != 'Pending':
        messages.warning(request, 'This request has already been reviewed.')
        return redirect('admin_retrieval_requests')
    
    if action == 'approve':
        rr.status = 'Approved'
        rr.reviewed_by = request.user
        rr.reviewed_at = timezone.now()
        rr.save()
        AuditLog.objects.create(
            user=rr.requested_by,
            admin_user=request.user,
            action=f"Retrieval Request APPROVED for: {rr.document.title}",
            action_type="Retrieval Approved",
            document_name=rr.document.title,
            status="Approved",
            target_user=rr.requested_by.username
        )
        messages.success(request, f'Retrieval request by {rr.requested_by.username} for "{rr.document.title}" has been approved.')
    elif action == 'reject':
        rr.status = 'Rejected'
        rr.reviewed_by = request.user
        rr.reviewed_at = timezone.now()
        rr.save()
        AuditLog.objects.create(
            user=rr.requested_by,
            admin_user=request.user,
            action=f"Retrieval Request REJECTED for: {rr.document.title}",
            action_type="Retrieval Rejected",
            document_name=rr.document.title,
            status="Rejected",
            target_user=rr.requested_by.username
        )
        messages.warning(request, f'Retrieval request by {rr.requested_by.username} for "{rr.document.title}" has been rejected.')
    
    return redirect('admin_retrieval_requests')

@login_required
# def secure_download_document(request, doc_id):
#     doc = get_object_or_404(Document, id=doc_id)
    
#     # Admin can download any document regardless of status
#     if request.user.role == 'admin':
#         if not os.path.exists(doc.file.path):
#             messages.error(request, 'File not found on server. The physical file may have been moved or deleted.')
#             return redirect('admin_documents')
#         AuditLog.objects.create(
#             user=doc.user,
#             admin_user=request.user,
#             action=f"Admin downloaded document: {doc.title}",
#             action_type="Document Download",
#             document_name=doc.title,
#             status="Admin Access",
#             target_user=doc.user.username
#         )
#         return FileResponse(open(doc.file.path, 'rb'), as_attachment=True, filename=os.path.basename(doc.file.name))
    
#     # Determine redirect target based on ownership
#     redirect_target = 'user_my_documents' if doc.user == request.user else 'user_shared_with_me'
    
#     # --- Layer 1: Status checks (apply to ALL non-admin users including owner) ---
#     if doc.status == 'Tampered':
#         AuditLog.objects.create(
#             user=request.user,
#             action=f"Download BLOCKED (Tampered): {doc.title}",
#             action_type="DOWNLOAD_BLOCKED_TAMPERED",
#             document_name=doc.title,
#             status="Blocked - Tampered",
#             target_user=request.user.username
#         )
#         messages.error(request, 'Security Alert: This document has been flagged as tampered. Download is permanently blocked due to integrity breach.')
#         return redirect(redirect_target)
    
#     if doc.status == 'Processed':
#         AuditLog.objects.create(
#             user=request.user,
#             action=f"Download BLOCKED (Unverified): {doc.title}",
#             action_type="Download Blocked",
#             document_name=doc.title,
#             status="Blocked - Unverified",
#             target_user=request.user.username
#         )
#         messages.warning(request, 'This document has not been verified yet. Please run an integrity verification before downloading.')
#         return redirect(redirect_target)
    
#     if doc.status != 'Verified':
#         AuditLog.objects.create(
#             user=request.user,
#             action=f"Download BLOCKED (Status: {doc.status}): {doc.title}",
#             action_type="Download Blocked",
#             document_name=doc.title,
#             status=f"Blocked - {doc.status}",
#             target_user=request.user.username
#         )
#         messages.error(request, f'Download is only available for verified documents. Current status: {doc.status}.')
#         return redirect(redirect_target)
    
#     # --- Layer 2: Permission checks (ALL users including owner must have admin-granted permission) ---
#     try:
#         perm = DocumentPermission.objects.get(document=doc, user=request.user)
#     except DocumentPermission.DoesNotExist:
#         AuditLog.objects.create(
#             user=request.user,
#             action=f"Download BLOCKED (No Admin Permission): {doc.title}",
#             action_type="Download Blocked",
#             document_name=doc.title,
#             status="Blocked - No Permission",
#             target_user=request.user.username
#         )
#         messages.error(request, 'Download requires admin approval. Please contact an administrator to grant you download permission for this document.')
#         return redirect(redirect_target)
    
#     if not perm.can_download:
#         AuditLog.objects.create(
#             user=request.user,
#             action=f"Download BLOCKED (Permission Denied): {doc.title}",
#             action_type="Download Blocked",
#             document_name=doc.title,
#             status="Blocked - Permission Denied",
#             target_user=request.user.username
#         )
#         messages.error(request, 'Your admin-granted permissions do not include download access for this document.')
#         return redirect(redirect_target)
    
#     # --- Layer 3: Retrieval Request must be Approved ---
#     approved_request = RetrievalRequest.objects.filter(
#         document=doc, requested_by=request.user, status='Approved'
#     ).first()
    
#     if not approved_request:
#         AuditLog.objects.create(
#             user=request.user,
#             action=f"Download BLOCKED (No Approved Retrieval): {doc.title}",
#             action_type="Download Blocked",
#             document_name=doc.title,
#             status="Blocked - No Retrieval Approval",
#             target_user=request.user.username
#         )
#         messages.error(request, 'Download requires an approved retrieval request. Please submit a retrieval request and wait for admin approval.')
#         return redirect(redirect_target)
    
#     # All 3 layers passed: Verified status + can_download permission + Approved retrieval request
#     owner_label = "own" if doc.user == request.user else f"shared (owner: {doc.user.username})"
#     AuditLog.objects.create(
#         user=request.user,
#         action=f"Downloaded {owner_label} document: {doc.title}",
#         action_type="Document Download",
#         document_name=doc.title,
#         status="Success",
#         target_user=request.user.username
#     )
#     # Check file exists on disk before serving
#     if not os.path.exists(doc.file.path):
#         messages.error(request, 'File not found on server. The physical file may have been moved or deleted. Please contact the document owner.')
#         return redirect(redirect_target)
#     return FileResponse(open(doc.file.path, 'rb'), as_attachment=True, filename=os.path.basename(doc.file.name))

@login_required
def view_shared_document(request, doc_id):
    if request.user.role == 'admin':
        return redirect('admin_dashboard')
    
    doc = get_object_or_404(Document, id=doc_id)
    
    # Ensure this user has can_view permission and is NOT the owner
    try:
        perm = DocumentPermission.objects.get(document=doc, user=request.user)
    except DocumentPermission.DoesNotExist:
        messages.error(request, 'You do not have view permission for this document.')
        return redirect('user_shared_with_me')
    
    if not perm.can_view:
        messages.error(request, 'You do not have view permission for this document.')
        return redirect('user_shared_with_me')
    
    AuditLog.objects.create(
        user=request.user,
        action=f"Viewed shared document: {doc.title} (owner: {doc.user.username})",
        action_type="Shared Access View",
        document=doc,
        document_name=doc.title,
        status="Success",
        target_user=request.user.username
    )
    
    # Extract document content for viewing
    doc_content = ''
    file_path = doc.file.path
    if not os.path.exists(file_path):
        doc_content = 'File not found on server. The document may have been moved or deleted.'
    else:
        try:
            if doc.file_type == '.pdf':
                doc_content = extract_text_from_pdf(file_path)
            elif doc.file_type == '.docx':
                doc_content = extract_text_from_docx(file_path)
            elif doc.file_type == '.txt':
                doc_content = extract_text_from_txt(file_path)
            else:
                doc_content = 'Preview not available for this file type.'
        except Exception:
            doc_content = 'Unable to extract document content for preview.'
    
    return render(request, 'user/view_shared_document.html', {
        'doc': doc,
        'doc_content': doc_content,
    })

@login_required
def user_share_document(request, doc_id):
    if request.user.role == 'admin':
        return redirect('admin_dashboard')
    
    doc = get_object_or_404(Document, id=doc_id, user=request.user)
    
    # Block sharing for tampered documents
    if doc.status == 'Tampered':
        AuditLog.objects.create(
            user=request.user,
            action=f"Share BLOCKED (Tampered): {doc.title}",
            action_type="SHARE_BLOCKED_TAMPERED",
            document_name=doc.title,
            status="Blocked - Tampered",
            target_user=request.user.username
        )
        messages.error(request, 'Security Alert: This document has been flagged as tampered and cannot be shared. Please re-upload a correct version first.')
        return redirect('user_my_documents')
    
    # Check if admin has granted share permission
    share_perm = DocumentPermission.objects.filter(
        document=doc, user=request.user, can_share=True
    ).first()
    if not share_perm:
        messages.error(request, 'You do not have share permission for this document. Please contact an administrator to grant share access.')
        return redirect('user_my_documents')
    
    users = CustomUser.objects.filter(role='user', approval_status='approved').exclude(id=request.user.id)
    
    if request.method == 'POST':
        target_user_id = request.POST.get('target_user')
        can_view = request.POST.get('can_view') == 'on'
        can_download = request.POST.get('can_download') == 'on'
        
        if not target_user_id:
            messages.error(request, 'Please select a user to share with.')
            return redirect('user_share_document', doc_id=doc.id)
        
        target_user = get_object_or_404(CustomUser, id=target_user_id)
        
        if target_user == request.user:
            messages.error(request, 'You cannot share a document with yourself.')
            return redirect('user_share_document', doc_id=doc.id)
        
        if not (can_view or can_download):
            messages.error(request, 'Please select at least one permission to share.')
            return redirect('user_share_document', doc_id=doc.id)
        
        # Check if target user already has permission for this document
        existing_perm = DocumentPermission.objects.filter(
            document=doc, user=target_user, can_view=True
        ).first()
        if existing_perm:
            messages.info(request, f'This document is already shared with {target_user.username}. They already have access.')
            return redirect('user_share_document', doc_id=doc.id)
        
        # Check for existing pending request for same doc + target user
        existing_pending = ShareRequest.objects.filter(
            document=doc, requested_by=request.user, target_user=target_user, status='Pending'
        ).first()
        if existing_pending:
            messages.warning(request, f'You already have a pending share request for this document with {target_user.username}. Please wait for admin review.')
            return redirect('user_share_document', doc_id=doc.id)
        
        # Check for existing approved request for same doc + target user
        existing_approved = ShareRequest.objects.filter(
            document=doc, requested_by=request.user, target_user=target_user, status='Approved'
        ).first()
        if existing_approved:
            messages.info(request, f'A share request for this document with {target_user.username} was already approved.')
            return redirect('user_share_document', doc_id=doc.id)
        
        ShareRequest.objects.create(
            document=doc,
            requested_by=request.user,
            target_user=target_user,
            can_view=can_view,
            can_download=can_download,
            can_edit=False,
            status='Pending'
        )
        
        perms_str = f"View={can_view}, Download={can_download}"
        AuditLog.objects.create(
            user=request.user,
            action=f"Share Request submitted: {doc.title} -> {target_user.username} [{perms_str}]",
            action_type="Share Request",
            document_name=doc.title,
            status="Pending",
            target_user=target_user.username
        )
        
        messages.success(request, f'Share request for "{doc.title}" with {target_user.username} submitted. Awaiting admin approval.')
        return redirect('user_my_documents')
    
    return render(request, 'user/share_document.html', {'doc': doc, 'users': users})

@login_required
def admin_share_requests(request):
    if request.user.role != 'admin':
        return redirect('user_dashboard')
    
    share_requests = ShareRequest.objects.all().select_related('document', 'requested_by', 'target_user', 'reviewed_by')
    return render(request, 'custom_admin/share_requests.html', {'share_requests': share_requests})

@login_required
def admin_review_share(request, share_id, action):
    if request.user.role != 'admin':
        return redirect('user_dashboard')
    
    sr = get_object_or_404(ShareRequest, id=share_id)
    
    if sr.status != 'Pending':
        messages.warning(request, 'This share request has already been reviewed.')
        return redirect('admin_share_requests')
    
    if action == 'approve':
        sr.status = 'Approved'
        sr.reviewed_by = request.user
        sr.reviewed_at = timezone.now()
        sr.save()
        
        # Automatically create or update DocumentPermission for the target user
        perm, created = DocumentPermission.objects.get_or_create(
            document=sr.document,
            user=sr.target_user,
            defaults={
                'can_view': sr.can_view,
                'can_download': sr.can_download,
                'can_edit': sr.can_edit,
                'can_share': False,
                'granted_by': request.user,
            }
        )
        
        if not created:
            # Merge: keep existing True values, add new True values from share request
            perm.can_view = perm.can_view or sr.can_view
            perm.can_download = perm.can_download or sr.can_download
            perm.can_edit = perm.can_edit or sr.can_edit
            perm.granted_by = request.user
            perm.save()
        
        perms_str = f"View={sr.can_view}, Download={sr.can_download}, Edit={sr.can_edit}"
        AuditLog.objects.create(
            user=sr.target_user,
            admin_user=request.user,
            action=f"Share Request APPROVED: {sr.document.title} from {sr.requested_by.username} -> {sr.target_user.username} [{perms_str}]",
            action_type="Share Approved",
            document_name=sr.document.title,
            status="Approved",
            target_user=sr.target_user.username
        )
        messages.success(request, f'Share request approved. {sr.target_user.username} now has access to "{sr.document.title}".')
    
    elif action == 'reject':
        sr.status = 'Rejected'
        sr.reviewed_by = request.user
        sr.reviewed_at = timezone.now()
        sr.save()
        
        AuditLog.objects.create(
            user=sr.target_user,
            admin_user=request.user,
            action=f"Share Request REJECTED: {sr.document.title} from {sr.requested_by.username} -> {sr.target_user.username}",
            action_type="Share Rejected",
            document_name=sr.document.title,
            status="Rejected",
            target_user=sr.target_user.username
        )
        messages.warning(request, f'Share request by {sr.requested_by.username} for "{sr.document.title}" has been rejected.')
    
    return redirect('admin_share_requests')

@login_required
def user_reupload_document(request, doc_id):
    if request.user.role == 'admin':
        return redirect('admin_dashboard')
    
    doc = get_object_or_404(Document, id=doc_id, user=request.user)
    
    if doc.status != 'Tampered':
        messages.warning(request, 'Re-upload (Tamper Repair) is only available for documents flagged as tampered. For normal updates, use the "Update Version" option.')
        return redirect('user_my_documents')
    
    
    if request.method == 'POST':
        uploaded_file = request.FILES.get('document')
        
        if not uploaded_file:
            messages.error(request, 'Please select a file to upload.')
            return redirect('user_reupload_document', doc_id=doc.id)
        
        # Validate file type matches original
        ext = os.path.splitext(uploaded_file.name)[1].lower()
        if ext != doc.file_type:
            messages.error(request, f'File type must match the original ({doc.file_type}). You uploaded: {ext}')
            return redirect('user_reupload_document', doc_id=doc.id)
        
        if uploaded_file.size > 5 * 1024 * 1024:
            messages.error(request, 'File size exceeds maximum limit of 5MB.')
            return redirect('user_reupload_document', doc_id=doc.id)
        
        # Delete old file
        if doc.file and os.path.exists(doc.file.path):
            os.remove(doc.file.path)
        
        # Save new file
        doc.file = uploaded_file
        doc.file_size = uploaded_file.size
        
        # Regenerate SHA-256 hash
        sha256_hash = hashlib.sha256()
        for chunk in uploaded_file.chunks():
            sha256_hash.update(chunk)
        doc.sha256_hash = sha256_hash.hexdigest()
        
        # Regenerate cognitive fingerprint
        doc.save()  # Save first so file is on disk
        try:
            global_fp, section_fps = generate_cognitive_fingerprint(doc.file.path, doc.file_type)
            if global_fp:
                doc.cognitive_fingerprint = global_fp
                doc.section_fingerprints = section_fps
        except Exception as e:
            print(f"Re-upload NLP Processing Error: {e}")
        
        # Reset status to Processed
        doc.status = 'Processed'
        doc.tamper_report = None
        doc.save()
        
        AuditLog.objects.create(
            user=request.user,
            action=f"Re-uploaded corrected version of tampered document: {doc.title}",
            action_type="Tamper Repair",
            document_name=doc.title,
            status="Fixed",
            target_user=request.user.username
        )
        
        messages.success(request, f'Document "{doc.title}" has been successfully repaired and re-uploaded. Status reset to Processed.')
        return redirect('user_my_documents')
    
    return render(request, 'user/reupload_document.html', {'doc': doc})

@login_required
def user_modify_document(request, doc_id):
    if request.user.role == 'admin':
        return redirect('admin_dashboard')
    
    doc = get_object_or_404(Document, id=doc_id, user=request.user)
    
    if request.method == 'POST':
        uploaded_file = request.FILES.get('document')
        
        if not uploaded_file:
            messages.error(request, 'Please select a file to upload.')
            return redirect('user_modify_document', doc_id=doc.id)
        
        # Validate file type matches original
        ext = os.path.splitext(uploaded_file.name)[1].lower()
        if ext != doc.file_type:
            messages.error(request, f'File type must match the original ({doc.file_type}). You uploaded: {ext}')
            return redirect('user_modify_document', doc_id=doc.id)
        
        if uploaded_file.size > 5 * 1024 * 1024:
            messages.error(request, 'File size exceeds maximum limit of 5MB.')
            return redirect('user_modify_document', doc_id=doc.id)
        
        # Delete old file
        if doc.file and os.path.exists(doc.file.path):
            os.remove(doc.file.path)
        
        # Save new file
        doc.file = uploaded_file
        doc.file_size = uploaded_file.size
        
        # Regenerate SHA-256 hash
        sha256_hash = hashlib.sha256()
        for chunk in uploaded_file.chunks():
            sha256_hash.update(chunk)
        doc.sha256_hash = sha256_hash.hexdigest()
        
        # Regenerate cognitive fingerprint
        doc.save()
        try:
            global_fp, section_fps = generate_cognitive_fingerprint(doc.file.path, doc.file_type)
            if global_fp:
                doc.cognitive_fingerprint = global_fp
                doc.section_fingerprints = section_fps
        except Exception as e:
            print(f"Modify NLP Processing Error: {e}")
        
        # Reset status to Processed
        doc.status = 'Processed'
        doc.tamper_report = None
        doc.save()
        
        AuditLog.objects.create(
            user=request.user,
            action=f"Updated document (New Version): {doc.title}",
            action_type="Version Update",
            document_name=doc.title,
            status="Updated",
            target_user=request.user.username
        )
        
        messages.success(request, f'Document "{doc.title}" has been updated to a new version successfully.')
        return redirect('user_my_documents')
    
    return render(request, 'user/modify_document.html', {'doc': doc})

@login_required
def admin_audit_logs(request):
    if request.user.role != 'admin':
        return redirect('user_dashboard')
    logs = AuditLog.objects.all().order_by('-timestamp')
    return render(request, 'custom_admin/audit_logs.html', {'logs': logs})

@login_required
def user_delete_document(request, doc_id):
    if request.user.role == 'admin':
        return redirect('admin_dashboard')
    
    doc = get_object_or_404(Document, id=doc_id, user=request.user)
    doc_title = doc.title
    
    if request.method == 'POST':
        # Delete the physical file if it exists
        if doc.file and os.path.exists(doc.file.path):
            os.remove(doc.file.path)
        
        # Log the deletion before deleting the record
        AuditLog.objects.create(
            user=request.user,
            action=f"Document Deleted: {doc_title}",
            action_type="Document Deleted",
            document_name=doc_title,
            status="Deleted",
            target_user=request.user.username
        )
        
        # Delete the document (cascades to permissions, share requests, retrieval requests, security alerts)
        doc.delete()
        
        messages.success(request, f'Document "{doc_title}" has been permanently deleted.')
        return redirect('user_my_documents')
    
    # GET request — shouldn't happen, redirect back
    return redirect('user_my_documents')

