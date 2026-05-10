import os
import PyPDF2
import docx
from sklearn.feature_extraction.text import TfidfVectorizer
import json

def extract_text_from_pdf(file_path):
    text = ""
    try:
        with open(file_path, 'rb') as f:
            reader = PyPDF2.PdfReader(f)
            for page in reader.pages:
                text += page.extract_text() or ""
    except Exception as e:
        print(f"Error extracting PDF: {e}")
    return text

def extract_text_from_docx(file_path):
    text = ""
    try:
        doc = docx.Document(file_path)
        for para in doc.paragraphs:
            text += para.text + "\n"
    except Exception as e:
        print(f"Error extracting DOCX: {e}")
    return text

def extract_text_from_txt(file_path):
    text = ""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            text = f.read()
    except Exception as e:
        print(f"Error extracting TXT: {e}")
    return text

def preprocess_text(text):
    # Basic preprocessing: lowercase and strip
    return text.lower().strip()

def generate_cognitive_fingerprint(file_path, file_type):
    content = ""
    if file_type == '.pdf':
        content = extract_text_from_pdf(file_path)
    elif file_type == '.docx':
        content = extract_text_from_docx(file_path)
    elif file_type == '.txt':
        content = extract_text_from_txt(file_path)
    
    if not content:
        return None, None

    preprocessed_full = preprocess_text(content)
    
    # Split into sections (paragraphs)
    sections = [s.strip() for s in content.split('\n\n') if s.strip()]
    if not sections: # Fallback if no double newlines
        sections = [s.strip() for s in content.split('\n') if s.strip()]
    
    # Global Fingerprint
    vectorizer = TfidfVectorizer(max_features=100)
    try:
        tfidf_matrix = vectorizer.fit_transform([preprocessed_full])
        feature_names = vectorizer.get_feature_names_out()
        tfidf_scores = tfidf_matrix.toarray()[0]
        global_fingerprint = json.dumps({feature_names[i]: float(tfidf_scores[i]) for i in range(len(feature_names)) if tfidf_scores[i] > 0})
        
        # Section-level Fingerprints
        section_data = []
        for i, section_text in enumerate(sections):
            p_text = preprocess_text(section_text)
            if len(p_text) < 10: continue # Skip very short sections
            
            s_vec = TfidfVectorizer(max_features=50)
            try:
                s_matrix = s_vec.fit_transform([p_text])
                s_features = s_vec.get_feature_names_out()
                s_scores = s_matrix.toarray()[0]
                s_fingerprint = {s_features[j]: float(s_scores[j]) for j in range(len(s_features)) if s_scores[j] > 0}
                section_data.append({
                    'index': i,
                    'original_text': section_text[:200] + "..." if len(section_text) > 200 else section_text,
                    'fingerprint': s_fingerprint
                })
            except:
                continue
                
        return global_fingerprint, json.dumps(section_data)
    except Exception as e:
        print(f"Error generating TF-IDF: {e}")
        return None, None

def calculate_cosine_similarity(f1_obj, f2_obj):
    # Overload to accept either JSON string or pre-parsed dict
    if isinstance(f1_obj, str): f1 = json.loads(f1_obj)
    else: f1 = f1_obj
    
    if isinstance(f2_obj, str): f2 = json.loads(f2_obj)
    else: f2 = f2_obj

    if not f1 or not f2:
        return 0.0
    
    try:
        # Get all unique words (features)
        all_words = set(f1.keys()).union(set(f2.keys()))
        if not all_words:
            return 0.0
            
        # Create vectors
        v1 = [f1.get(word, 0) for word in all_words]
        v2 = [f2.get(word, 0) for word in all_words]
        
        # Standard Cosine Similarity formula: (A . B) / (||A|| * ||B||)
        dot_product = sum(v1[i] * v2[i] for i in range(len(v1)))
        norm1 = sum(val**2 for val in v1)**0.5
        norm2 = sum(val**2 for val in v2)**0.5
        
        if norm1 == 0 or norm2 == 0:
            return 0.0
            
        return dot_product / (norm1 * norm2)
    except Exception as e:
        print(f"Similarity Error: {e}")
        return 0.0

def compare_sections(old_sections_json, new_content):
    if not old_sections_json: return []
    
    old_sections = json.loads(old_sections_json)
    
    # Split new content into sections
    current_sections = [s.strip() for s in new_content.split('\n\n') if s.strip()]
    if not current_sections:
        current_sections = [s.strip() for s in new_content.split('\n') if s.strip()]
        
    report = []
    threshold = 0.90 # Section level threshold

    # Attempt to correlate sections by index (naive approach)
    # In a more advanced version, we'd use fuzzy matching to find the best section match
    for i, old_sec in enumerate(old_sections):
        old_fingerprint = old_sec.get('fingerprint')
        original_index = old_sec.get('index', i)  # Use stored original index
        
        # If we have a corresponding current section at the ORIGINAL index
        if original_index < len(current_sections):
            curr_text = current_sections[original_index]
            p_curr = preprocess_text(curr_text)
            
            s_vec = TfidfVectorizer(max_features=50)
            try:
                s_matrix = s_vec.fit_transform([p_curr])
                s_features = s_vec.get_feature_names_out()
                s_scores = s_matrix.toarray()[0]
                curr_fingerprint = {s_features[j]: float(s_scores[j]) for j in range(len(s_features)) if s_scores[j] > 0}
                
                sim = calculate_cosine_similarity(old_fingerprint, curr_fingerprint)
                
                is_tampered = sim < threshold
                report.append({
                    'index': original_index,
                    'status': 'Tampered' if is_tampered else 'Verified',
                    'similarity': round(sim * 100, 2),
                    'text_preview': old_sec['original_text']
                })
            except:
                report.append({
                    'index': original_index,
                    'status': 'Error',
                    'similarity': 0,
                    'text_preview': old_sec['original_text']
                })
        else:
            report.append({
                'index': original_index,
                'status': 'Missing',
                'similarity': 0,
                'text_preview': old_sec['original_text']
            })
            
    return report
