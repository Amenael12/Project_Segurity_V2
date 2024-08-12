import re
import os
from django.conf import settings
import logging

logger = logging.getLogger(__name__)

def scan_folder_for_vulnerabilities(folder_path, confidence_threshold=5, context_lines=2):
    vulnerabilities = []
    total_files = 0
    
    logger.info(f"Starting scan of folder: {folder_path}")

    VULNERABILITY_PATTERNS = [
        (r"(?i)(?:select|insert|update|delete)\s+.*?(?:from|into|where)\s+.*?(?:\$_(?:GET|POST|REQUEST)\[|[\"']\s*\.\s*\$)", "SQL Injection", "SQL", 8),
        (r"<script\b[^>]*>.*?(?:\$_(?:GET|POST|REQUEST)\[|document\.(?:URL|location)|window\.name).*?</script>", "Cross-Site Scripting (XSS)", "XSS", 7),
        (r"(?i)(?:system|exec|shell_exec|passthru|eval)\s*\(\s*(?:\$_(?:GET|POST|REQUEST)\[|[\"']\s*\.\s*\$)", "Command Injection", "CMD", 9),
        (r"(?i)(?:include|require|include_once|require_once)\s*\(\s*(?:\$_(?:GET|POST|REQUEST)\[|[\"']\s*\.\s*\$)", "File Inclusion", "FILE", 8),
        (r"(?i)eval\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\[", "Code Injection", "CODE", 9),
        (r"(?i)unserialize\s*\(\s*(?:\$_(?:GET|POST|REQUEST)\[|[\"']\s*\.\s*\$)", "PHP Object Injection", "OBJ", 7),
        (r"(?i)password\s*=\s*['\"][^'\"]{8,}['\"]", "Hardcoded Password", "PWD", 6),
        (r"(?i)(?:ftp|http|https)://\S+", "Hardcoded URL", "URL", 5),
        (r"(?i)(?:api_key|access_token|secret_key)\s*=\s*['\"][A-Za-z0-9+/=]{32,}['\"]", "API Key Exposure", "API", 7),
        (r"(?i)(?:md5|sha1)\s*\(\s*(?:\$_(?:GET|POST|REQUEST)\[|[\"']\s*\.\s*\$)", "Weak Cryptography", "CRYPTO", 6),
        (r"(?i)echo\s+(?:\$_(?:GET|POST|REQUEST)\[|[\"']\s*\.\s*\$)", "Reflected User Input", "REFLECT", 7),
        (r"(?i)(?:chmod|chown|chgrp)\s*\(\s*[\"']?\S+[\"']?\s*,\s*0?777\b", "Insecure File Permissions", "PERM", 8),
        (r"(?i)header\s*\(\s*(?:\$_(?:GET|POST|REQUEST)\[|[\"']\s*\.\s*\$)", "Header Injection", "HEADER", 7),
        (r"(?i)(?:fopen|file_get_contents)\s*\(\s*(?:\$_(?:GET|POST|REQUEST)\[|[\"']\s*\.\s*\$)", "Unsafe File Operation", "FILE_OP", 6),
        (r"(?i)on(?:click|load|mouseover|error|keyup)\s*=\s*[\"'](?:.*?\$|(?:javascript|eval):)", "DOM-based XSS", "DOM_XSS", 7)
    ]

    for root, dirs, files in os.walk(folder_path):
        for file in files:
            if is_file_allowed(file):
                file_path = os.path.join(root, file)
                if not os.path.exists(file_path):
                    logger.warning(f"File not found: {file_path}")
                    continue
                
                total_files += 1
                relative_path = os.path.relpath(file_path, folder_path)
                logger.info(f"Scanning file: {relative_path}")
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                        lines = content.splitlines()
                        for i, line in enumerate(lines, start=1):
                            for pattern, vuln_name, vuln_type, base_score in VULNERABILITY_PATTERNS:
                                matches = re.finditer(pattern, line)
                                for match in matches:
                                    context = get_context_lines(lines, i, context_lines)
                                    vuln = {
                                        'file': relative_path,
                                        'line': i,
                                        'vulnerability': vuln_type,
                                        'description': vuln_name,
                                        'match': match.group(0).strip(),
                                        'context': line.strip(),
                                        'context_lines': context,
                                        'base_score': base_score
                                    }
                                    vuln['score'] = calculate_vulnerability_score(vuln, content)
                                    if vuln['score'] >= confidence_threshold:
                                        if vuln not in vulnerabilities:
                                            vulnerabilities.append(vuln)
                                            logger.info(f"Vulnerability found: {vuln_type} in {relative_path} at line {i}, score: {vuln['score']}")
                except Exception as e:
                    logger.error(f"Error scanning file {relative_path}: {str(e)}")

    logger.info(f"Scan completed. Total files scanned: {total_files}, Vulnerabilities found: {len(vulnerabilities)}")
    return {
        'vulnerabilities': vulnerabilities,
        'total_files': total_files
    }

def is_file_allowed(filename):
    ALLOWED_EXTENSIONS = ['.py', '.js', '.php', '.html', '.css', '.java', '.c', '.cpp']
    return any(filename.lower().endswith(ext) for ext in ALLOWED_EXTENSIONS)

def get_context_lines(lines, current_line, context=2):
    start = max(0, current_line - context - 1)
    end = min(len(lines), current_line + context)
    return lines[start:end]

def calculate_vulnerability_score(vuln, content):
    base_score = vuln['base_score']
    
    # Aumentar la puntuación si la vulnerabilidad está en una función sensible
    if re.search(r"function\s+\w+\s*\(", vuln['context']):
        base_score += 1
    
    # Aumentar la puntuación si hay múltiples ocurrencias en el mismo archivo
    occurrences = len(re.findall(vuln['match'], content))
    if occurrences > 1:
        base_score += min(occurrences - 1, 2)  # Máximo 2 puntos extra por múltiples ocurrencias
    
    # Reducir la puntuación si parece estar en un comentario
    if re.match(r"\s*(//|#|/\*)", vuln['context']):
        base_score -= 2
    
    # Ajustar la puntuación basada en el tipo de archivo
    if vuln['file'].endswith(('.min.js', '.min.css')):
        base_score -= 1
    elif vuln['file'].endswith(('.test.js', '.spec.js')):
        base_score -= 2
    
    return max(base_score, 0)  # Asegurar que la puntuación no sea negativa

def sanitize_filename(filename):
    return re.sub(r'[^\w\-_\. ]', '', filename)

def get_folder_path(user_id, folder_name):
    sanitized_folder_name = sanitize_filename(folder_name)
    return os.path.join(settings.MEDIA_ROOT, 'uploaded_folders', str(user_id), sanitized_folder_name)

def ensure_folder_exists(folder_path):
    os.makedirs(folder_path, exist_ok=True)