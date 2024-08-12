import logging
from celery import shared_task
from project.models import UploadedFolder, Vulnerability, ScanResult, UploadedFile
from .utils import scan_folder_for_vulnerabilities, is_file_allowed
from django.utils import timezone
from django.db import IntegrityError, OperationalError
import os

logger = logging.getLogger(__name__)

@shared_task
def scan_folder_task(folder_id):
    logger.info(f"Starting scan for folder_id: {folder_id}")
    try:
        folder = UploadedFolder.objects.get(id=folder_id)
    except UploadedFolder.DoesNotExist:
        logger.error(f"UploadedFolder with id {folder_id} does not exist")
        return None

    logger.info(f"Scanning folder path: {folder.folder_path}")

    # Verificar si la carpeta existe físicamente
    if not os.path.exists(folder.folder_path):
        logger.warning(f"Folder not found: {folder.folder_path}")
        folder.is_active = False
        folder.save()
        return None

    # Actualizar la lista de archivos
    existing_files = set()
    for root, dirs, files in os.walk(folder.folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            relative_path = os.path.relpath(file_path, folder.folder_path)
            existing_files.add(relative_path)
            try:
                UploadedFile.objects.update_or_create(
                    uploaded_folder=folder,
                    file_path=relative_path,
                    defaults={'file_name': file, 'is_active': True}
                )
            except IntegrityError:
                logger.error(f"IntegrityError updating file: {relative_path}")
            except OperationalError:
                logger.error(f"OperationalError updating file: {relative_path}")

    # Marcar archivos borrados como inactivos
    UploadedFile.objects.filter(uploaded_folder=folder).exclude(file_path__in=existing_files).update(is_active=False)

    # Limpiar vulnerabilidades antiguas
    Vulnerability.objects.filter(uploaded_file__uploaded_folder=folder).delete()
    logger.info(f"Deleted old vulnerabilities for folder_id: {folder_id}")

    scan_results = scan_folder_for_vulnerabilities(folder.folder_path)
    vulnerabilities = scan_results['vulnerabilities']
    total_files = scan_results['total_files']
    
    logger.info(f"Total files scanned: {total_files}")
    logger.info(f"Vulnerabilities found: {len(vulnerabilities)}")

    for vuln in vulnerabilities:
        try:
            uploaded_file = UploadedFile.objects.get(uploaded_folder=folder, file_path=vuln['file'])
            Vulnerability.objects.create(
                uploaded_file=uploaded_file,
                line_number=vuln['line'],
                vulnerability_type=vuln['vulnerability'],
                description=vuln['description'],
                detected_code=vuln['match']
            )
            logger.info(f"Vulnerability created: {vuln['vulnerability']} in {vuln['file']}")
        except UploadedFile.DoesNotExist:
            logger.error(f"UploadedFile not found for vulnerability: {vuln['file']}")
        except IntegrityError:
            logger.error(f"IntegrityError creating vulnerability for file: {vuln['file']}")
        except OperationalError:
            logger.error(f"OperationalError creating vulnerability for file: {vuln['file']}")
        except Exception as e:
            logger.error(f"Unexpected error creating vulnerability: {str(e)}")
    
    total_vulnerabilities = len(vulnerabilities)
    try:
        ScanResult.objects.create(
            uploaded_folder=folder,
            total_files_scanned=total_files,
            total_vulnerabilities_found=total_vulnerabilities,
            scan_date=timezone.now()
        )
        logger.info(f"ScanResult created for folder_id: {folder_id}")
    except IntegrityError:
        logger.error(f"IntegrityError creating ScanResult for folder_id: {folder_id}")
    except OperationalError:
        logger.error(f"OperationalError creating ScanResult for folder_id: {folder_id}")
    except Exception as e:
        logger.error(f"Unexpected error creating ScanResult: {str(e)}")
    
    logger.info(f"Scan completed for folder_id: {folder_id}")
    return {
        'folder_id': folder_id,
        'total_files': total_files,
        'total_vulnerabilities': total_vulnerabilities,
        'vulnerabilities': vulnerabilities 
    }