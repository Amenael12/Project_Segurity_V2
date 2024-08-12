from django.db import models
from django.contrib.auth.models import User
from django.conf import settings
from django.db.models.signals import post_save
from django.dispatch import receiver
import os


if not os.path.exists(os.path.join(settings.BASE_DIR, 'uploads')):
    os.makedirs(os.path.join(settings.BASE_DIR, 'uploads'))

class UploadedFolder(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE,  null=True)
    folder_name = models.CharField(max_length=255, null=True)
    folder_path = models.FilePathField(
        path=os.path.join(settings.BASE_DIR, 'uploads'),
        allow_files=False,
        allow_folders=True
    )
    upload_date = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return f"{self.folder_name} - {self.user.username}"

class UploadedFile(models.Model):
    uploaded_folder = models.ForeignKey(UploadedFolder, on_delete=models.CASCADE, related_name='files')
    file_name = models.CharField(max_length=255)
    file_path = models.CharField(max_length=500)
    upload_date = models.DateTimeField(auto_now_add=True)
    last_modified = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return f"{self.file_name} in {self.uploaded_folder.folder_name}"

class Vulnerability(models.Model):
    class VulnerabilityType(models.TextChoices):
        SQL = 'SQL', 'SQL Injection'
        XSS = 'XSS', 'Cross-Site Scripting'
        CSRF = 'CSRF', 'Cross-Site Request Forgery'
        FILE = 'FILE', 'File Inclusion'
        CMD = 'CMD', 'Command Injection'
        OTHER = 'OTHER', 'Other'

    uploaded_file = models.ForeignKey(UploadedFile, on_delete=models.CASCADE, related_name='vulnerabilities')
    line_number = models.IntegerField()
    vulnerability_type = models.CharField(
        max_length=10,
        choices=VulnerabilityType.choices,
        default=VulnerabilityType.OTHER,
        db_index=True
    )
    description = models.TextField()
    detected_code = models.TextField()
    detection_date = models.DateTimeField(auto_now_add=True, db_index=True)

    def __str__(self):
        return f"{self.vulnerability_type} in {self.uploaded_file.file_name} at line {self.line_number}"

class ScanResult(models.Model):
    uploaded_folder = models.ForeignKey(UploadedFolder, on_delete=models.CASCADE, related_name='scan_results')
    scan_date = models.DateTimeField(auto_now_add=True, db_index=True)
    total_files_scanned = models.IntegerField()
    total_vulnerabilities_found = models.IntegerField()

    def __str__(self):
        return f"Scan of {self.uploaded_folder.folder_name} on {self.scan_date}"
    
class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    bio = models.TextField(max_length=500, blank=True)
    location = models.CharField(max_length=30, blank=True)
    birth_date = models.DateField(null=True, blank=True)

    def __str__(self):
        return f"{self.user.username}'s profile"

@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.create(user=instance)

@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    instance.userprofile.save()