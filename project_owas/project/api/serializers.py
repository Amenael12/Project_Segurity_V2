from rest_framework import serializers
from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from project.models import UploadedFolder, Vulnerability, ScanResult

class VulnerabilitySerializer(serializers.ModelSerializer):
    class Meta:
        model = Vulnerability
        fields = ['id', 'file_path', 'line_number', 'vulnerability_type', 'description', 'detected_code', 'detection_date']

class ScanFolderSerializer(serializers.Serializer):
    folder_id = serializers.IntegerField()
    
class ScanResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanResult
        fields = ['id', 'scan_date', 'total_files_scanned', 'total_vulnerabilities_found']

class UploadedFolderSerializer(serializers.ModelSerializer):
    vulnerabilities = VulnerabilitySerializer(many=True, read_only=True)
    scan_results = ScanResultSerializer(many=True, read_only=True)

    class Meta:
        model = UploadedFolder
        fields = ['id', 'user', 'folder_name', 'folder_path', 'upload_date', 'vulnerabilities', 'scan_results']

class UploadedFolderCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = UploadedFolder
        fields = ['folder_name', 'folder_path']

    def create(self, validated_data):
        user = self.context['request'].user
        return UploadedFolder.objects.create(user=user, **validated_data)

class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'password']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password']
        )
        return user

class UserProfileSerializer(serializers.ModelSerializer):
    uploaded_folders = UploadedFolderSerializer(many=True, read_only=True)

    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'uploaded_folders']
        read_only_fields = ['id', 'username']

class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(style={'input_type': 'password'}, write_only=True)