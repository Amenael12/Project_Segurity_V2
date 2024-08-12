from django.shortcuts import get_object_or_404
from django.contrib.auth import login, logout
from django.utils.decorators import method_decorator
from django.views.decorators.cache import cache_page
import logging
from rest_framework import generics, status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.throttling import UserRateThrottle
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.authtoken.models import Token
from rest_framework.schemas import AutoSchema
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.pagination import PageNumberPagination
from rest_framework.filters import OrderingFilter
from django_filters.rest_framework import DjangoFilterBackend

from project.models import UploadedFolder, Vulnerability, ScanResult
from .serializers import (
    UploadedFolderSerializer, 
    UploadedFolderCreateSerializer, 
    ScanFolderSerializer, 
    ScanResultSerializer, 
    VulnerabilitySerializer,
    UserSerializer,
    UserProfileSerializer
)
from .task import scan_folder_task
from .utils import get_folder_path, ensure_folder_exists

import os
logger = logging.getLogger(__name__)

class UploadedFolderListCreateView(generics.ListCreateAPIView):
    permission_classes = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]
    serializer_class = UploadedFolderSerializer
    schema = AutoSchema()
    
    def get_queryset(self):
        return UploadedFolder.objects.filter(user=self.request.user)

    def get_serializer_class(self):
        if self.request and self.request.method == 'POST':
            return UploadedFolderCreateSerializer
        return UploadedFolderSerializer

    def perform_create(self, serializer):
        folder = serializer.save(user=self.request.user)
        folder_path = get_folder_path(self.request.user.id, folder.folder_name)
        ensure_folder_exists(folder_path)
        folder.folder_path = folder_path
        folder.save()

class UploadedFolderDetailView(generics.RetrieveAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = UploadedFolderSerializer
    throttle_classes = [UserRateThrottle]
    schema = AutoSchema()

    def get_queryset(self):
        return UploadedFolder.objects.filter(user=self.request.user)

    @method_decorator(cache_page(60 * 15))  # Cache for 15 minutes
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

class ScanFolderView(generics.CreateAPIView):
    permission_classes = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]
    serializer_class = ScanFolderSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        folder_id = serializer.validated_data['folder_id']
        
        try:
            folder = UploadedFolder.objects.get(id=folder_id, user=request.user)
        except UploadedFolder.DoesNotExist:
            return Response({"folder_id": "Invalid folder ID."}, status=status.HTTP_400_BAD_REQUEST)
        
        # Iniciar la tarea de escaneo asíncrona
        task = scan_folder_task.delay(folder_id)
        
        return Response({
            'message': 'Scan initiated. You will be notified when it completes.',
            'task_id': task.id
        }, status=status.HTTP_202_ACCEPTED)

class ScanResultView(generics.RetrieveAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = ScanResultSerializer
    throttle_classes = [UserRateThrottle]
    schema = AutoSchema()

    def get_queryset(self):
        return ScanResult.objects.filter(uploaded_folder__user=self.request.user)

    @method_decorator(cache_page(60 * 5))  # Cache for 5 minutes
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

class VulnerabilityListView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = VulnerabilitySerializer
    pagination_class = PageNumberPagination
    filter_backends = [DjangoFilterBackend, OrderingFilter]
    filterset_fields = ['vulnerability_type', 'file_path']
    ordering_fields = ['line_number', 'vulnerability_type']
    throttle_classes = [UserRateThrottle]
    schema = AutoSchema()

    def get_queryset(self):
        folder_id = self.kwargs['folder_id']
        return Vulnerability.objects.filter(uploaded_folder_id=folder_id, uploaded_folder__user=self.request.user).select_related('uploaded_folder')

class ScanStatusView(generics.RetrieveAPIView):
    permission_classes = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]
    schema = AutoSchema()

    def retrieve(self, request, *args, **kwargs):
        task_id = kwargs.get('task_id')
        task = scan_folder_task.AsyncResult(task_id)
        
        if task.state == 'PENDING':
            response = {
                'state': task.state,
                'status': 'Scan is pending...'
            }
        elif task.state != 'FAILURE':
            response = {
                'state': task.state,
                'status': 'Scan is in progress...'
            }
            if task.info:
                response['result'] = task.info
        else:
            response = {
                'state': task.state,
                'status': 'Scan failed',
                'error': str(task.info)
            }
        return Response(response)

class RegisterView(generics.CreateAPIView):
    permission_classes = [AllowAny]
    serializer_class = UserSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        token, created = Token.objects.get_or_create(user=user)
        return Response({
            "user": UserSerializer(user, context=self.get_serializer_context()).data,
            "token": token.key
        }, status=status.HTTP_201_CREATED)

class LoginView(ObtainAuthToken):
    def post(self, request, *args, **kwargs):
        print("Login attempt with data:", request.data)  # Log de los datos recibidos
        serializer = self.serializer_class(data=request.data, context={'request': request})
        if not serializer.is_valid():
            print("Serializer errors:", serializer.errors)  # Log de errores de validación
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        user = serializer.validated_data['user']
        token, created = Token.objects.get_or_create(user=user)
        login(request, user)
        response_data = {
            'token': token.key,
            'user_id': user.pk,
            'email': user.email
        }
        print("Login successful. Response:", response_data)  # Log de respuesta exitosa
        return Response(response_data)

class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        request.auth.delete()
        logout(request)
        return Response(status=status.HTTP_200_OK)

class UserProfileView(generics.RetrieveUpdateAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = UserProfileSerializer

    def get_object(self):
        return self.request.user

class FolderUploadView(APIView):
    parser_classes = (MultiPartParser, FormParser)
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        print("Received data:", request.data)
        print("Received files:", request.FILES)
        
        folder_name = request.data.get('folder_name')
        files = request.FILES.getlist('files')
        
        print(f"Folder name: {folder_name}")
        print(f"Number of files: {len(files)}")
        
        if not folder_name or not files:
            return Response({'error': 'Folder name and files are required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            folder = UploadedFolder.objects.create(user=request.user, folder_name=folder_name)
            folder_path = get_folder_path(request.user.id, folder_name)
            
            for file in files:
                relative_path = file.name
                full_path = os.path.join(folder_path, relative_path)
                os.makedirs(os.path.dirname(full_path), exist_ok=True)
                with open(full_path, 'wb+') as destination:
                    for chunk in file.chunks():
                        destination.write(chunk)

            folder.folder_path = folder_path
            folder.save()

            print("Starting synchronous scan...")
            result = scan_folder_task(folder.id)
            print(f"Scan result: {result['total_files']} files scanned, {result['total_vulnerabilities']} vulnerabilities found")
            
            # Imprimir detalles de las vulnerabilidades
            print("\nVulnerabilities found:")
            for vuln in result['vulnerabilities']:
                print(f"File: {vuln['file']}")
                print(f"Line: {vuln['line']}")
                print(f"Type: {vuln['vulnerability']}")
                print(f"Description: {vuln['description']}")
                print(f"Detected code: {vuln['match']}")
                print(f"Score: {vuln['score']}")
                print("Context:")
                for i, context_line in enumerate(vuln['context_lines'], start=vuln['line'] - len(vuln['context_lines']) // 2):
                    if i == vuln['line']:
                        print(f"  > {i}: {context_line}")
                    else:
                        print(f"    {i}: {context_line}")
                print("---")

            return Response({
                'message': 'Folder uploaded successfully and scan initiated',
                'folder_id': folder.id,
                'scan_result': result
            }, status=status.HTTP_201_CREATED)
        except Exception as e:
            print(f"Error processing upload: {str(e)}")
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)