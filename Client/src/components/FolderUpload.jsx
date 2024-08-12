import React, { useState } from 'react';
import { Button, Typography, Box, CircularProgress, LinearProgress } from '@mui/material';
import api from '../services/api';

const FolderUpload = () => {
  const [uploading, setUploading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [taskId, setTaskId] = useState(null);

  const BATCH_SIZE = 50; // Número de archivos por lote

  const uploadBatch = async (formData, folderName, totalFiles) => {
    try {
      const response = await api.post('upload-folder/', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });
      console.log("Batch uploaded successfully:", response.data);
      return response.data.task_id;
    } catch (error) {
      console.error('Error uploading batch:', error);
      throw error;
    }
  };

  const handleFolderUpload = async (event) => {
    const files = Array.from(event.target.files);
    if (files.length === 0) return;

    setUploading(true);
    setProgress(0);

    const folderName = files[0].webkitRelativePath.split('/')[0];
    let currentTaskId = null;

    try {
      for (let i = 0; i < files.length; i += BATCH_SIZE) {
        const batch = files.slice(i, i + BATCH_SIZE);
        const formData = new FormData();
        formData.append('folder_name', folderName);
        
        batch.forEach(file => {
          formData.append('files', file, file.webkitRelativePath);
        });

        currentTaskId = await uploadBatch(formData, folderName, files.length);
        setProgress(Math.min(100, ((i + BATCH_SIZE) / files.length) * 100));
      }

      setTaskId(currentTaskId);
      alert('Folder uploaded successfully!');
    } catch (error) {
      console.error('Error uploading folder:', error);
      alert('Error uploading folder: ' + (error.response?.data?.error || error.message));
    } finally {
      setUploading(false);
    }
  };

  return (
    <Box>
      <input
        accept="*/*"
        style={{ display: 'none' }}
        id="folder-upload"
        type="file"
        webkitdirectory=""
        directory=""
        onChange={handleFolderUpload}
        multiple
      />
      <label htmlFor="folder-upload">
        <Button variant="contained" component="span" disabled={uploading}>
          Upload Folder
        </Button>
      </label>
      {uploading && (
        <Box mt={2}>
          <LinearProgress variant="determinate" value={progress} />
          <Typography>Uploading folder... {Math.round(progress)}%</Typography>
        </Box>
      )}
      {taskId && (
        <Typography mt={2}>
          Scan initiated. Task ID: {taskId}
        </Typography>
      )}
    </Box>
  );
};

export default FolderUpload;