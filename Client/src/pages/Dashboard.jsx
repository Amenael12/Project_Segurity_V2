import React, { useState, useEffect } from 'react';
import { Typography, Container, Box, CircularProgress } from '@mui/material';
import FolderUpload from '../components/FolderUpload';
import ScanResults from '../components/ScanResults';

const Dashboard = () => {
  const [taskId, setTaskId] = useState(null);
  const [scanStatus, setScanStatus] = useState('idle'); // 'idle', 'scanning', 'completed', 'error'

  useEffect(() => {
    console.log('Task ID updated:', taskId);
  }, [taskId]);

  const handleUploadComplete = (newTaskId) => {
    console.log('Upload complete. New task ID:', newTaskId);
    setTaskId(newTaskId);
    setScanStatus('scanning');
  };

  const handleScanComplete = () => {
    console.log('Scan completed');
    setScanStatus('completed');
  };

  const handleScanError = (error) => {
    console.error('Scan error:', error);
    setScanStatus('error');
  };

  return (
    <Container>
      <Typography variant="h4" gutterBottom>
        Dashboard
      </Typography>
      <Box mb={4}>
        <FolderUpload onUploadComplete={handleUploadComplete} />
      </Box>
      {taskId && (
        <Box>
          <Typography variant="body1" gutterBottom>
            Scan initiated. Task ID: {taskId}
          </Typography>
          {scanStatus === 'scanning' && (
            <Box display="flex" alignItems="center">
              <CircularProgress size={24} />
              <Typography variant="body2" ml={1}>
                Scanning in progress...
              </Typography>
            </Box>
          )}
          <ScanResults 
            taskId={taskId} 
            onScanComplete={handleScanComplete}
            onScanError={handleScanError}
          />
        </Box>
      )}
      {scanStatus === 'error' && (
        <Typography color="error">
          An error occurred during the scan. Please try again.
        </Typography>
      )}
    </Container>
  );
};

export default Dashboard;