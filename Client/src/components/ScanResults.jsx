import React, { useState, useEffect } from 'react';
import { Typography, List, ListItem, ListItemText, Box, CircularProgress } from '@mui/material';
import api from '../services/api';

const ScanResults = ({ taskId, onScanComplete, onScanError }) => {
  const [scanStatus, setScanStatus] = useState(null);
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const checkScanStatus = async () => {
      if (!taskId) {
        console.log('No taskId provided');
        setLoading(false);
        return;
      }

      try {
        console.log(`Checking scan status for task ID: ${taskId}`);
        const response = await api.get(`scan-status/${taskId}/`);
        console.log('Scan status response:', response.data);
        setScanStatus(response.data);

        if (response.data.state === 'SUCCESS') {
          console.log('Scan completed successfully. Fetching vulnerabilities...');
          const folderId = response.data.result.folder_id;
          if (!folderId) {
            console.error('No folder_id found in scan result');
            onScanError('No folder ID found');
            setLoading(false);
            return;
          }
          console.log(`Folder ID: ${folderId}`);
          const resultsResponse = await api.get(`vulnerabilities/${folderId}/`);
          console.log('Vulnerabilities response:', resultsResponse.data);
          setVulnerabilities(resultsResponse.data.results || []);
          setLoading(false);
          onScanComplete();
        } else if (response.data.state === 'PENDING' || response.data.state === 'STARTED') {
          console.log('Scan still in progress. Checking again in 5 seconds...');
          setTimeout(checkScanStatus, 5000);
        } else {
          console.log('Scan failed or in unknown state:', response.data.state);
          onScanError(`Scan failed: ${response.data.state}`);
          setLoading(false);
        }
      } catch (error) {
        console.error('Error checking scan status:', error);
        onScanError(error.message);
        setLoading(false);
      }
    };

    checkScanStatus();
  }, [taskId, onScanComplete, onScanError]);

  if (loading) {
    return (
      <Box display="flex" alignItems="center">
        <CircularProgress />
        <Typography ml={2}>Checking scan status...</Typography>
      </Box>
    );
  }

  if (scanStatus?.state === 'FAILURE') {
    return <Typography color="error">Scan failed: {scanStatus.error}</Typography>;
  }

  console.log('Rendering scan results. Vulnerabilities:', vulnerabilities);

  return (
    <Box>
      <Typography variant="h6" gutterBottom>
        Scan Results
      </Typography>
      {vulnerabilities.length > 0 ? (
        <List>
          {vulnerabilities.map((vuln, index) => (
            <ListItem key={index}>
              <ListItemText
                primary={`${vuln.vulnerability_type} in ${vuln.file_path}`}
                secondary={`Line ${vuln.line_number}: ${vuln.description}`}
              />
            </ListItem>
          ))}
        </List>
      ) : (
        <Typography>No vulnerabilities found.</Typography>
      )}
    </Box>
  );
};

export default ScanResults;