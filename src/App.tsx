
import React, { useState } from 'react';
import axios from 'axios';
import {
    createTheme,
    ThemeProvider,
    CssBaseline,
    AppBar,
    Toolbar,
    Typography,
    Container,
    Button,
    Box,
    CircularProgress,
    Alert,
    Paper
} from '@mui/material';
import { DataGrid, GridColDef, GridRenderCellParams } from '@mui/x-data-grid';
import { Chart as ChartJS, ArcElement, Tooltip, Legend } from 'chart.js';
import { Pie } from 'react-chartjs-2';

ChartJS.register(ArcElement, Tooltip, Legend);

const darkTheme = createTheme({
    palette: {
        mode: 'dark',
    },
});

interface Device {
    id: string;
    ip: string;
    total_bytes: number;
}

interface ProtocolSummary {
    [protocol: string]: number;
}

interface DetailedEvent {
    id: number;
    date: string;
    time: string;
    server_ip: string;
    server_port: string;
    entry_vector_ip: string;
    entry_vector_port: string;
    protocol: string;
    service: string;
    app_layer_info?: { [key: string]: any };
}

function App() {
    const [devices, setDevices] = useState<Device[]>([]);
    const [protocolSummary, setProtocolSummary] = useState<ProtocolSummary>({});
    const [detailedEvents, setDetailedEvents] = useState<DetailedEvent[]>([]);
    const [error, setError] = useState<string | null>(null);
    const [loading, setLoading] = useState<boolean>(false);

    const handleFileChange = async (event: React.ChangeEvent<HTMLInputElement>) => {
        const files = event.target.files;
        if (files && files[0]) {
            const file = files[0];
            const formData = new FormData();
            formData.append('file', file);

            setLoading(true);
            setError(null);
            setDevices([]);
            setProtocolSummary({});

            const fileExtension = file.name.split('.').pop();
            let uploadUrl = '';

            if (fileExtension === 'log') {
                uploadUrl = '/api/upload/';
            } else if (fileExtension === 'pcap' || fileExtension === 'pcapng') {
                uploadUrl = '/api/upload_pcap/';
            } else {
                setError('Unsupported file type. Please upload a .log, .pcap, or .pcapng file.');
                setLoading(false);
                return;
            }

            try {
                const response = await axios.post(uploadUrl, formData, {
                    headers: {
                        'Content-Type': 'multipart/form-data'
                    }
                });
                                console.log('Data from backend:', response.data);
                const formattedDevices = response.data.devices.map((d: any, i: number) => ({ ...d, id: i }));
                setDevices(formattedDevices);
                setProtocolSummary(response.data.protocol_summary);
                const formattedDetailedEvents = response.data.detailed_events.map((e: any, i: number) => ({ ...e, id: i }));
                setDetailedEvents(formattedDetailedEvents);
            } catch (err: any) {
                setError(err.response ? `Error: ${err.response.data.detail}` : 'Could not connect to the backend.');
            }
            setLoading(false);
        }
    };

    const formatBytes = (bytes: number, decimals = 2) => {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const dm = decimals < 0 ? 0 : decimals;
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
    };

    const deviceColumns: GridColDef[] = [
        { field: 'ip', headerName: 'IP Address', flex: 1 },
        {
            field: 'total_bytes',
            headerName: 'Total Traffic',
            flex: 1,
            renderCell: (params: GridRenderCellParams<any, number>) => {
                if (params.value == null) {
                    return '';
                }
                return formatBytes(params.value);
            }
        },
    ];

    const detailedEventColumns: GridColDef[] = [
        { field: 'date', headerName: 'Date', width: 120 },
        { field: 'time', headerName: 'Time', width: 100 },
        { field: 'server_ip', headerName: 'Server IP', width: 150 },
        { field: 'server_port', headerName: 'Server Port', width: 120 },
        { field: 'entry_vector_ip', headerName: 'Entry IP', width: 150 },
        { field: 'entry_vector_port', headerName: 'Entry Port', width: 120 },
        { field: 'protocol', headerName: 'Protocol', width: 100 },
        { field: 'service', headerName: 'Service', width: 100 },
        {
            field: 'app_layer_info',
            headerName: 'App Layer Info',
            flex: 1,
            valueFormatter: (params: GridRenderCellParams<any, any>) => {
                if (params.value && Object.keys(params.value).length > 0) {
                    return JSON.stringify(params.value);
                }
                return '';
            },
        },
    ];

    const protocolChartData = {
        labels: Object.keys(protocolSummary),
        datasets: [
            {
                label: '# of Connections',
                data: Object.values(protocolSummary),
                backgroundColor: [
                    'rgba(255, 99, 132, 0.5)',
                    'rgba(54, 162, 235, 0.5)',
                    'rgba(255, 206, 86, 0.5)',
                    'rgba(75, 192, 192, 0.5)',
                ],
                borderColor: [
                    'rgba(255, 99, 132, 1)',
                    'rgba(54, 162, 235, 1)',
                    'rgba(255, 206, 86, 1)',
                    'rgba(75, 192, 192, 1)',
                ],
                borderWidth: 1,
            },
        ],
    };

    return (
        <ThemeProvider theme={darkTheme}>
            <CssBaseline />
            <AppBar position="static">
                <Toolbar>
                    <Typography variant="h6">NetVisor</Typography>
                </Toolbar>
            </AppBar>
            <Container maxWidth="lg" sx={{ mt: 4 }}>
                <Paper sx={{ p: 2, mb: 3 }}>
                    <Typography variant="h5" gutterBottom>Upload Log File</Typography>
                                        <Typography variant="body1" gutterBottom>Select a Zeek .log or PCAP file to begin analysis.</Typography>
                    <Button variant="contained" component="label">
                        Upload File
                                                <input type="file" hidden onChange={handleFileChange} accept=".log,.pcap,.pcapng" />
                    </Button>
                    {loading && <CircularProgress sx={{ display: 'block', mt: 2 }} />}
                    {error && <Alert severity="error" sx={{ mt: 2 }}>{error}</Alert>}
                </Paper>

                {devices.length > 0 && (
                    <Box sx={{ width: '100%' }}>
                        <Paper sx={{ p: 2, height: 400, width: '100%', mb: 3 }}>
                            <Typography variant="h6">Devices by Traffic</Typography>
                            <DataGrid
                                rows={devices}
                                columns={deviceColumns}
                                pageSizeOptions={[10, 25, 50]}
                                checkboxSelection
                            />
                        </Paper>
                        <Paper sx={{ p: 2, height: 400, width: '50%', margin: 'auto' }}>
                            <Typography variant="h6">Protocol Distribution</Typography>
                            <Box sx={{ height: '90%', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                              <Pie data={protocolChartData} options={{ maintainAspectRatio: false }}/>
                            </Box>
                        </Paper>
                    </Box>
                )}

                {detailedEvents.length > 0 && (
                    <Paper sx={{ p: 2, height: 400, width: '100%', mb: 3 }}>
                        <Typography variant="h6">Detailed Events</Typography>
                        <DataGrid
                            rows={detailedEvents}
                            columns={detailedEventColumns}
                            pageSizeOptions={[10, 25, 50]}
                            checkboxSelection
                        />
                    </Paper>
                )}
            </Container>
        </ThemeProvider>
    );
}

export default App;
