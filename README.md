# NetVisor

NetVisor is a web-based network analysis tool that allows users to upload Zeek connection logs (.log) and PCAP (Packet Capture) files (.pcap, .pcapng) for insightful visualization and detailed event analysis.

## Table of Contents
- [How the Program Works](#how-the-program-works)
- [Instructions for Use](#instructions-for-use)
  - [Prerequisites](#prerequisites)
  - [Setup and Running](#setup-and-running)
  - [Using the Application](#using-the-application)
- [Purpose of Functions](#purpose-of-functions)
  - [Backend API Endpoints](#backend-api-endpoints)
  - [Frontend Components](#frontend-components)
- [Machine-Readable Summary](#machine-readable-summary)

## How the Program Works
NetVisor is a full-stack application composed of three main services orchestrated by Docker Compose:

1.  **Frontend (React.js):** A user-friendly web interface built with React.js and Material-UI. It handles file uploads, displays visualizations (protocol distribution, device traffic), and presents detailed event logs.
2.  **Backend (FastAPI):** A Python API built with FastAPI that processes the uploaded network data. It uses `pandas` for Zeek log analysis and `pyshark` (which relies on `tshark`) for PCAP file parsing. It extracts connection summaries, device traffic, and detailed event information.
3.  **Nginx:** Acts as a reverse proxy, serving the static frontend assets and forwarding API requests to the backend service.

When a user uploads a file:
- The **Frontend** sends the file to the appropriate backend endpoint (`/api/upload/` for Zeek logs, `/api/upload_pcap/` for PCAP files).
- The **Backend** receives the file, parses it, extracts relevant data (protocol summaries, device traffic, detailed events), and sends the structured data back to the frontend.
- The **Frontend** then renders this data in various interactive components, including data grids and charts.

## Instructions for Use

### Prerequisites
Before you begin, ensure you have the following installed:
-   [Docker](https://docs.docker.com/get-docker/): Docker Engine and Docker Compose (usually included with Docker Desktop).

### Setup and Running
1.  **Clone the repository:**
    ```bash
    git clone https://github.com/GusOliveira/PCAP_Vision/tree/main
    cd NetVisor
    ```
2.  **Build and run the Docker containers:**
    ```bash
    docker compose up --build -d
    ```
    This command will:
    -   Build the `backend` Docker image (installing Python dependencies and `tshark`).
    -   Build the `frontend` Docker image (installing Node.js dependencies and building the React app).
    -   Start the `backend`, `frontend`, and `nginx` services in detached mode.
3.  **Access the application:**
    Open your web browser and navigate to `http://localhost:3000`.

### Using the Application
1.  **Upload a File:** Click the "Upload File" button and select either a Zeek connection log (`.log`) or a PCAP file (`.pcap`, `.pcapng`).
2.  **View Analysis:** Once the file is uploaded and processed, the application will display:
    -   **Devices by Traffic:** A table showing IP addresses and their total bytes transferred.
    -   **Protocol Distribution:** A pie chart illustrating the distribution of protocols.
    -   **Detailed Events:** A table providing granular information about each connection or packet, including date, time, server IP/port, entry vector (source IP/port), protocol, service, and application-layer details.

## Purpose of Functions

### Backend API Endpoints
-   **`GET /`**: Basic health check endpoint, returns `{"message": "NetVisor API is running"}`.
-   **`POST /upload/`**: Accepts a Zeek connection log (`.log`) file. Parses the log using `pandas` to extract protocol summaries, device traffic, and detailed connection events.
-   **`POST /upload_pcap/`**: Accepts a PCAP file (`.pcap`, `.pcapng`). Parses the PCAP using `pyshark` to extract protocol summaries, device traffic, and detailed packet events, including application-layer information for HTTP and DNS.

### Frontend Components
-   **`App.tsx`**: The main React component. It manages file uploads, communicates with the backend API, and renders the various data visualization and analysis components (tables, charts).

## Machine-Readable Summary

```yaml
project_name: NetVisor
version: v2
description: Web-based tool for Zeek log and PCAP file analysis.
services:
  - name: frontend
    technology: React.js, Material-UI
    role: User Interface, File Uploads, Data Visualization
  - name: backend
    technology: FastAPI, Python, pandas, pyshark, tshark
    role: Data Processing, API Endpoints
    endpoints:
      - path: /
        method: GET
        purpose: Health Check
      - path: /upload/
        method: POST
        purpose: Process Zeek .log files
        input: Zeek conn.log file
        output: Protocol summary, Device traffic, Detailed connection events
      - path: /upload_pcap/
        method: POST
        purpose: Process PCAP (.pcap, .pcapng) files
        input: PCAP file
        output: Protocol summary, Device traffic, Detailed packet events (incl. app-layer)
  - name: nginx
    technology: Nginx
    role: Reverse Proxy, Static File Server
data_analysis_features:
  - Protocol Summary (Pie Chart)
  - Devices by Traffic (Table)
  - Detailed Events (Table: Date, Time, Server IP/Port, Entry Vector IP/Port, Protocol, Service, App Layer Info)
```
