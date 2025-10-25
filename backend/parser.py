import pandas as pd
import pyshark
from collections import defaultdict
import traceback
import logging

# Configure logging for pyshark
logging.getLogger('pyshark').setLevel(logging.DEBUG)

def parse_pcap_file(pcap_file):
    try:
        cap = pyshark.FileCapture(pcap_file)
        
        protocol_counts = defaultdict(int)
        traffic_by_ip = defaultdict(int)

        # Iterate synchronously through packets
        for packet in cap:
            # Protocol Summary
            if 'ip' in packet:
                protocol = packet.ip.proto
                protocol_counts[protocol] += 1

            # Traffic by IP
            if 'IP' in packet:
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
                length = int(packet.length)
                traffic_by_ip[src_ip] += length
                traffic_by_ip[dst_ip] += length
        
        cap.close()

        # Format devices data
        devices = [{'ip': ip, 'total_bytes': byte_count} for ip, byte_count in traffic_by_ip.items()]
        devices.sort(key=lambda x: x['total_bytes'], reverse=True)

        # Extract detailed events from PCAP
        detailed_events = []
        cap.reset()
        for packet in cap:
            event = {
                "date": packet.sniff_time.strftime('%Y-%m-%d'),
                "time": packet.sniff_time.strftime('%H:%M:%S'),
                "server_ip": 'N/A',
                "server_port": 'N/A',
                "entry_vector_ip": 'N/A',
                "entry_vector_port": 'N/A',
                "protocol": 'N/A',
                "service": 'N/A',
                "app_layer_info": {}
            }

            if 'ip' in packet:
                event["entry_vector_ip"] = packet.ip.src
                event["server_ip"] = packet.ip.dst
                event["protocol"] = packet.ip.proto

            if 'tcp' in packet:
                event["entry_vector_port"] = packet.tcp.srcport
                event["server_port"] = packet.tcp.dstport
                event["protocol"] = "TCP"
                if 'http' in packet:
                    event["service"] = "HTTP"
                    event["app_layer_info"] = {
                        "method": getattr(packet.http, 'request_method', 'N/A'),
                        "uri": getattr(packet.http, 'request_uri', 'N/A')
                    }
            elif 'udp' in packet:
                event["entry_vector_port"] = packet.udp.srcport
                event["server_port"] = packet.udp.dstport
                event["protocol"] = "UDP"
                if 'dns' in packet:
                    event["service"] = "DNS"
                    event["app_layer_info"] = {
                        "query": getattr(packet.dns, 'qry_name', 'N/A')
                    }
            
            detailed_events.append(event)
        
        cap.close()

        return {
            "protocol_summary": dict(protocol_counts),
            "devices": devices,
            "detailed_events": detailed_events
        }
    except Exception as e:
        # Log the exception for debugging
        traceback.print_exc()
        return None

def parse_zeek_conn_log(log_file):
    """
    Parses a Zeek conn.log file and extracts connection summaries.
    """
    header_line = ''
    for line in log_file:
        if line.startswith('#fields'):
            header_line = line.strip()
            break
    
    if not header_line:
        raise ValueError("Could not find #fields header in the log file.")

    columns = header_line.split('\t')[1:]
    log_file.seek(0)

    df = pd.read_csv(
        log_file,
        sep='\t',
        comment='#',
        header=None,
        names=columns,
        na_values='-',
        low_memory=False
    )

    protocol_counts = df['proto'].value_counts().to_dict()

    df['orig_bytes'] = pd.to_numeric(df['orig_bytes'], errors='coerce').fillna(0)
    df['resp_bytes'] = pd.to_numeric(df['resp_bytes'], errors='coerce').fillna(0)

    orig_traffic = df.groupby('id.orig_h')['orig_bytes'].sum()
    resp_traffic = df.groupby('id.resp_h')['resp_bytes'].sum()

    total_traffic = orig_traffic.add(resp_traffic, fill_value=0).to_dict()

    devices = [{'ip': ip, 'total_bytes': int(bytes)} for ip, bytes in total_traffic.items()]
    devices.sort(key=lambda x: x['total_bytes'], reverse=True)

    # Extract detailed events
    detailed_events = []
    for index, row in df.iterrows():
        event = {
            "date": pd.to_datetime(row['ts'], unit='s').strftime('%Y-%m-%d'),
            "time": pd.to_datetime(row['ts'], unit='s').strftime('%H:%M:%S'),
            "server_ip": row['id.resp_h'],
            "server_port": row['id.resp_p'],
            "entry_vector_ip": row['id.orig_h'],
            "entry_vector_port": row['id.orig_p'],
            "protocol": row['proto'],
            "service": row['service'] if 'service' in row and pd.notna(row['service']) else 'N/A',
        }
        detailed_events.append(event)

    return {
        "protocol_summary": protocol_counts,
        "devices": devices,
        "detailed_events": detailed_events
    }