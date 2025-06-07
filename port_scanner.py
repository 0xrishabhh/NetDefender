import socket
import threading
from queue import Queue
import platform
import psutil
import json
from datetime import datetime
import os

# Comprehensive list of common ports
COMMON_PORTS = [
    # System ports
    1, 7, 9, 11, 13, 15, 17, 19, 20, 21, 22, 23, 25, 37, 42, 43, 49, 50, 53, 57, 65, 67, 68, 69, 70, 79, 80, 81, 88, 89, 90, 99, 100,
    # Common service ports
    106, 109, 110, 111, 113, 119, 123, 135, 137, 138, 139, 143, 161, 162, 163, 164, 174, 177, 178, 179, 191, 194, 199,
    # HTTP/Web ports
    443, 444, 445, 458, 465, 587, 993, 995, 1080, 1099, 1109, 1176, 1182, 1194, 1198, 1199, 1200, 1201, 1234, 1311, 1434, 1471,
    # Database ports
    1521, 1533, 1556, 1580, 1583, 1594, 1599, 2049, 2082, 2083, 2086, 2087, 2095, 2096, 2222, 2433, 2483, 2484, 2638, 3000, 3128,
    # Remote access ports
    3268, 3269, 3306, 3389, 3872, 4000, 4445, 4559, 4899, 5000, 5038, 5060, 5222, 5269, 5353, 5432, 5555, 5601, 5672,
    # Application ports
    5900, 5901, 5984, 5985, 5986, 6000, 6379, 6664, 6665, 6666, 6667, 6668, 6669, 7000, 7001, 7002, 7070, 7100, 7200, 7474, 7547,
    # Development ports
    8000, 8008, 8009, 8010, 8031, 8042, 8045, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8098, 8099,
    # Security ports
    8443, 8787, 8880, 8888, 8889, 8983, 9000, 9001, 9002, 9042, 9043, 9060, 9080, 9090, 9091, 9092, 9200, 9300, 9418,
    # Additional service ports
    9999, 10000, 10050, 10051, 10250, 10443, 11211, 27017, 27018, 27019, 28017, 50000, 50070, 50075, 50090
]

def get_service_name(port):
    try:
        service = socket.getservbyport(port)
        return service
    except:
        return "Unknown"

def scan_port(target, port, open_ports, lock):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            service = get_service_name(port)
            with lock:
                open_ports.append({
                    'port': port,
                    'service': service,
                    'status': 'Open'
                })
        sock.close()
    except Exception as e:
        print(f"Error scanning port {port}: {str(e)}")
    finally:
        try:
            sock.close()
        except:
            pass

def get_system_info():
    info = {
        'os': platform.system(),
        'os_version': platform.version(),
        'machine': platform.machine(),
        'processor': platform.processor(),
        'hostname': socket.gethostname(),
        'ip_address': socket.gethostbyname(socket.gethostname()),
        'cpu_cores': psutil.cpu_count(),
        'memory_total': psutil.virtual_memory().total,
        'memory_available': psutil.virtual_memory().available,
        'disk_partitions': []
    }
    
    for partition in psutil.disk_partitions():
        try:
            partition_usage = psutil.disk_usage(partition.mountpoint)
            info['disk_partitions'].append({
                'device': partition.device,
                'mountpoint': partition.mountpoint,
                'fstype': partition.fstype,
                'total': partition_usage.total,
                'used': partition_usage.used,
                'free': partition_usage.free
            })
        except:
            continue
    
    return info

def scan_ports(target_host, port_range=None, common_ports=False):
    if port_range is None and not common_ports:
        port_range = (1, 1024)
    
    open_ports = []
    threads = []
    thread_lock = threading.Lock()
    
    try:
        # Test if target is reachable
        socket.gethostbyname(target_host)
        
        if common_ports:
            ports_to_scan = COMMON_PORTS
        else:
            ports_to_scan = range(port_range[0], port_range[1] + 1)
        
        # Create thread pool with a maximum of 100 concurrent threads
        max_threads = 100
        active_threads = []
        
        for port in ports_to_scan:
            thread = threading.Thread(
                target=scan_port, 
                args=(target_host, port, open_ports, thread_lock)
            )
            active_threads.append(thread)
            thread.start()
            
            # If we've reached max threads or this is the last port,
            # wait for threads to complete
            if len(active_threads) >= max_threads or port == ports_to_scan[-1]:
                for t in active_threads:
                    t.join()
                active_threads = []
        
        return sorted(open_ports, key=lambda x: x['port'])
        
    except Exception as e:
        print(f"Error during scan: {str(e)}")
        return [{
            'error': f'Scan failed: {str(e)}',
            'target': target_host
        }]

def save_scan_results(results, system_info):
    try:
        # Ensure directory exists
        os.makedirs('static/scans', exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"scan_results_{timestamp}.json"
        
        data = {
            'timestamp': timestamp,
            'system_info': system_info,
            'scan_results': results
        }
        
        filepath = os.path.join('static', 'scans', filename)
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=4)
        
        print(f"Scan results saved to: {filepath}")
        return filename
        
    except Exception as e:
        print(f"Error saving results: {str(e)}")
        return None 