import pandas as pd
import numpy as np
import random
import socket
import struct

def generate_random_ip():
    return socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)))

def generate_internal_ip():
    return f"192.168.1.{random.randint(2, 254)}"

def generate_synthetic_iot23_data(num_samples=10000):
    np.random.seed(42)
    random.seed(42)
    
    data = []
    labels = ['Benign', 'Malicious']
    detailed_labels = {
        'Benign': ['None'],
        'Malicious': ['Mirai', 'PartOfAHorizontalPortScan', 'C&C', 'DDoS']
    }
    
    protocols = ['tcp', 'udp', 'icmp']
    conn_states = ['SF', 'S0', 'REJ', 'RSTO', 'RSTR', 'SH']
    services = ['http', 'dns', 'ssh', 'ssl', '-', 'dhcp']
    
    for _ in range(num_samples):
        # 30% Benign, 70% Malicious
        label = np.random.choice(labels, p=[0.3, 0.7])
        detailed = np.random.choice(detailed_labels[label])
        
        proto = np.random.choice(protocols)
        service = np.random.choice(services)
        conn_state = np.random.choice(conn_states)
        
        src_ip = generate_internal_ip()
        dst_ip = generate_random_ip()
        
        if label == 'Benign':
            duration = np.random.exponential(scale=2.0)
            orig_bytes = np.random.lognormal(mean=7, sigma=1)
            resp_bytes = np.random.lognormal(mean=8, sigma=1.5)
            orig_pkts = int(np.random.lognormal(mean=2, sigma=1)) + 1
            resp_pkts = int(np.random.lognormal(mean=2.5, sigma=1)) + 1
        else:
            if detailed == 'Mirai':
                duration = np.random.exponential(scale=0.1)
                orig_bytes = np.random.normal(loc=150, scale=20)
                resp_bytes = 0
                orig_pkts = np.random.randint(1, 5)
                resp_pkts = 0
                conn_state = 'S0'
                dst_ip = generate_random_ip() # Mirai scans random IPs
            elif detailed == 'DDoS':
                duration = np.random.exponential(scale=0.01)
                orig_bytes = np.random.normal(loc=1200, scale=100)
                resp_bytes = np.random.normal(loc=50, scale=10)
                orig_pkts = np.random.randint(10, 100)
                resp_pkts = np.random.randint(0, 5)
                dst_ip = f"10.0.0.{np.random.choice([10, 15, 20])}" # Focussed attack on few victim IPs
            else: # C&C or PortScan
                duration = np.random.exponential(scale=5.0)
                orig_bytes = np.random.lognormal(mean=5, sigma=1)
                resp_bytes = np.random.lognormal(mean=5, sigma=1)
                orig_pkts = int(np.random.lognormal(mean=1, sigma=0.5)) + 1
                resp_pkts = int(np.random.lognormal(mean=1, sigma=0.5)) + 0
                
        orig_p = np.random.randint(1024, 65535)
        resp_p = np.random.choice([80, 443, 53, 23, 22, 8080, 2323])
        
        row = {
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'duration': max(0, duration),
            'orig_bytes': max(0, orig_bytes),
            'resp_bytes': max(0, resp_bytes),
            'orig_pkts': max(1, orig_pkts),
            'resp_pkts': max(0, resp_pkts),
            'orig_p': orig_p,
            'resp_p': resp_p,
            'proto': proto,
            'service': service,
            'conn_state': conn_state,
            'label': label,
            'detailed_label': detailed
        }
        data.append(row)
        
    df = pd.DataFrame(data)
    df.to_csv('iot23_sample.csv', index=False)
    print(f"Generated synthetic IoT-23 dataset with IPs: iot23_sample.csv")

if __name__ == "__main__":
    generate_synthetic_iot23_data()
