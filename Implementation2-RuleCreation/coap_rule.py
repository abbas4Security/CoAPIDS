import sys
import pyshark
from datetime import datetime
import random

port = None 
# Create a Pyshark Capture object
capture = pyshark.FileCapture('coap.pcap')
# FUnction For getting information about Coap Protocol 
def get_coap_info(filename , ip_addr , src_port1 ):
    
    if(ip_addr == "any" and src_port1 == "any"):
        cap = pyshark.FileCapture(filename, display_filter='coap && (coap.code == 1 || coap.code == 2 || coap.code == 3 || coap.code == 4)')
        src_ip = ip_addr
        dst_ip = ip_addr
        src_port = ip_addr
    else:
        cap = pyshark.FileCapture(filename ,display_filter='coap ')
        
        for pkt1 in cap:
            if 'IP' in pkt1:
                ip_layer = packet['IP']
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                src_port = ip_layer.sport
                dst_port = ip_layer.dport
        
            elif 'IPv6' in packet and pkt1.ipv6.src == ip_addr:
                ip_layer = packet['IPv6']
                src_ip = ip_layer.src

                dst_ip = ip_layer.dst
                src_port = packet[packet.transport_layer].srcport
                dst_port = packet[packet.transport_layer].dstport
        
    rules = {}

    # search for Src IP and Dst IP and method for 'PUT' , 'GET', 'POST' , 'DELETE'
    for pkt in cap:
        
        global port
        method = pkt.coap.code
        port = src_port
        
        if (src_ip, dst_ip) not in rules:
            rules[(src_ip, dst_ip)] = {'get': 0, 'post': 0, 'delete': 0, 'put': 0 }

        if method == '1':
            rules[(src_ip, dst_ip)]['get'] += 1
            
        elif method == '2':
            rules[(src_ip, dst_ip)]['put'] += 1
            
        elif method == '3':
            rules[(src_ip, dst_ip)]['delete'] += 1
            
        elif method == '4':
            rules[(src_ip, dst_ip)]['post'] += 1
            

    return rules


# Initialize start and end timestamps to None
start_time = None
end_time = None

# Loop through each packet in the capture, and update start and end timestamps
for packet in capture:
    timestamp = float(packet.sniff_time.timestamp())
    if start_time is None:
        start_time = timestamp
    end_time = timestamp

# Convert timestamps to datetime objects, and format as strings
start_time = datetime.fromtimestamp(start_time)
end_time = datetime.fromtimestamp(end_time)

# Calculate the total time in seconds
total_time = int((end_time - start_time).total_seconds())
total_time = total_time+1


# Fucntion For Rules Gneration based on CoAP Protocol 
def alert_rules(rules):
    for (src_ip, dst_ip), methods_freq in rules.items():
        for method, count ,  in methods_freq.items():
            if count == 0:
                continue
            
            message_id = random.randint(22222,44444)
            
            #msg = f"CoAP traffic from {src_ip} to {dst_ip}; "
            #msg += f'sid: {message_id}; coap_method: {method}; threshold: type threshold, track by_src, count {count} seconds {total_time}'
            #alert_msg = f"alert coap {src_ip} {dst_ip} -> {dst_ip} {port}  (msg:\"{msg}\"; priority:1;)"

            alert_msg = f'alert coap {src_ip} {dst_ip} -> {dst_ip} {port} (msg:"CoAP traffic from {src_ip} to {dst_ip}"; sid: {message_id}; coap_method: {method}; threshold: type threshold, track by_src, count {count}, seconds {total_time}; priority:1;)'
            print(alert_msg)
            # write the alert message to the coap.rules file
            with open("coap.rules", "a") as f:
                f.write(alert_msg + "\n")
    rule_drop('coap.rules')

capture.close()
del capture

def rule_drop(filename):
    with open(filename, 'r') as f:
        lines = f.readlines()

    unique_lines = []
    for line in lines:
        if line not in unique_lines:
            unique_lines.append(line)

    with open(filename, 'w') as f:
        f.writelines(unique_lines)


#filename = 'coap.pcap'
if __name__ == '__main__':   
    if len(sys.argv) == 2:        
        # Create a Pyshark Capture object
        filename= sys.argv[1]
        capture = pyshark.FileCapture(filename)
        IP_addr = "any"
        Src_Port = "any"
        coap_info = get_coap_info(filename , IP_addr , Src_Port)
        alert_rules(coap_info)
    elif len(sys.argv) == 4:
        filename= sys.argv[1]
        IP_addr = sys.argv[2]
        Src_Port = sys.argv[3]
        coap_info = get_coap_info(filename, IP_addr , Src_Port)
        alert_rules(coap_info)
    else:
        print("Usage python3 coap_rule.py [PCAP_File] [IP_Addr(optional)] [Src_Port(optional)]")
