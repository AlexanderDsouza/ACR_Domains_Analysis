import os
import matplotlib.pyplot as plt
from scapy.all import *
import time
import csv
import numpy as np  # Import numpy for array manipulation


def read_csv_to_dict(file_path):
    data_dict = []

    with open(file_path, 'r') as csv_file:
        csv_reader = csv.DictReader(csv_file)
        for row in csv_reader:
            data_dict.append({
                "time": row["time"],
                "sent": int(row["sent"]),
                "received": int(row["received"])
            })

    return data_dict

def extract_data_from_time(pcap_file, domain_to_ips, my_ip):
    print("pre extraction")
    data = {"time": [], "sent": {domain: [] for domain in domain_to_ips}, "received": {domain: [] for domain in domain_to_ips}}
    start_time = 0
    last_packet_time = 0
    first_packet_time = 0
    cnt = 10


    for packet in rdpcap(pcap_file):
        print(f"packet loop{cnt}") 
        cnt +=1
        if IP in packet:
            if first_packet_time == 0:
                first_packet_time = float(packet.time) * 1000
            last_packet_time = float(packet.time) * 1000
    
    for packet in rdpcap(pcap_file):
        if IP in packet:
            timestamp = float(packet.time) * 1000
            curr_time = timestamp - first_packet_time
            data["time"].append(curr_time)

            for domain, target_ips in domain_to_ips.items():
                print(f"domain loop{cnt}")
                cnt +=1
                sent_len = sum(packet[IP].len for ip in target_ips if packet[IP].src == my_ip and packet[IP].dst == ip)
                received_len = sum(packet[IP].len for ip in target_ips if packet[IP].src == ip and packet[IP].dst == my_ip)
                data["sent"][domain].append(sent_len)
                data["received"][domain].append(received_len)
    return data




def plot_data(data, us_target_domains, uk_data, uk_domains, output_file, start_time, end_time):
    plt.figure(figsize=(10, 6))

    # Plot data for US domains
    for target_domain in us_target_domains:
        sent_data = data["sent"][target_domain]
        time_data = np.array(data["time"])  # Convert to NumPy array
        mask = (time_data >= start_time) & (time_data <= end_time)
        filtered_time_data = time_data[mask]
        plt.plot(filtered_time_data, np.array(sent_data)[mask], label=f"Sent to {target_domain}")

    # Plot data for UK domains
    for target_domain in uk_domains:
        sent_data = uk_data["sent"][target_domain]
        time_data = np.array(uk_data["time"])  # Convert to NumPy array
        mask = (time_data >= start_time) & (time_data <= end_time)
        filtered_time_data = time_data[mask]
        plt.plot(filtered_time_data, np.array(sent_data)[mask], label=f"Sent to {target_domain}")

    plt.xlabel('Time (s)')
    plt.ylabel('Bytes')
    plt.title(f'Bytes sent Over Time ({start_time}-{end_time} ms)')
    plt.legend()
    plt.savefig(output_file)
    plt.close()  # Close the figure to prevent displaying it



def generate_pairs(interval_size, max_interval):
    intervals = []
    for start_time in range(0, max_interval, interval_size):
        end_time = start_time + interval_size
        if end_time <= max_interval:
            intervals.append((start_time, end_time))
    return intervals





if __name__ == "__main__":
    pcap_file = "D:/PCAPFILES/round 3 filtered files/LG/mergedLGPCAP.pcap"
    uk_pcap_file = "D:/PCAPFILES/round 3 filtered files/LG/UK_acr_domains_scenario2_applicationdata_round3.pcap"
    
    target_ips = {
        'tkacr316.alphonso.tv': [
            '173.233.81.210'
        ],
        'tkacr387.alphonso.tv': [
            '173.233.81.137'
        ]
    }

    uk_target_ips = {
        'uk_tkacr': 
        ['96.47.5.159']
    }

    my_ip = "10.42.0.96"
    uk_ip = "18.10.0.3"
    output_dir = "D:/PCAPFILES/round 3 filtered files/LG/Plots/"

    max_value = 110000000
    interval_size = 15000
    interval_size_2 = 10000

    max_interval = 110000000

    time_intervals_1 = generate_pairs(interval_size, max_interval)
    time_intervals_2 = generate_pairs(interval_size_2, max_interval)
    #print(time_intervals_1)

    
    #print (uk_data["time"])
    # plt.figure(figsize=(10, 6))
    # start_time,end_time = time_intervals_1[0]
    # print(start_time)
    # print(end_time)

    # # for target_domain in uk_target_ips:
    # #     sent_data = uk_data["sent"][target_domain]
    # #     time_data = np.array(uk_data["time"])  # Convert to NumPy array
    # #     mask = (time_data >= start_time) & (time_data <= end_time)
    # #     filtered_time_data = time_data[mask]
    # #     plt.plot(filtered_time_data, np.array(sent_data)[mask], label=f"Sent to {target_domain}")
    # #     plt.xlabel('Time (s)')
    # #     plt.ylabel('Bytes')
    # #     plt.title(f'Bytes sent Over Time ({start_time}-{end_time} ms)')
    # #     plt.legend()
    # #     plt.show()
   
    uk_data = extract_data_from_time(uk_pcap_file, uk_target_ips, uk_ip)
    us_data = extract_data_from_time(pcap_file, target_ips, my_ip)

    for start_time, end_time in time_intervals_1:
        output_file = f"Round_3_LG_ACR_domains_bytes_over_time_fr_{start_time}_{end_time}.png"
        output_path = os.path.join(output_dir, output_file)
        print("before plot 1")
        plot_data(us_data, target_ips, uk_data, uk_target_ips, output_path,start_time,end_time)
        print("saved plto 1")


    for start_time, end_time in time_intervals_2:
        output_file = f"Round_3_LG_ACR_domains_bytes_over_time_fr_{start_time}_{end_time}.png"
        output_path = os.path.join(output_dir, output_file)
        plot_data(us_data, target_ips, uk_data, uk_target_ips, output_path,start_time,end_time)

