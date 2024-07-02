'''
Name: Scan Detector
Goal: Parse PCAP files with python to look for common scanning methods

[X]1. TCP SYN Scan (SS)
        open port   closed port
        0x0002      0x0002
        0x0012      0x0014
        0x0004
[]2. TCP ACK Scan (SA)
[]3. UDP Scan

'''
#Imports
import pyshark
import collection
#Vars
banner = """
███████╗██╗   ██╗ ██████╗██╗  ██╗    ██████╗ ██╗   ██╗████████╗██╗███╗   ██╗
██╔════╝██║   ██║██╔════╝██║ ██╔╝    ██╔══██╗██║   ██║╚══██╔══╝██║████╗  ██║
█████╗  ██║   ██║██║     █████╔╝     ██████╔╝██║   ██║   ██║   ██║██╔██╗ ██║
██╔══╝  ██║   ██║██║     ██╔═██╗     ██╔═══╝ ██║   ██║   ██║   ██║██║╚██╗██║
██║     ╚██████╔╝╚██████╗██║  ██╗    ██║     ╚██████╔╝   ██║   ██║██║ ╚████║
╚═╝      ╚═════╝  ╚═════╝╚═╝  ╚═╝    ╚═╝      ╚═════╝    ╚═╝   ╚═╝╚═╝  ╚═══╝
                                                                            
"""

print(banner)
pcap_path=input("Enter the file for analysis: ")
pcap=pyshark.FileCapture(pcap_path)
#Main Logic

#calc numb of packets in pcap
num_of_pkt=0
for pkt in pcap:
        num_of_pkt=num_of_pkt+1
print(str(num_of_pkt)+" packets in pcap")

#calc num of streams in pcap
streams=0
packet_range=range(0,num_of_pkt,1)
for pkt in packet_range:
        try:        
                stream = int(pcap[pkt].tcp.stream)
                streams = stream + 1
        except:
                pass
print("Number of Streams in pcap: "+ str(streams-1))

#allign streams to all packets in stream
stream_pkt_dict={}
stream_range=range(0,streams,1)
for pkt in packet_range:
        try:
                key=pcap[pkt].tcp.stream
                stream_pkt_dict.setdefault(key, [])
                stream_pkt_dict[key].append(pcap[pkt].frame_info.number)
        except:
                pass
print("[+]Checking for TCP SYN Scan...")
for stream in stream_range:
        ss_open_port_scan=['0x0002', '0x0012', '0x0004']
        ss_closed_port_scan=['0x0002', '0x0014']
        tmp_string=[]
        temp_stream=stream_pkt_dict[str(stream)]
        for pkt in temp_stream:
                pkt=int(pkt)-1
                flag = pcap[pkt].tcp.flags
                tmp_string.append(flag)
                if tmp_string==ss_open_port_scan:
                        print("TCP Syn Scan of open port detected in stream "+str(stream))
                if tmp_string==ss_closed_port_scan:
                        print("TCP Syn Scan of closed port detected in stream "+str(stream))


print('[+]Checking for TCP ACK Scan...')
for stream in stream_range:
        sa_port_scan=['0x0010', '0x0004']
        tmp_string=[]
        temp_stream=stream_pkt_dict[str(stream)]
        for pkt in temp_stream:
                pkt=int(pkt)-1
                flag=pcap[pkt].tcp.flags
                tmp_string.append(flag)
                if tmp_string==sa_port_scan:
                        print("TCP ACK Scan of open port detected in stream "+str(stream))

print("[+]Checking for TCP FIN Scan...")
for stream in stream_range:
        sf_open_port_scan=['0x0001', '0x0014']
        sf_closed_port_scan=['0x0001']
        tmp_string=[]
        temp_stream=stream_pkt_dict[str(stream)]
        for pkt in temp_stream:
                pkt=int(pkt)-1
                flag=pcap[pkt].tcp.flags
                tmp_string.append(flag)
                if tmp_string==sf_open_port_scan:
                        print("TCP FIN Scan of open port detected in stream "+str(stream))
                if tmp_string==sf_closed_port_scan:
                        print("TCP FIN Scan of closed port detected in stream "+str(stream))