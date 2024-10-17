import pyshark
import psutil
from termcolor import colored
banner = colored("""
--------------------------------------------------------------
░▒▓███████▓▒░░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░▒▓████████▓▒░      
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░          
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░          
░▒▓███████▓▒░░▒▓█▓▒░    ░▒▓██████▓▒░░▒▓████████▓▒░ ░▒▓█▓▒░          
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░          
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░          
░▒▓███████▓▒░░▒▓████████▓▒░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░          
---------------------------------------------------------------""",'green')
print(banner)
print(colored("1. Analyze PCAP for NMAP Port Scans\n2. Live Analysis for NMAP Portscans\n3. print fuck\n---------------------------------------------------------------",'green'))
Main_Choice=input(colored("Select analysis option: (1,2,3...): ",'green'))



match Main_Choice:
        case "1":
                input_text=colored("Enter the file for analysis: ", 'green')
                pcap_path=input(input_text)
                pcap=pyshark.FileCapture(pcap_path)
                #Main Logic
                scan_detection_counter=0
                scan_flags_dict={
                        'Open SYN Scan':['0x0002', '0x0012', '0x0004'],
                        'Closed SYN Scan':['0x0002', '0x0014'],
                        'TCP ACK Scan':['0x0010', '0x0004'],
                        'Open FIN Scan':['0x0001', '0x0014'],
                        'Closed FIN Scan':['0x0001'],
                }
                #Functions
                def Check_Protocol_And_Filter(pkt):
                        Protocol=pcap[pkt].frame_info.protocols
                        if "eth:ethertype:ip:tcp"==Protocol:
                                return "TCP"
                        if "eth:ethertype:ip:udp:data"==Protocol:
                                return "UDP"
                        else:
                                return "0"
                #Main Logic
                #calc numb of packets in pcap
                num_of_pkt=0
                for pkt in pcap:
                        num_of_pkt=num_of_pkt+1
                packet_text=colored(" packets in pcap",'green')
                print(str(colored(num_of_pkt,'green'))+ packet_text)
                #filter tcp and udp from file into lists for analysis
                packet_range=range(0,num_of_pkt,1)
                tcp_pkt_to_stream_dict={}
                udp_pkt_to_stream_dict={}
                for pkt in packet_range:
                        Protocol = Check_Protocol_And_Filter(pkt)
                        if Protocol=="TCP":
                                key=pcap[pkt].tcp.stream
                                tcp_pkt_to_stream_dict.setdefault(key, [])
                                tcp_pkt_to_stream_dict[key].append(pcap[pkt].frame_info.number)
                        if Protocol=="UDP":
                                key=pcap[pkt].udp.stream
                                udp_pkt_to_stream_dict.setdefault(key, [])
                                udp_pkt_to_stream_dict[key].append(pcap[pkt].frame_info.number)
                for key in tcp_pkt_to_stream_dict.keys():
                        pkts=tcp_pkt_to_stream_dict[key]
                        flag_str=[]
                        temp_stream=tcp_pkt_to_stream_dict[key]
                        for p in temp_stream:
                                p=int(p)-1
                                flag=pcap[p].tcp.flags
                                flag_str.append(flag)
                        for scans in scan_flags_dict.keys():
                                if flag_str == scan_flags_dict[scans]:
                                        print(str(colored(scans,'green'))+colored(" Dectected in stream ",'green')+ colored(key,'green'))
                                        scan_detection_counter = scan_detection_counter +1
                if scan_detection_counter==0:
                        print(colored("No Scans detected in PCAP :)",'green'))
                else:
                        print(colored("Number of Scans detected: ",'green')+str(colored(scan_detection_counter,'green')))
        
        case "2":
                print(colored("Select Interface:",'green'))
                interface=psutil.net_if_stats()
                print(colored(interface,'green'))
                interface=input(colored("Input Option: ",'green'))
                capture=pyshark.LiveCapture(interface=interface)
                capture.sniff(timeout=10)
                for pkt in capture:
                        try:
                                print(colored(pkt.data,'green'))
                        except:
                                print(colored(pkt.frame_info.protocols,'green'))

        case "3":
                print(colored("Fuck",'green'))
