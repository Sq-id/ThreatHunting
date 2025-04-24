import pyshark
import json
from Funcs import let_me_func


def tcp_udp_flag_header():

        tcp_pkt_to_stream_dict={}
        udp_pkt_to_stream_dict={}
        matrixData=[]
        num_of_pkt=0
        
        def Check_Protocol_And_Filter(pkt):
                Protocol=pcap[pkt].frame_info.protocols
                if "eth:ethertype:ip:tcp" == Protocol:
                        return "TCP"
                if "eth:ethertype:ip:udp:data" == Protocol:
                        return "UDP"
                else:
                        return "0"

        def gather_and_build_matrix(key,scans,port,length):
                appendMe=[key,scans,port]                
                matrixData.append(appendMe)                        
                
        with open('./Signatures/tcp_flag_headers.json', 'r') as sig_file:
                data_sig_file=json.load(sig_file)
        pcap_path=input("Please enter Path to PCAP: ")
        pcap=pyshark.FileCapture(pcap_path)
        scan_detection_counter=0
        scan_flags_dict={}
        
        for sig_json in data_sig_file["signatures"]:
                scan_flags_dict.update(
                    {sig_json['sig_name']: sig_json['sig_cont']})

        
        for pkt in pcap:
                num_of_pkt=num_of_pkt + 1
        print("Number of Packets: "+ str(num_of_pkt))
        packet_range=range(0, num_of_pkt, 1)
        
        for pkt in packet_range:
                Protocol=Check_Protocol_And_Filter(pkt)
                if Protocol == "TCP":
                        key=pcap[pkt].tcp.stream
                        tcp_pkt_to_stream_dict.setdefault(key, [])
                        tcp_pkt_to_stream_dict[key].append(
                            pcap[pkt].frame_info.number)
                if Protocol == "UDP":
                        key=pcap[pkt].udp.stream
                        udp_pkt_to_stream_dict.setdefault(key, [])
                        udp_pkt_to_stream_dict[key].append(
                            pcap[pkt].frame_info.number)
        length=len(tcp_pkt_to_stream_dict)
        for key in tcp_pkt_to_stream_dict.keys():
                
                pkts=tcp_pkt_to_stream_dict[key]
                flag_str=[]
                temp_stream=tcp_pkt_to_stream_dict[key]
                for val in temp_stream:
                        val=int(val) - 1
                        flag=pcap[val].tcp.flags
                        flag_str.append(flag)
                        port=pcap[int(temp_stream[0]) - 1].tcp.dstport
                        
                        for scans in scan_flags_dict.keys():
                               if flag_str == scan_flags_dict[scans]:
                                        print(str(scans) + " Dectected in stream " + key)   
                                        scan_detection_counter=scan_detection_counter + 1
                                        gather_and_build_matrix(key,scans,port,range(length))
                                        
                                        
        for key in udp_pkt_to_stream_dict.keys():
                pkts=udp_pkt_to_stream_dict[key]
                flag_str=[]
                temp_stream=udp_pkt_to_stream_dict[key]
                for p in temp_stream:
                        p=int(p) - 1
                        flag=pcap[p].udp.stream
                        flag_str.append(flag)
                
                for scans in scan_flags_dict.keys():
                        if flag_str == scan_flags_dict[scans]:
                                print(str(scans) + " Dectected in stream " + key)
                                scan_detection_counter=scan_detection_counter + 1
                                
                if scan_detection_counter == 0:
                        print("No Scans detected in PCAP :)")
                else:
                        print("Number of Scans detected:", scan_detection_counter)
                        headers=["Index","Status","Port"]
                        let_me_func.generate_csv("flag_header_detect", headers ,matrixData)
                        print(matrixData)
        

        if scan_detection_counter == 0:
            print("No Scans detected in PCAP :)")
        else:
            print("Number of Scans detected:", scan_detection_counter)
            headers=["Index","Status","Port"]
            let_me_func.generate_csv("flag_header_detect", headers ,matrixData)
            
