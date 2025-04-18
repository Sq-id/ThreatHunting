import pyshark
import json
from rich.console import Console
from rich.table import Table


def tcp_udp_flag_header():
        with open('./Signatures/tcp_flag_headers.json', 'r') as sig_file:
                data_sig_file = json.load(sig_file)
        pcap_path = input("Please enter Path to PCAP: ")
        pcap = pyshark.FileCapture(pcap_path)
        scan_detection_counter = 0
        scan_flags_dict = {}
        for sig_json in data_sig_file["signatures"]:
                scan_flags_dict.update(
                    {sig_json['sig_name']: sig_json['sig_cont']})
        print(scan_flags_dict)

        def Check_Protocol_And_Filter(pkt):
                Protocol = pcap[pkt].frame_info.protocols
                if "eth:ethertype:ip:tcp" == Protocol:
                        return "TCP"
                if "eth:ethertype:ip:udp:data" == Protocol:
                        return "UDP"
                else:
                        return "0"

        num_of_pkt = 0
        for pkt in pcap:
                num_of_pkt = num_of_pkt + 1
        packet_text = "Number of Packets: "
        print(packet_text + str(num_of_pkt))
        packet_range = range(0, num_of_pkt, 1)

        tcp_pkt_to_stream_dict = {}
        udp_pkt_to_stream_dict = {}
        port_dict = {}
        for pkt in packet_range:
                Protocol = Check_Protocol_And_Filter(pkt)
                if Protocol == "TCP":
                        key = pcap[pkt].tcp.stream
                        tcp_pkt_to_stream_dict.setdefault(key, [])
                        tcp_pkt_to_stream_dict[key].append(
                            pcap[pkt].frame_info.number)
                if Protocol == "UDP":
                        key = pcap[pkt].udp.stream
                        udp_pkt_to_stream_dict.setdefault(key, [])
                        udp_pkt_to_stream_dict[key].append(
                            pcap[pkt].frame_info.number)

        for key in tcp_pkt_to_stream_dict.keys():
                pkts = tcp_pkt_to_stream_dict[key]
                flag_str = []
                temp_stream = tcp_pkt_to_stream_dict[key]
                for p in temp_stream:
                        p = int(p) - 1
                        flag = pcap[p].tcp.flags
                        flag_str.append(flag)
                        port = pcap[p].tcp.dstport
                for scans in scan_flags_dict.keys():
                        if flag_str == scan_flags_dict[scans]:
                                print(
                                    str(scans) + " Dectected in stream " +
                                    key + " on port " + port)
                                scan_detection_counter = scan_detection_counter + 1

        for key in udp_pkt_to_stream_dict.keys():
                pkts = udp_pkt_to_stream_dict[key]
                flag_str = []
                temp_stream = udp_pkt_to_stream_dict[key]
                for p in temp_stream:
                        p = int(p) - 1
                        flag = pcap[p].udp.stream
                        flag_str.append(flag)

                for scans in scan_flags_dict.keys():
                        if flag_str == scan_flags_dict[scans]:
                                print(
                                    str(scans) + " Dectected in stream " + key)
                                scan_detection_counter = scan_detection_counter + 1

        if scan_detection_counter == 0:
                print("No Scans detected in PCAP :)")
        else:
                print("Number of Scans detected:", scan_detection_counter)
