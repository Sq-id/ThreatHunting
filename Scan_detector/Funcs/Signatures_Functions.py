import json
from Funcs import let_me_func


def tcp_udp_flag_header():
        import pyshark
        tcp_pkt_to_stream_dict = {}
        udp_pkt_to_stream_dict = {}
        matrixData = []
        num_of_pkt = 0

        def Check_Protocol_And_Filter(pkt):
                Protocol = pcap[pkt].frame_info.protocols
                if "eth:ethertype:ip:tcp" == Protocol:
                        return "TCP"
                if "eth:ethertype:ip:udp:data" == Protocol:
                        return "UDP"
                else:
                        return "0"

        def gather_and_build_matrix(key, scans, port, src_ip, length):
                appendMe = [key, scans, port, src_ip]
                matrixData.append(appendMe)

        with open('./Signatures/tcp_flag_headers.json', 'r') as sig_file:
                data_sig_file = json.load(sig_file)
        pcap_path = input("Please enter Path to PCAP: ")
        pcap = pyshark.FileCapture(pcap_path)
        scan_detection_counter = 0
        scan_flags_dict = {}

        for sig_json in data_sig_file["signatures"]:
                scan_flags_dict.update(
                    {sig_json['sig_name']: sig_json['sig_cont']})

        for pkt in pcap:
                num_of_pkt = num_of_pkt + 1
        print("Number of Packets: " + str(num_of_pkt))
        packet_range = range(0, num_of_pkt, 1)

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

        length = len(tcp_pkt_to_stream_dict)
        for key in tcp_pkt_to_stream_dict.keys():

                pkts = tcp_pkt_to_stream_dict[key]
                flag_str = []
                temp_stream = tcp_pkt_to_stream_dict[key]
                for val in temp_stream:
                        val = int(val) - 1
                        flag = pcap[val].tcp.flags
                        flag_str.append(flag)
                        port = pcap[int(temp_stream[0]) - 1].tcp.dstport
                        src_ip = pcap[int(temp_stream[0]) - 1].ip.src
                        for scans in scan_flags_dict.keys():
                                if flag_str == scan_flags_dict[scans]:
                                        print(
                                            str(scans) +
                                            " Detected in stream " + key + " from source IP: " + src_ip)
                                        scan_detection_counter = scan_detection_counter + 1
                                        gather_and_build_matrix(
                                            key, scans, port, src_ip, range(length))

        for key in udp_pkt_to_stream_dict.keys():
                pkts = udp_pkt_to_stream_dict[key]
                flag_str = []
                temp_stream = udp_pkt_to_stream_dict[key]
                for p in temp_stream:
                        p = int(p) - 1
                        flag = pcap[p].udp.stream
                        flag_str.append(flag)
                        port = pcap[int(temp_stream[0]) - 1].udp.dstport
                        src_ip = pcap[int(temp_stream[0]) - 1].ip.src
                        for scans in scan_flags_dict.keys():
                                if flag_str == scan_flags_dict[scans]:
                                        print(
                                            str(scans) +
                                            " Detected in stream " + key + " from source IP: " + src_ip)
                                        scan_detection_counter = scan_detection_counter + 1
                                        gather_and_build_matrix(
                                            key, scans, port, src_ip, range(length))

        if scan_detection_counter == 0:
                print("No Scans detected in PCAP :)")
        else:
                print("Number of Scans detected:", scan_detection_counter)
                headers = ["Index", "Status", "Port", "Source_IP"]
                let_me_func.generate_csv("flag_header_detect", headers,
                                         matrixData)


def dissect_packets_by_stream():
        '''
        Completely dissects packets and organizes them by stream
        Returns detailed packet information for analysis
        '''
        import pyshark
        
        pcap_path = input("Please enter Path to PCAP: ")
        pcap = pyshark.FileCapture(pcap_path)
        
        tcp_streams = {}
        udp_streams = {}
        packet_details = {}
        
        print("Analyzing packets...")
        
        for pkt in pcap:
                packet_num = int(pkt.frame_info.number)
                protocol = pkt.frame_info.protocols
                
                # Basic packet info
                packet_info = {
                        'packet_number': packet_num,
                        'timestamp': pkt.frame_info.time_epoch,
                        'protocols': protocol,
                        'length': pkt.frame_info.len
                }
                
                # IP layer information
                if hasattr(pkt, 'ip'):
                        packet_info.update({
                                'src_ip': pkt.ip.src,
                                'dst_ip': pkt.ip.dst,
                                'ip_version': pkt.ip.version,
                                'ttl': pkt.ip.ttl,
                                'ip_id': pkt.ip.id
                        })
                
                # TCP specific information
                if hasattr(pkt, 'tcp'):
                        stream_id = pkt.tcp.stream
                        packet_info.update({
                                'src_port': pkt.tcp.srcport,
                                'dst_port': pkt.tcp.dstport,
                                'seq_num': pkt.tcp.seq,
                                'ack_num': pkt.tcp.ack,
                                'flags': pkt.tcp.flags,
                                'window_size': pkt.tcp.window_size,
                                'tcp_len': pkt.tcp.len
                        })
                        
                        # Organize by TCP stream
                        if stream_id not in tcp_streams:
                                tcp_streams[stream_id] = []
                        tcp_streams[stream_id].append(packet_num)
                
                # UDP specific information
                elif hasattr(pkt, 'udp'):
                        stream_id = pkt.udp.stream
                        packet_info.update({
                                'src_port': pkt.udp.srcport,
                                'dst_port': pkt.udp.dstport,
                                'udp_length': pkt.udp.length
                        })
                        
                        # Organize by UDP stream
                        if stream_id not in udp_streams:
                                udp_streams[stream_id] = []
                        udp_streams[stream_id].append(packet_num)
                
                # Store complete packet details
                packet_details[packet_num] = packet_info
        
        # Print summary
        print(f"Total packets analyzed: {len(packet_details)}")
        print(f"TCP streams found: {len(tcp_streams)}")
        print(f"UDP streams found: {len(udp_streams)}")
        
        # Display stream details
        for stream_id, packets in tcp_streams.items():
                first_pkt = packet_details[packets[0]]
                print(f"TCP Stream {stream_id}: {first_pkt['src_ip']}:{first_pkt['src_port']} -> {first_pkt['dst_ip']}:{first_pkt['dst_port']} ({len(packets)} packets)")
        
        for stream_id, packets in udp_streams.items():
                first_pkt = packet_details[packets[0]]
                print(f"UDP Stream {stream_id}: {first_pkt['src_ip']}:{first_pkt['src_port']} -> {first_pkt['dst_ip']}:{first_pkt['dst_port']} ({len(packets)} packets)")
        
        return {
                'tcp_streams': tcp_streams,
                'udp_streams': udp_streams,
                'packet_details': packet_details,
                'pcap_path': pcap_path
        }


def tcp_udp_flag_header_enhanced(dissected_data=None):
        '''
        Enhanced version that can use pre-dissected packet data
        '''
        import pyshark
        import json
        
        if dissected_data is None:
                # Use original function logic
                return tcp_udp_flag_header()
        
        # Use pre-dissected data
        tcp_streams = dissected_data['tcp_streams']
        udp_streams = dissected_data['udp_streams']
        packet_details = dissected_data['packet_details']
        pcap_path = dissected_data['pcap_path']
        
        pcap = pyshark.FileCapture(pcap_path)
        matrixData = []
        scan_detection_counter = 0
        
        # Load signatures
        with open('./Signatures/tcp_flag_headers.json', 'r') as sig_file:
                data_sig_file = json.load(sig_file)
        
        scan_flags_dict = {}
        for sig_json in data_sig_file["signatures"]:
                scan_flags_dict.update({sig_json['sig_name']: sig_json['sig_cont']})
        
        def gather_and_build_matrix(key, scans, port, src_ip, length):
                appendMe = [key, scans, port, src_ip]
                matrixData.append(appendMe)
        
        # Analyze TCP streams using dissected data
        for stream_id, packet_nums in tcp_streams.items():
                flag_str = []
                first_pkt_details = packet_details[packet_nums[0]]
                
                for pkt_num in packet_nums:
                        pkt_details = packet_details[pkt_num]
                        if 'flags' in pkt_details:
                                flag_str.append(pkt_details['flags'])
                
                # Check against signatures
                for scan_name, scan_flags in scan_flags_dict.items():
                        if flag_str == scan_flags:
                                print(f"{scan_name} Detected in TCP stream {stream_id} from source IP: {first_pkt_details['src_ip']}")
                                scan_detection_counter += 1
                                gather_and_build_matrix(
                                        stream_id, scan_name, 
                                        first_pkt_details['dst_port'], 
                                        first_pkt_details['src_ip'], 
                                        len(tcp_streams)
                                )
        
        # Analyze UDP streams using dissected data
        for stream_id, packet_nums in udp_streams.items():
                flag_str = []
                first_pkt_details = packet_details[packet_nums[0]]
                
                for pkt_num in packet_nums:
                        flag_str.append(stream_id)  # UDP uses stream ID as signature
                
                # Check against signatures
                for scan_name, scan_flags in scan_flags_dict.items():
                        if flag_str == scan_flags:
                                print(f"{scan_name} Detected in UDP stream {stream_id} from source IP: {first_pkt_details['src_ip']}")
                                scan_detection_counter += 1
                                gather_and_build_matrix(
                                        stream_id, scan_name,
                                        first_pkt_details['dst_port'],
                                        first_pkt_details['src_ip'],
                                        len(udp_streams)
                                )
        
        if scan_detection_counter == 0:
                print("No Scans detected in PCAP :)")
        else:
                print("Number of Scans detected:", scan_detection_counter)
                headers = ["Index", "Status", "Port", "Source_IP"]
                let_me_func.generate_csv("flag_header_detect", headers, matrixData)


def tcp_udp_flag_create_rule():
        '''
        1. Take input from tcp_udp_flag_header func
        2. Take streams that triggered positive detection
        3. Create rules that block based on ip in positive stream
        '''

