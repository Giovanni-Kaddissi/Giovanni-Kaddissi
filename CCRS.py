from scapy.all import sniff, ICMP, IP
from collections import defaultdict
import time
import sys
import pprint
import hashlib
from datetime import datetime

# Define a dictionary to store information about ICMP packets for each destination IP
icmp_packets = defaultdict(lambda: {'echo_requests': 0, 'packets': [], 'last_echo_timestamp': None,
                                     'avg_time_between_echo': None, 'payload_content_hash': set(),
                                     'NumberOfDifferentPayloads': 0, 'CounterSize32Bytes': 0,
                                     'CounterSize56Bytes': 0, 'HighestSequenceNumberCounter': 0,
                                     'NbOfSequenceNbLessThanHighest': 0, 'CountSeqNbisNoneOrNull': 0,
                                     'SequenceNumbersValues': set(), 'SeqNbRepeatingCounter': 0,
                                     'CountTypeCodeAnomaly': 0, 'HighestIpIdCounter': 0, 
                                     'NbOfIpIdLessThanHighest': 0, 'IpIdValues': set(), 
                                     'IpIdRepeatingCounter': 0, 'CountIpHeaderOptSet': 0,
                                     'payload_content_sizes': set()})
#HighestIpIdCounter
#NbOfIpIdLessThanHighest





def is_payload_size_suspicious(payload_size):
    return payload_size not in (32, 56)



#--------------First Repeating Check
def is_repeating(payload_content_utf): 
    for i in range(1, len(payload_content_utf)):
        if payload_content_utf[:i] * (len(payload_content_utf) // i) + payload_content_utf[:len(payload_content_utf) % i] == payload_content_utf:
            return True
    return False


#--------------Second Repeating Check
def check_repeating(payload_content_utf):
    length = len(payload_content_utf)
    for x in range(1, length):
        substring = payload_content_utf[:x]
        if substring * (length//x) + substring[:length%x] == payload_content_utf:
            return True
    return False



#--------------Third Repeating Check - Longest Pattern Matching Beginning Payload
def count_non_overlapping(payload_content_utf, sub):
    count = start = 0
    while start < len(payload_content_utf):
        pos = payload_content_utf.find(sub, start)
        if pos != -1:
            start = pos + len(sub)
            count += 1
        else:
            break
    return count

def find_non_overlapping_patterns(payload_content_utf):
    length = len(payload_content_utf)
    patterns = {}
    longest_pattern = ""
    for size in range(1, length // 2 + 1):
        for i in range(length - size + 1):
            sub = payload_content_utf[i:i+size]
            if sub not in patterns:
                patterns[sub] = count_non_overlapping(payload_content_utf, sub)
                if len(sub) > len(longest_pattern) and patterns[sub] > 1:
                    longest_pattern = sub
    return patterns, longest_pattern


def get_size(obj, seen=None):
    """Recursively finds size of objects."""
    size = sys.getsizeof(obj)
    if seen is None:
        seen = set()
    obj_id = id(obj)
    if obj_id in seen:
        return 0
    seen.add(obj_id)
    if isinstance(obj, dict):
        size += sum([get_size(v, seen) for v in obj.values()])
        size += sum([get_size(k, seen) for k in obj.keys()])
    elif hasattr(obj, '__dict__'):
        size += get_size(obj.__dict__, seen)
    elif hasattr(obj, '__iter__') and not isinstance(obj, (str, bytes, bytearray)):
        size += sum([get_size(i, seen) for i in obj])
    return size

def packet_callback(packet):

    #SECTIONNNNNNNN : IMPORTANT::: Process Only the IP Header section for ICMP Packets
    if packet.haslayer(ICMP) and packet[ICMP].type != 0:  # IMPORTANT::: Process Only the IP Header section for ICMP Packets + Process all packets except echo reply.
        #print("===========IP ID Processing Section Test Visual==========")
        destination_ip = packet.getlayer(IP).dst
        if IP in packet:
            ip_packet = packet[IP]
            # Check if the IP packet has the Identification field
            if hasattr(ip_packet, 'id'):
                ip_id = ip_packet.id
                #print("IP ID is:")
                #print(ip_id)
              
            # Update the highest IP Identification (IpId) number counter
            if ip_id is not None:
                if ip_id > icmp_packets[destination_ip]['HighestIpIdCounter']:
                    icmp_packets[destination_ip]['HighestIpIdCounter'] = ip_id
                    
            # Check if the latest Ip Id number is less than the highest, increase counter if true
            if ip_id is not None and ip_id < icmp_packets[destination_ip]['HighestIpIdCounter']:
                icmp_packets[destination_ip]['NbOfIpIdLessThanHighest'] += 1
                       




                       
            #Check if IP ID number is repeating, by iretating over IpIdValues in db, if yes, increase IpIdRepeatingCounter to +1
            if ip_id in icmp_packets[destination_ip]['IpIdValues']:
                icmp_packets[destination_ip]['IpIdRepeatingCounter'] += 1
                #print("-IP Identification Number is REPEATING in Database")
                #test
                #print(icmp_packets[destination_ip]['IpIdValues'])
            
            #Add Ip Id number value of database if it's new to dst $IP
            if ip_id not in icmp_packets[destination_ip]['IpIdValues']:
                icmp_packets[destination_ip]['IpIdValues'].add(ip_id)
                #test
                #print(icmp_packets[destination_ip]['IpIdValues'])  
             




            #Check if Option size is set, if yes, increase counter CountIpHeaderOptSet by +1
            ip_header_len = packet[IP].ihl * 4  # Total length of IP header
            ip_options_len = ip_header_len - 20  # Calculate the length of IP header options
            if ip_options_len != 0:
                icmp_packets[destination_ip]['CountIpHeaderOptSet'] += 1


# 'IpIdValues': set()
# 'IpIdRepeatingCounter': 0


# 'SequenceNumbersValues': set()
# 'SeqNbRepeatingCounter': 0




    #SECTIONNNNNNNN : IMPORTANT::: Process all packets except echo & reply -- to detect Type & Code Anomaly
    if packet.haslayer(ICMP) and packet[ICMP].type != 8 and packet[ICMP].type != 0:  # IMPORTANT::: Process all packets except echo & reply -- to detect Type & Code Anomaly
        print("\n" + "=" * 40 + " Packet Detected " + "=" * 40)
        typecode_dict = {
            0: [0],  # Echo Reply
            8: [0],  # Echo Request
            3: list(range(16)),  # Destination Unreachable
            4: [0],  # Source Quench
            5: list(range(4)),  # Redirect
            11: [0, 1],  # Time Exceeded
            12: [0, 1, 2],  # Parameter Problem
            13: [0],  # Timestamp Request
            14: [0],  # Timestamp Reply
            15: [0],  # Information Request
            16: [0],  # Information Reply
            17: [0],  # Address Mask Request
            18: [0]   # Address Mask Reply
        }
        
        
        
        destination_ip = packet.getlayer(IP).dst
        
        
        
        
        icmp_type = packet[ICMP].type
        icmp_code = packet[ICMP].code

        if icmp_type in typecode_dict.keys() and icmp_code in typecode_dict[icmp_type]:
            print(f"-Detected ICMP Type: {icmp_type}, Code: {icmp_code} - Matches database")
            local_anomaly_acount = icmp_packets[destination_ip]['CountTypeCodeAnomaly']
            print(f"-Count of Type and Code Anomaly Packets for {destination_ip} is: {local_anomaly_acount}")
        else:
            print(f"-Detected ICMP Type: {icmp_type}, Code: {icmp_code} - Doesn't match database")
            icmp_packets[destination_ip]['CountTypeCodeAnomaly'] += 1
            local_anomaly_acount = icmp_packets[destination_ip]['CountTypeCodeAnomaly']
            print(f"-Count of Type and Code Anomaly Packets for {destination_ip} is: {local_anomaly_acount}")
            
            
            
            
        print("=" * 92)
            
            
            
            
            
            
            
            
            
            
            
            
            
    
    
    
    #SECTIONNNNNNNN : PROCESSING ECHO REQUESTS
    if packet.haslayer(ICMP) and packet[ICMP].type == 8:  # IMPORTANT::: Process ONLY ICMP ECHO REQUEST TYPE 8
        print("\n" + "=" * 40 + " Packet Detected " + "=" * 40)
        print("\n*****ICMP Packet Summary:")
        print(packet.summary())

        destination_ip = packet.getlayer(IP).dst

        # Update the timestamp for the destination IP
        timestamp = time.time()
        icmp_packets[destination_ip]['packets'].append({'timestamp': timestamp})

        # Increment the echo request count
        icmp_packets[destination_ip]['echo_requests'] += 1

        # Calculate average time between echo requests
        last_echo_timestamp = icmp_packets[destination_ip]['last_echo_timestamp']
        if last_echo_timestamp is not None:
            time_difference = timestamp - last_echo_timestamp
            current_avg_time = icmp_packets[destination_ip]['avg_time_between_echo']
            if current_avg_time is None:
                current_avg_time = time_difference
            else:
                total_time = current_avg_time * (icmp_packets[destination_ip]['echo_requests'] - 1)
                total_time += time_difference
                current_avg_time = total_time / icmp_packets[destination_ip]['echo_requests']
            icmp_packets[destination_ip]['avg_time_between_echo'] = current_avg_time
        icmp_packets[destination_ip]['last_echo_timestamp'] = timestamp








        # Extract and print the IP header information
        if packet.haslayer(IP):
            ip_header_len = packet[IP].ihl * 4  # Total length of IP header
            ip_options_len = ip_header_len - 20  # Calculate the length of IP header options
            
            #Get IP ID
            ip_packet = packet[IP]
            ip_id = ip_packet.id
       
            print("\n*****IP Header Information:")
            print("-IP Identification ID Number: {}".format(ip_id))
            print("-IP header option size: {} bytes".format(ip_options_len))
            print("-IP header total size : {} bytes".format(ip_header_len))
            















        # Extract and print the sequence number if available in the ICMP layer
        icmp_layer = packet.getlayer(ICMP)
        if icmp_layer:
            seq_num = icmp_layer.seq
            print("\n*****ICMP Header Information:")
            print("-ICMP Sequence Number: {}".format(seq_num))
            
            
            if seq_num is None or seq_num == 0:
                print("-ICMP Sequence Number is: None or Null")
                icmp_packets[destination_ip]['CountSeqNbisNoneOrNull'] += 1
            
            

            # Check if the latest sequence number is less than the highest
            # if seq_num < icmp_packets[destination_ip]['HighestSequenceNumberCounter']: // this line was causing error so it is commented out, fixed in line under it.
            if seq_num is not None and seq_num < icmp_packets[destination_ip]['HighestSequenceNumberCounter']:
                icmp_packets[destination_ip]['NbOfSequenceNbLessThanHighest'] += 1

            # Print the number of sequence numbers spotted less than the latest
            # Gio - This is moved to be printed in ICMP Header section in DB Info
            #print("-Count of Sequence Numbers detected, smaller than highest recorded : {}".format(icmp_packets[destination_ip]['NbOfSequenceNbLessThanHighest']))

            # Update the highest sequence number counter
            if seq_num is not None:
                if seq_num > icmp_packets[destination_ip]['HighestSequenceNumberCounter']:
                    icmp_packets[destination_ip]['HighestSequenceNumberCounter'] = seq_num
            



            #Check if sequence number is repeating, by iretating over SequenceNumbersValues in db, if yes, increase SeqNbRepeatingCounter to +1
            if seq_num in icmp_packets[destination_ip]['SequenceNumbersValues']:
                icmp_packets[destination_ip]['SeqNbRepeatingCounter'] += 1
                print("-ICMP Sequence Number is REPEATING in Database")
                #test
                #print(icmp_packets[destination_ip]['SequenceNumbersValues'])
            
            #Add sequence number value of database if it's new to dst $IP
            if seq_num not in icmp_packets[destination_ip]['SequenceNumbersValues']:
                icmp_packets[destination_ip]['SequenceNumbersValues'].add(seq_num)
                #test
                #print(icmp_packets[destination_ip]['SequenceNumbersValues'])
                    
















            

        # Check if there's a payload
        if packet.haslayer('Raw'):
            payload_size = len(packet['Raw'].load)
            #payload_text = packet['Raw'].load.decode('utf-8', errors='ignore')
            #payload_hex = packet['Raw'].load.hex()
            #payload_bytes = packet['Raw'].load
            #payload_byte_values = list(packet['Raw'].load)
            #payload_binary = ''.join(format(byte, '08b') for byte in packet['Raw'].load)
            #import base64
            #payload_base64 = base64.b64encode(packet['Raw'].load).decode('utf-8')
            
            payload_content_utf = packet['Raw'].load.decode('utf-8', errors='ignore')    # Decode payload content in UTF8 for Visual presentation
            payload_content_binary = ''.join(format(byte, '08b') for byte in packet['Raw'].load) # For Testing purposes in the end at the bottom.
            # Hash MD5 payload content to store it in DB for optimal size
            md5_hash = hashlib.md5(payload_content_binary.encode()).hexdigest() 
            payload_content_hash = md5_hash
            
            
            
            print("\n*****Payload Information:")
            # Determine if the packet is suspicious
            if is_payload_size_suspicious(payload_size):
                print("-Payload size: {} bytes".format(payload_size))
            else:
                print("-Payload size: {} bytes".format(payload_size))
            print("-Payload Content: " + payload_content_utf)
            
            
            
            
            # Add payload sizes to the database
            if payload_size not in icmp_packets[destination_ip]['payload_content_sizes']:
                icmp_packets[destination_ip]['payload_content_sizes'].add(payload_size)
            #print(icmp_packets[destination_ip]['payload_content_sizes'])
            
            
            
            
            #------------------------------------------------Payload Repeating Section----------------------------------------
            
            
            
            
            #-----remove this section---------
            #print("")
            #print("-----test--------")
            #Edge Cases Payloads:
                #yzjbyZNN6CUSpUy4QKxRSwBn9sqnQAouIab7uiZ2XVscGiQz0W7vWuMy     -- repeating for first and second checks, lol
                #D1aNeSe0rkOD8sXeA3FHiM76GRTipAhfyJTprIVhlXTD1aGNPLnrum5lEywX -- repeating for third check, lol
            #test payload for both scripts
            #payload_content_utf = "yzjbyZNN6CUSpUy4QKxRSwBn9sqnQAouIab7uiZ2XVscGiQz0W7vWuMy"
            #payload_content_utf = "abca"
            #print(payload_content_utf)
            #print("-----------------")
            #---------------------------------
            
            
            
            
            
            
            
            
            
            # identifying the classifier for checks 1,2 and 3 as 0 initially.
            
            PlClass1 = 0
            PlClass2 = 0
            PlClass3 = 0
            
            
            
            
            # Check if payload content is repeating (first check)
            if is_repeating(payload_content_utf):
                #print("-Payload is Repeating. [first check]")
                PlClass1 = 1
                #icmp_packets[destination_ip]['packets'][-1]['repeating'] = True
            else:
                #print("-Payload is not Repeating. [first check]")
                PlClass1 = 0
                #icmp_packets[destination_ip]['packets'][-1]['not_repeating'] = True
                
               


               
                
                
            # Check if payload content is repeating (second check)
            if check_repeating(payload_content_utf):
                #print("-Payload is Repeating. [second check]")
                PlClass2 = 1
            else:
                #print("-Payload is not Repeating. [second check]")
                PlClass2 = 0
                
                
            
            
            # Check if payload content is repeating (third check - Longest Pattern Matching Beginning Payload)
            patterns, longest_pattern = find_non_overlapping_patterns(payload_content_utf)
            #for pattern, count in patterns.items():
            #    if count > 1 and len(pattern) > 2:
            #        print(f"{pattern} x {count} times")
            
            if longest_pattern and len(longest_pattern) > 2:
                #print(f"The longest repeating pattern found is: {longest_pattern}")
                if payload_content_utf.startswith(longest_pattern):
                    #print("Longest repeating pattern found matches exactly beginning pattern of input string") // original
                    #print("-Payload is Repeating. [third check - LongestPatternMatchBeginningPayload]")
                    PlClass3 = 1
                else:
                    #print("Longest repeating pattern found does not match beginning pattern of input string") // original
                    #print("-Payload is not Repeating. [third check - LongestPatternMatchBeginningPayload]")
                    PlClass3 = 0
            else:
                #print(f"The longest repeating pattern found is: {longest_pattern}")
                #print("No repeating patterns found.") // original
                #print("-Payload is not Repeating. [third check - LongestPatternMatchBeginningPayload]")
                PlClass3 = 0
            
            
            
            
            
            #Print the classes
            # Class == 1 is repeating  &&  Class == 0 is not repeating
            #print("-Payload Classes for Checks 1,2 and 3 are:", PlClass1, PlClass2, PlClass3)
            
            PlClassResult = PlClass1 * PlClass2 * PlClass3
            #print("-Result of multiplication:", PlClassResult)
            
            
            #final classification
            if PlClassResult == 0:
                print("-Payload is not Sequential. [final classification]", PlClass1, PlClass2, PlClass3)
                icmp_packets[destination_ip]['packets'][-1]['not_repeating'] = True
            if PlClassResult == 1:
                print("-Payload is Sequential. [final classification]", PlClass1, PlClass2, PlClass3)
                icmp_packets[destination_ip]['packets'][-1]['repeating'] = True
                
            
            
            
            #------------------------------------------------------------------------------------------------------
            
            
            
            
            
            
            
            # Save payload content in the database
            icmp_packets[destination_ip]['packets'][-1]['payload_content_hash'] = payload_content_hash

            # Update payload size information in the database
            if payload_size == 32:
                icmp_packets[destination_ip]['packets'][-1]['payload_size_32_56'] = True
                icmp_packets[destination_ip]['packets'][-1]['payload_size_empty'] = False
                icmp_packets[destination_ip]['CounterSize32Bytes'] += 1
            elif payload_size == 56:
                icmp_packets[destination_ip]['packets'][-1]['payload_size_32_56'] = True
                icmp_packets[destination_ip]['packets'][-1]['payload_size_empty'] = False
                icmp_packets[destination_ip]['CounterSize56Bytes'] += 1
            else:
                icmp_packets[destination_ip]['packets'][-1]['payload_size_32_56'] = False
                if payload_size == 0:
                    icmp_packets[destination_ip]['packets'][-1]['payload_size_empty'] = True
                else:
                    icmp_packets[destination_ip]['packets'][-1]['payload_size_empty'] = False
                    icmp_packets[destination_ip]['packets'][-1]['payload_size_not_32_56'] = True

            # Check if payload is new
            if payload_content_hash not in icmp_packets[destination_ip]['payload_content_hash']:
                icmp_packets[destination_ip]['payload_content_hash'].add(payload_content_hash)
                icmp_packets[destination_ip]['NumberOfDifferentPayloads'] += 1

        else:
            print("\nICMP packet without payload detected.")
            # Increase the counter for "Number of Payload size is empty"
            icmp_packets[destination_ip]['packets'][-1]['payload_size_empty'] = True







        # Print database information for the destination IP
        print("\n*****Database information for destination IP {}:".format(destination_ip))     
        print("-----General Details--------")
        total_echo_requests = icmp_packets[destination_ip]['echo_requests']
        print("- Total Number Of ECHO requests : {}".format(total_echo_requests))
        # Print average time between echo requests for the destination IP
        avg_time_between_echo = icmp_packets[destination_ip]['avg_time_between_echo']
        if avg_time_between_echo is not None:
            print("- Avg Request Time to {} is: {:.5f} seconds".format(destination_ip, avg_time_between_echo))  
            
            
        print()  # Add space here
        print("-----IP Header--------")
        local_NbOfIpIdLessThanHighest = icmp_packets[destination_ip]['NbOfIpIdLessThanHighest']
        print(f"- Count of IP Identification Number detected, smaller than highest recorded for {destination_ip} is: {local_NbOfIpIdLessThanHighest} -----------IP HEADER PROCESSING SECTION")
        print("- Count of IP Identification ID Numbers Repeating is: {} -------------------------------------------------IP HEADER PROCESSING SECTION".format(icmp_packets[destination_ip]['IpIdRepeatingCounter']))
        local_CountIpHeaderOptSet = icmp_packets[destination_ip]['CountIpHeaderOptSet']
        print(f"- Count of IP Header Options set for {destination_ip} is: {local_CountIpHeaderOptSet} ------------------------------------------------------IP HEADER PROCESSING SECTION")
        
        print()  # Add space here
        print("-----ICMP Header--------")
        print("- Count of Sequence Numbers detected, smaller than highest recorded : {}".format(icmp_packets[destination_ip]['NbOfSequenceNbLessThanHighest']))
        print("- Count of Sequence Numbers 'None or Null' is: {}".format(icmp_packets[destination_ip]['CountSeqNbisNoneOrNull']))
        print("- Count of Sequence Numbers Repeating is: {}".format(icmp_packets[destination_ip]['SeqNbRepeatingCounter']))
        local_anomaly_acount = icmp_packets[destination_ip]['CountTypeCodeAnomaly']
        print(f"- Count of Type and Code Anomaly Packets for {destination_ip} is: {local_anomaly_acount} ----------------------------------------------TYPE CODE PROCESSING SECTION")
        
        print()  # Add space here        
        print("-----ICMP Payload--------")
        payload_size_empty_count = sum(1 for packet_info in icmp_packets[destination_ip]['packets'] if packet_info.get('payload_size_empty', False))
        print("- Number of EMPTY Payload : {}".format(payload_size_empty_count))
        print()  # Add space here
        repeating_count = sum(1 for packet_info in icmp_packets[destination_ip]['packets'] if 'repeating' in packet_info)
        not_repeating_count = sum(1 for packet_info in icmp_packets[destination_ip]['packets'] if 'not_repeating' in packet_info)
        print("- Number of Sequential payload: {}".format(repeating_count))
        print("- Number of NOT Sequential payload: {}".format(not_repeating_count))
        print()  # Add space here
        
        if not icmp_packets[destination_ip]['payload_content_sizes']:
            print("- Number of Different Payload Sizes is: 0 -- Packet(s) still have empty payloads.")
        elif len(icmp_packets[destination_ip]['payload_content_sizes']) == 1:
            print(f"- Number of Different Payload Sizes: {len(icmp_packets[destination_ip]['payload_content_sizes'])} -- Packet(s) have the same SIZE")
        else:
            print(f"- Number of Different Payload Sizes: {len(icmp_packets[destination_ip]['payload_content_sizes'])}")

            
        
        local_NumberOfDifferentPayloads = icmp_packets[destination_ip]['NumberOfDifferentPayloads']
        if local_NumberOfDifferentPayloads == 1:
            print(f"- Number of Different Payload Value: {local_NumberOfDifferentPayloads} -- Packet(s) have same Payload Value")
        else:
            print("- Number of Different Payload Value: {}".format(icmp_packets[destination_ip]['NumberOfDifferentPayloads']))
         
         
        print()  # Add space here
        print("- Number of Payload Size EQUAL to 32 bytes: {}".format(icmp_packets[destination_ip]['CounterSize32Bytes']))
        print("- Number of Payload Size EQUAL to 56 bytes: {}".format(icmp_packets[destination_ip]['CounterSize56Bytes']))
        # Print additional payload size information
        payload_size_not_32_56_count = sum(1 for packet_info in icmp_packets[destination_ip]['packets'] if packet_info.get('payload_size_not_32_56', False))
        print("- Number of Payload Size NOT EQUAL to 32 or 56: {}".format(payload_size_not_32_56_count))
        print()  # Add space here


        
      
        

        
        
        







        # Print database general information
        print("\n*****Database general information:")
        total_size_bytes = get_size(icmp_packets)
        total_size_kb = total_size_bytes / 1024  # Convert bytes to kilobytes
        print("- Total size of current database is : {} bytes  // {:.1f} KB".format(total_size_bytes, total_size_kb))
        print("- The database has information about the following IP Addresses:")
        pprint.pprint(list(icmp_packets.keys()))

        print("=" * 92)
        
        
        """
        print("===========Test section==========")
        try:
            print("--UTF:", payload_content_utf)
        except NameError:
            print("--UTF: <not defined>")
        try:
            print("--Binary: ", payload_content_binary)
        except NameError:
            print("--Binary: <not defined>")                        
        try:
            print("--Hash: ", payload_content_hash)
        except NameError:
            print("--Hash: <not defined>")
        """

            
            





    #SECTIONNNNNNNN : RESETTING DATABSE USING REPLY TO 8.8.8.8 or 8.8.4.4 or 1.1.1.1
    if packet.haslayer(ICMP) and packet[ICMP].type == 0:  # IMPORTANT::: Process ONLY ICMP ECHO REPLY TYPE 0 // this is Custom only used to reset Database when reply to 100.100.100.100
        destination_ip = packet.getlayer(IP).dst
        
        if destination_ip == "8.8.8.8" or destination_ip == "8.8.4.4" or destination_ip == "1.1.1.1":
            print("\n" + "=" * 40 + " Packet Detected " + "=" * 40)
            
            print("===========Resetting Database==========")
            #Print current information of the database before reset
            total_size_bytes = get_size(icmp_packets)
            total_size_kb = total_size_bytes / 1024  # Convert bytes to kilobytes
            print("- Total size of database BEFORE RESET : {} bytes  // {:.1f} KB".format(total_size_bytes, total_size_kb))
            pprint.pprint(list(icmp_packets.keys()))
        
            #resetting database values
            icmp_packets[destination_ip] = {'echo_requests': 0, 'packets': [], 'last_echo_timestamp': None,
                 'avg_time_between_echo': None, 'payload_content_hash': set(),
                 'NumberOfDifferentPayloads': 0, 'CounterSize32Bytes': 0,
                 'CounterSize56Bytes': 0, 'HighestSequenceNumberCounter': 0,
                 'NbOfSequenceNbLessThanHighest': 0, 'CountSeqNbisNoneOrNull': 0,
                 'SequenceNumbersValues': set(), 'SeqNbRepeatingCounter': 0,
                 'CountTypeCodeAnomaly': 0}
                 
            #Deleting the key itself of the destination ip from the database icmp_packets
            del icmp_packets[destination_ip] 
                     
                     
            print("- DB has been reset!")
            #Print current information of the database before reset
            total_size_bytes = get_size(icmp_packets)
            total_size_kb = total_size_bytes / 1024  # Convert bytes to kilobytes
            print("- Total size of database AFTER RESET : {} bytes  // {:.1f} KB".format(total_size_bytes, total_size_kb))
            pprint.pprint(list(icmp_packets.keys()))
            
            print("=" * 92)
            
             
        
        
        
        
        
        
        """ This is commented out, this will reset the values for ALL DSTs IPs
        if destination_ip == "8.8.8.8":
            #Print current information of the database before reset
            total_size_bytes = get_size(icmp_packets)
            total_size_kb = total_size_bytes / 1024  # Convert bytes to kilobytes
            print("- Total size of database BEFORE RESET : {} bytes  // {:.1f} KB".format(total_size_bytes, total_size_kb))
        
            #resetting database values
            for key in icmp_packets.keys():
                icmp_packets[key] = {'echo_requests': 0, 'packets': [], 'last_echo_timestamp': None,
                         'avg_time_between_echo': None, 'payload_content_hash': set(),
                         'NumberOfDifferentPayloads': 0, 'CounterSize32Bytes': 0,
                         'CounterSize56Bytes': 0, 'HighestSequenceNumberCounter': 0,
                         'NbOfSequenceNbLessThanHighest': 0, 'CountSeqNbisNoneOrNull': 0,
                         'SequenceNumbersValues': set(), 'SeqNbRepeatingCounter': 0,
                         'CountTypeCodeAnomaly': 0}
                         
            print("- DB has been reset!")
            #Print current information of the database before reset
            total_size_bytes = get_size(icmp_packets)
            total_size_kb = total_size_bytes / 1024  # Convert bytes to kilobytes
            print("- Total size of database AFTER RESET : {} bytes  // {:.1f} KB".format(total_size_bytes, total_size_kb))  
            
        """
        
        
        
# Start sniffing for ICMP packets
sniff(filter="icmp", prn=packet_callback)
#sniff(iface="vEthernet (Default Switch)", filter="icmp", prn=packet_callback)


