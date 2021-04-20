#! /usr/bin/python3

"""
File: ScapySynScan.py
Version: 1.0
Date: 02 Apr 2021
Author: Pseudoer
Description: This python script utilises Scapy to Syn scan a range of ports provided by the attacker
			 Information on Scapy and installation can be found: https://scapy.net/
"""

import argparse, time, re
from scapy.all import *

# Function to test if the host is up
def is_up(ip):
	return sr1(IP(dst=ip)/ICMP(), timeout=10, verbose=False)

# Function to check if the attacker entered a correct range of ports, removes duplicate ports and enters ports into a list
def port_list(port):
    # Search pattern for RegEx to confirm port argument structure
	regex = "^[0-9]+(?:\-[0-9]+){0,1}(?:\,[0-9]+(?:\-[0-9]+){0,1})*$"

	# Tests port argument structure against RegEx
	if re.search(regex,port): # If port argument is valid
		ports = []
		port_split = re.split(",",port) # Split port argument by ","
		for p in port_split:
			if re.search("-",p): # Determine if single port or range of ports, search for range indicated by "-"
				port_range = re.split("-",p) # Split range
				port_range[0] = int(port_range[0]) # First number in range
				port_range[1] = int(port_range[1]) # Second number in range
				# First number < Second number in range
				if port_range[0] < port_range[1]:
					for n in range(port_range[0], port_range[1] + 1):
						if n not in ports: # If port not already in port list
							ports.append(n)
				# First number < Second number in range
				elif port_range[0] > port_range[1]:
					for n in range(port_range[1], port_range[0] + 1):
						if n not in ports: # If port not already in port list
							ports.append(n)
				# First number == Second number in range
				else:
					if port_range[0] not in ports: # If port not already in port list
						ports.append(port_range[0])
			else: # If single port
				if int(p) not in ports: # If port not already in port list
					ports.append(int(p))
		return ports
	else: # If port argument is not valid
		return None

# Function to split list into smaller groups of lists
def chunks (item_list, groups_of):
	for i in range (0, len(item_list), groups_of):
		yield item_list[i:i + groups_of]

# Function to scan host against a port list and return if the port is open, filtered or closed.
def port_scan(ip,port_list):
	start_time = time.time() # Time the scan started
	if is_up(ip) == None: # If host is not up
		print(f"Host {ip} is down, scan complete.")
	else: # If host is up
		print(f"Host {ip} is up, starting scan...\n")
		packets_received = 0
		open_ports, closed_ports, filtered_ports, unans_ports = [], [], [], []

		for ports in chunks(port_list, 100): # For each chunk of ports
			packet = IP(dst = ip) / TCP(sport=RandShort(), dport = ports, flags="S") # Forging SYN packets
			ans, unans = sr(packet, timeout = 0.2, verbose = False)  # Send the packets

			for req, resp in ans: # For each answered packets
				packets_received += 1
				if resp is None: # If host does not respond to SYN packet, port is being filtered
					filtered_ports.append(req.dport) # Add port to filtered list
				elif resp.haslayer(TCP): # If host responds to SYN packet with a TCP packet, port is either open or closed
					if resp.getlayer(TCP).flags == 0x12: # If host responds to SYN packet with a SYN, ACK packet, port is open 
						open_ports.append(req.dport) # Add port to open list
					elif resp.getlayer(TCP).flags == 0x14: # If host responds to SYN packet with a RST, ACK packet, port is closed
						closed_ports.append(req.dport) # Add port to closed list
				elif resp.haslayer(ICMP): # If host responds tp SYN packet with an ICMP error type 3 and code 1, 2, 3, 9, 10 or 13, port is being filtered
					if (int(resp.getlayer(ICMP).type) == 3 and int(resp.getlayer(ICMP).code) in (1, 2, 3, 9, 10, 13)):
						filtered_ports.append(req.dport) # Add port to filtered list

			for req in unans: # For each unanswered packets
				unans_ports.append(req.dport) # Add port to unanswered list

		duration = time.time() - start_time # Scan time = current time - start time
		hits = round((packets_received / len(port_list) * 100), 1) # Calculate percentage of received packets

		print(f"=====----- {len(open_ports)} Open Ports -----=====")
		for ports in chunks(open_ports, 10): # For each port in open list
			print(*ports, sep = " , ")

		print(f"\n=====----- {len(filtered_ports)} Filtered Ports -----=====")
		for ports in chunks(filtered_ports, 10): # For each port in filtered list
			print(*ports, sep = " , ")

		print(f"\n=====----- {len(closed_ports)} Closed Ports -----=====")
		for ports in chunks(closed_ports, 10): # For each port in closed list
			print(*ports, sep = " , ")

		print(f"\n=====----- {len(unans_ports)} Ports Dropped Packets -----=====")
		for ports in chunks(unans_ports, 10): # For each port in unanswered list
			print(*ports, sep = " , ")

		print(f"\n{len(port_list)} packets sent, {packets_received} packets received. {hits}% hits")
		print(f"{ip} scan complete in {duration:.2f} seconds\n")

# Main Program
parser = argparse.ArgumentParser(description="This script utilises Scapy to Syn scan a range of ports provided by the attacker")

# Possible parsed arguments when executing the script
parser.add_argument("--host", required=True, help="Target Host IP address (e.g. --host 192.168.1.1)") # Target Host IP address
parser.add_argument("--port", "-p", help="List/Range of port(s) to scan (e.g. -p 80,443,1000-1337). If not supplied the top 1,000 TCP ports will be scanned.") # Ports to scan
args = parser.parse_args() # Argument initialisation

if args.port: # If port list/range supplied
	ports = port_list(args.port)
else: # If port list/range not supplied
	# Top 1,000 TCP Ports from https://nullsec.us/top-1-000-tcp-and-udp-ports-nmap-default/
	Top1000 = "1,3-4,6-7,9,13,17,19-26,30,32-33,37,42-43,49,53,70,79-85,88-90,99-100,106,109-111,113,119,125,135,139,143-144,146,161,163,179,199,211-212,222,254-256,259,264,280,"
	Top1000 = Top1000 + "301,306,311,340,366,389,406-407,416-417,425,427,443-445,458,464-465,481,497,500,512-515,524,541,543-545,548,554-555,563,587,593,616-617,625,631,636,646,"
	Top1000 = Top1000 + "648,666-668,683,687,691,700,705,711,714,720,722,726,749,765,777,783,787,800-801,808,843,873,880,888,898,900-903,911-912,981,987,990,992-993,995,999-1002,"
	Top1000 = Top1000 + "1007,1009-1011,1021-1100,1102,1104-1108,1110-1114,1117,1119,1121-1124,1126,1130-1132,1137-1138,1141,1145,1147-1149,1151-1152,1154,1163-1166,1169,1174-1175,"
	Top1000 = Top1000 + "1183,1185-1187,1192,1198-1199,1201,1213,1216-1218,1233-1234,1236,1244,1247-1248,1259,1271-1272,1277,1287,1296,1300-1301,1309-1311,1322,1328,1334,1352,1417,"
	Top1000 = Top1000 + "1433-1434,1443,1455,1461,1494,1500-1501,1503,1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666,1687-1688,1700,1717-1721,1723,1755,1761,1782-1783,1801,"
	Top1000 = Top1000 + "1805,1812,1839-1840,1862-1864,1875,1900,1914,1935,1947,1971-1972,1974,1984,1998-2010,2013,2020-2022,2030,2033-2035,2038,2040-2043,2045-2049,2065,2068,2099-2100,"
	Top1000 = Top1000 + "2103,2105-2107,2111,2119,2121,2126,2135,2144,2160-2161,2170,2179,2190-2191,2196,2200,2222,2251,2260,2288,2301,2323,2366,2381-2383,2393-2394,2399,2401,2492,2500,"
	Top1000 = Top1000 + "2522,2525,2557,2601-2602,2604-2605,2607-2608,2638,2701-2702,2710,2717-2718,2725,2800,2809,2811,2869,2875,2909-2910,2920,2967-2968,2998,3000-3001,3003,3005-3007,"
	Top1000 = Top1000 + "3011,3013,3017,3030-3031,3052,3071,3077,3128,3168,3211,3221,3260-3261,3268-3269,3283,3300-3301,3306,3322-3325,3333,3351,3367,3369-3372,3389-3390,3404,3476,3493,"
	Top1000 = Top1000 + "3517,3527,3546,3551,3580,3659,3689-3690,3703,3737,3766,3784,3800-3801,3809,3814,3826-3828,3851,3869,3871,3878,3880,3889,3905,3914,3918,3920,3945,3971,3986,3995,"
	Top1000 = Top1000 + "3998,4000-4006,4045,4111,4125-4126,4129,4224,4242,4279,4321,4343,4443-4446,4449,4550,4567,4662,4848,4899-4900,4998,5000-5004,5009,5030,5033,5050-5051,5054,"
	Top1000 = Top1000 + "5060-5061,5080,5087,5100-5102,5120,5190,5200,5214,5221-5222,5225-5226,5269,5280,5298,5357,5405,5414,5431-5432,5440,5500,5510,5544,5550,5555,5560,5566,5631,5633,"
	Top1000 = Top1000 + "5666,5678-5679,5718,5730,5800-5802,5810-5811,5815,5822,5825,5850,5859,5862,5877,5900-5904,5906-5907,5910-5911,5915,5922,5925,5950,5952,5959-5963,5987-5989,"
	Top1000 = Top1000 + "5998-6007,6009,6025,6059,6100-6101,6106,6112,6123,6129,6156,6346,6389,6502,6510,6543,6547,6565-6567,6580,6646,6666-6669,6689,6692,6699,6779,6788-6789,6792,6839,"
	Top1000 = Top1000 + "6881,6901,6969,7000-7002,7004,7007,7019,7025,7070,7100,7103,7106,7200-7201,7402,7435,7443,7496,7512,7625,7627,7676,7741,7777-7778,7800,7911,7920-7921,7937-7938,"
	Top1000 = Top1000 + "7999-8002,8007-8011,8021-8022,8031,8042,8045,8080-8090,8093,8099-8100,8180-8181,8192-8194,8200,8222,8254,8290-8292,8300,8333,8383,8400,8402,8443,8500,8600,8649,"
	Top1000 = Top1000 + "8651-8652,8654,8701,8800,8873,8888,8899,8994,9000-9003,9009-9011,9040,9050,9071,9080-9081,9090-9091,9099-9103,9110-9111,9200,9207,9220,9290,9415,9418,9485,9500,"
	Top1000 = Top1000 + "9502-9503,9535,9575,9593-9595,9618,9666,9876-9878,9898,9900,9917,9929,9943-9944,9968,9998-10004,10009-10010,10012,10024-10025,10082,10180,10215,10243,10566,"
	Top1000 = Top1000 + "10616-10617,10621,10626,10628-10629,10778,11110-11111,11967,12000,12174,12265,12345,13456,13722,13782-13783,14000,14238,14441-14442,15000,15002-15004,15660,15742,"
	Top1000 = Top1000 + "16000-16001,16012,16016,16018,16080,16113,16992-16993,17877,17988,18040,18101,18988,19101,19283,19315,19350,19780,19801,19842,20000,20005,20031,20221-20222,20828,"
	Top1000 = Top1000 + "21571,22939,23502,24444,24800,25734-25735,26214,27000,27352-27353,27355-27356,27715,28201,30000,30718,30951,31038,31337,32768-32785,33354,33899,34571-34573,35500,"
	Top1000 = Top1000 + "38292,40193,40911,41511,42510,44176,44442-44443,44501,45100,48080,49152-49161,49163,49165,49167,49175-49176,49400,49999-50003,50006,50300,50389,50500,50636,50800,"
	Top1000 = Top1000 + "51103,51493,52673,52822,52848,52869,54045,54328,55055-55056,55555,55600,56737-56738,57294,57797,58080,60020,60443,61532,61900,62078,63331,64623,64680,65000,65129,"
	Top1000 = Top1000 + "65389"

	ports = port_list(Top1000)

if ports == None: # If port list invalid against RegEx search pattern
	print("\nYou entered an invalid list/range of port(s). List/Range of port(s) to scan (e.g. -p 80,443,1000-1337).")
else: # If port list is valid
	port_scan(args.host, ports)