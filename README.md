# About me
- 👋 Hi, I’m @Giovanni-Kaddissi
- 👀 I’m interested in Cyber Seucrity, GenAI , System and Network Administration, Cloud technologies and more.
- 🌱 I’m currently learning Generative AI and Cyber Security specifically focusing on Network Security
- 💞️ I’m looking to collaborate on enhancing my ICMP Covert Channel Ranking System Model (CCRS or C2RS) by adding more detection features and make it compatible on Linux OS and IoT.
- 📫 How to reach me : You can send me a message here on GitHub!
- 😄 Pronouns: Gio
- ⚡ Fun fact: If you can beat me 1v1 in Counter-Strike 1.6 , map awp_india.bsp or aim_dust2003.bsp , I will make you my partner :D (no scripts ;) )



# Model : ICMP C2RS Model: Covert Channel Ranking System

## Related MSc Thesis Paper:
Securing Networks Against ICMP Covert Channels: Detection and Countermeasures



# Model Project file:
**_CCRS.py_**



 
## What is it ? 
**Developed in 2024 by Giovanni Kaddissi during his Masters Degree in Cyber Security and Forensics,** The ICMP C2RS Model is a Python-based sniffer designed to detect covert data exfiltration through ICMP (Internet Control Message Protocol) packets in real-time on Windows systems.


This model focuses on identifying anomalies within ICMP packets by analyzing three key sections: 
- The IP header. (Inspections on: IP Identification ID, IP Header Options set)
- The ICMP header. (Inspections on: Sequence Numbers, Type and Code Anomaly)
- The ICMP payload. (Inspections on: Payload Size, Value hash, Sequentiality or null)

The model collects metrics for each destination address being contacted from the source host, related to potential anomalies in ICMP packets being sent.
These collected metrics can be used to append the model further over code, since it's open source, by invoking a specific behavior based on the user's need, for example "Send an Alert" or "Isolate the host" or whatever.


## Use cases - Includes but not limited to:
- Network Security: Detect covert data exfiltration attempts by malicious actors using ICMP packets to bypass traditional network security measures.
- Intrusion Detection: Enhance the detection of compromised systems in a network, especially those utilizing covert channels for communication.
- Monitoring and Forensics: Provides a tool for administrators to monitor network traffic for anomalies and investigate potential breaches.

## How to use ?
Simply ensure you have Python installed on your os with the required libraries, and run the tool:

**_python CCRS.py_**


Then, try for example issuing a ping while the model is running, and you will start seeing the metrics being collected to the destination, on the running tool terminal.


If you encouter error running the "CCRS.py" , ensure you have the necessary libraries installed , missing libraries will display on the terminal, and install them via pip.
Important libabry to meet:
- pip install scapy
- pip install libpcap
- pip install winpcap or download it from https://npcap.com/#download




## Play around as a white-hat-hacker to test the model's metrics.

***PLEASE DO NOT USE FOR HARMING PURPOSES, THIS IS ONLY FOR EDUCATIONAL PURPOSES and TEST THE MODEL***
======================================================================================================

I have uploaded a file named **"_ICMP Covert Channels - Data Exfiltration Simulations.rar_"**

The file contains 5 scenarios of Sending and Receiving packets over ICMP, as ICMP Covert Channels, which are:
- 1- IP Header Exfiltration:
	- Manipulation of the IP Identification ID Field in the IP Header.
	- Options Manipulation in the IP Header of the ICMP Packet


- 2- ICMP Header Exfiltration:
	 - ICMP Header Manipulation: Type and Code fields

- 3- Payload Exfiltration
	- Ptunnel -- Connect to a website via icmp // modified version to make it easier for my use case, original author is https://github.com/utoni/ptunnel-ng
	- Send a file over icmp


For each scenario, you have a **SEND** and **Receive** scripts over python, that will craft the ICMP Packet to send it based on the specified scenario, some of them contains commands on how to send as well.

Ensure you are running **_python CCRS.py_** aside, while you run each scenario for your use case, and you will see the model's behavior by collecting different type of metrics for each section of the ICMP Packet. You can modify the scenarios for your use case, simply edit them.



# Please leave a comment if you can and let me know if you find this model helpful 😊! It will be encouraging for future development. Thank you!
