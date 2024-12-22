# About me
- 👋 Hi, I’m @Giovanni-Kaddissi
- 👀 I’m interested in Cyber Seucrity, GenAI , System and Network Administration, Cloud technologies and more.
- 🌱 I’m currently learning Generative AI and Cyber Security specifically focusing on Network Security
- 💞️ I’m looking to collaborate on enhancing my ICMP Covert Channel Ranking System Model (CCRS or C2RS) by adding more detection features and make it compatible on Linux OS and IoT.
- 📫 How to reach me : You can send me a message here on GitHub!
- 😄 Pronouns: Gio
- ⚡ Fun fact: If you can beat me 1v1 in Counter-Strike 1.6 , map awp_india.bsp or aim_dust2003.bsp , I will make you my partner :D (no scripts ;) )



# Model : ICMP C2RS Model: Covert Channel Ranking System

## Project file:
CCRS.py


## What is it ? 
**Developed in 2024 by Giovanni Kaddissi during his Masters Degree in Cyber Security and Forensics,** The ICMP C2RS Model is a Python-based sniffer designed to detect covert data exfiltration through ICMP (Internet Control Message Protocol) packets in real-time on Windows systems.


This model focuses on identifying anomalies within ICMP packets by analyzing three key sections: 
- The IP header. (Inspections on: IP Identification ID, IP Header Options set)
- The ICMP header. (Inspections on: Sequence Numbers, Type and Code Anomaly)
- The ICMP payload. (Inspections on: Payload Size, Value hash, Sequentiality or null)

The model collects metrics for each destination address being contacted from the source host, related to potential anomalies in ICMP packets being sent.
These collected metrics can be used to append the model further over code, since it's open source, by invoking a specific behavior based on the user's need, for example "Send an Alert" or "Isolate the host" or whatever.


## Use cases:
- Network Security: Detect covert data exfiltration attempts by malicious actors using ICMP packets to bypass traditional network security measures.
- Intrusion Detection: Enhance the detection of compromised systems in a network, especially those utilizing covert channels for communication.
- Monitoring and Forensics: Provides a tool for administrators to monitor network traffic for anomalies and investigate potential breaches.

## How to use and test it ?
Simply ensure you have Python installed on your os with the required libraries, and run the tool:

**_python CCRS.py_**


Then, try for example issuing a ping while the model is running, and you will start seeing the metrics being collected to the destination, on the running tool terminal.


If you encouter error running the "CCRS.py" , ensure you have the necessary libraries installed , missing libraries will display on the terminal, and install them via pip.
Important libabry to meet:
- pip install scapy
- pip install libpcap
- pip install winpcap or download it from https://npcap.com/#download
