# Nmap Vulnerability Scan and Kibana Visualization of Metasploitable 2

This project demonstrates an Nmap vulnerability scan performed on a Metasploitable 2 virtual machine in my home lab. The scan results were analyzed and visualized using the ELK stack (Elasticsearch, Logstash, and Kibana) to create a detailed report and dashboards for easy information retrieval.

## Overview

- **Target System**: Metasploitable 2 (IP Address: `192.168.56.102`)
- **Host System**: Kali Linux
- **Tools Used**:
  - Nmap (Network Mapper) for scanning
  - ELK stack (Elasticsearch, Logstash, Kibana) for report creation and visualization
  - Python for file conversion

## Project Steps

### 1. Setting Up the Lab

1. Installed VirtualBox and set up two VMs:
   - Kali Linux for scanning
   - Metasploitable 2 as the target system
2. Configured Metasploitable 2 with a static IP address `192.168.56.102` using the command:
   ```bash
   ifconfig eth0 192.168.56.102 netmask 255.255.255.0 up
   ```

### 2. Scanning with Nmap

Executed a comprehensive Nmap scan to gather all relevant information about the target. The results were saved in XML format for further analysis. Command used:
```bash
nmap -A -T4 -p- --script vuln -oA nmap_scan_results 192.168.56.102
```
This command performs:
- **`-A`**: Enables OS detection, version detection, script scanning, and traceroute.
- **`-T4`**: Sets the timing template to "aggressive" for faster scans.
- **`-p-`**: Scans all 65,535 ports.
- **`--script vuln`**: Runs vulnerability detection scripts.
- **`-oA nmap_scan_results`**: Saves the results in three formats: `.nmap`, `.xml`, and `.gnmap`.

### 3. Converting XML to CSV

Converted the Nmap XML scan results into a CSV format using a Python script:
```python
import xml.etree.ElementTree as ET
import csv

# Parse the XML file
tree = ET.parse('nmap_scan_results.xml')
root = tree.getroot()

# Create a CSV file
with open('nmap_scan_results.csv', 'w', newline='') as csvfile:
    csvwriter = csv.writer(csvfile)
    csvwriter.writerow(['Protocol', 'Port', 'Service', 'State', 'Script Output'])

    for port in root.findall(".//port"):
        protocol = port.get('protocol')
        port_id = port.get('portid')
        state = port.find("state").get('state')
        service = port.find("service").get('name') if port.find("service") is not None else 'Unknown'
        script = port.find("script")
        script_output = script.get('output') if script is not None else 'N/A'

        csvwriter.writerow([protocol, port_id, service, state, script_output])
```

### 4. Setting Up ELK Stack

1. Installed ELK stack on a Windows machine.
2. Configured Logstash to ingest the CSV data into Elasticsearch using the following pipeline:
   ```
   input {
       file {
           path => "C:/path/to/nmap_scan_results.csv"
           start_position => "beginning"
           sincedb_path => "/dev/null"
           codec => "csv" {
               separator => ","
               columns => ["Protocol", "Port", "Service", "State", "Script Output"]
           }
       }
   }

   output {
       elasticsearch {
           hosts => ["http://localhost:9200"]
           index => "nmap-scan-results"
       }
       stdout { codec => rubydebug }
   }
   ```
3. Created dashboards in Kibana to visualize the data.

### 5. Visualizing Data

Designed Kibana dashboards to present:
- **OS Types** (Pie Chart)
- **Port Vulnerabilities** (Table)
- **Service Information** (Table)
- **Port Enumeration** (Table)

### 6. Results

The following screenshots from the Kibana dashboard summarize the findings:

- **OS Types**:
  ![OS Types](Project%20Screenshots%20from%20Kibana%20dashboard/OS%20Type.png)
- **Port Vulnerabilities**:
  ![Port Vulnerabilities](Project%20Screenshots%20from%20Kibana%20dashboard/Port%20Vulnerabilities.png)
- **Service Information**:
  ![Service Information](Project%20Screenshots%20from%20Kibana%20dashboard/Service%20information.png)
- **Port Enumeration**:
  ![Port Enumeration](Project%20Screenshots%20from%20Kibana%20dashboard/Port%20Enumeration.png)

### 7. Key Findings

- Identified multiple vulnerabilities including:
  - **ftp-vsftpd-backdoor** on port 21
  - **distcc-cve2004-2687** on port 3632
  - **rmi-vuln-classloader** on port 1099
- Detected services and their configurations, e.g., Apache Jserv and OpenSSH.

## Conclusion

This project demonstrates a thorough vulnerability scan workflow and visual analysis using Nmap and the ELK stack. The process provides an effective way for SOC analysts to identify and report vulnerabilities in a systematic manner.

## Files

- `nmap_scan_results.xml`: Original scan results in XML format.
- `nmap_scan_results.csv`: Converted results in CSV format.
- `OS Type.png`: Screenshot of OS type analysis.
- `Port Vulnerabilities.png`: Screenshot of port vulnerability analysis.
- `Service Information.png`: Screenshot of service information.
- `Port Enumeration.png`: Screenshot of port enumeration analysis.
