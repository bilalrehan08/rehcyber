# rehcyber
This Python script automates information gathering for cybersecurity. It performs DNS lookup, WHOIS lookup, port scanning, banner grabbing, traceroute, geolocation, and Shodan scanning. Using multithreading for speed, it saves results in JSON or CSV formats, helping professionals with security assessments and reconnaissance.
DNS Lookup:

Purpose: Resolves the domain name to its corresponding IP address.
Usage: The DNS lookup provides insight into how a target domain is mapped to a physical server's IP, which is the first step in any network analysis.
WHOIS Lookup:

Purpose: Retrieves domain registration information such as owner, registration date, expiration date, and contact details.
Usage: WHOIS data can give details about the owner of the domain, which can be important for social engineering or understanding the history of the domain.
Port Scanning with Nmap:

Purpose: Scans the target for open ports (from 1 to 1024) and identifies the services running on these ports.
Usage: Port scanning helps identify which services (like HTTP, FTP, SSH) are exposed on the target server. It’s crucial for understanding potential attack surfaces on the network.
Banner Grabbing:

Purpose: Retrieves HTTP headers and banners from a web server to understand what type of software is running (e.g., Apache, Nginx) and its version.
Usage: Helps identify the technology stack (web server, application server) of the target, which can be used to discover known vulnerabilities in the software.
Traceroute:

Purpose: Traces the network path from the local machine to the target, showing the routers and intermediate hops along the way.
Usage: Traceroute provides insight into the network topology and helps identify any intermediary devices or firewalls between the attacker and the target.
IP Geolocation:

Purpose: Uses the Geocoder library to determine the geographic location of the target’s IP address.
Usage: Helps associate an IP address with its physical location, revealing country, city, and potentially even the ISP or data center that owns the IP address.
Shodan Integration:

Purpose: Uses the Shodan API to gather data from Shodan.io about the exposed services, devices, and vulnerabilities related to the target IP or domain.
Usage: Shodan helps discover internet-facing devices and associated vulnerabilities, offering a powerful way to explore exposed services that may be vulnerable.
Multithreading:

Purpose: The script uses multithreading to run multiple information-gathering tasks concurrently, improving the speed and efficiency of data collection.
Usage: Since each function (e.g., DNS lookup, port scanning, WHOIS) runs independently, multithreading ensures that the entire information gathering process is faster.
Result Saving (CSV/JSON):

Purpose: The script provides options to save the results to a CSV or JSON file for easy reporting, analysis, and sharing.
Usage: Users can save the gathered data in structured formats (CSV or JSON) that are easy to process later, either for documentation or as input for further analysis.
