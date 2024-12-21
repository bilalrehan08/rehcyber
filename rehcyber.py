import socket
import whois
import nmap
import requests
import subprocess
import threading
import json
import csv
from datetime import datetime
import geocoder
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import shodan
import os

# Disable InsecureRequestWarnings from requests
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Function to perform DNS Lookup
def dns_lookup(domain, result):
    try:
        ip = socket.gethostbyname(domain)
        result['dns'] = ip
        print(f"[+] DNS Lookup for {domain}: {ip}")
    except socket.gaierror:
        result['dns'] = None
        print(f"[-] Error resolving {domain}")

# Function to perform WHOIS Lookup
def whois_lookup(domain, result):
    try:
        domain_info = whois.whois(domain)
        result['whois'] = domain_info
        print(f"[+] WHOIS Information for {domain}:")
        print(domain_info)
    except Exception as e:
        result['whois'] = None
        print(f"[-] Error during WHOIS lookup: {e}")

# Function to perform Nmap Port Scanning
def port_scanning(target, result):
    nm = nmap.PortScanner()
    try:
        nm.scan(target, '1-1024')  # Scan ports 1 to 1024
        result['ports'] = {}
        for protocol in nm[target].all_protocols():
            result['ports'][protocol] = {}
            ports = nm[target][protocol].keys()
            for port in ports:
                result['ports'][protocol][port] = nm[target][protocol][port]['state']
                print(f"Port {port} - State: {nm[target][protocol][port]['state']}")
    except Exception as e:
        result['ports'] = None
        print(f"[-] Error during port scanning: {e}")

# Function to grab HTTP headers and banners
def banner_grabbing(target, result):
    try:
        response = requests.get(f"http://{target}", timeout=5, verify=False)
        result['http_header'] = response.headers
        print(f"[+] Banner Grabbing on {target}:")
        print(f"HTTP Response Status: {response.status_code}")
        print(f"Server: {response.headers.get('Server')}")
        print(f"Content-Type: {response.headers.get('Content-Type')}")
    except requests.exceptions.RequestException as e:
        result['http_header'] = None
        print(f"[-] Error during banner grabbing: {e}")

# Function to perform Traceroute
def traceroute(target, result):
    try:
        output = subprocess.check_output(["traceroute", target])
        result['traceroute'] = output.decode()
        print(f"[+] Traceroute to {target}:")
        print(output.decode())
    except subprocess.CalledProcessError as e:
        result['traceroute'] = None
        print(f"[-] Error during traceroute: {e}")

# Function to get IP Geolocation
def geolocation(ip, result):
    g = geocoder.ip(ip)
    result['geolocation'] = g.json
    print(f"[+] Geolocation of {ip}: {g.json}")

# Function to integrate Shodan API for exposed services and vulnerabilities
def shodan_scan(api_key, target, result):
    try:
        api = shodan.Shodan(api_key)
        host = api.host(target)
        result['shodan'] = host
        print(f"[+] Shodan data for {target}:")
        print(host)
    except shodan.APIError as e:
        result['shodan'] = None
        print(f"[-] Error with Shodan API: {e}")

# Function to save results to a JSON file
def save_to_json(result):
    filename = "gathered_info.json"
    with open(filename, 'w') as json_file:
        json.dump(result, json_file, indent=4)
    print(f"[+] Results saved to {filename}")

# Function to save results to CSV
def save_to_csv(result):
    filename = "gathered_info.csv"
    with open(filename, 'w', newline='') as csvfile:
        fieldnames = ['dns', 'whois', 'ports', 'http_header', 'traceroute', 'geolocation', 'shodan']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerow(result)
    print(f"[+] Results saved to {filename}")

# Function to gather all information concurrently
def gather_info(target, api_key=None):
    result = {}

    # Use threading for faster information gathering
    threads = []
    
    # DNS Lookup
    thread = threading.Thread(target=dns_lookup, args=(target, result))
    threads.append(thread)
    thread.start()

    # WHOIS Lookup
    thread = threading.Thread(target=whois_lookup, args=(target, result))
    threads.append(thread)
    thread.start()

    # Port Scanning
    thread = threading.Thread(target=port_scanning, args=(target, result))
    threads.append(thread)
    thread.start()

    # Banner Grabbing
    thread = threading.Thread(target=banner_grabbing, args=(target, result))
    threads.append(thread)
    thread.start()

    # Traceroute
    thread = threading.Thread(target=traceroute, args=(target, result))
    threads.append(thread)
    thread.start()

    # Geolocation
    thread = threading.Thread(target=geolocation, args=(result.get('dns', None), result))
    threads.append(thread)
    thread.start()

    # Shodan Scan
    if api_key:
        thread = threading.Thread(target=shodan_scan, args=(api_key, target, result))
        threads.append(thread)
        thread.start()

    # Wait for all threads to finish
    for thread in threads:
        thread.join()

    return result

# Main function
def main():
    target = input("Enter the domain or IP address to gather information: ")
    api_key = input("Enter your Shodan API key (or press Enter to skip): ")
    
    start_time = datetime.now()
    
    print(f"\n[+] Gathering information for {target}...")
    result = gather_info(target, api_key)
    
    # Print the final results
    print("\n[+] Information Gathering Completed:")
    print(json.dumps(result, indent=4))

    # Save the results to a file
    save_option = input("\nWould you like to save the results? (json/csv/none): ").strip().lower()
    if save_option == "json":
        save_to_json(result)
    elif save_option == "csv":
        save_to_csv(result)
    
    end_time = datetime.now()
    print(f"\n[+] Information gathering completed in: {end_time - start_time}")

if __name__ == "__main__":
    main()
