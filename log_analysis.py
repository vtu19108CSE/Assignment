import re
import sys
import csv
from collections import defaultdict, Counter

def parse_log_file(file_path):
    ip_requests = defaultdict(int)
    endpoint_requests = defaultdict(int)
    failed_logins = defaultdict(int)

    failed_login_threshold = 10

    with open(file_path, 'r') as log_file:
        for line in log_file:
            match = re.match(r'(?P<ip>\S+) .*? "(?P<method>\S+) (?P<endpoint>\S+) .*?" (?P<status>\d{3})', line)
            if match:
                ip = match.group('ip')
                endpoint = match.group('endpoint')
                status = match.group('status')

                ip_requests[ip] += 1
                endpoint_requests[endpoint] += 1

                if status == '401':  # Detect failed login attempts
                    failed_logins[ip] += 1

    return ip_requests, endpoint_requests, failed_logins, failed_login_threshold

def display_and_save_results(ip_requests, endpoint_requests, failed_logins, failed_login_threshold):
    # Sort IP addresses by request count
    sorted_ips = sorted(ip_requests.items(), key=lambda x: x[1], reverse=True)

    print("\nIP Address           Request Count")
    print("----------------------------------")
    for ip, count in sorted_ips:
        print(f"{ip:<20} {count}")

    # Most frequently accessed endpoint
    most_accessed_endpoint = max(endpoint_requests.items(), key=lambda x: x[1])
    print(f"\nMost Frequently Accessed Endpoint:\n{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    # Detect suspicious activity
    print("\nSuspicious Activity Detected:")
    print("IP Address           Failed Login Attempts")
    print("------------------------------------------")
    for ip, count in failed_logins.items():
        if count > failed_login_threshold:
            print(f"{ip:<20} {count}")

    # Save results to CSV
    with open('log_analysis_results.csv', 'w', newline='') as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(['IP Address', 'Request Count'])
        writer.writerows(sorted_ips)
        
        writer.writerow([])
        writer.writerow(['Most Accessed Endpoint', 'Access Count'])
        writer.writerow(most_accessed_endpoint)

        writer.writerow([])
        writer.writerow(['IP Address', 'Failed Login Count'])
        for ip, count in failed_logins.items():
            if count > failed_login_threshold:
                writer.writerow([ip, count])
    

def main():
    if len(sys.argv) != 2:
        print("Usage: python log_analysis.py <log_file_path>")
        sys.exit(1)

    log_file_path = sys.argv[1]
    try:
        ip_requests, endpoint_requests, failed_logins, failed_login_threshold = parse_log_file(log_file_path)

        display_and_save_results(ip_requests, endpoint_requests, failed_logins, failed_login_threshold)
    except FileNotFoundError:
        print(f"Error: File '{log_file_path}' not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()

