import re
import csv
from collections import Counter, defaultdict

def parse_log_file(log_file_path):
    """Parses the log file and extracts relevant information."""
    ip_regex = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    endpoint_regex = r'"(?:GET|POST|PUT|DELETE|PATCH) ([^\s]+)'
    failed_login_regex = r'401|Invalid credentials'
    
    ip_requests = Counter()
    endpoint_requests = Counter()
    failed_logins = defaultdict(int)

    try:
        with open(log_file_path, 'r') as log_file:
            for line in log_file:
                ip_match = re.search(ip_regex, line)
                endpoint_match = re.search(endpoint_regex, line)
                failed_login_match = re.search(failed_login_regex, line)
                
                if ip_match:
                    ip = ip_match.group()
                    ip_requests[ip] += 1

                if endpoint_match:
                    endpoint = endpoint_match.group(1)
                    endpoint_requests[endpoint] += 1

                if failed_login_match and ip_match:
                    failed_logins[ip] += 1

    except FileNotFoundError:
        print(f"Error: File '{log_file_path}' not found.")
        return None, None, None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None, None, None

    return ip_requests, endpoint_requests, failed_logins

def save_to_csv(ip_requests, most_accessed_endpoint, failed_logins, output_file='log_analysis_results.csv'):
    """Saves the analysis results to a CSV file."""
    try:
        with open(output_file, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            
            # Write Requests per IP
            writer.writerow(["Requests per IP"])
            writer.writerow(["IP Address", "Request Count"])
            for ip, count in ip_requests.items():
                writer.writerow([ip, count])

            # Write Most Accessed Endpoint
            writer.writerow([])
            writer.writerow(["Most Accessed Endpoint"])
            writer.writerow(["Endpoint", "Access Count"])
            writer.writerow(most_accessed_endpoint)

            # Write Suspicious Activity
            writer.writerow([])
            writer.writerow(["Suspicious Activity"])
            writer.writerow(["IP Address", "Failed Login Count"])
            for ip, count in failed_logins.items():
                writer.writerow([ip, count])

        print(f"Results saved to {output_file}")
    except Exception as e:
        print(f"An error occurred while saving to CSV: {e}")

def main():
    log_file_path = input("Enter the path to the log file: ")
    ip_requests, endpoint_requests, failed_logins = parse_log_file(log_file_path)
    
    if ip_requests is None or endpoint_requests is None or failed_logins is None:
        return

    # Display Requests per IP
    print(f"\n{'IP Address':<20}{'Request Count':<15}")
    print("-" * 35)
    for ip, count in ip_requests.most_common():
        print(f"{ip:<20}{count:<15}")
    
    # Display Most Accessed Endpoint
    most_accessed_endpoint = endpoint_requests.most_common(1)[0]
    print(f"\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    # Display Suspicious Activity
    print(f"\nSuspicious Activity Detected:")
    print(f"{'IP Address':<20}{'Failed Login Attempts':<15}")
    print("-" * 35)
    for ip, count in failed_logins.items():
        if count > 10:  # Configurable threshold
            print(f"{ip:<20}{count:<15}")
    
    # Save results to CSV
    save_to_csv(ip_requests, most_accessed_endpoint, failed_logins)

if __name__ == "__main__":
    main()
