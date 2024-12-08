import re
import csv
from collections import defaultdict, Counter
from itertools import islice

class LogAnalyzer:
    def __init__(self, log_file, threshold=10):
        """
        Initialize the LogAnalyzer with a log file and a threshold for suspicious activities.
        """
        self.log_file = log_file
        self.threshold = threshold
        self.ip_requests = Counter()
        self.endpoint_requests = Counter()
        self.failed_logins = defaultdict(int)

        # Precompile regular expressions for performance optimization
        self.ip_pattern = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})")  # IP address pattern
        self.endpoint_pattern = re.compile(r"\"(?:GET|POST|PUT|DELETE|HEAD) (.*?) HTTP")  # Endpoint pattern
        self.status_code_pattern = re.compile(r"\" (\d{3}) ")  # Status code pattern
        self.failure_messages = ["Invalid credentials", "Authentication failed", "Forbidden", "Access Denied"]

    def process_logs(self):
        """
        Process the log file line by line for efficient memory usage.
        """
        with open(self.log_file, 'r', buffering=8192) as file:  # Buffered reading for large files
            for line in file:
                self._process_line(line)

    def _process_line(self, line):
        """
        Process a single line of the log file and extract relevant information.
        """
        if not line.strip():  # Skip empty lines
            return

        # Match IP address
        ip_match = self.ip_pattern.search(line)
        if ip_match:
            ip_address = ip_match.group(1)
            self.ip_requests[ip_address] += 1
        else:
            return  # If no IP address is found, skip the line

        # Match endpoint
        endpoint_match = self.endpoint_pattern.search(line)
        if endpoint_match:
            endpoint = endpoint_match.group(1)
            self.endpoint_requests[endpoint] += 1

        # Match status code and detect failed logins (for any failure message)
        status_code_match = self.status_code_pattern.search(line)
        if status_code_match:
            status_code = status_code_match.group(1)
            # Check for various failure status codes or failure messages in the log
            if status_code == "401" or status_code == "403" or any(failure_msg in line for failure_msg in self.failure_messages):
                self.failed_logins[ip_address] += 1

    def get_top_ips(self):
        """
        Retrieve IP addresses sorted by request count.
        """
        return self.ip_requests.most_common()

    def get_most_accessed_endpoint(self):
        """
        Get the endpoint that was accessed the most.
        """
        return self.endpoint_requests.most_common(1)[0] if self.endpoint_requests else ("N/A", 0)

    def get_suspicious_activities(self):
        """
        Identify IP addresses with failed login attempts exceeding the threshold.
        """
        return {ip: count for ip, count in self.failed_logins.items() if count > self.threshold}

    def save_to_csv(self, output_file="log_analysis_results.csv", chunk_size=1000):
        """
        Save the analysis results to a CSV file, batching writes to handle large datasets.
        """
        with open(output_file, "w", newline='') as csvfile:
            writer = csv.writer(csvfile)

            # Write IP requests
            writer.writerow(["IP Address", "Request Count"])
            for chunk in self._generate_chunks(self.ip_requests.items(), chunk_size):
                writer.writerows(chunk)

            writer.writerow([])

            # Write most accessed endpoint
            writer.writerow(["Endpoint", "Access Count"])
            writer.writerow(self.get_most_accessed_endpoint())

            # Write suspicious activities
            suspicious_activities = self.get_suspicious_activities()
            if suspicious_activities:
                writer.writerow([])
                writer.writerow(["IP Address", "Failed Login Count"])
                for chunk in self._generate_chunks(suspicious_activities.items(), chunk_size):
                    writer.writerows(chunk)

    @staticmethod
    def _generate_chunks(data, chunk_size):
        """
        Generate chunks of data for batch processing.
        """
        iterator = iter(data)
        for first in iterator:
            yield [first] + list(islice(iterator, chunk_size - 1))

    def display_results(self):
        """
        Display the analysis results on the console.
        """
        print("\nIP Address\tRequest Count")
        for ip, count in self.get_top_ips():
            print(f"{ip:<20} {count}")

        print("\nMost Frequently Accessed Endpoint:")
        endpoint, count = self.get_most_accessed_endpoint()
        print(f"{endpoint} (Accessed {count} times)")

        suspicious_activities = self.get_suspicious_activities()
        if suspicious_activities:
            print("\nSuspicious Activities Detected:")
            print("IP Address\tFailed Login Attempts")
            for ip, count in suspicious_activities.items():
                print(f"{ip:<20} {count}")
        else:
            print("No suspicious activities detected.")


def main():
    log_file = "sample.log"
    analyzer = LogAnalyzer(log_file)

    print("Processing log file...")
    analyzer.process_logs()

    print("\nResults:")
    analyzer.display_results()

    print("\nSaving results to CSV...")
    analyzer.save_to_csv()
    print("Results saved successfully.")


if __name__ == "__main__":
    main()
