# ---------------------------------------------------
# Program to check the blockchain status
# 
# Ilias Papalamprou
# ---------------------------------------------------
import requests
import time
import argparse

# Function to send request and handle response
def poll_fpga_data(token, topic, interval=5):
    url = f"http://10.160.3.213:3001/api/transactions/GetByFPGAID?FPGAID={topic}"
    headers = {
        'Authorization': f'Bearer {token}'
    }

    while True:
        try:
            # Send the GET request
            response = requests.get(url, headers=headers)
            
            # Check for successful response
            if response.status_code == 200:
                print("Data received:", response.text)
            else:
                print(f"Error {response.status_code}: {response.text}")

        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")
        
        # Wait for the specified interval (in seconds) before the next request
        time.sleep(interval)

if __name__ == "__main__":
    # Set up argument parser
    parser = argparse.ArgumentParser(description="Poll FPGA data from a server continuously.")
    
    # Define token argument
    parser.add_argument('--token', type=str, required=True, help="Authorization Bearer token")
    
    # Define topic (FPGAID) argument
    parser.add_argument('--topic', type=str, required=True, help="FPGAID topic to poll")

    # Define optional interval argument
    parser.add_argument('--interval', type=int, default=5, help="Polling interval in seconds (default: 5)")
    
    # Parse the arguments
    args = parser.parse_args()
    
    # Call the polling function with parsed arguments
    poll_fpga_data(args.token, args.topic, args.interval)
