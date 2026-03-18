# ---------------------------------------------------
# Communication with the Blockchain
# 
# Ilias Papalamprou
# ---------------------------------------------------
import requests
import json

# VPN is needed to connect to NCSRD infrastructure
url = "http://10.160.3.213:3001"

# ---------------------------------------------------
# Function to obtain the JWT token needed for authentication
# Note: Token is valid for one day
def obtain_jwt_token(url):
	# URL containing the issue name
	url_token = url + "/issueJwtToken"

	payload = {}
	headers = {
	  'Authorization': 'Bearer {{jwtEverything}}'
	}

	response = requests.request("GET", url_token, headers=headers, data=payload)

	# Extract the token from the received data
	response_json = response.json()
	token = response_json.get("data")
	return token


# ---------------------------------------------------
# Function to upload a json structure to the Blockchain
def push_data(json_structure, url, jwt_token):
	# URL containing the issue name
	url_push_data = url + "/api/transactions/storeFPGAData"

	# Header for pushing data
	header = {
		'Content-Type': 'application/json',
		'Authorization': f'Bearer {jwt_token}'
	}


	# Push the data to the Blockchain
	response = requests.request(
		"POST", 
		url_push_data,
		headers=header,
		data=json_structure,
		timeout=10
    	)


# ---------------------------------------------------
# Obtain data from the Blockchain using FPGA-ID
def obtain_data(fpga_id, url):
	# URL containing the issue name
	url_obtain = url + "/api/transactions/GetByFPGAID?FPGAID=" + fpga_id

	payload = {}
	header = {
		'Authorization': f'Bearer {jwt_token}'
	}

	# Obtain data from the Blockchain
	response = requests.request("GET", url_obtain, headers=header, data=payload)
	return response
