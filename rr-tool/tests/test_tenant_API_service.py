import requests

url = "http://10.101.41.206:6000/api/partition/0"

# Send GET request
response = requests.get(url, verify=False)

# Check response status code
if response.status_code == 200:
    # Print the response content
    print(response.text)
else:
    print("Error:", response.status_code)
