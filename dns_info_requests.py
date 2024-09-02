import requests

# Function to get DNS information for a given IP
def get_dns_info(ip_address):
    url = f"http://ip-api.com/json/{ip_address}"
    response = requests.get(url)
    
    # Check if the request was successful
    if response.status_code == 200:
        data = response.json()
        return data
    else:
        print(f"Error: Unable to fetch data for {ip_address}")
        return None

# Example usage
ip_address = "8.8.8.8"  # Replace with the IP address you want to query
dns_info = get_dns_info(ip_address)

if dns_info:
    try:
        print(f"IP: {dns_info['query']}")
        print(f"Country: {dns_info['country']}")
        print(f"Region: {dns_info['regionName']}")
        print(f"City: {dns_info['city']}")
        print(f"ISP: {dns_info['isp']}")
    except BaseException:
        print("Unexpected Error")
else:
    print("Failed to retrieve information.")
