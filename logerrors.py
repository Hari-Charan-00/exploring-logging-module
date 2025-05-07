import requests
import time
import pandas as pd
import threading
import logging

# Configure logging to a file
logging.basicConfig(filename='asset_inventory.log', level=logging.ERROR,
                    format='%(asctime)s - %(levelname)s - %(message)s')

URL = ""
CLIENT_ID = ""
CLIENT_SECRET = ""

class TokenManager:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls, url, client_id, client_secret):
        with cls._lock:
            if not cls._instance:
                cls._instance = super(TokenManager, cls).__new__(cls)
                cls._instance.url = url
                cls._instance.client_id = client_id
                cls._instance.client_secret = client_secret
                cls._instance.access_token = None
                cls._instance.expiry_timestamp = None
        return cls._instance

    def _get_new_token(self):
        try:
            token_url = self.url + "auth/oauth/token"
            auth_data = {
                'client_secret': self.client_secret,
                'grant_type': 'client_credentials',
                'client_id': self.client_id
            }
            headers = {'Content-Type': 'application/x-www-form-urlencoded'}
            response = requests.post(token_url, data=auth_data, headers=headers, verify=True)
            response.raise_for_status()
            data = response.json()
            self.access_token = data.get('access_token')
            expires_in = data.get('expires_in')
            if self.access_token and expires_in:
                self.expiry_timestamp = time.time() + expires_in
                print("New token obtained.")
                return True
            else:
                logging.error("Error: Failed to retrieve access token details.")
                print("An issue occurred during authorization.")
                return False
        except requests.exceptions.RequestException as e:
            logging.error(f"Error during token request: {e}")
            print("An issue occurred during authorization.")
            return False
        except ValueError:
            logging.error("Error: Invalid JSON response during token request.")
            print("An issue occurred during authorization.")
            return False

    def get_token(self):
        with self._lock:
            if not self._instance.access_token or (self._instance.expiry_timestamp and time.time() >= self._instance.expiry_timestamp - 60):
                if not self._get_new_token():
                    return None
            return self._instance.access_token

token_manager = TokenManager(URL, CLIENT_ID, CLIENT_SECRET)

def fetch_clients(partner_id, partner_name, base_url, max_retries=3, retry_delay=5):
    clients = {}
    page = 1
    retries = 0

    while True:
        access_token = token_manager.get_token()
        if not access_token:
            logging.error(f"Failed to retrieve a valid token while fetching clients for partner '{partner_name}' (ID: {partner_id})")
            print("Failed to retrieve a valid token. Cannot fetch clients.")
            break

        try:
            headers = {'Authorization': f'Bearer {access_token}', 'Content-Type': 'application/json'}
            url = f"{base_url}api/v2/tenants/{partner_id}/clients/search?pageNo={page}&pageSize=100"
            response = requests.get(url, headers=headers, verify=True)
            response.raise_for_status()

            data = response.json()
            results = data.get('results', [])
            for client in results:
                client_id = client.get("uniqueId", "NA")
                client_name = client.get("name", "NA")
                if client_id != "NA" and client_name != "NA":
                    clients[client_id] = client_name

            total_pages = data.get('totalPages', 1)
            if page >= total_pages:
                break
            page += 1
            retries = 0 # Reset retries on successful attempt

        except requests.exceptions.HTTPError as e:
            if e.response.status_code in [401, 407] and "invalid_token" in e.response.text.lower():
                print("Token expired. Regenerating and retrying client list...")
                continue
            else:
                logging.error(f"HTTP Error fetching clients for partner '{partner_name}' (ID: {partner_id}): {e}")
                print("An issue occurred while retrieving client information.")
                break
        except requests.exceptions.RequestException as e:
            logging.error(f"Request Error fetching clients for partner '{partner_name}' (ID: {partner_id}), attempt {retries + 1}/{max_retries}: {e}")
            print("A network issue occurred while retrieving client information. Retrying...")
            retries += 1
            if retries >= max_retries:
                print("Max retries reached for fetching clients. Aborting client retrieval for partner '{partner_name}'.")
                break
            time.sleep(retry_delay)
            continue
        except ValueError as e:
            logging.error(f"Value Error fetching clients for partner '{partner_name}' (ID: {partner_id}): {e}")
            print("The script received unexpected information from the server.")
            break

    print(f"Total clients fetched for partner '{partner_name}': {len(clients)}")
    return clients

def get_noc_name(partner_id, partner_name, client_id, client_name, base_url, max_retries=3, retry_delay=5):
    access_token = token_manager.get_token()
    if not access_token:
        logging.error(f"Failed to retrieve a valid token while getting NOC name for client '{client_name}' (ID: {client_id}) under partner '{partner_name}' (ID: {partner_id})")
        print(f"Failed to retrieve a valid token. Cannot get NOC name for {client_name}.")
        return "N/A"

    retries = 0
    while retries < max_retries:
        try:
            auth_header = {'Authorization': f'Bearer {access_token}', 'Content-Type': 'application/json'}
            noc_details_url = base_url + f"api/v2/tenants/{partner_id}/clients/{client_id}"
            response = requests.get(noc_details_url, headers=auth_header, verify=True)
            response.raise_for_status()
            noc_data = response.json()
            noc_details = noc_data.get('nocDetails', {})
            return noc_details.get('name', 'N/A')
        except requests.exceptions.HTTPError as e:
            if e.response.status_code in [401, 407] and "invalid_token" in e.response.text.lower():
                print(f"Token expired. Regenerating and retrying NOC name for client '{client_name}' under partner '{partner_name}'...")
                access_token = token_manager.get_token()
                if not access_token:
                    logging.error(f"Failed to retrieve a valid token after expiry while getting NOC name for client '{client_name}' under partner '{partner_name}'")
                    print(f"Failed to retrieve a valid token after expiry. Cannot get NOC name for {client_name}.")
                    break
                continue
            else:
                logging.error(f"HTTP Error fetching NOC details for client '{client_name}' under partner '{partner_name}': {e}")
                break
        except requests.exceptions.RequestException as e:
            logging.error(f"Request Error fetching NOC details for client '{client_name}' under partner '{partner_name}', attempt {retries + 1}/{max_retries}: {e}")
            print(f"A network issue occurred while getting NOC name for {client_name}.")
            retries += 1
            time.sleep(retry_delay)
        except Exception as e:
            logging.error(f"Unexpected error fetching NOC details for client '{client_name}' under partner '{partner_name}': {e}")
            break
    return "N/A"

def fetch_devices(client_id, client_name, partner_name, base_url, max_retries=3, retry_delay=5):
    access_token = token_manager.get_token()
    if not access_token:
        logging.error(f"Failed to retrieve a valid token while fetching devices for client '{client_name}' (ID: {client_id}) under partner '{partner_name}'")
        print(f"Failed to retrieve a valid token. Cannot fetch devices for {client_name}.")
        return {}

    devices = {}
    retries = 0
    while retries < max_retries:
        try:
            auth_header = {'Authorization': f'Bearer {access_token}', 'Content-Type': 'application/json'}
            devices_url = f"{base_url}/api/v2/tenants/{client_id}/resources/minimal"
            response = requests.get(devices_url, headers=auth_header, verify=True)
            response.raise_for_status()
            devices_data = response.json()

            if isinstance(devices_data, list):
                for device in devices_data:
                    device_name = device.get("hostName", 'NA')
                    device_id = device.get("id", "NA")
                    if device_id and device_name:
                        devices[device_name] = device_id
                return devices # Return devices on success
            else:
                logging.error(f"Unexpected response format for devices for client '{client_name}' under partner '{partner_name}': {response.text}")
                print(f"An issue occurred while retrieving device information for {client_name}.")
                break # Break on unexpected format (not a transient error)

        except requests.exceptions.HTTPError as e:
            if e.response.status_code in [401, 407] and "invalid_token" in e.response.text.lower():
                print(f"Token expired. Regenerating and retrying devices for client '{client_name}' under partner '{partner_name}'...")
                access_token = token_manager.get_token()
                if not access_token:
                    logging.error(f"Failed to retrieve a valid token after expiry while fetching devices for client '{client_name}' under partner '{partner_name}'")
                    print(f"Failed to retrieve a valid token after expiry. Cannot fetch devices for {client_name}.")
                    break
                continue # Retry immediately with the new token
            else:
                logging.error(f"HTTP Error fetching devices for client '{client_name}' under partner '{partner_name}': {e}")
                break
        except requests.exceptions.RequestException as e:
            logging.error(f"Request Error fetching devices for client '{client_name}' under partner '{partner_name}', attempt {retries + 1}/{max_retries}: {e}")
            print(f"A network issue occurred while getting devices for {client_name}.")
            retries += 1
            time.sleep(retry_delay)
        except Exception as e:
            logging.error(f"Error fetching device IDs for client '{client_name}' under partner '{partner_name}': {e}")
            print(f"An issue occurred while retrieving device information for {client_name}.")
            break
    return {} # Return empty dict if max retries fail

def get_device_details(client_id, client_name, partner_name, device_name, device_id, base_url, max_retries=3, retry_delay=5):
    access_token = token_manager.get_token()
    if not access_token:
        logging.error(f"Failed to retrieve a valid token while getting details for device ID '{device_id}' of client '{client_name}' under partner '{partner_name}'")
        print(f"Failed to retrieve a valid token. Cannot get details for device {device_id} of {client_name}.")
        return None

    tagvalue_1 = "NA"
    tagvalue_2= "NA"
    retries = 0
    while retries < max_retries:
        try:
            auth_header = {'Authorization': f'Bearer {access_token}', 'Content-Type': 'application/json'}
            device_url = base_url + f"api/v2/tenants/{client_id}/resources/{device_id}"
            response = requests.get(device_url, headers=auth_header, verify=True)
            response.raise_for_status()
            if response.status_code == 200:
                device_data = response.json()
                ip = device_data.get("ipAddress", "NA")
                model = device_data.get("model", "NA")
                status = device_data.get("status", "NA")
                gnrlinfo = device_data.get("generalInfo")
                make = gnrlinfo.get('make', 'No value available') if gnrlinfo else 'No value available'
                firmwareVersion = gnrlinfo.get('firmwareVersion', 'No value available') if gnrlinfo else 'No value available'
                resourceType = gnrlinfo.get('resourceType', 'No value available') if gnrlinfo else 'No value available'
                tags = device_data.get('tags', [])

                if isinstance(tags, list):
                    for tag in tags:
                        tagname = tag.get('name', 'NA')
                        tagvalue = tag.get('value', 'NA')
                        if tagname == "Service - Partner Scope":
                            tagvalue_1 = tagvalue
                        elif tagname == "SKU Device - Partner Scope":
                            tagvalue_2 = tagvalue
                else:
                    tagvalue_1 = "No tag assigned"
                    tagvalue_2 = "No tag assigned"
                return ip, model, make, tagvalue_1, tagvalue_2, resourceType, status, firmwareVersion
            else:
                logging.error(f"Unexpected status code {response.status_code} fetching device details for client '{client_name}' under partner '{partner_name}', device ID '{device_id}'")
                break # Break on unexpected status (not necessarily transient)

        except requests.exceptions.HTTPError as e:
            if e.response.status_code in [401, 407] and "invalid_token" in e.response.text.lower():
                print(f"Token expired. Regenerating and retrying device details for device ID '{device_id}' of client '{client_name}' under partner '{partner_name}'...")
                access_token = token_manager.get_token()
                if not access_token:
                    logging.error(f"Failed to retrieve a valid token after expiry while getting details for device ID '{device_id}' of client '{client_name}' under partner '{partner_name}'")
                    print(f"Failed to retrieve a valid token after expiry. Cannot get device details for {device_name} of {client_name}.")
                    break
                continue # Retry immediately with the new token
            else:
                logging.error(f"HTTP Error fetching device details for client '{client_name}' under partner '{partner_name}', device ID '{device_id}': {e}")
                break
        except requests.exceptions.RequestException as e:
            logging.error(f"Request Error fetching device details for client '{client_name}' under partner '{partner_name}', device ID '{device_id}', attempt {retries + 1}/{max_retries}: {e}")
            print(f"A network issue occurred while getting details for device {device_name} of {client_name}.")
            retries += 1
            time.sleep(retry_delay)
        except Exception as e:
            logging.error(f"Unexpected error fetching device details for client '{client_name}' under partner '{partner_name}', device ID '{device_id}': {e}")
            break
    return None

def main():
    partners_data = {
        "b46ba025-0c99-416d-955d-10129cf4ed15": "Helixstorm",
"9384a74d-5370-573a-0608-9a14a25b234e": "All Covered",
    "fee7887c-1c4e-90aa-b4bc-e6870ac060fc": "Agiliti",
    "70d37846-efe6-bc75-2907-8ca6e0a9c1f5": "Trace3"
    }

    all_devices_info = []
    partner_counter = 0
    total_partners = len(partners_data)

    for partner_id, partner_name in partners_data.items():
        partner_counter += 1
        print(f"\nProcessing Partner [{partner_counter}/{total_partners}]: {partner_name}")

        clients = fetch_clients(partner_id, partner_name, URL)
        client_counter = 0
        total_clients = len(clients)

        for client_id, client_name in clients.items():
            client_counter += 1
            noc_name = get_noc_name(partner_id, partner_name, client_id, client_name, URL)
            if noc_name in ["SRO1", "SRO2", "Vistara NOC"]:
                print(f"Fetching devices for client [{client_counter}/{total_clients}]: {client_name}")
                devices = fetch_devices(client_id, client_name, partner_name, URL)

                if not devices:
                    print(f"No devices found for client: {client_name}")
                    continue

                for device_name, device_id in devices.items():
                    device_details = get_device_details(client_id, client_name, partner_name, device_name, device_id, URL)

                    if device_details:
                        ip, model, make, tagvalue_1, tagvalue_2, resourceType, status, firmwareVersion = device_details
                        device_info = {
                            "Partner Name": partner_name,
                            "Client Name": client_name,
                            "Resource Name": device_name,
                            "Ip Address": ip,
                            "Service - Partner Scope": tagvalue_1,
                            "SKU Device - Partner Scope": tagvalue_2,
                            "Make": make,
                            "Model": model,
                            "Device State": status,
                            "Type": resourceType,
                            "Firmware Version": firmwareVersion
                        }
                        all_devices_info.append(device_info)
            else:
                print(f"Skipping client [{client_counter}/{total_clients}]: {client_name} (NOC Name: {noc_name})")

    if all_devices_info:
        df = pd.DataFrame(all_devices_info)
        df.to_excel("Asset_inventory.xlsx", index=False)
        print("\nExcel file 'Asset_inventory.xlsx' created successfully.")
    else:
        print("No device data found to export.")

if __name__ == "__main__":
    main()
