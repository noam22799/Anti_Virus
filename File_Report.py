# Import modules
import requests

# VirusTotal API Key
API_KEY = "d7d746f3bdabafb03cbd93607e54098f9fc39dc6683387d1159dbcd9eb23fbff"

# Request headers
headers = {
    "accept": "application/json",
    "x-apikey": API_KEY
}

# Prints the report of file
def Report_SingleFile(id):
    # Analysis ID returned from file upload
    analysis_id = id   
    # VirusTotal analysis URL
    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    
    response = requests.get(url, headers=headers)
    print(response.text)

