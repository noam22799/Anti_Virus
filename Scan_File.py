# Import moudles
import requests
import os
import File_Report

# VirusTotal API Key
API_KEY = "d7d746f3bdabafb03cbd93607e54098f9fc39dc6683387d1159dbcd9eb23fbff"

# VirusTotal API URL
url = "https://www.virustotal.com/api/v3/files"

# Request headers
headers = {
"accept": "application/json",
"x-apikey": API_KEY
}

# Scan a single file
def scan_file(file_path):
    with open(file_path, "rb") as file:
        files = {"file": (file_path, file)}
        response = requests.post(url, files=files, headers=headers)
    return response.json()

# Scan all files in a directory and print each file report
def scan_directory(directory):
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            scan=scan_file(file_path)
            answer="File path: {0}\nResult: {1}\n\n".format(file_path, scan)     
            # Print file scanning
            print(answer)          
            # Gets file id
            id=scan['data']['id']
            # Print file report
            File_Report.Report_SingleFile(id)
