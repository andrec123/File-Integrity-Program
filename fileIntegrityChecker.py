#!/usr/bin/env python3

import sys
import hashlib
import requests

# Your VirusTotal API key
API_KEY = '18c617db0f76843e6437b795654f62eae104666588a6f1613d64e5f2f89e4e17'
VT_API_URL = 'https://www.virustotal.com/api/v3/files'

def hashfile(file_path, algorithm='sha256'):
    """Compute the hash of a file using the specified algorithm."""
    hash_func = hashlib.new(algorithm)
    BUF_SIZE = 65536  # 64 kilobytes

    try:
        with open(file_path, 'rb') as f:
            while True:
                data = f.read(BUF_SIZE)
                if not data:
                    break
                hash_func.update(data)
    except FileNotFoundError:
        print(f"File '{file_path}' not found.")
        return None
    
    return hash_func.hexdigest()

def scan_virustotal(file_hash):
    """Scan the file hash using VirusTotal API."""
    headers = {
        'x-apikey': API_KEY
    }
    
    url = f"{VT_API_URL}/{file_hash}"
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        result = response.json()
        scan_results = result.get('data', {}).get('attributes', {}).get('last_analysis_results', {})
        print(f"\nVirusTotal scan results for SHA-256 hash ({file_hash}):")
        for engine, details in scan_results.items():
            print(f"{engine}: {details['result']}")
    elif response.status_code == 204:
        print("File not found in VirusTotal database.")
    else:
        print(f"Error: {response.status_code}, {response.text}")

def main():
    if len(sys.argv) != 2:
        print("Usage: python fileIntegrityChecker.py <file_path>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    
    # Compute the SHA-256 hash
    sha256_hash = hashfile(file_path, 'sha256')
    
    if sha256_hash:
        print(f"SHA-256 hash: {sha256_hash}")
        scan_virustotal(sha256_hash)

if __name__ == "__main__":
    main()
