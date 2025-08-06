#!/usr/bin/env python3
"""
Test script to verify node communication after fixing HTTP 415 error.
Run this after starting both blockchain-PC.py nodes.
"""

import requests
import json
import sys

def test_transaction_endpoint(node_address):
    """Test the /transactions/new endpoint with JSON data"""
    url = f"http://{node_address}/transactions/new"
    
    # Test transaction data
    test_data = {
        'name': 'test_file.txt',
        'file': 'VGVzdCBmaWxlIGNvbnRlbnQ=',  # Base64 encoded "Test file content"
        'file_hash': 'abc123def456',
        'ct': 'encrypted_content',
        'pi': 'proof_of_integrity',
        'pk': 'public_key_data'
    }
    
    try:
        # Send as JSON with proper headers
        headers = {'Content-Type': 'application/json'}
        response = requests.post(url, json=test_data, headers=headers)
        
        print(f"Testing {url}")
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.text}")
        
        if response.status_code == 201:
            print("✓ Transaction endpoint working correctly!")
            return True
        else:
            print("✗ Transaction endpoint returned unexpected status code")
            return False
            
    except requests.exceptions.ConnectionError:
        print(f"✗ Could not connect to {node_address}")
        print("Make sure blockchain-PC.py is running on this address")
        return False
    except Exception as e:
        print(f"✗ Error: {e}")
        return False

def test_chain_endpoint(node_address):
    """Test the /chain endpoint"""
    url = f"http://{node_address}/chain"
    
    try:
        response = requests.get(url)
        print(f"\nTesting {url}")
        print(f"Status Code: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"Chain length: {data.get('length', 0)}")
            print("✓ Chain endpoint working correctly!")
            return True
        else:
            print("✗ Chain endpoint returned unexpected status code")
            return False
            
    except Exception as e:
        print(f"✗ Error: {e}")
        return False

def main():
    if len(sys.argv) < 2:
        print("Usage: python test_node_communication.py <node_address>")
        print("Example: python test_node_communication.py localhost:5000")
        sys.exit(1)
    
    node_address = sys.argv[1]
    
    print(f"Testing communication with node at {node_address}\n")
    print("=" * 50)
    
    # Test both endpoints
    transaction_ok = test_transaction_endpoint(node_address)
    chain_ok = test_chain_endpoint(node_address)
    
    print("\n" + "=" * 50)
    if transaction_ok and chain_ok:
        print("✓ All tests passed! Node communication is working.")
    else:
        print("✗ Some tests failed. Please check the errors above.")

if __name__ == "__main__":
    main()