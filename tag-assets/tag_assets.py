#
#  Sample script to read hostname and tags from a CSV file and invoke the Xshield API
#  to tag the assets.
#
#  ColorTokens Inc.
#  Venky Raju
#  Feb 12, 2024 

# pip install requests
import requests
import json
import csv

from ngapi import create_signature

tag_url = 'https://ng.colortokens.com/api/assets/annotations'
tag_method = 'PUT'

def _exec_api(url, method, body=None):

    headers = {}
    req_body = json.dumps(body) if body != None else None

    # Add the signature to the headers
    headers_with_signature = create_signature(url, method, headers, req_body)

    # Send the request with the signed headers and body
    api_req = getattr(requests, str.lower(method))
    response = api_req(url, headers=headers_with_signature, data=req_body)

    return response

def _read_csv(filename):
    with open(filename, 'r') as file:
        reader = csv.reader(file, skipinitialspace=True)
        variables = next(reader)
        data = []
        for row in reader:
            if len(row) < 1:  # Skip rows with no tag values
                continue
            data.append(row)
    return variables, data

def _handle_row (variables, row):

    assetname = row[0].strip()
    businessValue = row[1].strip()
    variables = variables[2:]
    row = row[2:]
    
    req_body = {}
    req_body['criteria'] = f"assetname = '{assetname}'"

    if businessValue:
        req_body['businessValue'] = businessValue
    
    coreTags = {}
    for tag, value in zip(variables, row):
        if value:
            coreTags[tag] = value
    
    if len(coreTags) > 0:
        req_body['coreTags'] = coreTags

    resp = _exec_api(tag_url, tag_method, req_body)
    if not resp.ok:
        print("Unable to tag asset: "+assetname)
        print(resp.text)

    return resp.ok
                
def main():
    filename = input("Enter the CSV filename: ")
    try:
        variables, data = _read_csv(filename)
        expected_variables = ["assetname", "businessValue", "application", "environment", "role", "location", "owner"]
        if variables != expected_variables:
            print("Variables in the file do not match the expected variables.")
            return

        for row in data:
            if len(row) != len(expected_variables):
                print("Skipping malformed row: ", row)
                continue

            _handle_row(variables, row)

    except FileNotFoundError:
        print("File not found.")

if __name__ == "__main__":
    main()
