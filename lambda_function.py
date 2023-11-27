import json
import boto3
import base64
from botocore.vendored import requests
import hmac

# Your secret's name and region
secret_name = "hackerone"
region_name = "us-east-1"

#Set up our Session and Client
session = boto3.session.Session()
client = session.client(
    service_name='secretsmanager',
    region_name=region_name
)

def lambda_handler(event, context):
    payload = str(event).replace("\"", "\\\"").replace("\'", "\"").replace("False","\"False\"")
    json_opt = json.loads(payload)

    # Calling SecretsManager
    get_secret_value_response = client.get_secret_value(
        SecretId=secret_name
    )
    
    API_KEY_NAME = "api_testing_fws"

    #Extracting the key/value from the secret
    secret = get_secret_value_response['SecretString']
    API_KEY = json.loads(secret)['hackerone_api_key']
    
    auth = (API_KEY_NAME, API_KEY)
    
    body = json.loads(json_opt["body"], strict= False)
    report_id = body["data"]["report"]["id"]
    reporter = body["data"]["report"]["relationships"]["reporter"]["data"]["attributes"]["username"]

    headers = {
      "Content-Type": "application/json",
      "Accept": "application/json"
    }
    
    # denying the disclosure request
    if json_opt["headers"]["x-h1-event"] == "report_agreed_on_going_public":
        data = {
                "data": {
                    "attributes": {
                        "message": f"Hi @{reporter},\n\nWe don't allow public disclosure as per the program policy: https://hackerone.com/freshworks. We appreciate your effort in securing Freshworks application and we look forward for your next submission."
                    }
                }
            }
        
        r = requests.delete(
                f"https://api.hackerone.com/v1/reports/{report_id}/disclosure_requests",
                auth=auth,
                json=data,
                headers=headers
            )
        print("Status:", r.status_code ,"\nResponse body:", r.json)
    
   # first response  
  if json_opt["headers"]["x-h1-event"] == "report_created":
        data = {
                "data": {
                    "type": "activity-comment",
                    "attributes": {
                        "message": f"Hi @{reporter},\n\nThank you for reporting this issue. We will look into it and get back to you if we need more information.",
                        "internal": False,
                        "attachment_ids": []
                    }
                }
            }
        

        r = requests.post(
                f"https://api.hackerone.com/v1/reports/{report_id}/activities",
                auth=auth,
                json=data,
                headers=headers,
                verify=False
            )
            
        print("Status:", r.status_code ,"\nResponse body:", r.json)
    
