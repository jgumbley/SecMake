import google.auth
import requests
import yara
import json

def chronicle_round_trip_poc():
    try:
        # 1. Authentication
        credentials, project = google.auth.default()
        auth_token = credentials.token

        # 2. API Call (Example: List Rules - adjust endpoint as needed)
        chronicle_api_url = "https://chronicle.googleapis.com/v2/rules" #example endpoint.
        headers = {
            "Authorization": f"Bearer {auth_token}",
            "Content-Type": "application/json",
        }
        response = requests.get(chronicle_api_url, headers=headers)
        response.raise_for_status()  # Raise HTTPError for bad responses

        # 3. Data Retrieval
        data = response.json()
        print("Chronicle API Response:", json.dumps(data, indent=2))

        # 4. Yara Rule Application (Optional)
        if "rules" in data and len(data["rules"]) > 0:
            rule_string = 'rule test_rule : test { strings: $a = "test" condition: $a }'
            rule = yara.compile(source=rule_string)
            for rule_item in data["rules"]:
                if "ruleText" in rule_item:
                    matches = rule.match(data=rule_item["ruleText"])
                    if matches:
                        print("Yara Rule Matches:", matches)

        print("Chronicle SecOps round-trip proof of concept successful!")
        return True

    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            print("Chronicle SecOps round-trip proof of concept failed: The API endpoint was not found. This could indicate that your account does not have the necessary permissions to access the Chronicle SecOps API or the API is not enabled. Please ensure you have the correct access rights and the API is enabled in your Google Cloud project.")
        else:
            print(f"Chronicle SecOps round-trip proof of concept failed: {e}")
        return False
    except Exception as e:
        print(f"Chronicle SecOps round-trip proof of concept failed: {e}")
        return False

if __name__ == "__main__":
    chronicle_round_trip_poc()