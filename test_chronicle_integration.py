import google.auth
import requests
import yara
import json
import os
import configparser

def load_config():
    config = configparser.ConfigParser()
    config_file = "config.ini"  # Name of your config file
    if not os.path.exists(config_file):
        raise FileNotFoundError(f"Configuration file '{config_file}' not found.")
    config.read(config_file)
    return config

def chronicle_round_trip_poc():
    try:
        config = load_config()
        chronicle_api_url = config.get("Chronicle", "api_url")

        credentials, project = google.auth.default()
        auth_token = credentials.token

        headers = {
            "Authorization": f"Bearer {auth_token}",
            "Content-Type": "application/json",
        }
        response = requests.get(chronicle_api_url, headers=headers)
        response.raise_for_status()

        data = response.json()
        print("Chronicle API Response:", json.dumps(data, indent=2))

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
        print(f"Chronicle SecOps round-trip proof of concept failed: HTTP error {e.response.status_code} - {e.response.text}")
        return False
    except FileNotFoundError as e:
        print(f"Chronicle SecOps round-trip proof of concept failed: {e}")
        return False
    except Exception as e:
        print(f"Chronicle SecOps round-trip proof of concept failed: {e}")
        return False

if __name__ == "__main__":
    chronicle_round_trip_poc()