"""The function to read secrets from file: "secrets.txt"
An unique function of misc code (will run locally)
Please name the secret txt file as secrets.txt
The pairs should be of format: key="value"
Credentials needed: 
 - Datadog key pair: API and APP keys (with READ access to TEAM and SERVICEs)
 - GitHub key: GitHub Access Token
 - JIRA key: Atlassian Access Token
"""


def get_secrets():
    secrets = {}

    with open("secrets.txt", "r") as file:
        for line in file:
            line = line.strip()
            if line and not line.startswith("#"):  # Ignore empty lines and comments
                key, value = line.split("=", 1)
                secrets[key.strip()] = value.strip('"')

    return secrets
