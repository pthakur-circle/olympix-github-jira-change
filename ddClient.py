import requests
import warnings
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Suppress only the InsecureRequestWarning from urllib3
warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)


class ddClient:
    """
    class ddClient
    Extract information from the Datadog pages to fill the assignee part& more
    """

    def __init__(self, API_KEY, APP_KEY, org, debug=False):
        self.header = {
            "Accept": "application/json",
            "DD-API-KEY": API_KEY,
            "DD-APPLICATION-KEY": APP_KEY,
        }
        self.params = {"schema_version": "v2.2"}
        self.org = org
        self.debug_mode = debug
        if self.verify_datadog_keys(API_KEY, APP_KEY) == False:
            exit(0)
