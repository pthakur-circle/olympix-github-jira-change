"""
Git client

Git client to get GitHub alerts and request for additional info for alerts
"""

import json
import requests

class gitClient:
    """
    gitClient class
    Use GitHub API to get GHAS alerts information.
    Prepares the alert object for JIRA client
    """

    def __init__(self, access_token, org, debug=False):
        """initialize the Github client

        Args:
            access_token (string): github access token
            org (string): expecting circlefin or cybavo
            debug (bool, optional):Defaults to False.
        """
        self.headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {access_token}",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        self.org = org
        self.debug_mode = debug
        self.github_api_repo_base_url = "https://api.github.com/repos"
        self.github_api_org_base_url = "https://api.github.com/orgs"

    def _shorten_file_path(self, path):
        """Shortens the path file - helper function

        Args:
            path (string): path to be shorten

        Returns:
            string: shortened path
        """
        if path.count("/") <= 4:
            return path
        directories = path.split("/")
        shortened_path = f".../{'/'.join(directories[-4:])}"
        return shortened_path

    def _remove_duplicate_string(self, explanation):
        """helper function remove duplicated string

        Args:
            explanation (string): string with potential duplicated phrases

        Returns:
            string: cleaned explaination
        """
        sentences = explanation.split(".")
        sentences = [
            sentence.strip().replace("\n", "")
            for sentence in sentences
            if sentence.strip()
        ]
        sentences = list(set(sentences))
        return ". ".join(sentences)

    # def verify_github_repo(self, repo):
    #     """Verify the existence of a GitHub repository.

    #     Args:
    #         repo (string): A github repo's name

    #     Returns:
    #         boolean: True if the repo exists on Github, false if otherwise
    #     """

    #     url = f"{self.github_api_repo_base_url}/{self.org}/{repo}"

    #     response = requests.get(url, headers=self.headers)

    #     if response.status_code == 200:
    #         print(f"Repository '{self.org}/{repo}' found.")
    #         return True
    #     elif response.status_code == 404:
    #         print(f"Repository '{self.org}/{repo}' not found.")
    #         return False
    #     else:
    #         print(f"Failed to verify repository. Status code: {response.status_code}")
    #         return False

    def _create_alert_obj(  # pylint: disable=inconsistent-return-statements
        self, payload, alert_type, repo=None
    ):
        """Given the HTML payload extracted from GHAS pages, return reconstructed payload for the GHAS alert object

        Args:
            payload (object): HTML content extracted from GHAS page
            alert_type (string): GHAS alert type
            repo (string, optional): Which repo the GHAS alert was generated on. Defaults to None.

        Returns:
            dict: an object created from GHAS alerts. Customized according to the alert type
        """
        try:

            # General alert fields
            alert = payload
            if repo is None:
                repo = alert.get("repository", {}).get("name", None)  # in case None
            new_alert = {
                # "type": alert_type,    #  Add Olympix
                "id": alert["number"],
                "repo": repo,
                "org": self.org,
                # "git_id": f"{alert_type}: {repo} {alert['number']}",     # Add Olympix
                "created": alert.get("created_at", None),  # in case None
                "updated": alert.get("updated_at", None),
                "alert_url": alert.get("html_url", None),
            }

            # Specific fields
            if alert_type == "CodeQL":
                new_alert["severity"] = alert["rule"]["security_severity_level"]
                # new_alert["summary"] = alert["rule"]["description"]
                if alert["tool"]["name"] == "Trivy":
                    new_alert["explanation"] = alert["most_recent_instance"]["message"][
                        "text"
                    ]
                else:
                    new_alert["explanation"] = self._remove_duplicate_string(
                        alert["most_recent_instance"]["message"]["text"]
                    )
                # Add Olympix 
                if alert["tool"]["name"] == "Olympix Integrated Security":
                    new_alert["summary"] = alert["rule"]["id"]
                    new_alert["type"] = alert["tool"]["name"]
                    new_alert["git_id"] = f"{alert['tool']['name']}: {repo} {alert['number']}"
                else:
                   new_alert["summary"] = alert["rule"]["description"]
                   new_alert["type"] = alert_type  
                   new_alert["git_id"] = f"{alert_type}: {repo} {alert['number']}"

                new_alert["location"] = (
                    f"\nVulnerable code: {self._shorten_file_path(alert['most_recent_instance']['location']['path'])}, lines {alert['most_recent_instance']['location']['start_line']}-{alert['most_recent_instance']['location']['end_line']}"
                )
                if "most_recent_instance" in alert:
                    if "commit_sha" in alert["most_recent_instance"]:
                        new_alert["commit_sha"] = alert["most_recent_instance"][
                            "commit_sha"
                        ]
                    if "location" in alert["most_recent_instance"]:
                        new_alert["repo_path"] = alert["most_recent_instance"][
                            "location"
                        ]["path"]

            if alert_type == "Dependabot":
                new_alert["type"] = alert_type    # Add Olympix
                new_alert["severity"] = alert["security_advisory"]["severity"]
                new_alert["summary"] = alert["security_advisory"]["summary"]
                new_alert["explanation"] = (
                    f"Vulnerable package: {alert['dependency']['package']['name']} ({alert['dependency']['package']['ecosystem']}), affected versions: [{alert['security_vulnerability']['vulnerable_version_range']}], {alert['security_advisory']['cve_id']}"
                )
                new_alert["location"] = (
                    f"\nVulnerable code: {alert['dependency']['manifest_path']}"
                )
                new_alert["full_description"] = alert["security_advisory"][
                    "description"
                ]
                if "most_recent_instance" in alert:
                    if "commit_sha" in alert["most_recent_instance"]:
                        new_alert["commit_sha"] = alert["most_recent_instance"].get(
                            "commit_sha"
                        )

            if alert_type == "Secret":
                new_alert["type"] = alert_type    # Add Olympix
                new_alert["severity"] = "critical"
                new_alert["summary"] = alert["secret_type_display_name"]
                new_alert["explanation"] = (
                    f"Secret of type {alert['secret_type']} detected"
                )
                new_alert["full_description"] = (
                    "Secret is exposed in plaintext, recommended to follow Remediation steps listed in attached alert"
                )
                if "most_recent_instance" in alert:
                    if "commit_sha" in alert["most_recent_instance"]:
                        new_alert["commit_sha"] = alert["most_recent_instance"].get(
                            "commit_sha"
                        )
                    if "location" in alert["most_recent_instance"]:
                        new_alert["repo_path"] = (
                            alert["most_recent_instance"].get("location").get("path")
                        )
            return new_alert

        except Exception as ex:  # pylint: disable=broad-exception-caught
            error_msg = "Error in _create_alert_obj"
            if self.debug_mode:
                error_msg += f": {ex}"
            print(error_msg)

    def _get_alerts(  # pylint: disable=inconsistent-return-statements
        self, alert_type, repo=None, time=None, severity=None
    ):
        """Get new alerts from GHAS based on the given conditions

        Args:
            alert_type (string): type of the alert
            repo (string, optional):name of the repo to listen on. Defaults to None.
            time (string, optional): time since when the alert is wanted. Defaults to None.
            severity (string, optional): severity of the alert desired. Defaults to None.

        Returns:
            list: new alerts on GHAS based on given conditions
        """
        try:
            url_alert_types = {
                "CodeQL": "code-scanning",
                "Secret": "secret-scanning",
                "Dependabot": "dependabot",
            }
            url = f"{self.github_api_org_base_url}/{self.org}/{url_alert_types[alert_type]}/alerts"
            if repo:
                url = f"{self.github_api_repo_base_url}/{self.org}/{repo}/{url_alert_types[alert_type]}/alerts"
            params = {
                "per_page": 100,
                "page": 1,
                "state": "open",
                "direction": "desc",
                "sort": "created",
            }
            if severity in [
                "critical",
                "high",
                "medium",
                "low",
                "warning",
                "note",
                "error",
            ]:
                params["severity"] = severity
            response = requests.request(
                "GET", url, headers=self.headers, params=params, timeout=60
            )

            new_alerts = []
            check_next = True
            while check_next:
                if (
                    response.status_code == 404
                ):  # special case, no alert found with the specified URL
                    print(f"No alert available in {url}")
                    return None

                elif response.status_code != 200:
                    error_msg = f"Error in _get_alerts: {response.status_code}, {url}"
                    if self.debug_mode:
                        error_msg += f", {response.text}"
                    print(error_msg)
                    break
                # Update new alerts
                alerts = json.loads(response.text)
                for alert in alerts:
                    alert_obj = self._create_alert_obj(alert, alert_type, repo=repo)

                    if time and alert_obj["created"] < time:
                        return new_alerts
                    new_alerts.append(alert_obj)
                # Check if next page
                check_next = "next" in response.links
                if check_next:
                    # Get next page
                    response = requests.request(
                        "GET",
                        response.links["next"]["url"],
                        headers=self.headers,
                        timeout=60,
                    )
            return new_alerts
        except Exception as ex:  # pylint: disable=broad-exception-caught
            error_msg = "Error in _get_alerts"
            if self.debug_mode:
                error_msg += f": {ex}"
            print(error_msg)

    def list_active_org_alerts(  # pylint: disable=inconsistent-return-statements
        self, repo=None, time=None, severity=None, alertTypes=None
    ):
        """Get all active alerts for org (since last scan)

        Args:
            repo (string, optional): name of the Gitub repo. Defaults to None.
            time (string, optional): time since when the alert is wanted. Defaults to None.
            severity (string, optional): severity of the alert desired. Defaults to None.
            alertTypes (_type_, optional): type of the alert  . Defaults to None.

        Returns:
            list: List of active alerts given parameters
        """
        try:
            if alertTypes is None:
                alertTypes = ["CodeQL", "Secret", "Dependabot"]   

            all_alerts = []
            for alertType in alertTypes:
                if alertType in ["CodeQL", "Secret", "Dependabot"]:  
                    new_alerts = self._get_alerts(
                        alertType, repo=repo, time=time, severity=severity
                    )  # some repos may not have any alerts. Only append to the list when there is alert available
                    if new_alerts and len(new_alerts) != 0:
                        for alert in new_alerts:
                            all_alerts.append(alert)

            return all_alerts
        except Exception as ex:  # pylint: disable=broad-exception-caught
            error_msg = "Error in list_active_org_alerts"
            if self.debug_mode:
                error_msg += f": {ex}"
            print(error_msg)

    def close_alert(self, repo, alert_num, dismissed_reason, dismissed_comment):
        """
        Input: Repo name, alert number, reason for dismissal, dismissal comment
        Output: Closes alert and prints confirmation
        """
        try:
            if dismissed_reason not in [
                "null",
                "false positive",
                "won't fix",
                "used in tests",
            ]:
                print("Error: dismissed_reason invalid")
                return
            url = f"{self.github_api_repo_base_url}/{self.org}/{repo}/code-scanning/alerts/{alert_num}"
            data = {
                "state": "dismissed",
                "dismissed_reason": dismissed_reason,
                "dismissed_comment": dismissed_comment,
            }
            response = requests.request(
                "PATCH", url, headers=self.headers, data=data, timeout=60
            )
            # Check response was successful
            if response.status_code != 200:
                error_msg = f"Error in close_alert: {response.status_code}"
                if self.debug_mode:
                    error_msg += f", {response.text}"
                print(error_msg)
                return
            print(f"Alert #{alert_num} was successfully closed")
        except Exception as ex:  # pylint: disable=broad-exception-caught
            error_msg = f"Error in close_alert - failed to closet GitHub alert #{alert_num} in repo: {repo}"
            if self.debug_mode:
                error_msg += f": {ex}"
            print(error_msg)

    def update_alerts(self, alerts):  # pylint: disable=inconsistent-return-statements
        """
        Input: List of alerts
        Output: Alerts with updated info
        """
        try:
            for alert in alerts:
                if alert["type"] == "CodeQL":
                    url = f"{self.github_api_repo_base_url}/{self.org}/{alert['repo']}/code-scanning/alerts/{alert['id']}"
                    response = requests.request(
                        "GET", url, headers=self.headers, timeout=60
                    )
                    # Check response was successful
                    if response.status_code != 200:
                        error_msg = f"Error: {response.status_code}"
                        if self.debug_mode:
                            error_msg += f", {response.text}"
                        print(error_msg)
                        continue
                    # Print response
                    info = json.loads(response.text)
                    alert["full_description"] = info["rule"]["full_description"]
                elif alert["type"] == "Secret":
                    url = f"{self.github_api_repo_base_url}/{self.org}/{alert['repo']}/secret-scanning/alerts/{alert['id']}/locations"
                    response = requests.request(
                        "GET", url, headers=self.headers, timeout=60
                    )
                    # Check response was successful
                    if response.status_code != 200:
                        error_msg = f"Error in update_alerts: {response.status_code}"
                        if self.debug_mode:
                            error_msg += f", {response.text}"
                        print(error_msg)
                        continue
                    # Print response
                    info = json.loads(response.text)
                    locations = []
                    for location in info:
                        locations.append(
                            f"{self._shorten_file_path(location['details']['path'])}, lines {location['details']['start_line']}-{location['details']['end_line']}"
                        )
                    location_text = "\n".join(locations)
                    alert["location"] = f"\nVulnerable code: {location_text}"
            return alerts
        except Exception as ex:  # pylint: disable=broad-exception-caught
            error_msg = "Error in update_alerts"
            if self.debug_mode:
                error_msg += f": {ex}"
            print(error_msg)

    def add_alerts(self, to_add):
        """add alerts of the GHAS link to the list

        Args:
            to_add (string): link to a GHAS alert

        Returns:
            list: new alerts
        """
        try:
            alert_types = {
                "code-scanning": "CodeQL",
                "secret-scanning": "Secret",
                "dependabot": "Dependabot",
            }
            if not isinstance(to_add, list):
                to_add = [to_add]
            new_alerts = []
            for url in to_add:
                print(url)
                vals = url.split("/")
                alert_num = vals[-1]
                alert_type = vals[-2]
                repo = vals[-4]
                org = vals[-5]
                url = f"{self.github_api_repo_base_url}/{org}/{repo}/{alert_type}/alerts/{alert_num}"
                response = requests.request(
                    "GET", url, headers=self.headers, timeout=60
                )

                if response.status_code != 200:
                    error_msg = f"Error in add_alerts: {response.status_code}"
                    if self.debug_mode:
                        error_msg += f", {response.text}"
                    print(error_msg)
                    break

                alert = json.loads(response.text)
                alert_obj = self._create_alert_obj(
                    alert, alert_types[alert_type], repo=repo
                )
                new_alerts.append(alert_obj)
            return new_alerts
        except Exception as ex:  # pylint: disable=broad-exception-caught
            error_msg = "Error in add_alerts"
            if self.debug_mode:
                error_msg += f": {ex}"
            print(error_msg)

    def verify_github_repo(self, repo):
        """Verify the existence of a GitHub repository.

        Args:
            repo (string): A github repo's name

        Returns:
            boolean: True if the repo exists on Github, false if otherwise
        """

        url = f"{self.github_api_repo_base_url}/{self.org}/{repo}"
        print(url)
        response = requests.get(url, headers=self.headers)
        
        if response.status_code == 200:
            print(f"Repository '{self.org}/{repo}' found.")
            return True
        elif response.status_code == 404:
            print(f"Repository '{self.org}/{repo}' not found.")
            return False
        else:
            print(f"Failed to verify repository. Status code: {response.status_code}")
            return False

    def get_github_repos(self, org):
        """get all Github repos under an organization

        Args:
            org (string): an Github organization

        Returns:
            list, int : a list containing all the repos' numbers, number of repos under the organization
        """
        url = f"{self.github_api_org_base_url}/{org}/repos"

        params = {
            "per_page": 100,  # Get 100 repos per page (maximum allowed)
            "page": 1,
        }
        repoCount = 0
        repo_names = []
        while True:
            response = requests.get(
                url, headers=self.headers, params=params, verify=False
            )
            if response.status_code == 200:

                repos = response.json()
                if not repos:
                    break
                repo_names.extend([repo["name"] for repo in repos])
                for repo in repos:
                    repoCount += 1
                params["page"] += 1
            else:
                print(
                    f"Failed to retrieve repositories. Status code: {response.status_code}"
                )
                print(f"Response: {response.text}")
                break

        return repo_names, repoCount
