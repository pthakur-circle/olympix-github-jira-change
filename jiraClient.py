"""
Jira client

Jira client to handle jira related requests and create and open tickets
PR1: Changing __init__ header and parameters to prepare for further update
"""

import json
import datetime
import traceback
import requests
from requests.auth import HTTPBasicAuth


class jiraClient:
    """
    jiraClient class
    """

    def __init__(
        self, email, api_token, gitClient, org, test, debug=False
    ):
        self.headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        self.auth = HTTPBasicAuth(email, api_token)
        self.debug_mode = debug
        self.test = test
        self.severity_to_priority = {  # map GHAS severity to JIRA board priority rank
            "critical": "Highest",
            "high": "High",
            "medium": "Medium",
            "low": "Low",
        }
        self.base_atlassian_url = "https://circlepay.atlassian.net"
        self.base_github_url = "https://www.github.com"
        self.issue_type = "Bug"  # issue type
        self.board_num = 464  # SECENG board number
        self.git_id_field = "12939"  # custome_field id to put GIT ID
        self.remote_link_field = "12961"  # custome_field id to put remote link
        self.alert_dismissal_field = "12957"  # custome_field id to put alert dismissal
        self.git_owner_name = "13243"  # custome_field id to put JIRA USER/GIT OWNER
        self.git_owner_email = "13172"  # custome_field id to put GIT OWNER email

    def _create_alert_issue(  # pylint: disable=inconsistent-return-statements
        self, alert
    ):
        """v2 UPDATED - 2024: add blame info& git repo URL. Custome field depending on alert type
        Will creates Jira issue for provided alert

        Args:
            alert (obj): alert object
        """

        if alert is None:
            print("alert_issues is None, initializing as empty list.")
            return

        try:
            summary = f"{alert['type']} [{alert['repo']}]: {alert['summary']}"
            url = f"{self.base_atlassian_url}/rest/api/3/issue"
            priority = self.severity_to_priority[alert["severity"].lower()]

            JIRAid = None
            if "JIRAid" in alert:
                JIRAid = alert["JIRAid"]

            payload = None  # vary according to board and alert type

            if alert["type"] == "Dependabot":
                description = {
                    "type": "doc",
                    "version": 1,
                    "content": [
                        {
                            "type": "paragraph",
                            "content": [
                                {
                                    "type": "text",
                                    "text": "Link to Alert: ",
                                    "marks": [{"type": "strong"}],
                                },
                                {
                                    "type": "text",
                                    "text": alert["alert_url"],
                                    "marks": [
                                        {
                                            "type": "link",
                                            "attrs": {"href": alert["alert_url"]},
                                        }
                                    ],
                                },
                            ],
                        },
                        {
                            "type": "paragraph",
                            "content": [
                                {
                                    "type": "text",
                                    "text": "Git ID: ",
                                    "marks": [{"type": "strong"}],
                                },
                                {"type": "text", "text": alert["git_id"]},
                            ],
                        },
                        {
                            "type": "paragraph",
                            "content": [
                                {
                                    "type": "text",
                                    "text": "GITHUB repo name: ",
                                    "marks": [{"type": "strong"}],
                                },
                                {"type": "text", "text": alert["repo"]},
                            ],
                        },
                        {
                            "type": "paragraph",
                            "content": [
                                {
                                    "type": "text",
                                    "text": "Explanation of the alert: ",
                                    "marks": [{"type": "strong"}],
                                },
                                {"type": "text", "text": alert["explanation"]},
                            ],
                        },
                        {
                            "type": "paragraph",
                            "content": [
                                {
                                    "type": "text",
                                    "text": "Full description: ",
                                    "marks": [{"type": "strong"}],
                                },
                                {"type": "text", "text": alert["full_description"]},
                            ],
                        },
                    ],
                }
                if self.test:  # Dependabot test board - SEO
                    payload = {
                        "fields": {
                            "project": {"key": "SEO"},
                            "summary": f"{summary}",
                            "description": description,
                            "issuetype": {"name": self.issue_type},  # Bug - hardcoded
                            "priority": {"name": priority},
                            # Don't assign to anyone, SEO is a security board
                        }
                    }
                else:  # Dependabot non-test board - VULN
                    payload = {
                        "fields": {
                            "project": {"key": "VULN"},
                            "summary": f"{summary}",
                            "description": description,
                            "issuetype": {"name": self.issue_type},  # Bug - hardcoded
                            "priority": {"name": priority},
                            "assignee": {"accountId": JIRAid},  # could be None
                        }
                    }
            else:  # type is CodeQL or Secret
                if self.test:  # Non-dependabot alerts , test
                    # Add Olympix
                    if alert["type"] == "Olympix Integrated Security":
                        description = {
                        "type": "doc",
                        "version": 1,
                        "content": [
                            {
                                "type": "paragraph",
                                "content": [
                                    {
                                        "type": "text",
                                        "text": "Link to Alert: ",
                                        "marks": [{"type": "strong"}],
                                    },
                                    {
                                        "type": "text",
                                        "text": alert["alert_url"],
                                        "marks": [
                                            {
                                                "type": "link",
                                                "attrs": {"href": alert["alert_url"]},
                                            }
                                        ],
                                    },
                                ],
                            },
                            {
                                "type": "paragraph",
                                "content": [
                                    {
                                        "type": "text",
                                        "text": "Git ID: ",
                                        "marks": [{"type": "strong"}],
                                    },
                                    {"type": "text", "text": alert["git_id"]},
                                ],
                            },
                            {
                                "type": "paragraph",
                                "content": [
                                    {
                                        "type": "text",
                                        "text": "GITHUB repo name: ",
                                        "marks": [{"type": "strong"}],
                                    },
                                    {"type": "text", "text": alert["repo"]},
                                ],
                            },
                            {
                                "type": "paragraph",
                                "content": [
                                    {
                                        "type": "text",
                                        "text": "Link to Github repo ",
                                        "marks": [{"type": "strong"}],
                                    },
                                    {
                                        "type": "text",
                                        "text": f"{self.base_github_url}/{alert['org']}/{alert['repo']}/tree/master/{alert['repo_path']}",
                                    },
                                ],
                            },
                            {
                                "type": "paragraph",
                                "content": [
                                    {
                                        "type": "text",
                                        "text": "Explanation of the alert: ",
                                        "marks": [{"type": "strong"}],
                                    },
                                    {"type": "text", "text": alert["explanation"]},
                                ],
                            },
                        ],
                    }  
                    else:
                        description = {
                            "type": "doc",
                            "version": 1,
                            "content": [
                                {
                                    "type": "paragraph",
                                    "content": [
                                        {
                                            "type": "text",
                                            "text": "Link to Alert: ",
                                            "marks": [{"type": "strong"}],
                                        },
                                        {
                                            "type": "text",
                                            "text": alert["alert_url"],
                                            "marks": [
                                                {
                                                    "type": "link",
                                                    "attrs": {"href": alert["alert_url"]},
                                                }
                                            ],
                                        },
                                    ],
                                },
                                {
                                    "type": "paragraph",
                                    "content": [
                                        {
                                            "type": "text",
                                            "text": "Git ID: ",
                                            "marks": [{"type": "strong"}],
                                        },
                                        {"type": "text", "text": alert["git_id"]},
                                    ],
                                },
                                {
                                    "type": "paragraph",
                                    "content": [
                                        {
                                            "type": "text",
                                            "text": "GITHUB repo name: ",
                                            "marks": [{"type": "strong"}],
                                        },
                                        {"type": "text", "text": alert["repo"]},
                                    ],
                                },
                                {
                                    "type": "paragraph",
                                    "content": [
                                        {
                                            "type": "text",
                                            "text": "Link to Github repo ",
                                            "marks": [{"type": "strong"}],
                                        },
                                        {
                                            "type": "text",
                                            "text": f"{self.base_github_url}/{alert['org']}/{alert['repo']}/tree/master/{alert['repo_path']}",
                                        },
                                    ],
                                },
                                {
                                    "type": "paragraph",
                                    "content": [
                                        {
                                            "type": "text",
                                            "text": "Explanation of the alert: ",
                                            "marks": [{"type": "strong"}],
                                        },
                                        {"type": "text", "text": alert["explanation"]},
                                    ],
                                },
                                {
                                    "type": "paragraph",
                                    "content": [
                                        {
                                            "type": "text",
                                            "text": "Full description: ",
                                            "marks": [{"type": "strong"}],
                                        },
                                        {"type": "text", "text": alert["full_description"]},
                                    ],
                                },
                                {
                                    "type": "paragraph",
                                    "content": [
                                        {
                                            "type": "text",
                                            "text": "Git Owner Name: ",
                                            "marks": [{"type": "strong"}],
                                        },
                                        {"type": "text", "text": alert["committer_name"]},
                                    ],
                                },
                                {
                                    "type": "paragraph",
                                    "content": [
                                        {
                                            "type": "text",
                                            "text": "Git Owner Email: ",
                                            "marks": [{"type": "strong"}],
                                        },
                                        {"type": "text", "text": alert["committer_email"]},
                                    ],
                                },
                            ],
                        }    

                    payload = {
                        "fields": {
                            "project": {
                                "key": "SEO"  # CodeQL & secrect test - sending to SEO board
                            },
                            "summary": f"{summary}",
                            "description": description,
                            "issuetype": {"name": self.issue_type},  # "Bug" - hardcoded
                            "priority": {"name": priority},
                            # Don't assign tickets to anyone. It is a Security board (even test board) and people might not have access?
                        }
                    }

                else:  # Non-dependabot alerts , non-test -> SECENG board

                    type_to_summary = {
                        "CodeQL": "GitHub CodeQL",
                        "Secret": "GitHub Secret Scan",
                    }
                    url = f"{self.base_atlassian_url}/rest/api/3/issue"
                    created = datetime.datetime.strptime(
                        alert["created"], "%Y-%m-%dT%H:%M:%SZ"
                    ).strftime("%B %d, %Y %H:%M")
                    summary = f"{type_to_summary[alert['type']]} [{alert['repo']}]: {alert['summary']}"
                    description1 = f"Alert created on {created}"
                    if alert["updated"] != alert["created"]:
                        description1 += f" (updated on {datetime.datetime.strptime(alert['updated'], '%Y-%m-%dT%H:%M:%SZ').strftime('%B %d, %Y %H:%M')})"
                    description1 += f"\n\nDiscovered in {alert['org']}/"

                    payload = {
                        "fields": {
                            "project": {"key": "SECENG"},
                            "summary": summary,
                            "description": {
                                "content": [
                                    {
                                        "content": [
                                            {
                                                "type": "text",
                                                "text": "Link to Alert: ",
                                                "marks": [{"type": "strong"}],
                                            },
                                            {
                                                "type": "text",
                                                "text": alert["alert_url"],
                                                "marks": [
                                                    {
                                                        "type": "link",
                                                        "attrs": {
                                                            "href": alert["alert_url"]
                                                        },
                                                    }
                                                ],
                                            },
                                            {"text": description1, "type": "text"},
                                            {
                                                "text": alert["repo"],
                                                "type": "text",
                                                "marks": [{"type": "strong"}],
                                            },
                                            {"text": alert["location"], "type": "text"},
                                            {
                                                "text": "\n\nOverview: ",
                                                "type": "text",
                                                "marks": [{"type": "strong"}],
                                            },
                                            {
                                                "text": alert["explanation"],
                                                "type": "text",
                                            },
                                            {
                                                "text": "\nDescription: ",
                                                "type": "text",
                                                "marks": [{"type": "strong"}],
                                            },
                                            {
                                                "text": alert["full_description"],
                                                "type": "text",
                                            },
                                        ],
                                        "type": "paragraph",
                                    }
                                ],
                                "type": "doc",
                                "version": 1,
                            },
                            f"customfield_{self.git_id_field}": alert["git_id"],
                            f"customfield_{self.remote_link_field}": alert["alert_url"],
                            f"customfield_{self.alert_dismissal_field}": {
                                "value": alert["type"]
                            },
                            f"customfield_{self.git_owner_email}": alert[
                                "committer_email"
                            ],
                            "issuetype": {
                                "name": self.issue_type
                            },  # don't assign to anyone yet
                            "priority": {
                                "name": self.severity_to_priority[alert["severity"]]
                            },
                        }
                    }
                    if "committer_email" in alert:
                        fieldpayload = self._get_JIRA_user_obj_by_email(
                            alert["committer_email"]
                        )
                        if fieldpayload:
                            payload["fields"][
                                f"customfield_{self.git_owner_name}"
                            ] = fieldpayload

            response = requests.post(
                url,
                headers=self.headers,
                data=json.dumps(payload),
                auth=self.auth,
                verify=False,
            )

            if response.status_code == 201:
                print("Issue created successfully.", response.json())
            else:
                print(
                    f"Failed to create issue: {response.status_code} - {response.text}"
                )

        except Exception as e:
            print(f"Exception in jiraClient _create_alert_issue {e}")

    def get_board_key_given_alert_url(self, alert_link):

        """return the board key given the alert url, based on whether is testing

        Args:
            alert_link (string): link to the GHAS alert

        Returns:
            string: board key this JIRA ticket should be created/updated on (can be SEO, VULN, SECENG)
            | None if the alert type is wrong
        """
        url_parts = urlparse(alert_link)
        alert_type = url_parts.path.split("/")[-2]
        if (
            alert_type != "dependabot"
            and alert_type != "code-scanning"
            and alert_type != "secret-scanning"
        ):
            print(
                f"Err: Could not find the board to update this alert {alert_link}. Getting {alert_type} - Only expecting dependabot, code-scanning and secret-scanning. Please fix"
            )
            return None
        if self.test:
            return "SEO"
        else:
            if alert_type == "dependabot":
                return "VULN"
            else:
                return "SECENG"

    def _get_issue_by_alert_url(self, alert_link):
        """Searches for a JIRA issue provided with link to the GHAS alert using jql query
        SEO and VULN does not have a custom field for GIT ID. But has link to GHAS alert in description. Since every GHAS alert link is unique, will use GHAS alert link to extract JIRA issue

        Args:
            alert_link (string): link to the GHAS alert

        Returns:
            object: JIRA the issue's payload if such ticket exists. None if no such ticket exists
        """
        try:
            url = f"{self.base_atlassian_url}/rest/api/3/search"
            board_key = self.get_board_key_given_alert_url(alert_link)
            if board_key == None:
                return None

            jql_query = f'project={board_key} AND description ~ "{alert_link}"'
            params = {"jql": jql_query}

            response = requests.request(
                "GET",
                url,
                headers=self.headers,
                auth=self.auth,
                params=params,
                timeout=60,
                verify=False,
            )

            if response.status_code != 200:
                error_msg = f"Error in get_issue_by_alert_url: {response.status_code}"
                if self.debug_mode:
                    error_msg += f", {response.text}"
                print(error_msg)
                return None

            issues = json.loads(response.text)["issues"]
            theIssue = None
            issueCount = 0
            if issues is not None:
                for issue in issues:
                    if issue is not None:
                        issueCount += 1
                        description = (
                            issue["fields"]
                            .get("description", {"type": "", "content": []})
                            .get("content", [])
                        )
                        for block in description:
                            if block.get("type") == "paragraph":
                                for content in block.get("content", []):
                                    if content.get(
                                        "type"
                                    ) == "text" and alert_link in content.get(
                                        "text", ""
                                    ):
                                        if issueCount <= 1:
                                            theIssue = issue
                                        else:
                                            print(
                                                f"Key Err:{issueCount} JIRA tickets with the same GHAS link found"
                                            )
                                            break
            return theIssue

        except Exception as ex:  # pylint: disable=broad-exception-caught
            error_msg = f"Error in get_issue_by_alert_url - failed to get issue by alert url: {alert_link}"
            if self.debug_mode:
                error_msg += f": {ex}"
            print(error_msg)
            return None

    def _get_issue_by_git_id(  # pylint: disable=inconsistent-return-statements
        self, custom_field_val
    ):
        """
        SECENG board has a custom field for GIT ID, following the old way of extracting JIRA issues.
        only used for alerts on SECENG board (will only operate on SECENG board no matter the input)
        Input: git id value
        Output: returns true if such an issue exists, else false
        """
        try:
            if custom_field_val == "":
                return None
            url = f"{self.base_atlassian_url}/rest/api/3/search"
            jql_query = (
                f'project="SECENG" AND cf[{self.git_id_field}]~"{custom_field_val}"'
            )
            params = {"jql": jql_query}
            # Get issue
            response = requests.request(
                "GET",
                url,
                headers=self.headers,
                auth=self.auth,
                params=params,
                timeout=60,
            )
            # Check response was successful
            if response.status_code != 200:
                error_msg = f"Error in _get_issue_by_git_id: {response.status_code}"
                if self.debug_mode:
                    error_msg += f", {response.text}"
                print(error_msg)
                return
            # Print issue info
            issues = json.loads(response.text)["issues"]

            theIssue = None
            issueCount = 0
            if issues is not None:
                for issue in issues:
                    issueCount += 1
                    if (
                        issue["fields"][f"customfield_{self.git_id_field}"]
                        == custom_field_val
                    ):
                        if issueCount <= 1:
                            theIssue = issue

            if issueCount > 1:
                print(
                    f"Key Err:{issueCount} JIRA tickets with the same GHAS link found"
                )
            return theIssue

        except Exception as ex:  # pylint: disable=broad-exception-caught
            error_msg = f"Error in _get_issue_by_git_id - failed to get issue # by git_id ({self.git_id_field}): {custom_field_val}"
            if self.debug_mode:
                error_msg += f": {ex}"
            print(error_msg)


    def update_issues(self, alerts):
        
        """update_issues:
        Will create with a list of issues on the preferred JIRA board
        1. If no old JIRA issue with the link in description found, will create a new issue from given GHAS alert
        2. If an old JIRA issue with the link in description found, this function also updates the assignee field, following the rules

        Args:
            alerts (list): list of alert objects

        Returns:
            list: list of alert objects that were never reported in Jira
        """
        try:

            alerts_added = []
            for alert in alerts:

                oldIssueIfApplies = None
                if alert["type"] == "Dependabot" or self.test == True:
                    # SEO or VULN board
                    # These 2 boards does not have a custom field for GIT ID. But has link to GHAS alert in description. Since every GHAS alert link is unique, will use GHAS alert link to extract JIRA issue
                    # If more boards are to be added, should check the issue's payload/ custom fields
                    oldIssueIfApplies = self._get_issue_by_alert_url(alert["alert_url"])
                else:
                    # SECENG board. This board has a custom field for GIT ID, following the old way of extracting JIRA issues.
                    oldIssueIfApplies = self._get_issue_by_git_id(alert["git_id"])

                # Create a new alert if no corresponding old alert found
                if oldIssueIfApplies is None:
                    print(f"...Creating issue for {alert['alert_url']}")
                    issue = self._create_alert_issue(alert)
                    alerts_added.append(issue)

                else:
                    jira_key = oldIssueIfApplies["key"]
                    if self.test == True:
                        # SEO: (assignees are always None) - check the 'link to alert'
                        #    - if Dependabot: check
                        print(
                            f"Issue already exists on JIRA board for {alert['alert_url']}. And this is on SEO board, so will not sync. However, SECENG & VULN board do have the syncing in place"
                        )

                    else:

                        if alert["type"] == "Dependabot":
                            # VULN: (Dependabot - expect assignees)
                            #    - will update the assignee field if the old JIRA issue does not have an assignee, and JIRAid info is available in the new GHAS alert
                            if (
                                oldIssueIfApplies.get("fields", {}).get("assignee")
                                is None
                                and "JIRAid" in alert
                            ):

                                url = f"{self.base_atlassian_url}/rest/api/3/issue/{jira_key}/assignee"
                                headers = {
                                    "Content-Type": "application/json",
                                }
                                payload = {"accountId": alert["JIRAid"]}
                                response = requests.put(
                                    url,
                                    headers=headers,
                                    auth=self.auth,
                                    data=json.dumps(payload),
                                    verify=False,
                                )

                                if response.status_code == 204:
                                    print(
                                        f'Issue already exists on JIRA board for {alert["alert_url"]}. Successfully updated the assignee for issue {jira_key} to {alert["JIRAid"]}.'
                                    )

                                else:
                                    print(
                                        f'Issue already exists on JIRA board for {alert["alert_url"]}. Failed to update the assignee for issue {jira_key}. Status code: {response.status_code}'
                                    )
                                    print(f"Response: {response.text}")
                            else:
                                print(
                                    f'Issue already exists on JIRA board for {alert["alert_url"]}, and nothing to update'
                                )
                        else:
                            # SECENG: (CodeQL&Secret - assignees are always None) - check if 'GIT owner email' is NULL or 'GIT owner/JIRA user is None'
                            #    - update the GIT OWNER field
                            if (
                                (
                                    f"customfield_{self.git_owner_email}"
                                    in oldIssueIfApplies["fields"]
                                    and oldIssueIfApplies["fields"][
                                        f"customfield_{self.git_owner_email}"
                                    ]
                                    is None
                                )
                                or (
                                    f"customfield_{self.git_owner_name}"
                                    in oldIssueIfApplies["fields"]
                                    and oldIssueIfApplies["fields"][
                                        f"customfield_{self.git_owner_name}"
                                    ]
                                    is None
                                )
                                and "committer_email" in alert
                            ):
                                headers = {
                                    "Content-Type": "application/json",
                                }
                                payload = {"accountId": alert["JIRAid"]}

                                payload = {
                                    "fields": {
                                        f"customfield_{self.git_owner_email}": alert[
                                            "committer_email"
                                        ]
                                    }
                                }
                                fieldpayload = self._get_JIRA_user_obj_by_email(
                                    alert["committer_email"]
                                )
                                if fieldpayload:
                                    payload["fields"][
                                        f"customfield_{self.git_owner_name}"
                                    ] = fieldpayload
                                url = f"{self.base_atlassian_url}/rest/api/3/issue/{jira_key}"

                                response = requests.put(
                                    url,
                                    headers=headers,
                                    auth=self.auth,
                                    json=payload,
                                    verify=False,
                                )

                                if response.status_code == 204:
                                    print(
                                        f'Issue already exists on JIRA board for {alert["alert_url"]}. Successfully updated the committer fields for issue {jira_key} to {alert["JIRAid"]}.'
                                    )

                                else:
                                    print(
                                        f'Issue already exists on JIRA board for {alert["alert_url"]}. Failed to update the committer fields for issue {jira_key}. Status code: {response.status_code}'
                                    )
                                    print(f"Response: {response.text}")
                            else:
                                print(
                                    f'Issue already exists on JIRA board for {alert["alert_url"]}, and nothing to update'
                                )

            return alerts_added

        except Exception as ex:  # pylint: disable=broad-exception-caught
            error_msg = "Error in update_issues - failed to find new alert issues"
            if self.debug_mode:
                error_msg += f": {ex}"
            traceback.print_exc()
            print(error_msg)


    def _get_issue_by_git_id(  # pylint: disable=inconsistent-return-statements
        self, custom_field_val
    ):
        """
        only used for alerts on SECENG board (will only operate on SECENG board no matter the input)
        Input: git id value
        Output: returns true if such an issue exists, else false
        """
        try:
            if custom_field_val == "":
                return None
            url = f"{self.base_atlassian_url}/rest/api/3/search"
            jql_query = (
                f'project="SECENG" AND cf[{self.git_id_field}]~"{custom_field_val}"' # only SECENG get issue by git id. others get issue by GHAS alert URL
            )
            params = {"jql": jql_query}
            # Get issue
            response = requests.request(
                "GET",
                url,
                headers=self.headers,
                auth=self.auth,
                params=params,
                timeout=60,
            )
            # Check response was successful
            if response.status_code != 200:
                error_msg = f"Error in _get_issue_by_git_id: {response.status_code}"
                if self.debug_mode:
                    error_msg += f", {response.text}"
                print(error_msg)
                return
            # Print issue info
            issues = json.loads(response.text)["issues"]

            theIssue = None
            issueCount = 0
            if issues is not None:
                for issue in issues:
                    issueCount += 1
                    if (
                        issue["fields"][f"customfield_{self.git_id_field}"]
                        == custom_field_val
                    ):
                        if issueCount <= 1:
                            theIssue = issue

            if issueCount > 1:
                print(
                    f"Key Err:{issueCount} JIRA tickets with the same GHAS link found"
                )
            return theIssue

        except Exception as ex:  # pylint: disable=broad-exception-caught
            error_msg = f"Error in _get_issue_by_git_id - failed to get issue # by git_id ({self.git_id_field}): {custom_field_val}"
            if self.debug_mode:
                error_msg += f": {ex}"
            print(error_msg)

    def delete_issue(self, alert_link):
        """Delete an issue on JIRA using jql_queired using the link to GHAS alert as key

        Args:
            alert_link (string): link to the GHAS alert

        Returns:
            boolean: True if deleted sucessfully, False if else
        """
        try:
            issue = None
            if (
                self._get_alert_type_by_url(alert_link) == "dependabot"
                or self.test == True
            ):  # on SEO board, or is a dependbaot type alert -- VULN board. These 2 boards does not have a custom field for GIT ID. But has link to GHAS alert in description. Since every GHAS alert link is unique, will use GHAS alert link to extract JIRA issue
                # If more boards are to be added, should check the issue's payload/ custom fields
                issue = self._get_issue_by_alert_url(alert_link)
            else:   # on SECENG board. secret-scanning and code-scan. This board has a custom field for GIT ID, following the old way of extracting JIRA issues.
                issue = self._get_issue_by_git_id(self._get_git_id_by_url(alert_link))

            if not issue:
                print(f"No issue found with alert link: {alert_link}")
                return False  # either no such issue found, or worng alert type

            issue_key = issue["key"]
            delete_url = f"{self.base_atlassian_url}/rest/api/3/issue/{issue_key}"

            response = requests.delete(
                delete_url, headers=self.headers, auth=self.auth, timeout=60
            )

            if response.status_code == 204:
                print(f"Successfully deleted issue {issue_key}")
                return True
            else:
                error_msg = f"Error in delete_issue: {response.status_code}"
                if self.debug_mode:
                    error_msg += f", {response.text}"
                print(error_msg)
                return False

        except Exception as ex:
            error_msg = f"Error in delete_issue - failed to delete issue by alert url: {alert_link}"
            if self.debug_mode:
                error_msg += f": {ex}"
            print(error_msg)
            return False


    def move_issue(self, issue_id, transition_id, update_comment):
        """
        Function to transition issue
        (not currently in use)
        """
        try:
            url = f"{self.base_atlassian_url}/rest/api/3/issue/{issue_id}/transitions"
            payload = json.dumps(
                {
                    "transition": {"id": transition_id},
                    "update": {
                        "comment": [
                            {
                                "add": {
                                    "body": {
                                        "content": [
                                            {
                                                "content": [
                                                    {
                                                        "text": update_comment,
                                                        "type": "text",
                                                    }
                                                ],
                                                "type": "paragraph",
                                            }
                                        ],
                                        "type": "doc",
                                        "version": 1,
                                    }
                                }
                            }
                        ]
                    },
                }
            )
            # Move issue
            response = requests.request(
                "POST",
                url,
                data=payload,
                headers=self.headers,
                auth=self.auth,
                timeout=60,
            )
            # Check response was successful
            if response.status_code != 204:
                error_msg = f"Error in move_issue: {response.status_code}"
                if self.debug_mode:
                    error_msg += f", {response.text}"
                print(error_msg)
                return
            # Print confirmation
            print(f"Successfully moved issue {issue_id}")
        except Exception as ex:  # pylint: disable=broad-exception-caught
            error_msg = f"Error in move_issue - failed to move issue #{issue_id}"
            if self.debug_mode:
                error_msg += f": {ex}"
            print(error_msg)

    def assign_issue(self, issue_id, account_id=None):
        """
        Function to assign issue
        (not currently in use)
        """
        try:
            url = (
                f"{self.base_atlassian_url}/rest/api/3/issue/{issue_id}/assignee"
            )
            payload = json.dumps({"accountId": account_id})
            # assign issue
            response = requests.request(
                "PUT",
                url,
                data=payload,
                headers=self.headers,
                auth=self.auth,
                timeout=60,
            )
            # Check response was successful
            if response.status_code != 204:
                error_msg = f"Error in assign_issue: {response.status_code}"
                if self.debug_mode:
                    error_msg += f", {response.text}"
                print(error_msg)
                return
            # Print confirmation
            print(f"Successfully assigned issue {issue_id} to account #{account_id}")
        except Exception as ex:  # pylint: disable=broad-exception-caught
            error_msg = f"Error in assign_issue - failed to assign issue #{issue_id}"
            if self.debug_mode:
                error_msg += f": {ex}"
            print(error_msg)
