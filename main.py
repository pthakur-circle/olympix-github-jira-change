"""
Ghas jira syncer

Program to sync specific GitHub code alerts with the Jira SECENG board
ALERT: PR in progress. This code creates all alerts on the SECENG board
"""

import datetime
import argparse
from gitClient import gitClient
# from ddClient import ddClient
from jiraClient import jiraClient
from secretReader import get_secrets
import json

secrets = (
    get_secrets()
)  # This is misc code, which operates locally. Will use secret manager in AWS lambda code
orgs = [
    "circlefin",
    "cybavo",
    "pthakur-circle",    # Add Olympix
]  # hard-coded organization name. These are the organizations whose GHAS alerts will be created/synced on JIRA. Extend if more organizations added/needed.


def sync_GHAS_VULN(
    git,
    jira,
    last_scanned_time=None,
    repo=None,
    severity=None,
    alertTypes=None,
    alert_urls_to_add=None,
):
    """
    Function to sync specific GitHub alerts with the Jira SECENG board
    Return:
        List of ids of alerts added to Jira board, current time at which the scan started
    """

    # Record scan start time
    current_time = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")

    if alert_urls_to_add:
        # add a specific alert by its URL
        alerts = git.add_alerts(alert_urls_to_add)
    else:
        # Get all active alerts for org (since last scan)
        alerts = git.list_active_org_alerts(
            time=last_scanned_time, repo=repo, severity=severity, alertTypes=alertTypes
        )
        # Olympix
        file_path = "alerts.json"
        with open(file_path, "w") as json_file:
            json.dump(alerts, json_file, indent = 4)

    if alerts == None or len(alerts) == 0:
        print(f"No active alerts since last scan for repo: {repo}")
        return None

    # instead of only get unreported alerts on Jira, will get all alerts from GHAS
    # duplicate check in update_issues()

    # Get additional info on new alerts
    alerts = git.update_alerts(alerts)

    # Create/update issues on preferred JIRA board & Assign dependabot issue directly to the repo owner
    issues_created = jira.update_issues(alerts) # a replacement of update_alert_issue. Contains duplicate check

    if issues_created:
        print(
            f"{len(issues_created)} alerts created for repo: {repo} on {current_time}"
        )
    else:
        print(f"No new alert created for repo: {repo}\n on {current_time}")

    return issues_created, current_time


def str2bool(v):
    """Parses the input for CLI argument: test

    Args:
        v (string): input from the CLI, can be anything

    Raises:
        argparse.ArgumentTypeError: if what is given cannot be converted to a boolean value

    Returns:
        boolean:true or false based on input
    """
    if isinstance(v, bool):
        return v
    if v.lower() in ("yes", "true", "t", "y", "1"):
        return True
    elif v.lower() in ("no", "false", "f", "n", "0"):
        return False
    else:
        raise argparse.ArgumentTypeError("Boolean value expected.")


def parseRepoName(v):
    """Parse the input for CLI argument: repo

    Args:
        v (string): input from the CLI, can be anything

    Returns:
        string: return either ["all", a repo name]
    """
    if v.lower() in ("all", "circlefin", "cybavo", "pthakur-circle"):    # Add Olympix
        return "all"
    else:
        return v


def parseOrgName(v):
    """Parse the input for CLI argument: org
        will exit program if org name is bad

    Args:string
        v (string): input from the CLI, can be anything

    Returns:
        string: will only return one of ["all", "circlefin", "cybavo"]
    """

    if v.lower() in ("all"):
        return "all"
    if v.lower() in ("circlefin"):
        return "circlefin"
    if v.lower() in ("cybavo"):
        return "cybavo"
    if v.lower() in ("pthakur-circle"):                      # Add Olympix
        return "pthakur-circle"

    exit(-1)


def initialize_Clients(args):
    """initialize GitHub, Datadog, JIRA client given the args

    Args:
        args (_type_): command line arguments provied by user

    Returns:
        client objects: GitHub client, Datadog client, JIRA client
    """
    # initialize clients
    git = gitClient(secrets["git_access_token"], args.org, debug=args.debug)
    # dd = ddClient(secrets["API_KEY"], secrets["APP_KEY"], args.org, debug=args.debug)
    jira = jiraClient(
        secrets["email"],
        secrets["jira_api_token"],
        # ddClient=dd,
        gitClient=git,
        org=args.org,
        test=args.test,
        debug=args.debug,
    )
    # return git, dd, jira
    return git, jira


def main():
    parser = argparse.ArgumentParser(
        description="Script that accepts optional keyword arguments."
    )
    parser.add_argument(
        "--repo",
        type=parseRepoName,
        help="Expecting string: the repo's name on Github. By including this arg and specifying the repo's name, will execute the code on targeted Github repo only. If enter 'all' or 'circlefin', will work on all Circlefin repos. Example: developer-web. No default value, have to be specified",
    )
    parser.add_argument(
        "--org",
        type=parseOrgName,
        help="Expecting string: the org's name on Github. By including this arg and specifying the repo's name, will execute the code on targeted Github org only. Expect 'circlefin', 'cybavo' or 'all'. No default value, have to be specified",
    )
    parser.add_argument(
        "--test",
        type=str2bool,
        default=True,
        help="Expect boolean value. Default to True. If True, will create all issues on the SEO board. If False, will create Dependabot issues on VULN, codeQL&secrect scanning on SECENG",
    )
    parser.add_argument(
        "--url",
        default=None,
        help="Expect a GHAS alert's link. Default to None. By specifying this, can add a specific GHAS",
    )
    parser.add_argument(
        "--debug",
        type=str2bool,
        default=False,
        help="Expect boolean value. Default to False. If True, will print detailed error messages.",
    )
    print("Before")
    args = parser.parse_args()
    print(args.repo)

    if args.url is not None:
        print(
            f"*** Executing code on GHAS alert url: {args.url} and test - {args.test} ***"
        )
        git, jira = initialize_Clients(args)
        sync_GHAS_VULN(git, jira, last_scanned_time=0, alert_urls_to_add=args.url)
    else:
        if args.repo != "all":
            if args.org != "all":
                # run this code on a specific repo of a specific org
                print(
                    f"*** Executing code on repo: {args.repo} and test - {args.test} ***"
                )
                git, jira = initialize_Clients(args)

                if git.verify_github_repo(args.repo):
                    sync_GHAS_VULN(git, jira, last_scanned_time=0, repo=args.repo)
                else:
                    print(f"Repo {args.org}/{args.repo} does not exist")
                    exit(-1)
            else:
                # Err: attempting to run this code on a specified repo on multiple organizations - cannot identify the exact repo
                print(
                    f"*** Err: Received command to execute on one specific repo: {args.repo} and all organizaions, please also specify the organization name, aborting ***"
                )
                exit(-1)

        else:
            if args.org == "all":
                # Run this code on all repos of all organizations, based on the 'orgs' list
                for org in orgs:
                    print(
                        f"*** Executing code on all repos under {org} and test - {args.test} ***"
                    )
                    git, jira = initialize_Clients(args)
                    repos, repoCount = git.get_github_repos(org)
                    if repoCount > 0:
                        counter = 0
                        for repo in repos:
                            if git.verify_github_repo(repo):
                                counter += 1
                                print(
                                    f"Working on repo: {counter}/{repoCount} for repo {repo}"
                                )
                                sync_GHAS_VULN(
                                    git, jira, last_scanned_time=0, repo=repo
                                )
                            else:
                                print(f"Repo {args.org}/{args.repo} does not exist")
                                exit(-1)

                    else:
                        print(f"No repo found in org: {org}")
            else:
                # Run this code on all repos of one specific organization
                print(
                    f"*** Executing code on all repos under {args.org} and test - {args.test} ***"
                )

                git, jira = initialize_Clients(args)
                repos, repoCount = git.get_github_repos(args.org)
                if repoCount > 0:
                    counter = 0
                    for repo in repos:
                        if git.verify_github_repo(repo):
                            counter += 1
                            print(
                                f"Working on repo: {counter}/{repoCount} for repo {repo}"
                            )
                            sync_GHAS_VULN(git, jira, last_scanned_time=0, repo=repo)
                        else:
                            print(f"Repo {args.org}/{args.repo} does not exist")
                            exit(-1)

                else:
                    print(f"No repo found in org: {args.org}")


if __name__ == "__main__":
    main()
