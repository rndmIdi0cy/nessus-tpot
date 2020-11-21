#!/usr/bin/env python3
# -*- coding: utf-8 -*-

####################################################################
# Requirements:
#   pip3 install requests prettytable
#
# About:
#   This python script will compare the selected policy to current
#   FOUND vulnerabilities based on the number of days selected. It
#   will then disable the plugins that have not been found in X
#   number of days.
#
# Help:
#   usage: tpot.py [-h] [-p PID] [-l] [-o OUTPUT] [-w] [-d DAYS]
#
#    optional arguments:
#     -h, --help  show this help message and exit
#     -p PID      Scan policy id
#     -l          List available policies
#     -o OUTPUT   Disabled plugin csv file location (Default: /Users/[username]/disabled_plugins_1584626350.csv)
#     -w          Run but do not commit changes
#     -d DAYS     Number of days to search plugins against (Default: 30)
#
# Examples:
#   Get available policies
#   ./tpot.py -l
#
#   Disable plugins checking back 7 days
#   ./tpot.py -p 13 -d 7
#
#   Check for vulnerabilities that would be disabled going back 7; but do not disable
#   ./tpot.py -p 13 -d 7 -w


import argparse
import sys
import os
import json
import requests
import time

# import logging
from prettytable import PrettyTable


#####################################################################
# Tenable.IO API Configuration
BASE_URL = "https://cloud.tenable.com"
ACCESS_KEY = "_PUT_YOUR_ACCESS_KEY_HERE_"
SECRET_KEY = "_PUT_YOUR_SECRET_KEY_HERE_"
#####################################################################

#####################################################################
# Requests headers
HEADERS = {
    "accept": "application/json",
    "X-ApiKeys": "accessKey={}; secretKey={}".format(ACCESS_KEY, SECRET_KEY),
    "User-Agent": "TIOApi/1.0 Python/{0:d}.{1:d}.{2:d}".format(
        sys.version_info[0], sys.version_info[1], sys.version_info[2]
    ),
}
#####################################################################


def print_success(msg):
    if os.name == "nt":
        print("[+] {}".format(msg))
    else:
        print("\033[1;32m[+] \033[1;m{}".format(msg))


def print_status(msg):
    if os.name == "nt":
        print("[*] {}".format(msg))
    else:
        print("\033[1;34m[*] \033[1;m{}".format(msg))


def print_failure(msg):
    if os.name == "nt":
        print("[-] {}".format(msg))
    else:
        print("\033[1;31m[-] \033[1;m{}".format(msg))


def print_error(msg):
    if os.name == "nt":
        print("[!] {}".format(msg))
    else:
        print("\033[1;33m[!] \033[1;m{}".format(msg))


def get_home_directory():
    return os.path.expanduser("~")


def generate_filename():
    current_time = int(time.time())
    return os.path.join(
        get_home_directory(), "disabled_plugins_{0}.csv".format(current_time)
    )


def get_policy_details(url):
    # Returns the details for the specified policy
    try:
        response = requests.get(url, headers=HEADERS)

        if response.status_code != 200:
            print_error("Error: {}".format(response.json()["error"]))
            sys.exit(1)

        return response.json()
    except Exception as e:
        print_error("Failed to get policy details : {}".format(str(e)))
        sys.exit(1)


def get_enabled_plugins(plugins):
    # Returns only enabled plugins
    enabled_plugins = {}
    for plugin_family in plugins:
        plugin_family_status = plugins[plugin_family]["status"]

        if not plugin_family_status == "disabled":
            if "individual" in plugins[plugin_family]:
                for p, p_status in plugins[plugin_family]["individual"].items():
                    enabled_plugins[p] = plugin_family

    return enabled_plugins


def get_plugin_details(plugin_id):
    # Gets plugin details and returns the name and family
    try:
        response = requests.get(
            "https://www.tenable.com/plugins/api/v1/nessus/{}".format(plugin_id),
            headers=HEADERS,
        )

        if response.status_code != 200:
            print_error("{}".format(response.json()["error"]))
            sys.exit(1)

        resp = response.json()["data"]["_source"]

        if resp["risk_factor_score"] > 1:
            details = {
                "name": resp["script_name"],
                "family": resp["script_family"],
                "publication_date": resp["plugin_publication_date"],
            }
        else:
            details = {"name": ""}

        return details
    except Exception as e:
        print_error("Failed to get plugin details : {}".format(str(e)))
        sys.exit(1)


def get_vulnerabilities(days):
    # Return found vulnerabilities via the workbench
    try:
        querystring = {"date_range": days}

        response = requests.get(
            "{0}/workbenches/vulnerabilities".format(BASE_URL),
            headers=HEADERS,
            params=querystring,
        )

        if response.status_code != 200:
            print_error("{}".format(response.json()["error"]))
            sys.exit(1)

        return response.json()
    except Exception as e:
        print_error(
            "Failed to get vulnerabilities from the workbench : {}".format(str(e))
        )
        sys.exit(1)


def get_policies():
    # List available policies based on applicable permissions
    try:
        response = requests.get("{0}/policies".format(BASE_URL), headers=HEADERS)

        if response.status_code != 200:
            print_error("{}".format(response.json()["error"]))
            sys.exit(1)

        policies = response.json()["policies"]

        policy_table = PrettyTable(["Policy Name", "ID"])
        policy_table.align["Policy Name"] = "l"

        for policy in policies:
            policy_table.add_row([policy["name"], policy["id"]])

        print(policy_table)
    except Exception as e:
        print_error("Failed to list policies : {}".format(str(e)))


def get_policy_config_details(policy_id):
    # Get policy configuration details from editor
    # needed to get total family counts
    try:
        response = requests.get(
            "{0}/editor/policy/{1}".format(BASE_URL, policy_id), headers=HEADERS
        )

        if response.status_code != 200:
            print_error("{}".format(response.json()["error"]))
            sys.exit(1)

        return response.json()["plugins"]["families"]
    except Exception as e:
        print_error("Failed to get policy configuration : {}".format(str(e)))


def update_policy(policy_id, policy_data):
    # Save updated plugin status
    try:
        response = requests.put(
            "{0}/policies/{1}".format(BASE_URL, policy_id),
            headers=HEADERS,
            data=json.dumps(policy_data),
        )

        if response.status_code != 200:
            print_error("{}".format(response.json()["error"]))
            sys.exit()
        else:
            print_success("Successfully updated policy")
    except Exception as e:
        print_error("Failed to update the policy : {}".format(str(e)))


########
# MAIN #
########
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", dest="pid", help="Scan policy id", type=int)
    parser.add_argument(
        "-l", dest="plist", action="store_true", help="List available policies"
    )
    parser.add_argument(
        "-o",
        dest="output",
        help="Disabled plugin csv file location (Default: {})".format(
            os.path.join(get_home_directory(), generate_filename())
        ),
        type=str,
        default=os.path.join(get_home_directory(), generate_filename()),
    )
    parser.add_argument(
        "-w",
        dest="whatif",
        action="store_true",
        help="Run but do not commit changes",
        default=False,
    )
    parser.add_argument(
        "-d",
        dest="days",
        help="Number of days to search plugins against (Default: 30)",
        type=int,
        default="30",
    )
    args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        exit()

    if (ACCESS_KEY == "_PUT_YOUR_ACCESS_KEY_HERE_") or (
        SECRET_KEY == "_PUT_YOUR_SECRET_KEY_HERE_"
    ):
        print_error(
            "Please get your API key from Tenable.IO and replace ACCESS_KEY and SECRET_KEY"
        )
        exit(1)

    if args.plist:
        get_policies()
        exit(0)

    if not args.pid:
        print_error("Missing policy id; use -l/--list to show available policies")
        sys.exit(1)

    if args.whatif:
        print("\n////////////////////////////////////////////")
        print("[!!!]   RUNNING IN WHAT-IF MODE        [!!!]")
        print("[!!!]   CHANGES WILL NOT BE COMMITED   [!!!]")
        print("////////////////////////////////////////////\n")

    print_success("Retrieving scan policy details")
    policy_data = get_policy_details("{0}/policies/{1}".format(BASE_URL, int(args.pid)))

    print_success("Retrieving policy configuration")
    policy_config = get_policy_config_details(int(args.pid))

    print_success("Getting enabled plugins from policy")
    policy_plugins = get_enabled_plugins(policy_data["plugins"])

    if len(policy_plugins) < 1:
        print_error("No enabled plugins found")
        sys.exit(1)

    print_success(
        "Retrieving FOUND vulnerabilities for the past {0} days (workbench)".format(
            args.days
        )
    )
    vulns = get_vulnerabilities(args.days)

    if vulns["total_vulnerability_count"] > 0:
        print_status(
            "Total Unique Vulnerabilities: {}".format(len(vulns["vulnerabilities"]))
        )
        print_status(
            "Total Vulnerabilities: {}".format(vulns["total_vulnerability_count"])
        )

        found_plugins = {}
        for vuln in vulns["vulnerabilities"]:
            found_plugins[vuln["plugin_id"]] = vuln["plugin_name"]

        print_status(
            "Total unique plugins enabled for policy: {}".format(len(found_plugins))
        )
        print_status("Total plugins enabled for policy: {}".format(len(policy_plugins)))

        family_disable_count = 0
        total_disable_count = 0
        process_count = 0
        plugin_data = {}
        status_tracker = {}

        print_success("Pulling plugin details, this may take awhile")

        output_file = open(args.output, "a")
        output_file.write('"PluginID","PluginName","Family","Publication Date"\n')
        output_file.close()

        for pid, pfamily in policy_plugins.items():
            progress = round(100.0 * process_count / float(len(policy_plugins)), 1)
            sys.stdout.write(
                "[*] Processing... %s / %s (%s%s)\r"
                % (process_count, len(policy_plugins), progress, "%")
            )
            sys.stdout.flush()

            if int(pid) not in found_plugins.keys():
                details = get_plugin_details(pid)

                if details["name"]:
                    if details["family"] in plugin_data:
                        data = {pid: "disabled"}

                        plugin_data[details["family"]]["individual"].update(data)

                        family_disable_count = status_tracker[details["family"]][
                            "disabled_count"
                        ]
                        family_disable_count += 1
                        status_data = {
                            details["family"]: {"disabled_count": family_disable_count}
                        }

                        status_tracker.update(status_data)

                        if (
                            policy_config[details["family"]]["count"]
                            == family_disable_count
                        ):
                            data = {details["family"]: {"status": "disabled"}}

                            plugin_data.update(data)
                            print_status("Disabled family {}".format(details["family"]))
                    else:
                        if policy_config[details["family"]]["count"] == 1:
                            data = {details["family"]: {"status": "disabled"}}

                            plugin_data.update(data)
                            print_status("Disabled family {}".format(details["family"]))
                        else:
                            data = {
                                details["family"]: {
                                    "status": "mixed",
                                    "individual": {pid: "disabled"},
                                }
                            }
                            plugin_data.update(data)
                            status_data = {details["family"]: {"disabled_count": 1}}

                            status_tracker.update(status_data)

                    disabled_plugin = '"{0}","{1}","{2}","{3}"\n'.format(
                        pid,
                        details["name"],
                        details["family"],
                        details["publication_date"],
                    )

                    with open(args.output, "a") as f:
                        f.write(disabled_plugin)
                    f.close()

                    total_disable_count += 1

                process_count += 1

        scan_policy = {
            "uuid": policy_data["uuid"],
            "settings": policy_data["settings"],
            "plugins": {},
        }

        scan_policy["plugins"].update(plugin_data)

        if total_disable_count == 0:
            print_success("No changes to be made, exiting...")
            sys.exit()

        print_status("Number of plugins to be disabled: {}".format(total_disable_count))
        print_status(
            "CSV of plugins to be disabled has been written to: {}".format(args.output)
        )

        if not args.whatif:
            print_success("Committing changes")
            update_policy(args.pid, scan_policy)
    else:
        print_error("Seems to be no vulnerabilities yet?")

    print_success("Finished")

