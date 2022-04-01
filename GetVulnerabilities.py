#!/usr/bin/env python3

import argparse
import os
import requests
import json
import logging
import http.client

from requests import HTTPError

parser = argparse.ArgumentParser()
parser.add_argument("--query", type=str, help="File with a graphql query", required=False)
parser.add_argument("--token", type=str, help="Auth token", required=True)
parser.add_argument("--cve", type=str, help="CVE to find", required=True)
parser.add_argument("--debug", action="store_true", help="Increase debug")
parser.add_argument("--cache", type=str, help="cache file")
args = parser.parse_args()

if args.debug:
    logging.basicConfig()
    logging.getLogger().setLevel(logging.DEBUG)
    requests_log = logging.getLogger("requests.packages.urllib3")
    requests_log.setLevel(logging.DEBUG)
    requests_log.propagate = True
    http.client.HTTPConnection.debuglevel = 1

url = 'https://api.github.com/graphql'
token = args.token
headers = {"Authorization": f"bearer {token}"}
cve = args.cve

variables = { 'login': 'Flutter-Global', 'number_of_repos': 100, 'number_of_vulns': 100, 'org_or_user': 'organization' }

vuln_query = """query($login:String!, $number_of_repos:Int!, $number_of_vulns:Int!, $next_cursor:String) {
  organization(login: $login) {
    repositories(first: $number_of_repos, after: $next_cursor) {  # for users, we could also use repositoriesContributedTo
      totalCount
      pageInfo {
        hasNextPage
        hasPreviousPage
        startCursor
        endCursor
      }
      nodes {
        name
        isArchived
        vulnerabilityAlerts(first: $number_of_vulns) {
          totalCount
          pageInfo {
            hasNextPage
            hasPreviousPage
            startCursor
            endCursor
          }
          nodes {
            createdAt
            vulnerableRequirements
            dismissedAt
            dismissReason
            securityVulnerability {
              advisory {
                description
                identifiers {
                  value
                }
              }
              severity
              package {
                ecosystem
                name
              }
              updatedAt
              vulnerableVersionRange

            }
          }
        }
      }
    }
  }
}"""

basic_query = """
{
  viewer {
    login
  }
  rateLimit {
    limit
    cost
    remaining
    resetAt
  }
}
"""

query = vuln_query

def post_query(query):
    if args.cache and os.path.exists(args.cache):
        f = open(args.cache)
        cache = json.load(f)
        for data in cache:
            check_vulns(data)
        f.close()
        return cache

    response = requests.post(url, json={'query': query, 'variables': variables}, headers=headers)

    try:
        response.raise_for_status()
    except HTTPError:
        print(
            f'Status: {response.status_code} Headers: {response.headers} Error Response: '
            f'{json.dumps(response.json(), indent=4, sort_keys=True)}')
        raise

    dataCollection = list()
    data = response.json()
    if args.debug:
        print(f'{data}')
    dataCollection.append(data)
    check_vulns(data)
    
    while data['data']['organization']['repositories']['pageInfo']['hasNextPage']:
        variables['next_cursor'] = data['data']['organization']['repositories']['pageInfo']['endCursor']

        response = requests.post(url, json={'query': query, 'variables': variables}, headers=headers)

        try:
            response.raise_for_status()
        except HTTPError:
            print(
                f'Status: {response.status_code} Headers: {response.headers} Error Response: '
                f'{json.dumps(response.json(), indent=4, sort_keys=True)}')
            raise

        data = response.json()
        check_vulns(data)
        dataCollection.append(data)


    if args.cache:
        fw = open(args.cache, "w")
        json.dump(dataCollection, fw)
        fw.close()
        print (f"Populated cache {args.cache}")
    else:
        return response.json()


def main():
    post_query(query)

def check_vulns(json_response: dict):
    for repo_node in json_response['data']['organization']['repositories']['nodes']:
        if "vulnerabilityAlerts" in repo_node and repo_node['vulnerabilityAlerts']['totalCount'] > 0:
            #print (f'{repo_node["name"]} has {repo_node["vulnerabilityAlerts"]["totalCount"]} vulnerabilities')
            for vuln_node in repo_node["vulnerabilityAlerts"]["nodes"]:
                for identifier in vuln_node["securityVulnerability"]["advisory"]["identifiers"]:
                    if cve in identifier.values():
                        print (f'{repo_node["name"]}|{cve}')
        #else:
            #print (f'Repo: {repo_node["name"]} has no vulnerabilities')


if __name__ == '__main__':
    # execute only if run as the entry point into the program
    main()
