#!/usr/bin/env python3

import argparse
import csv
import os
import re
import sys
import time
from urllib.parse import quote_plus

import boto3
import requests


def main():
    args = get_args()

    repo_slug = quote_plus("open-cluster-management/governance-policy-framework")
    repo_url = f"https://api.travis-ci.com/repo/{repo_slug}"
    ids = get_new_build_ids(
        repo_url,
        args.travis_token,
        args.last_build,
        args.max_new_builds,
        batch_size=args.get_builds_batch_size,
        delay=args.request_delay,
        initial_offset=args.initial_offset,
        timeout=args.request_timeout,
    )

    if args.latest_build_out_file:
        with open(args.latest_build_out_file, "w") as file:
            file.write(str(ids[0]))

    if args.out_file:
        output_name = args.out_file
    else:
        output_name = f"{ids[-1]}_to_{ids[0]}.csv"

    with open(output_name, "w") as csvfile:
        if args.include_headers:
            writer = csv.DictWriter(csvfile, fieldnames=CSV_FIELD_NAMES, dialect="unix")
            writer.writeheader()

        for id in ids:
            print(f"Getting results for build id={id}")
            BuildInfo(args.travis_token, id).write_results(csvfile)
            time.sleep(args.request_delay)  # Reduce changes of Travis rate-limiting

    if args.local_only:
        return

    client = boto3.client(
        "s3",
        endpoint_url=args.s3_endpoint,
        aws_access_key_id=args.s3_access_key,
        aws_secret_access_key=args.s3_secret_key,
        verify=(not args.skip_s3_verify),
    )
    key = f"{args.s3_key_path}/{output_name}"

    with open(output_name, "rb") as data:
        print(client.put_object(Bucket=args.s3_bucket, Key=key, Body=data))


def get_args():
    parser = argparse.ArgumentParser(
        description=(
            "Scrape Travis for new framework governance-policy-framework test runs, "
            "analyze them, and upload the details to s3."
        )
    )
    parser.add_argument(
        "--travis-token",
        default=os.environ.get("TRAVIS_TOKEN", ""),
        help="Token from Travis for accessing builds and logs",
    )
    parser.add_argument(
        "--s3-access-key",
        default=os.environ.get("S3_ACCESS_KEY", ""),
        help="S3 Access Key, also known as the key id",
    )
    parser.add_argument(
        "--s3-secret-key",
        default=os.environ.get("S3_SECRET_KEY", ""),
        help="S3 Secret Key, also known as the secret access key",
    )
    parser.add_argument(
        "--s3-endpoint",
        required=True,
        help="URL of the s3 instance to connect to",
    )
    parser.add_argument(
        "--s3-bucket",
        required=True,
        help="name of the bucket to put files in - not an s3://... path",
    )
    parser.add_argument(
        "--s3-key-path",
        required=True,
        help="base 'directory' in the bucket to store the results in",
    )
    parser.add_argument(
        "--last-build",
        required=True,
        type=int,
        help="Travis build id (not repo-specific) of the last known build",
    )
    parser.add_argument(
        "--out-file",
        help=(
            "Name of the results file both locally and on s3. If not provided, "
            "a name will be generated based on the builds analyzed"
        ),
    )
    parser.add_argument(
        "--latest-build-out-file",
        help="File to write the id of the newest analyzed build",
    )
    parser.add_argument(
        "--max-new-builds",
        type=int,
        default=250,
        help=(
            "A limit (not strictly enforced) for the number of builds to analyze "
            "if the last known build is not found"
        ),
    )
    parser.add_argument(
        "--get-builds-batch-size",
        type=int,
        default=20,
        help=(
            "The number of builds ids to fetch from Travis when paginating "
            "through to find builds to analyze"
        ),
    )
    parser.add_argument(
        "--initial-offset",
        default=0,
        help=(
            "Start from this offset when paginating through to find new builds "
            "to analyze; useful if getting old builds"
        ),
    )
    parser.add_argument(
        "--request-delay",
        type=float,
        default=1.0,
        help="A delay between requests to travis, in case it might rate-limit the script",
    )
    parser.add_argument(
        "--request-timeout",
        type=float,
        default=16.0,
        help="The request timeout for requests to Travis",
    )
    parser.add_argument(
        "--local-only",
        action="store_true",
        help="If enabled, no data will be sent to s3",
    )
    parser.add_argument(
        "--include-headers",
        action="store_true",
        help="If enabled, the csv headers will be prepended to the output file",
    )
    parser.add_argument(
        "--skip-s3-verify",
        action="store_true",
        help="If enabled, the connection to S3 will not be verified",
    )
    args = parser.parse_args()

    if not args.travis_token:
        sys.exit("Argument --travis-key or environment variable TRAVIS_KEY must be set")
    if not args.local_only:
        if not args.s3_access_key:
            sys.exit(
                "Argument --s3-access-key or environment variable S3_ACCESS_KEY must be set"
            )
        if not args.s3_secret_key:
            sys.exit(
                "Argument --s3-secret-key or environment variable S3_SECRET_KEY must be set"
            )

    return args


def get_new_build_ids(
    repo_url,
    token,
    last_known_id,
    max,
    batch_size=25,
    delay=1.0,
    initial_offset=0,
    timeout=16.0,
):
    ids = []
    offset = initial_offset

    headers = {"Travis-API-Version": "3", "Authorization": f"token {token}"}

    last_not_found_yet = True
    while last_not_found_yet and (len(ids) < max):
        print(f"Getting build ids, offset={offset}")
        payload = {"limit": batch_size, "offset": offset}
        r = requests.get(
            repo_url + "/builds", params=payload, headers=headers, timeout=timeout
        )

        builds = r.json()["builds"]

        if not builds:
            break

        for build in builds:
            id = build["id"]
            # Note: Travis returns builds in descending order, like 10, 9, 8, 7 ...
            if id == last_known_id:
                last_not_found_yet = False
                break
            if build["event_type"] != "pull_request":
                # The framework tests don't run on pull requests
                ids.append(id)
        else:
            offset += batch_size
            time.sleep(delay)

    if len(ids) >= max:
        print(
            f"WARNING: reached max allowed new builds ({max}) before finding build {last_known_id}"
        )

    return ids


CSV_FIELD_NAMES = [
    "id",
    "number",
    "started_at",
    "finished_at",
    "duration",
    "state",
    "source",
    "commit_sha",
    "repo_name",
    "failing_job",
    "domain",
    "cause",
    "cause_details",
]


class BuildInfo:
    def __init__(self, token, build_id):
        headers = {"Travis-API-Version": "3", "Authorization": f"token {token}"}
        payload = {"include": "job.state"}
        r = requests.get(
            f"https://api.travis-ci.com/build/{build_id}",
            params=payload,
            headers=headers,
        )
        build = r.json()

        self.id = build["id"]
        self.number = build["number"]
        self.started_at = build["started_at"]
        self.finished_at = build["finished_at"]
        self.duration = build["duration"]
        self.state = build["state"]

        self.commit_sha = build["commit"]["sha"]
        self.repo_name = build["repository"]["name"]

        self.failing_jobs = []
        for i, job in enumerate(build["jobs"]):
            if job["state"] == "failed":
                self.failing_jobs.append(
                    JobFail(
                        token=token,
                        job_id=job["id"],
                        name=get_job_name(
                            self.repo_name, i + 1
                        ),  # travis numbering is from 1
                    )
                )

    def write_results(self, csvfile):
        writer = csv.DictWriter(csvfile, fieldnames=CSV_FIELD_NAMES, dialect="unix")
        res = {
            "id": self.id,
            "number": self.number,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration": self.duration,
            "state": self.state,
            "source": "Traivs",
            "commit_sha": self.commit_sha,
            "repo_name": self.repo_name,
            "domain": "Pass",
        }

        if len(self.failing_jobs) == 0:
            writer.writerow(res)

        for j in self.failing_jobs:
            res["failing_job"] = j.name
            res["domain"] = j.domain
            res["cause"] = j.cause
            res["cause_details"] = j.details
            writer.writerow(res)


def get_job_name(repo_name, job_number):
    if repo_name != "governance-policy-framework":
        print(
            f"WARNING: unknown repository name: {repo_name}, couldn't lookup job name"
        )
        return f"unknown-{job_number}"

    job_names = {
        1: "Patch cluster to latest",
        2: "Clean up cluster",
        3: "Governance framework UI e2e tests -- basic",
        4: "Governance framework UI e2e tests -- extended",
        5: "Governance framework e2e tests",
        6: "Governance framework e2e tests with deployOnHub=true",
        7: "Test grc-framework",
        8: "Fast forwarding GRC repos",
    }

    if job_number in job_names:
        return job_names[job_number]
    print(f"WARNING: could not find the name of job number {job_number}")
    return f"unknown-{job_number}"


class BasicPattern:
    def __init__(self, domain, pattern, cause=""):
        self.domain = domain.strip()
        self.pattern = pattern.strip()
        # returns the entire line where the pattern occurs for extra details
        self.regex = re.compile(f".*{pattern}.*", re.M)
        if cause:
            self.cause = cause
        else:
            self.cause = pattern

    def match(self, text):
        return self.regex.search(text)

    def get_cause(self, match):
        return self.domain, self.pattern, match.group().strip()


# Example:
# Uploading screenshot /opt/app-root/src/grc-ui/test-output/cypress/screenshots/Namespace_governance.spec.js/@extended @bvt RHACM4K-1725 - GRC UI [P1][Sev1][console] Namespace policy governance -- Check that policy test-namespace-policy-1639109426 is present in the policy listing (failed).png # noqa
# group 1: RHACM4K-1725
# group 2: GRC UI [P1][Sev1][console] Namespace policy governance
# group 3: Check that policy test-namespace-policy-1639109426 is present in the policy listing (failed) # noqa
CYPRESS_SCREENSHOT_REGEX = (
    r"Uploading screenshot.*\/(?:@\S+\s)*(.*) - (.*) -- (.*)\.png"
)


class CypressElementDetached(BasicPattern):
    def __init__(self, domain, cause):
        detached_regex = "CypressError:.*element is detached from the DOM"
        # Matches the specifc detached error, and also the screenshot log for extra details.
        pattern = f"(?:{detached_regex})|(?:{CYPRESS_SCREENSHOT_REGEX})"

        super().__init__(domain, pattern, cause=cause)

    def match(self, text):
        matches = []
        for m in self.regex.finditer(text):
            matches.append(m)
        if len(matches) < 2:
            # No matches, or just the screenshot match (from any cypress error)
            return None

        # return just the screenshot match, since that will have better details.
        return matches[-1]

    def get_cause(self, match):
        details = f"{match.group(1).strip()} - {match.group(2).strip()} : {match.group(3).strip()}"
        return self.domain, self.cause, details


class CypressUncaughtError(BasicPattern):
    def __init__(self, domain, cause):
        pattern = (
            r"Uploading screenshot .*/(.*)/An uncaught error was "
            r"detected outside of a test \(failed\).png"
        )
        super().__init__(domain, pattern, cause=cause)

    def get_cause(self, match):
        details = match.group(1).strip()
        return self.domain, self.cause, details


class CypressFromScreenshotAutogenerate(BasicPattern):
    def __init__(self, domain):
        super().__init__(domain, CYPRESS_SCREENSHOT_REGEX)

    def get_cause(self, match):
        cause = f"{match.group(1).strip()} - {match.group(2)}".strip()
        details = match.group(3).strip()
        return self.domain, cause, details


class GinkgoFailAutogenerate(BasicPattern):
    def __init__(self, domain):
        super().__init__(domain, "")

        # Example:
        # [Fail]  RHACM4K-1274/RHACM4K-1282 GRC: [P1][Sev1][policy-grc] Test community/policy-gatekeeper-sample [It] Creating an invalid ns should generate a violation message # noqa
        # group 1: RHACM4K-1274/RHACM4K-1282
        # group 2: GRC: [P1][Sev1][policy-grc] Test community/policy-gatekeeper-sample
        # group 3: Creating an invalid ns should generate a violation message
        self.regex = re.compile(r"^\[Fail\]\s*(\S*)\s*(.*)\s\[It\]\s(.*)", re.M)

    def get_cause(self, match):
        cause = f"{match.group(1).strip()} {match.group(2)}".strip()
        details = match.group(3).strip()
        return self.domain, cause, details


class MakeTargetFailAutogenerate(BasicPattern):
    def __init__(self, domain):
        super().__init__(domain, "")

        # Example:
        # Makefile:154: recipe for target 'kind-deploy-olm' failed
        # group 1: kind-deploy-olm
        self.regex = re.compile(
            "Makefile.*recipe for target '((?!component/test/e2e).*)' failed", re.M
        )

    def get_cause(self, match):
        cause = match.group(1).strip()
        details = match.group().strip()  # The whole line
        return self.domain, cause, details


PATTERNS = [
    BasicPattern("External failure", "503 Service Unavailable"),
    BasicPattern("External failure", "502: Bad Gateway"),
    BasicPattern(
        "External failure",
        r"gnutls_handshake\(\) failed",
        "curl error: gnutls_handshake() failed",
    ),
    BasicPattern(
        "External failure",
        "No rule to make target 'component/test/e2e'",
        "Build-Harness uninitialized",
    ),
    BasicPattern(
        "External failure",
        "Error response from daemon: toomanyrequests",
        "Docker pull rate-limiting",
    ),
    BasicPattern("Go build fail", "module requires Go 1.16"),
    BasicPattern("Go build fail", "go: inconsistent vendoring"),
    BasicPattern(
        "UI flakiness",
        "Cypress failed to make a connection to the Chrome DevTools Protocol",
    ),
    CypressElementDetached("UI flakiness", "Cypress: element is detached from the DOM"),
    CypressUncaughtError("UI test fail", "Cypress: Uncaught error"),
    CypressFromScreenshotAutogenerate("UI test fail"),
    GinkgoFailAutogenerate("Go test fail"),
    MakeTargetFailAutogenerate("Make target fail"),
]


class JobFail:
    def __init__(self, token, job_id, name):
        self.id = job_id
        self.name = name

        headers = {"Travis-API-Version": "3", "Authorization": f"token {token}"}
        r = requests.get(
            f"https://api.travis-ci.com/job/{job_id}/log.txt", headers=headers
        )
        text = re.sub(r"\x1b[^m]*m", "", r.text)  # remove ANSI escapes

        for pattern in PATTERNS:
            match = pattern.match(text)
            if match is not None:
                self.domain, self.cause, self.details = pattern.get_cause(match)
                return

        self.domain = "Unknown failure"
        self.cause = "Unknown"
        self.details = "Unknown"


if __name__ == "__main__":
    main()
