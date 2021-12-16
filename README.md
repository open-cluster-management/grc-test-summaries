# grc-test-summaries

[![Docker Repository on Quay](https://quay.io/repository/justinkuli/grc-test-summaries/status "Docker Repository on Quay")](https://quay.io/repository/justinkuli/grc-test-summaries)

Script/image to scrape ACM-GRC test results from Travis, analyze them, and send the results to S3 for data visualization.

Image URL: `quay.io/justinkuli/grc-test-summaries:main` 

## Deployment

The script is designed to be used via the associated Tekton Tasks and Pipeline. Additional resources required on the namespace running the pipeline:

1. A secret containing the Travis credentials (as `TRAVIS_TOKEN`) and S3 credentials (as `S3_ACCESS_KEY` and `S3_SECRET_KEY`).
2. A configmap to store the last known build ID.

The names of each of these resources can be configured using the pipeline parameters.

Additionally, the `cronjob.yaml` file is a template for a cronjob that can be filled in with the parameters for the pipelinerun. If this cronjob is used, a service account with permission to create PipelineRuns is required - in an OpenShift cluster, the `pipeline` service account can be used as shown.

## Development

Additional data fields can be added to the `CSV_FIELD_NAMES`, they should be added to the `BuildInfo` class, and initialized in its `__init__` method. Be sure to add it to the `res` in `BuildInfo.write_results` as well.

If the data fields in the CSV are changed, the table schema for pulling the data from S3 will need to be updated. Try to do this sparingly.

Additional patterns for labelling failures can be implemented either as a new Class implementing `match` and `get_cause` from `BasicPattern`, or just by creating a new `BasicPattern` if the regex is somewhat simple. In either case, remember to add the pattern to the `PATTERNS` global so it can be used.

New patterns should be picked up when the next scheduled run occurs, but will not be applied to older builds. Manual intervention would be required to do that.

### Failure categorization implementation

The patterns in `PATTERNS` are run through in the order of the list. The first one to not return `None` when passed the failing job log text to its `match` method is considered the reason for the failure. So far, the patterns all use regular expressions.

Some of the patterns use capturing groups during the initial `match` in order to get more information to categorize the failure. For example, the `GinkgoFailAutogenerate` uses groups to identify the test suite, specific test, and specific part of the test that is failing.

The `domain` of the failure is something broad: for example, "External Failure" or "Go test failure".

The `cause` of the failure is a more specific reason for the failure. Ideally, this reason is not absolutely specific to just one instance of the failure. For a failing Go test, this might be the test name, but not the specific assertion that failed.

The `cause_details` is for the most specific details about the failure. For a failing Go test, this would be the specific assertion that failed.
