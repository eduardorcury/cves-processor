import json
import boto3
import pandas as pd
from botocore.exceptions import NoCredentialsError, PartialCredentialsError


def lambda_handler(event, context):

    s3 = boto3.client('s3')
    dfs = []

    for record in event['Records']:
        key = record['s3']['object']['key']
        bucket = record['s3']['bucket']['name']

        print(f"Processing file {key} in bucket {bucket}")

        try:
            s3_object = s3.get_object(Bucket=bucket, Key=key)
            df = process_file(json.load(s3_object["Body"]))
            dfs.append(df)
        except NoCredentialsError:
            print("Error: AWS credentials not found.")
        except PartialCredentialsError:
            print("Error: Incomplete AWS credentials provided.")
        except Exception as e:
            print(f"Error processing file {key} from S3: {e}")

    result = pd.concat(dfs)
    print(result.head())

    return {
        "statusCode": 200,
        "body": json.dumps({
            "message": "ok"
        }),
    }

def extract_problem_data(problems):
    ids = []
    descriptions = []
    for problem in problems:
        for description in problem["descriptions"]:
            if "cweId" in problem["descriptions"][0]:
                ids.append(description["cweId"])
            else:
                ids.append("-")
            descriptions.append(description["description"])
    return ids, descriptions

def process_file(data):

    cve_df = pd.json_normalize(data)

    df = pd.DataFrame(columns=["cve_id", "state", "assigner", "affected", "description", "cvss_score", "cvss_severity",
                               "cwe_id", "cwe_description"])

    df["cve_id"] = cve_df["cveMetadata.cveId"]
    df["state"] = cve_df["cveMetadata.state"]
    df["assigner"] = cve_df["cveMetadata.assignerShortName"]
    df["affected"] = cve_df["containers.cna.affected"]
    df["description"] = cve_df["containers.cna.descriptions"][0][0]["value"]

    if "containers.cna.metrics" in cve_df.columns:
        df["cvss_score"] = cve_df["containers.cna.metrics"][0][0]["cvssV3_1"]["baseScore"]
        df["cvss_severity"] = cve_df["containers.cna.metrics"][0][0]["cvssV3_1"]["baseSeverity"]

    df["cwe_id"] = extract_problem_data(cve_df["containers.cna.problemTypes"][0])[0]
    df["cwe_description"] = extract_problem_data(cve_df["containers.cna.problemTypes"][0])[1]
    return df