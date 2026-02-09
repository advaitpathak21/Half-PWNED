# Half-PWNED

## Cloud Resume Challenge: AWS Edition
- This project is a cloud-native, serverless website deployed on AWS. The goal was to design, deploy, and secure a high-availability infrastructure using AWS best practices.
- This is an extension to the original Cloud Resume Challenge [Here](https://github.com/advaitpathak21/cloud-resume) as I have deployed another app in the same infrastructure.

![Cloud Resume Challenge Architecture](/Half-PWNED/docs/attachments/assets/CRC_v3.jpg)

## Infrastructure Implementation
The infrastructure was built manually using a security-first approach to ensure high availability and data integrity.

#### 1. Storage & Origin (S3)
- Static Hosting: Configured S3 buckets to host the resume frontend and static assets (images/scripts).

- CORS Policy: Implemented strict Cross-Origin Resource Sharing (CORS) to allow the website to securely fetch assets across subdomains.

- Bucket Security: Disabled direct public access, ensuring the bucket is only accessible via the CloudFront CDN.

#### 2. Global Distribution (CloudFront & ACM)
- Content Delivery: Created a CloudFront distribution to serve content from Edge locations, reducing latency.

- SSL/TLS: Provisioned a public certificate via ACM (N. Virginia region) to enable end-to-end HTTPS encryption.

- Protocol Enforcement: Set "Viewer Protocol Policy" to Redirect HTTP to HTTPS to ensure secure connections.

#### 3. DNS & Security Mods (Route 53 & KMS)
- Domain Mapping: Created Alias (A) Records in Route 53 to map custom subdomains to the CloudFront endpoint.

- DNSSEC: Enabled DNS Security Extensions to prevent DNS spoofing and cache poisoning.

- KMS Integration: Generated an Asymmetric KMS Key to sign DNS records, establishing a cryptographic chain of trust for the domain.

#### 4. Serverless Backend (API & Lambda)
- DynamoDB: Created a NoSQL table to store and persist the visitor count as a single atomic item.

- API Gateway: Deployed a REST/HTTP API to expose a public endpoint. This allows the frontend JavaScript to securely trigger the Lambda function without giving users direct access to the database.

- AWS Lambda: Wrote a Python (Boto3) function that serves as the "middleman." It triggers on every site visit to retrieve, increment, and return the latest visitor count from DynamoDB.

- API Management: Configured API Gateway to exclusively allow requests from my resume's subdomains, preventing unauthorized external API calls.

### Security Mods added:
#### 1. DNSSEC with AWS KMS:
- To prevent DNS spoofing and "Man-in-the-Middle" attacks, enabled DNSSEC on Route 53.

#### 2. S3 Origin Access Control (OAC)
- Disabled direct public access to my S3 buckets (Block Public Access).

#### 3. HTTPS Enforcement
- Used AWS Certificate Manager (ACM) for custom domain.
- Configured CloudFront to automatically Redirect HTTP to HTTPS

#### 4. CORS & Least Privilege (IAM)
- Implemented a strict Cross-Origin Resource Sharing (CORS) policy on my assets bucket to ensure only my resume domain can fetch resources like images and scripts.
- IAM Least Privilege: Followed the principle of least privilege for the IAM users used in deployment

#### To-do:
- Add Terraform IaC