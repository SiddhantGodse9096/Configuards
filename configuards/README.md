# Configuards - Cloud Security Monitoring and Auto-Remediation System

An automated cloud security monitoring system that detects and safely fixes misconfigurations in AWS environments.

## What is Configuards?

Configuards is a Cloud Security Monitoring and Auto-Remediation System that:
- **Detects** security problems in AWS cloud resources
- **Shows** them to the user with risk assessment
- **Asks permission** before making any changes
- **Fixes** them safely with automated remediation

## Purpose

### 1️⃣ Detect Cloud Security Risks
Cloud environments often have mistakes like:
- Public storage buckets
- Open network ports
- Over-permissive permissions

These mistakes can lead to data leaks or cyber attacks. Configuards scans the cloud to find these mistakes automatically.

### 2️⃣ Improve Cloud Security
Instead of checking everything manually, the system:
- Scans resources automatically
- Detects insecure configurations
- Warns the user with detailed risk information

### 3️⃣ Provide Safe Auto-Fix
Configuards provides **permission-based remediation**:
1. Detects the problem
2. Explains the risk
3. Asks user permission
4. Applies the fix safely

## Features

- **User Authentication** (Signup/Login/Logout)
- **AWS Integration** (Connect with AWS Access Keys)
- **Real-time Security Scanning**
  - S3 Bucket public access detection
  - Security Group open port detection
  - EC2 unencrypted volume detection
- **Automated Remediation**
  - Fix S3 public buckets
  - Close open security group ports
- **Dashboard** with live security findings
- **Compliance Score** calculation
- **Security Reports**
- **User Profile Management**
- **Change Password**
- **Two-Factor Authentication Toggle**
- **Feedback System**

## Installation

1. **Install Python 3.8 or higher**

2. **Install dependencies:**
```bash
pip install -r requirements.txt
```

## AWS Setup

To use the scanning and remediation features:

1. **Create AWS IAM User** with programmatic access
2. **Attach policies:**
   - AmazonS3ReadOnlyAccess
   - AmazonEC2ReadOnlyAccess
   - IAMReadOnlyAccess
   - (For remediation) S3FullAccess, EC2FullAccess
3. **Get Access Keys** (Access Key ID and Secret Access Key)

## Running the Application

1. **Navigate to project directory:**
```bash
cd configuards
```

2. **Run the Flask application:**
```bash
python app.py
```

3. **Open browser:**
```
http://127.0.0.1:5000
```

## Usage

### Step 1: Sign Up & Login
- Create account with your details
- Login to access dashboard

### Step 2: Configure AWS Credentials
- Go to **Profile**
- Add your AWS Access Key and Secret Key
- Select AWS Region
- Save changes

### Step 3: Scan Resources
- Click **Scan Resources** on dashboard
- System scans your AWS environment
- Findings appear automatically

### Step 4: View Findings
- Go to **Findings** page
- See all detected security issues
- Review severity and risk details

### Step 5: Fix Issues
- Click **Fix Issue** button
- Confirm the remediation
- System applies the fix automatically

## How It Works

### Scanning Process
1. **Connect to AWS** using boto3 library
2. **Scan Resources:**
   - S3 buckets for public access
   - Security groups for open ports
   - EC2 instances for unencrypted volumes
3. **Detect Issues** and calculate risk
4. **Log Findings** in the dashboard

### Remediation Process
1. **User clicks Fix Issue**
2. **System asks for confirmation**
3. **Applies fix via AWS API:**
   - S3: Enable public access block
   - Security Groups: Remove 0.0.0.0/0 rules
4. **Confirms success** and refreshes findings

## Technologies Used

- **Backend**: Flask (Python)
- **AWS SDK**: Boto3
- **Frontend**: HTML, CSS, JavaScript
- **Storage**: JSON files (demo)

## Simple Definition

**Configuards is an automated cloud security monitoring system that detects and safely fixes misconfigurations in AWS environments.**
