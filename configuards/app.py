from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import os
import json
from datetime import datetime
import boto3
from botocore.exceptions import ClientError, NoCredentialsError

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Load users from file
def load_users():
    try:
        with open('users.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

# Save users to file
def save_users():
    with open('users.json', 'w') as f:
        json.dump(users, f, indent=4)

users = load_users()

# AWS Security Scanner Class
class AWSSecurityScanner:
    def __init__(self, aws_access_key=None, aws_secret_key=None, region='us-east-1'):
        self.region = region
        try:
            if aws_access_key and aws_secret_key:
                self.s3 = boto3.client('s3', aws_access_key_id=aws_access_key, aws_secret_access_key=aws_secret_key, region_name=region)
                self.ec2 = boto3.client('ec2', aws_access_key_id=aws_access_key, aws_secret_access_key=aws_secret_key, region_name=region)
                self.iam = boto3.client('iam', aws_access_key_id=aws_access_key, aws_secret_access_key=aws_secret_key, region_name=region)
            else:
                self.s3 = boto3.client('s3', region_name=region)
                self.ec2 = boto3.client('ec2', region_name=region)
                self.iam = boto3.client('iam', region_name=region)
            self.connected = True
        except:
            self.connected = False
    
    def scan_s3_buckets(self):
        findings = []
        try:
            buckets = self.s3.list_buckets()['Buckets']
            for bucket in buckets:
                bucket_name = bucket['Name']
                try:
                    acl = self.s3.get_bucket_acl(Bucket=bucket_name)
                    for grant in acl['Grants']:
                        if grant['Grantee'].get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                            findings.append({
                                'id': f's3-{bucket_name}',
                                'resource': 'S3 Bucket',
                                'name': bucket_name,
                                'issue': 'Public access enabled - Bucket is accessible to everyone',
                                'severity': 'high',
                                'status': 'Open',
                                'fix_available': True,
                                'risk': 'Data leakage, unauthorized access'
                            })
                except:
                    pass
        except:
            pass
        return findings
    
    def scan_security_groups(self):
        findings = []
        try:
            sgs = self.ec2.describe_security_groups()['SecurityGroups']
            for sg in sgs:
                for rule in sg.get('IpPermissions', []):
                    for ip_range in rule.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            port = rule.get('FromPort', 'All')
                            findings.append({
                                'id': f'sg-{sg["GroupId"]}',
                                'resource': 'Security Group',
                                'name': sg['GroupName'],
                                'issue': f'Port {port} open to internet (0.0.0.0/0)',
                                'severity': 'high' if port in [22, 3389, 3306, 5432] else 'medium',
                                'status': 'Open',
                                'fix_available': True,
                                'risk': 'Unauthorized access, potential breach'
                            })
        except:
            pass
        return findings
    
    def scan_ec2_instances(self):
        findings = []
        try:
            instances = self.ec2.describe_instances()
            for reservation in instances['Reservations']:
                for instance in reservation['Instances']:
                    if instance['State']['Name'] == 'running':
                        for vol in instance.get('BlockDeviceMappings', []):
                            if not vol.get('Ebs', {}).get('Encrypted', False):
                                findings.append({
                                    'id': f'ec2-{instance["InstanceId"]}',
                                    'resource': 'EC2 Instance',
                                    'name': instance['InstanceId'],
                                    'issue': 'Unencrypted EBS volume attached',
                                    'severity': 'medium',
                                    'status': 'Open',
                                    'fix_available': False,
                                    'risk': 'Data exposure if volume is compromised'
                                })
        except:
            pass
        return findings
    
    def fix_s3_public_access(self, bucket_name):
        try:
            self.s3.put_public_access_block(
                Bucket=bucket_name,
                PublicAccessBlockConfiguration={
                    'BlockPublicAcls': True,
                    'IgnorePublicAcls': True,
                    'BlockPublicPolicy': True,
                    'RestrictPublicBuckets': True
                }
            )
            return True, 'Public access blocked successfully'
        except Exception as e:
            return False, str(e)
    
    def fix_security_group(self, group_id, port):
        try:
            self.ec2.revoke_security_group_ingress(
                GroupId=group_id,
                IpPermissions=[{
                    'IpProtocol': 'tcp',
                    'FromPort': port,
                    'ToPort': port,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                }]
            )
            return True, f'Port {port} access from 0.0.0.0/0 removed'
        except Exception as e:
            return False, str(e)

@app.route("/")
def home():
    return redirect(url_for("login"))

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        fullname = request.form["fullname"]
        mobile = request.form["mobile"]
        email = request.form["email"]
        aws_builder_id = request.form["aws_builder_id"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        if email in users:
            return render_template("signup.html", error="Email already exists")
        if password != confirm_password:
            return render_template("signup.html", error="Passwords do not match")
        
        users[email] = {
            "fullname": fullname,
            "mobile": mobile,
            "aws_builder_id": aws_builder_id,
            "password": password,
            "aws_access_key": "",
            "aws_secret_key": "",
            "aws_region": "us-east-1"
        }
        save_users()
        return redirect(url_for("login"))

    return render_template("signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["username"]
        password = request.form["password"]

        if email in users and users[email]["password"] == password:
            session["user"] = users[email]["fullname"]
            session["user_info"] = {
                "fullname": users[email]["fullname"],
                "email": email,
                "mobile": users[email]["mobile"],
                "aws_builder_id": users[email]["aws_builder_id"]
            }
            return redirect(url_for("dashboard"))
        else:
            return render_template("login.html", error="Invalid credentials")

    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))

    # Get real-time findings if AWS credentials are configured
    email = session["user_info"]["email"]
    user_data = users[email]
    
    findings = []
    stats = {"critical": 0, "high": 0, "medium": 0, "resolved": 0, "compliance": 0}
    
    if user_data.get("aws_access_key") and user_data.get("aws_secret_key"):
        scanner = AWSSecurityScanner(
            user_data["aws_access_key"],
            user_data["aws_secret_key"],
            user_data.get("aws_region", "us-east-1")
        )
        
        if scanner.connected:
            findings.extend(scanner.scan_s3_buckets())
            findings.extend(scanner.scan_security_groups())
            findings.extend(scanner.scan_ec2_instances())
            
            # Calculate stats
            for f in findings:
                if f['severity'] == 'critical':
                    stats['critical'] += 1
                elif f['severity'] == 'high':
                    stats['high'] += 1
                elif f['severity'] == 'medium':
                    stats['medium'] += 1
            
            total_issues = stats['critical'] + stats['high'] + stats['medium']
            stats['compliance'] = max(0, 100 - (total_issues * 5))
    else:
        # Demo data if no AWS credentials
        findings = [
            {"resource": "Amazon S3", "issue": "Configure AWS credentials to scan", "severity": "medium"},
            {"resource": "Setup Required", "issue": "Add AWS Access Keys in Profile", "severity": "high"}
        ]
        stats = {"critical": 0, "high": 1, "medium": 1, "resolved": 0, "compliance": 50}
    
    recent_activity = [
        {"text": "Security scan completed", "time": datetime.now().strftime("%H:%M")},
        {"text": f"Found {len(findings)} security findings", "time": datetime.now().strftime("%H:%M")}
    ]

    return render_template("dashboard.html", user=session["user"], findings=findings[:8], stats=stats, recent_activity=recent_activity)

@app.route("/profile", methods=["GET", "POST"])
def profile():
    if "user" not in session:
        return redirect(url_for("login"))
    
    if request.method == "POST":
        email = session["user_info"]["email"]
        users[email]["fullname"] = request.form["fullname"]
        users[email]["mobile"] = request.form["mobile"]
        users[email]["aws_builder_id"] = request.form["aws_builder_id"]
        users[email]["aws_access_key"] = request.form.get("aws_access_key", "")
        users[email]["aws_secret_key"] = request.form.get("aws_secret_key", "")
        users[email]["aws_region"] = request.form.get("aws_region", "us-east-1")
        save_users()
        
        session["user"] = users[email]["fullname"]
        session["user_info"]["fullname"] = users[email]["fullname"]
        session["user_info"]["mobile"] = users[email]["mobile"]
        session["user_info"]["aws_builder_id"] = users[email]["aws_builder_id"]
    
    user_info = session.get("user_info", {})
    email = user_info.get("email")
    aws_configured = bool(users.get(email, {}).get("aws_access_key"))
    return render_template("profile.html", user=session["user"], user_info=user_info, aws_configured=aws_configured)

@app.route("/findings")
def findings():
    if "user" not in session:
        return redirect(url_for("login"))
    
    email = session["user_info"]["email"]
    user_data = users[email]
    findings = []
    
    if user_data.get("aws_access_key") and user_data.get("aws_secret_key"):
        scanner = AWSSecurityScanner(
            user_data["aws_access_key"],
            user_data["aws_secret_key"],
            user_data.get("aws_region", "us-east-1")
        )
        if scanner.connected:
            findings.extend(scanner.scan_s3_buckets())
            findings.extend(scanner.scan_security_groups())
            findings.extend(scanner.scan_ec2_instances())
    else:
        findings = [
            {"resource": "Setup Required", "name": "N/A", "issue": "Configure AWS credentials in Profile", "severity": "high", "status": "Open", "fix_available": False}
        ]
    
    return render_template("findings.html", user=session["user"], findings=findings)

@app.route("/scan", methods=["POST"])
def scan():
    if "user" not in session:
        return jsonify({"success": False, "message": "Not logged in"})
    
    email = session["user_info"]["email"]
    user_data = users[email]
    
    if not user_data.get("aws_access_key") or not user_data.get("aws_secret_key"):
        return jsonify({"success": False, "message": "AWS credentials not configured"})
    
    scanner = AWSSecurityScanner(
        user_data["aws_access_key"],
        user_data["aws_secret_key"],
        user_data.get("aws_region", "us-east-1")
    )
    
    findings = []
    findings.extend(scanner.scan_s3_buckets())
    findings.extend(scanner.scan_security_groups())
    findings.extend(scanner.scan_ec2_instances())
    
    return jsonify({"success": True, "findings": len(findings), "message": f"Scan complete. Found {len(findings)} issues"})

@app.route("/remediate", methods=["POST"])
def remediate():
    if "user" not in session:
        return jsonify({"success": False, "message": "Not logged in"})
    
    data = request.json
    finding_id = data.get("finding_id")
    resource_type = data.get("resource_type")
    resource_name = data.get("resource_name")
    
    email = session["user_info"]["email"]
    user_data = users[email]
    
    scanner = AWSSecurityScanner(
        user_data["aws_access_key"],
        user_data["aws_secret_key"],
        user_data.get("aws_region", "us-east-1")
    )
    
    if resource_type == "S3 Bucket":
        success, message = scanner.fix_s3_public_access(resource_name)
        return jsonify({"success": success, "message": message})
    elif resource_type == "Security Group":
        port = data.get("port", 22)
        success, message = scanner.fix_security_group(resource_name, port)
        return jsonify({"success": success, "message": message})
    
    return jsonify({"success": False, "message": "Fix not available for this resource type"})

@app.route("/reports")
def reports():
    if "user" not in session:
        return redirect(url_for("login"))
    
    email = session["user_info"]["email"]
    user_data = users[email]
    
    # Get real findings for report
    findings = []
    if user_data.get("aws_access_key") and user_data.get("aws_secret_key"):
        scanner = AWSSecurityScanner(
            user_data["aws_access_key"],
            user_data["aws_secret_key"],
            user_data.get("aws_region", "us-east-1")
        )
        if scanner.connected:
            findings.extend(scanner.scan_s3_buckets())
            findings.extend(scanner.scan_security_groups())
            findings.extend(scanner.scan_ec2_instances())
    
    # Calculate stats
    stats = {"total": len(findings), "high": 0, "medium": 0, "compliance": 100, "resources": len(findings), "scanned": len(findings)}
    for f in findings:
        if f.get('severity') == 'high':
            stats['high'] += 1
        elif f.get('severity') == 'medium':
            stats['medium'] += 1
    stats['compliance'] = max(0, 100 - (len(findings) * 5))
    
    return render_template("reports.html", user=session["user"], stats=stats, current_date=datetime.now().strftime("%B %d, %Y"))

@app.route("/download-report/<report_type>")
def download_report(report_type):
    if "user" not in session:
        return redirect(url_for("login"))
    
    from flask import make_response
    email = session["user_info"]["email"]
    user_data = users[email]
    
    # Get findings
    findings = []
    if user_data.get("aws_access_key") and user_data.get("aws_secret_key"):
        scanner = AWSSecurityScanner(
            user_data["aws_access_key"],
            user_data["aws_secret_key"],
            user_data.get("aws_region", "us-east-1")
        )
        if scanner.connected:
            findings.extend(scanner.scan_s3_buckets())
            findings.extend(scanner.scan_security_groups())
            findings.extend(scanner.scan_ec2_instances())
    
    # Generate report content
    report_content = f"""CONFIGUARDS SECURITY REPORT
{'='*60}
Report Type: {report_type.replace('-', ' ').title()}
Generated: {datetime.now().strftime('%B %d, %Y %H:%M:%S')}
User: {session['user']}
AWS Region: {user_data.get('aws_region', 'us-east-1')}
{'='*60}

SUMMARY
{'-'*60}
Total Findings: {len(findings)}
High Severity: {sum(1 for f in findings if f.get('severity') == 'high')}
Medium Severity: {sum(1 for f in findings if f.get('severity') == 'medium')}
Compliance Score: {max(0, 100 - (len(findings) * 5))}%

DETAILED FINDINGS
{'-'*60}
"""
    
    for i, finding in enumerate(findings, 1):
        report_content += f"""
{i}. {finding.get('resource', 'Unknown')} - {finding.get('name', 'N/A')}
   Issue: {finding.get('issue', 'No description')}
   Severity: {finding.get('severity', 'unknown').upper()}
   Status: {finding.get('status', 'Open')}
   Risk: {finding.get('risk', 'Not specified')}
{'-'*60}
"""
    
    if not findings:
        report_content += "\nNo security findings detected.\n"
    
    report_content += f"\n\nEnd of Report\nGenerated by Configuards - Cloud Security Monitoring System\n"
    
    # Create response
    response = make_response(report_content)
    response.headers['Content-Type'] = 'text/plain'
    response.headers['Content-Disposition'] = f'attachment; filename=configuards_{report_type}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt'
    
    return response

@app.route("/about")
def about():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("about.html", user=session["user"])

@app.route("/settings")
def settings():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("settings.html", user=session["user"])

@app.route("/change-password", methods=["GET", "POST"])
def change_password():
    if "user" not in session:
        return redirect(url_for("login"))
    
    if request.method == "POST":
        email = session["user_info"]["email"]
        current_password = request.form["current_password"]
        new_password = request.form["new_password"]
        confirm_password = request.form["confirm_password"]
        
        if users[email]["password"] != current_password:
            return render_template("change_password.html", user=session["user"], error="Current password is incorrect")
        if new_password != confirm_password:
            return render_template("change_password.html", user=session["user"], error="New passwords do not match")
        
        users[email]["password"] = new_password
        save_users()
        return render_template("change_password.html", user=session["user"], success="Password changed successfully")
    
    return render_template("change_password.html", user=session["user"])

@app.route("/two-factor", methods=["GET", "POST"])
def two_factor():
    if "user" not in session:
        return redirect(url_for("login"))
    
    email = session["user_info"]["email"]
    if "two_factor" not in users[email]:
        users[email]["two_factor"] = False
    
    if request.method == "POST":
        users[email]["two_factor"] = not users[email]["two_factor"]
        save_users()
        status = "enabled" if users[email]["two_factor"] else "disabled"
        return render_template("two_factor.html", user=session["user"], two_factor_enabled=users[email]["two_factor"], success=f"Two-Factor Authentication {status}")
    
    return render_template("two_factor.html", user=session["user"], two_factor_enabled=users[email]["two_factor"])

@app.route("/feedback", methods=["GET", "POST"])
def feedback():
    if "user" not in session:
        return redirect(url_for("login"))
    
    if request.method == "POST":
        subject = request.form["subject"]
        message = request.form["message"]
        rating = request.form["rating"]
        
        # Save feedback to file
        try:
            with open('feedback.json', 'r') as f:
                feedbacks = json.load(f)
        except FileNotFoundError:
            feedbacks = []
        
        feedbacks.append({
            "user": session["user"],
            "subject": subject,
            "message": message,
            "rating": rating
        })
        
        with open('feedback.json', 'w') as f:
            json.dump(feedbacks, f, indent=4)
        
        return render_template("feedback.html", user=session["user"], success="Thank you for your feedback!")
    
    return render_template("feedback.html", user=session["user"])

@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)