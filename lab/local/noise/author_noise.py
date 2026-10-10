#!/usr/bin/env python3
"""Authoring script for the nimbus noise estate (P0-NOISE).
Emits lab/local/noise/estate.yaml and lab/noise_truth.yaml from one source of truth.
Usage: python3 -I author_noise.py <repo_root>"""
import hashlib, json, re, sys, os

ROOT = sys.argv[1]

PROD, SHARED, DATA, DEV, SBX, SEC = "310000000001", "310000000002", "310000000003", "310000000004", "310000000005", "310000000006"
AZ = "7a1e0000-0000-4000-8000-000000000010"
GCP, GCPDEV = "halyard-prod-gcp", "halyard-dev-gcp"
EKS, EKSDEV = "halyard-eks-prod", "halyard-eks-dev"
GH = "halyard"
R = "us-east-1"

ACCOUNTS = [
    ("aws", PROD, "halyard-prod", "production workloads"),
    ("aws", SHARED, "halyard-shared-services", "CI/CD, networking, tooling (org member)"),
    ("aws", DATA, "halyard-data", "data platform (org member)"),
    ("aws", DEV, "halyard-dev", "development account, tagged environment=dev, synthetic data only"),
    ("aws", SBX, "halyard-sandbox", "sandbox account, tagged environment=sandbox, no production data, no trust into prod"),
    ("aws", SEC, "halyard-security", "security/audit account (org member, holds the SSO SAML provider)"),
    ("azure", AZ, "halyard-azure-prod", None),
    ("gcp", GCP, "halyard-prod-gcp", None),
    ("gcp", GCPDEV, "halyard-dev-gcp", "development project, synthetic data only"),
    ("kubernetes", EKS, "halyard-eks-prod", "EKS cluster halyard-eks-prod (private endpoint)"),
    ("kubernetes", EKSDEV, "halyard-eks-dev", "EKS cluster halyard-eks-dev"),
    ("github", GH, "halyard", "GitHub organisation"),
]

CLASSES = {
    "NZ01": ("public_website_bucket", "Public buckets that only serve public website assets (no sensitive tag), mostly behind CloudFront"),
    "NZ02": ("alb_private_imdsv2", "Internet-facing ALBs in front of private instances (no public IP, IMDSv2 required, scoped roles, no exploitable CVE)"),
    "NZ03": ("sg_443_alb_only", "Security groups open to 0.0.0.0/0 on 443 only, attached only to load balancers fronting ECS services"),
    "NZ04": ("scoped_readonly_role", "Roles with broad-but-scoped read-only policies, trusted only by SSO or AWS services"),
    "NZ05": ("unreachable_admin_role", "Admin roles only assumable via SSO SAML with MFA condition; no workload or external trust"),
    "NZ06": ("org_cross_account_trust", "Cross-account trusts to the org's own accounts (PrincipalOrgID / ExternalId conditions)"),
    "NZ07": ("lambda_url_iam_auth", "Lambda function URLs with AuthType AWS_IAM (some with org-scoped resource policies scanners call public)"),
    "NZ08": ("eks_private_endpoint", "EKS clusters with private-only API endpoints"),
    "NZ09": ("k8s_namespaced_read_sa", "K8s service accounts bound to namespaced read-only roles"),
    "NZ10": ("gcp_custom_least_priv_sa", "GCP instances running as custom least-privilege service accounts"),
    "NZ11": ("azure_private_storage", "Azure storage with private endpoints and no public blob; VMs with scoped managed identities"),
    "NZ12": ("github_protected_repo", "GitHub repos with branch protection; OIDC deploy roles pinned to protected environments"),
    "NZ13": ("iam_user_mfa_rotated", "IAM users with MFA and rotated keys"),
    "NZ14": ("cve_nonkev_private_host", "CVEs not in CISA KEV with low EPSS on private, non-internet-reachable hosts"),
    "NZ15": ("dev_sandbox_tagged", "Dev/sandbox accounts and projects, tagged as such, holding only synthetic data and no trust into prod"),
    "NZ16": ("private_data_store", "Sensitive data stores that are private and only reachable from unexposed principals"),
    "NZ90": ("near_miss", "Alarming names (admin/prod/pii/customer/root/secret) but benign attributes"),
    "NZT1": ("true_positive", "Deliberate, labelled true positives (3 chains)"),
}

resources, weaknesses, truth = [], [], {}
wn = [0]

def h(s, n=17):
    return hashlib.sha256(s.encode()).hexdigest()[:n]

def res(cls, rid, provider, account, rtype, name, attrs=None, rels=None, region=None, why="", near=False, tp=None):
    assert rid not in truth, rid
    r = {"id": rid, "scenario": cls, "provider": provider, "account": account}
    if region: r["region"] = region
    r["type"] = rtype; r["name"] = name
    if attrs: r["attributes"] = attrs
    if rels: r["relationships"] = rels
    resources.append(r)
    truth[rid] = {"class": cls, "near_miss": near, "tp": tp, "why": why, "findings": []}
    return rid

def weak(rid, check, sev, ws, title, attrs=None):
    wn[0] += 1
    wid = "N%03d" % wn[0]
    w = {"id": wid, "resource": rid, "check_id": check, "severity": sev, "weaknesses": ws, "title": title}
    if attrs: w["attributes"] = attrs
    weaknesses.append(w)
    truth[rid]["findings"].append(wid)
    return wid

def rel(kind, to, via=None):
    d = {"kind": kind, "to": to}
    if via: d["via"] = via
    return d

def inst_arn(acct, name): return "arn:aws:ec2:%s:%s:instance/i-0%s" % (R, acct, h(name, 16))
def sg_arn(acct, name): return "arn:aws:ec2:%s:%s:security-group/sg-0%s" % (R, acct, h(name, 16))
def role_arn(acct, name): return "arn:aws:iam::%s:role/%s" % (acct, name)
def user_arn(acct, name): return "arn:aws:iam::%s:user/%s" % (acct, name)
def s3(name): return "arn:aws:s3:::" + name
def alb_arn(acct, name, kind="app"): return "arn:aws:elasticloadbalancing:%s:%s:loadbalancer/%s/%s/%s" % (R, acct, kind, name, h(name, 16))
def fn_arn(acct, name): return "arn:aws:lambda:%s:%s:function:%s" % (R, acct, name)
def ddb(acct, name): return "arn:aws:dynamodb:%s:%s:table/%s" % (R, acct, name)
def rds(acct, name): return "arn:aws:rds:%s:%s:db:%s" % (R, acct, name)

SSO = "arn:aws:iam::%s:saml-provider/halyard-okta" % SEC
SSO_TRUST = {"principal": SSO, "conditions": {"Bool": {"aws:MultiFactorAuthPresent": "true"}, "StringEquals": {"SAML:aud": "https://signin.aws.amazon.com/saml"}}}

# ------------------------------------------------------------------ shared anchors
res("NZ05", SSO, "aws", SEC, "aws_iam_saml_provider", "halyard-okta",
    {"issuer": "http://www.okta.com/exk1halyard", "mfa_enforced_by_idp": True, "session_duration_seconds": 3600},
    why="Identity provider; Okta enforces phishing-resistant MFA before issuing assertions.")

# ------------------------------------------------------------------ NZ01 public website buckets
sites = [("halyard-www-static", "www.halyard.example"), ("halyard-docs-site", "docs.halyard.example"),
         ("halyard-marketing-assets", "assets.halyard.example"), ("halyard-status-page", "status.halyard.example"),
         ("halyard-careers-site", "careers.halyard.example"), ("halyard-brand-kit", None),
         ("halyard-press-images", None), ("halyard-downloads-public", "downloads.halyard.example")]
for i, (b, dom) in enumerate(sites):
    attrs = {"tags": {"data_classification": "public", "environment": "production", "owner": "web-platform", "purpose": "static-website"},
             "public_access_block": False, "bucket_policy_principal": "*", "bucket_policy_actions": ["s3:GetObject"],
             "website_hosting": dom is not None, "versioning": True, "encryption": "AES256",
             "object_prefixes": ["index.html", "assets/", "img/", "css/"] if dom else ["logos/", "press/"],
             "object_count": 1200 + 137 * i, "contains_sensitive_data": False}
    rid = res("NZ01", s3(b), "aws", PROD, "aws_s3_bucket", b, attrs, region=R,
              why="Public read of intentionally public website assets; bucket tagged data_classification=public; no write, no list, no sensitive objects.")
    weak(rid, "s3_bucket_public_access", "CRITICAL", ["PUBLIC_DATA_STORE"], "S3 bucket %s allows public read" % b,
         {"exposure_cidrs": ["0.0.0.0/0"]})
    if i % 3 == 0:
        weak(rid, "s3_bucket_server_access_logging_enabled", "LOW", ["NO_LOGGING"], "S3 bucket %s has no server access logging" % b)
    if dom and i < 4:
        dist = "arn:aws:cloudfront::%s:distribution/E%s" % (PROD, h(b, 12).upper())
        res("NZ01", dist, "aws", PROD, "aws_cloudfront_distribution", dom,
            {"aliases": [dom], "viewer_protocol_policy": "redirect-to-https", "origin": b + ".s3.amazonaws.com",
             "origin_access_control": True, "waf_web_acl": "halyard-edge-waf", "minimum_protocol_version": "TLSv1.2_2021"},
            [rel("allows_traffic_to", rid, "origin access control (GET/HEAD only)")],
            why="CDN for public static content; read-only origin access.")

# ------------------------------------------------------------------ NZ16 private sensitive data stores (declared early so others can reference)
data_stores = {}
for name, cls_tag, acct in [("halyard-customer-profiles", "pii", DATA), ("halyard-billing-exports", "confidential", DATA),
                            ("halyard-app-uploads", "confidential", PROD), ("halyard-analytics-raw", "pii", DATA)]:
    rid = res("NZ16", s3(name), "aws", acct, "aws_s3_bucket", name,
              {"tags": {"data_classification": cls_tag, "environment": "production", "owner": "data-platform"},
               "public_access_block": True, "bucket_policy_principal": "account-only", "encryption": "aws:kms",
               "kms_key": "alias/halyard-data", "versioning": True, "object_lock": False, "deny_insecure_transport": True},
              region=R, why="Sensitive but private (BPA on, KMS, TLS-only); only reachable from principals that are themselves unexposed.")
    data_stores[name] = rid
for name, eng, acct in [("halyard-orders-db", "postgres", PROD), ("halyard-ledger-db", "aurora-postgresql", DATA)]:
    rid = res("NZ16", rds(acct, name), "aws", acct, "aws_db_instance", name,
              {"tags": {"data_classification": "confidential", "environment": "production"}, "engine": eng,
               "publicly_accessible": False, "storage_encrypted": True, "subnet_group": "private-db", "iam_auth": True,
               "multi_az": name != "halyard-orders-db"}, region=R,
              why="Private RDS in private subnets, encrypted, no public endpoint.")
    data_stores[name] = rid
    if name == "halyard-orders-db":
        weak(rid, "rds_instance_multi_az", "LOW", ["NO_BACKUP", "DATABASE"], "RDS instance %s is not Multi-AZ" % name)
        weak(rid, "rds_instance_minor_version_upgrade_enabled", "LOW", ["UNPATCHED", "DATABASE"], "RDS instance %s does not auto-apply minor upgrades" % name)
for name, acct in [("halyard-sessions", PROD), ("halyard-feature-flags", PROD)]:
    rid = res("NZ16", ddb(acct, name), "aws", acct, "aws_dynamodb_table", name,
              {"tags": {"data_classification": "internal", "environment": "production"}, "sse": "aws:kms", "pitr": True},
              region=R, why="Private DynamoDB table; no resource policy; reachable only through IAM from private workloads.")
    data_stores[name] = rid

# ------------------------------------------------------------------ NZ02 ALB -> private IMDSv2 instances
stacks = [("storefront", "halyard-app-uploads"), ("checkout", "halyard-orders-db"), ("account-portal", "halyard-sessions"),
          ("search", None), ("partner-api", None)]
for app, data in stacks:
    alb = alb_arn(PROD, "%s-alb" % app)
    albsg = sg_arn(PROD, "%s-alb-sg" % app)
    appsg = sg_arn(PROD, "%s-app-sg" % app)
    role = role_arn(PROD, "%s-instance-role" % app)
    insts = [inst_arn(PROD, "%s-%02d" % (app, n)) for n in range(1, 4)]
    res("NZ02", albsg, "aws", PROD, "aws_security_group", "%s-alb-sg" % app,
        {"ingress": [{"protocol": "tcp", "from_port": 443, "to_port": 443, "cidr": "0.0.0.0/0", "description": "HTTPS from internet"}],
         "egress": [{"protocol": "tcp", "from_port": 8080, "to_port": 8080, "security_group": appsg}],
         "attached_to_types": ["aws_lb"]},
        [rel("allows_traffic_to", alb, "tcp/443 only")], region=R,
        why="Open on 443 by design; attached only to the ALB, which terminates TLS.")
    weak(albsg, "ec2_securitygroup_allow_wide_open_public_ipv4", "MEDIUM", ["PUBLIC_NETWORK_EXPOSURE"],
         "Security group %s-alb-sg allows ingress from 0.0.0.0/0" % app, {"exposure_cidrs": ["0.0.0.0/0"], "exposure_ports": [443]})
    res("NZ02", alb, "aws", PROD, "aws_lb", "%s-alb" % app,
        {"scheme": "internet-facing", "type": "application", "listeners": [{"port": 443, "protocol": "HTTPS", "ssl_policy": "ELBSecurityPolicy-TLS13-1-2-2021-06"}],
         "http_redirect_to_https": True, "waf_web_acl": "halyard-regional-waf", "drop_invalid_header_fields": True,
         "target_port": 8080, "tags": {"environment": "production", "app": app}},
        [rel("attached_to", albsg)] + [rel("allows_traffic_to", i, "listener 443 -> target group HTTP/8080") for i in insts], region=R,
        why="Internet-facing by design; forwards only HTTP/8080 application traffic to targets; no admin port.")
    weak(alb, "elbv2_internet_facing", "MEDIUM", ["PUBLIC_NETWORK_EXPOSURE"], "Load balancer %s-alb is internet-facing" % app,
         {"exposure_cidrs": ["0.0.0.0/0"], "exposure_ports": [443]})
    res("NZ02", appsg, "aws", PROD, "aws_security_group", "%s-app-sg" % app,
        {"ingress": [{"protocol": "tcp", "from_port": 8080, "to_port": 8080, "source_security_group": albsg, "description": "from ALB only"}]},
        [rel("allows_traffic_to", i, "tcp/8080 from %s-alb-sg only" % app) for i in insts], region=R,
        why="Ingress only from the ALB security group; no CIDR rule.")
    grants = [rel("grants_access_to", data_stores[data], "app-scoped policy")] if data else []
    res("NZ02", role, "aws", PROD, "aws_iam_role", "%s-instance-role" % app,
        {"attached_policies": ["arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore", "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"],
         "inline_policy": ("scoped data access for %s on %s" % (app, data)) if data else "ssm:GetParameter on /%s/*" % app,
         "trust_principals": ["ec2.amazonaws.com"], "permissions_boundary": "arn:aws:iam::%s:policy/workload-boundary" % PROD},
        grants, why="Workload role scoped to its own app data; only reachable by code running on private, IMDSv2-only instances.")
    for n, i in enumerate(insts, 1):
        res("NZ02", i, "aws", PROD, "aws_instance", "%s-%02d" % (app, n),
            {"tags": {"environment": "production", "app": app}, "public_ip": None, "subnet": "private-app-%s" % "abc"[n - 1],
             "metadata_http_tokens": "required", "metadata_hop_limit": 1, "instance_profile": "%s-instance-profile" % app,
             "ami": "ami-0%s" % h(app, 16), "patch_compliance": "COMPLIANT"},
            [rel("attached_to", appsg), rel("runs_as", role, "instance profile %s-instance-profile" % app)], region=R,
            why="No public IP, IMDSv2 required (hop limit 1), patched, reachable only via ALB application port.")

# ------------------------------------------------------------------ NZ03 443-only SG -> LB -> ECS services
for svc in ["notifications-api", "pricing-api", "webhooks-ingest", "media-resizer"]:
    lb = alb_arn(PROD, "%s-lb" % svc)
    sg = sg_arn(PROD, "%s-lb-sg" % svc)
    ecs = "arn:aws:ecs:%s:%s:service/halyard-prod/%s" % (R, PROD, svc)
    trole = role_arn(PROD, "%s-task-role" % svc)
    res("NZ03", sg, "aws", PROD, "aws_security_group", "%s-lb-sg" % svc,
        {"ingress": [{"protocol": "tcp", "from_port": 443, "to_port": 443, "cidr": "0.0.0.0/0"}], "attached_to_types": ["aws_lb"]},
        [rel("allows_traffic_to", lb, "tcp/443 only")], region=R, why="443 to an ALB only.")
    if svc != "media-resizer":
        weak(sg, "ec2_securitygroup_allow_wide_open_public_ipv4", "MEDIUM", ["PUBLIC_NETWORK_EXPOSURE"],
             "Security group %s-lb-sg allows ingress from 0.0.0.0/0" % svc, {"exposure_cidrs": ["0.0.0.0/0"], "exposure_ports": [443]})
    res("NZ03", lb, "aws", PROD, "aws_lb", "%s-lb" % svc,
        {"scheme": "internet-facing", "type": "application", "listeners": [{"port": 443, "protocol": "HTTPS"}],
         "authentication": "cognito" if svc == "webhooks-ingest" else "app-level (HMAC/JWT)", "waf_web_acl": "halyard-regional-waf"},
        [rel("attached_to", sg), rel("allows_traffic_to", ecs, "listener 443 -> awsvpc target 8443")], region=R,
        why="Public API front door; app-level auth; forwards to Fargate tasks in private subnets.")
    res("NZ03", ecs, "aws", PROD, "aws_ecs_service", svc,
        {"launch_type": "FARGATE", "assign_public_ip": False, "task_role": trole, "platform_version": "1.4.0",
         "readonly_root_filesystem": True, "privileged": False},
        [rel("runs_as", trole, "task role")], region=R, why="Fargate in private subnets; no host access; no public IP.")
    res("NZ03", trole, "aws", PROD, "aws_iam_role", "%s-task-role" % svc,
        {"trust_principals": ["ecs-tasks.amazonaws.com"], "inline_policy": "sqs:SendMessage on queue %s-events; logs:PutLogEvents" % svc},
        why="Task role limited to its own queue and logs.")

# ------------------------------------------------------------------ NZ04 scoped read-only roles
ro = [("finops-cost-reader", ["arn:aws:iam::aws:policy/AWSBillingReadOnlyAccess"], None),
      ("observability-reader", ["arn:aws:iam::aws:policy/CloudWatchReadOnlyAccess"], None),
      ("security-hub-reader", ["arn:aws:iam::aws:policy/AWSSecurityHubReadOnlyAccess"], None),
      ("config-auditor", ["arn:aws:iam::aws:policy/SecurityAudit"], None),
      ("support-viewonly", ["arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"], None),
      ("analytics-reader", [], "halyard-analytics-raw"),
      ("billing-export-reader", [], "halyard-billing-exports"),
      ("catalog-browser", ["arn:aws:iam::aws:policy/AWSGlueConsoleFullAccess-readonly-custom"], None),
      ("ecr-pull-only", ["arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"], None),
      ("route53-reader", ["arn:aws:iam::aws:policy/AmazonRoute53ReadOnlyAccess"], None),
      ("trail-log-reader", [], None),
      ("inventory-collector", ["arn:aws:iam::aws:policy/ReadOnlyAccess"], None)]
for name, pols, data in ro:
    acct = DATA if data else PROD
    attrs = {"attached_policies": pols, "trust": SSO_TRUST if name not in ("ecr-pull-only", "inventory-collector") else
             {"principal": "ec2.amazonaws.com" if name == "ecr-pull-only" else "config.amazonaws.com"},
             "max_session_duration": 3600}
    if data: attrs["inline_policy"] = "s3:GetObject, s3:ListBucket on %s with aws:SourceVpce condition vpce-0%s" % (data, h(data, 8))
    if name == "trail-log-reader": attrs["inline_policy"] = "s3:GetObject on halyard-org-cloudtrail/AWSLogs/*"
    rels = [rel("trusts", SSO)] if "principal" in attrs["trust"] and attrs["trust"]["principal"] == SSO else []
    if data: rels.append(rel("grants_access_to", data_stores[data], "read-only, VPC-endpoint-conditioned"))
    rid = res("NZ04", role_arn(acct, name), "aws", acct, "aws_iam_role", name, attrs, rels,
              why="Read-only, scoped; assumable only via SSO with MFA or by an AWS service; no workload exposure.")
    if name == "inventory-collector":
        weak(rid, "iam_policy_attached_only_to_group_or_roles_readonly_broad", "LOW", ["OVERPRIVILEGED_IDENTITY"],
             "Role inventory-collector has broad ReadOnlyAccess")

# ------------------------------------------------------------------ NZ05 unreachable admin roles
for name, acct in [("org-admin-sso", PROD), ("data-admin-sso", DATA), ("network-admin-sso", SHARED), ("security-admin-sso", SEC)]:
    rid = res("NZ05", role_arn(acct, name), "aws", acct, "aws_iam_role", name,
              {"attached_policies": ["arn:aws:iam::aws:policy/AdministratorAccess"], "trust": SSO_TRUST,
               "max_session_duration": 3600, "instance_profiles": [], "last_used_days": 6,
               "session_tags_required": ["approver"]},
              [rel("trusts", SSO)],
              why="Admin by design; only reachable through Okta SSO with MFA; no instance profile, no service or external trust.")
    weak(rid, "iam_aws_attached_policy_no_administrative_privileges", "HIGH", ["OVERPRIVILEGED_IDENTITY"],
         "Role %s has AdministratorAccess" % name)

# ------------------------------------------------------------------ NZ06 org cross-account trusts
src = {"ci-deployer": role_arn(SHARED, "ci-deployer"), "security-scanner": role_arn(SEC, "security-scanner"),
       "backup-operator": role_arn(SHARED, "backup-operator")}
res("NZ06", src["ci-deployer"], "aws", SHARED, "aws_iam_role", "ci-deployer",
    {"trust": {"principal": "codebuild.amazonaws.com"}, "inline_policy": "sts:AssumeRole on arn:aws:iam::*:role/deploy-target with aws:PrincipalOrgID o-halyard01"},
    why="CodeBuild service role in shared-services; assumes only org deploy-target roles.")
res("NZ06", src["security-scanner"], "aws", SEC, "aws_iam_role", "security-scanner",
    {"trust": {"principal": "ecs-tasks.amazonaws.com"}, "inline_policy": "sts:AssumeRole on arn:aws:iam::*:role/audit-readonly"},
    why="Security account scanner task role (private ECS).")
res("NZ06", src["backup-operator"], "aws", SHARED, "aws_iam_role", "backup-operator",
    {"trust": {"principal": "backup.amazonaws.com"}, "inline_policy": "sts:AssumeRole on arn:aws:iam::*:role/backup-target"},
    why="AWS Backup service role.")
targets = [("audit-readonly", PROD, "security-scanner", ["arn:aws:iam::aws:policy/SecurityAudit", "arn:aws:iam::aws:policy/ReadOnlyAccess"], True),
           ("audit-readonly", DATA, "security-scanner", ["arn:aws:iam::aws:policy/SecurityAudit", "arn:aws:iam::aws:policy/ReadOnlyAccess"], True),
           ("audit-readonly", SHARED, "security-scanner", ["arn:aws:iam::aws:policy/SecurityAudit", "arn:aws:iam::aws:policy/ReadOnlyAccess"], True),
           ("audit-readonly", DEV, "security-scanner", ["arn:aws:iam::aws:policy/SecurityAudit", "arn:aws:iam::aws:policy/ReadOnlyAccess"], True),
           ("deploy-target", PROD, "ci-deployer", [], False),
           ("deploy-target", DATA, "ci-deployer", [], False),
           ("deploy-target", DEV, "ci-deployer", [], False),
           ("backup-target", PROD, "backup-operator", ["arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"], False),
           ("backup-target", DATA, "backup-operator", ["arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"], False)]
for name, acct, s, pols, flagged in targets:
    attrs = {"attached_policies": pols, "trust_principals": [src[s]],
             "trust_conditions": {"StringEquals": {"aws:PrincipalOrgID": "o-halyard01"}},
             "trusted_account_owner": "same-organization"}
    if name == "deploy-target":
        attrs["inline_policy"] = "cloudformation:* on stacks app-*; iam:PassRole on roles app-* (permissions boundary workload-boundary enforced)"
        attrs["permissions_boundary"] = "arn:aws:iam::%s:policy/deploy-boundary" % acct
    rid = res("NZ06", role_arn(acct, name), "aws", acct, "aws_iam_role", name, attrs,
              [rel("trusts", src[s], "aws:PrincipalOrgID o-halyard01")],
              why="Trusts a role in the organisation's own %s account, with PrincipalOrgID condition; source role is unexposed." %
                  ("security" if s == "security-scanner" else "shared-services"))
    if flagged:
        weak(rid, "iam_role_cross_account_readonlyaccess_policy", "HIGH", ["CROSS_ACCOUNT_TRUST"],
             "Role audit-readonly in %s allows cross-account ReadOnlyAccess" % acct)

# ------------------------------------------------------------------ NZ07 Lambda URLs with IAM auth
lambdas = [("report-renderer", None, False), ("thumbnail-signer", "halyard-app-uploads", False), ("invoice-pdf", "halyard-billing-exports", True),
           ("usage-aggregator", "halyard-sessions", False), ("feature-flag-reader", "halyard-feature-flags", True),
           ("audit-forwarder", None, False), ("slack-notifier", None, False), ("tenant-provisioner", None, True)]
for name, data, orgpol in lambdas:
    fr = role_arn(PROD, "%s-fn-role" % name)
    attrs = {"function_url_auth_type": "AWS_IAM", "runtime": "python3.12", "vpc_config": "private-app subnets",
             "reserved_concurrency": 20}
    if orgpol:
        attrs["resource_policy"] = {"Principal": "*", "Action": "lambda:InvokeFunctionUrl",
                                    "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-halyard01", "lambda:FunctionUrlAuthType": "AWS_IAM"}}}
    fid = res("NZ07", fn_arn(PROD, name), "aws", PROD, "aws_lambda_function", name, attrs, [rel("runs_as", fr)], region=R,
              why="Function URL requires SigV4 (AWS_IAM); resource policy (where present) is limited to the org.")
    if orgpol:
        weak(fid, "awslambda_function_not_publicly_accessible", "HIGH", ["PUBLIC_NETWORK_EXPOSURE"],
             "Lambda function %s resource policy has Principal *" % name)
    res("NZ07", fr, "aws", PROD, "aws_iam_role", "%s-fn-role" % name,
        {"trust_principals": ["lambda.amazonaws.com"],
         "inline_policy": ("read on %s" % data) if data else "logs:PutLogEvents; sns:Publish on %s-topic" % name},
        [rel("grants_access_to", data_stores[data], "function-scoped policy")] if data else None,
        why="Function execution role scoped to its own resources.")

# ------------------------------------------------------------------ NZ08 EKS private endpoints (+ NZ09 K8s namespaced SAs)
eks_prod = "arn:aws:eks:%s:%s:cluster/halyard-eks-prod" % (R, PROD)
eks_data = "arn:aws:eks:%s:%s:cluster/halyard-eks-data" % (R, DATA)
ns_bindings = []
namespaces = [("storefront-web", True), ("catalog", False), ("orders-worker", False), ("reporting", False), ("observability", False), ("feature-svc", False)]
for ns, public in namespaces:
    sa = "%s/serviceaccount/%s-app" % (ns, ns)
    role = "%s/role/%s-read" % (ns, ns)
    rb = "%s/rolebinding/%s-app-read" % (ns, ns)
    ns_bindings.append(rb)
    res("NZ09", role, "kubernetes", EKS, "k8s_role", "%s-read" % ns,
        {"namespace": ns, "rules": [{"apiGroups": [""], "resources": ["configmaps", "endpoints"], "verbs": ["get", "list", "watch"]}]},
        why="Namespaced Role: read configmaps/endpoints in its own namespace only; no secrets, no pods/exec.")
    res("NZ09", rb, "kubernetes", EKS, "k8s_role_binding", "%s-app-read" % ns,
        {"namespace": ns, "role_ref": "Role/%s-read" % ns, "subjects": [sa]}, [rel("bound_to", role)],
        why="Binds the app SA to the namespaced read Role.")
    res("NZ09", sa, "kubernetes", EKS, "k8s_service_account", "%s-app" % ns,
        {"namespace": ns, "automount_service_account_token": False, "irsa_role": None}, [rel("bound_to", rb)],
        why="No cloud role (no IRSA annotation); token not automounted.")
    for k in range(2):
        pod = "%s/pod/%s-%s" % (ns, ns, h(ns + str(k), 5))
        attrs = {"namespace": ns, "service_account": "%s-app" % ns, "image": "123456789012.dkr.ecr.us-east-1.amazonaws.com/%s:2026.09.%d" % (ns, 12 + k),
                 "run_as_non_root": True, "read_only_root_filesystem": True, "privileged": False, "allow_privilege_escalation": False}
        if public:
            attrs["exposed_by"] = "ingress/storefront-web (ALB, 443, WAF) -> service/storefront-web ClusterIP"
        pid = res("NZ09", pod, "kubernetes", EKS, "k8s_pod", "%s-%s" % (ns, h(ns + str(k), 5)), attrs, [rel("runs_as", sa)],
                  why=("Internet-reachable web tier, but SA only reads configmaps in its namespace and has no cloud role; no exploitable CVE."
                       if public else "Cluster-internal pod; SA only reads configmaps in its namespace."))
        if public:
            weak(pid, "service_type_loadbalancer_public", "MEDIUM", ["PUBLIC_NETWORK_EXPOSURE"],
                 "Pod reachable from the internet through ingress storefront-web", {"exposure_ports": [443]})
        if ns in ("reporting", "observability") and k == 0:
            weak(pid, "core_minimize_containers_without_limits", "LOW", ["NO_RESOURCE_LIMITS"], "Pod has no CPU/memory limits")
        if ns == "orders-worker" and k == 1:
            weak(pid, "CVE-2024-26458", "LOW", ["UNPATCHED"], "krb5 memory leak (CVE-2024-26458) in image %s" % attrs["image"],
                 {"cve": "CVE-2024-26458", "kev": False, "epss": 0.0005, "cvss": 5.3, "package": "libkrb5-3", "network_reachable": False})
res("NZ08", eks_prod, "aws", PROD, "aws_eks_cluster", "halyard-eks-prod",
    {"endpoint_public_access": False, "endpoint_private_access": True, "public_access_cidrs": [], "secrets_encryption": "kms",
     "authentication_mode": "API", "version": "1.31"},
    [rel("contains", b) for b in ns_bindings], region=R, why="Private-only API endpoint; access via VPN + SSO-mapped access entries.")
res("NZ08", eks_data, "aws", DATA, "aws_eks_cluster", "halyard-eks-data",
    {"endpoint_public_access": False, "endpoint_private_access": True, "public_access_cidrs": [], "secrets_encryption": "kms", "version": "1.31"},
    region=R, why="Private-only API endpoint.")

# ------------------------------------------------------------------ NZ10 GCP custom least-privilege SAs
def gsa(proj, name): return "//iam.googleapis.com/projects/%s/serviceAccounts/%s@%s.iam.gserviceaccount.com" % (proj, name, proj)
def gce(proj, zone, name): return "//compute.googleapis.com/projects/%s/zones/%s/instances/%s" % (proj, zone, name)
def gfw(proj, name): return "//compute.googleapis.com/projects/%s/global/firewalls/%s" % (proj, name)
sas = {}
for name, roles in [("web-frontend-sa", ["roles/logging.logWriter", "roles/monitoring.metricWriter"]),
                    ("api-sa", ["roles/logging.logWriter", "roles/monitoring.metricWriter", "roles/cloudtrace.agent"]),
                    ("batch-sa", ["roles/logging.logWriter", "projects/halyard-prod-gcp/roles/batchQueueConsumer"]),
                    ("cache-sa", ["roles/logging.logWriter"]),
                    ("ingest-sa", ["roles/logging.logWriter", "roles/pubsub.publisher"])]:
    sas[name] = res("NZ10", gsa(GCP, name), "gcp", GCP, "gcp_service_account", "%s@%s.iam.gserviceaccount.com" % (name, GCP),
                    {"project_roles": roles, "user_managed_keys": 0, "disabled": False},
                    why="Custom SA with log/metric writer and narrowly scoped custom roles; no keys.")
fw_https = res("NZ10", gfw(GCP, "allow-https-lb"), "gcp", GCP, "gcp_compute_firewall", "allow-https-lb",
               {"source_ranges": ["0.0.0.0/0"], "allowed": ["tcp:443"], "target_tags": ["https-web"], "direction": "INGRESS"},
               why="Allows only 443 to web-tagged instances.")
fw_hc = res("NZ10", gfw(GCP, "allow-gfe-healthchecks"), "gcp", GCP, "gcp_compute_firewall", "allow-gfe-healthchecks",
            {"source_ranges": ["35.191.0.0/16", "130.211.0.0/22"], "allowed": ["tcp:8080"], "target_tags": ["lb-backend"]},
            why="Google front-end health-check ranges only.")
fw_iap = res("NZ10", gfw(GCP, "allow-iap-ssh"), "gcp", GCP, "gcp_compute_firewall", "allow-iap-ssh",
             {"source_ranges": ["35.235.240.0/20"], "allowed": ["tcp:22"], "target_tags": ["iap-ssh"]},
             why="SSH only from Identity-Aware Proxy range (IAP enforces SSO).")
gi = [("web-fe-1", "web-frontend-sa", True), ("web-fe-2", "web-frontend-sa", True), ("api-1", "api-sa", True), ("api-2", "api-sa", True),
      ("batch-1", "batch-sa", False), ("batch-2", "batch-sa", False), ("cache-1", "cache-sa", False), ("ingest-1", "ingest-sa", False)]
https_targets, hc_targets, iap_targets = [], [], []
for name, sa, ext in gi:
    rid = gce(GCP, "us-central1-a", name)
    res("NZ10", rid, "gcp", GCP, "gcp_compute_instance", name,
        {"external_ip": ("34.120.%d.%d" % (len(name), 10 + len(sa))) if ext else None, "service_account": sas[sa].split("/")[-1],
         "scopes": ["https://www.googleapis.com/auth/cloud-platform"], "shielded_vm": True, "os_login": True,
         "metadata_server": "v1 (Google metadata requires Metadata-Flavor header)", "network_tags": (["https-web", "lb-backend"] if ext else ["iap-ssh"]),
         "labels": {"env": "prod"}},
        [rel("runs_as", sas[sa])], region="us-central1",
        why=("External IP but only 443 allowed; runs as custom SA limited to log/metric writer." if ext else
             "No external IP; SSH via IAP only; custom least-privilege SA."))
    if ext:
        https_targets.append(rid); hc_targets.append(rid)
        weak(rid, "compute_instance_public_ip", "MEDIUM", ["PUBLIC_NETWORK_EXPOSURE"], "GCE instance %s has an external IP" % name,
             {"exposure_ports": [443]})
    else:
        iap_targets.append(rid)
for r in resources:
    if r["id"] == fw_https: r["relationships"] = [rel("allows_traffic_to", t, "tcp/443") for t in https_targets]
    if r["id"] == fw_hc: r["relationships"] = [rel("allows_traffic_to", t, "tcp/8080 health checks") for t in hc_targets]
    if r["id"] == fw_iap: r["relationships"] = [rel("allows_traffic_to", t, "tcp/22 from IAP") for t in iap_targets]
for b, pub in [("halyard-gcp-web-assets", True), ("halyard-gcp-batch-staging", False), ("halyard-gcp-logs-archive", False)]:
    rid = res("NZ10", "//storage.googleapis.com/projects/_/buckets/" + b, "gcp", GCP, "gcp_storage_bucket", b,
              {"uniform_bucket_level_access": True, "public_access_prevention": "inherited" if pub else "enforced",
               "iam_members": (["allUsers:roles/storage.objectViewer"] if pub else []),
               "labels": {"data_classification": "public" if pub else "internal", "env": "prod"}}, region="us-central1",
              why="Public website assets only" if pub else "Private bucket, public access prevention enforced.")
    if pub:
        weak(rid, "cloudstorage_bucket_public_access", "HIGH", ["PUBLIC_DATA_STORE"], "Cloud Storage bucket %s is publicly readable" % b)

# ------------------------------------------------------------------ NZ11 Azure private storage + scoped identities
def azid(rg, prov, name): return "/subscriptions/%s/resourceGroups/%s/providers/%s/%s" % (AZ, rg, prov, name)
vnet = res("NZ11", azid("halyard-net-rg", "Microsoft.Network", "virtualNetworks/halyard-hub-vnet"), "azure", AZ,
           "azure_virtual_network", "halyard-hub-vnet", {"address_space": ["10.40.0.0/16"]}, region="eastus",
           why="Private hub network.")
accts = ["halyardinvoices", "halyardmlfeatures", "halyardbackups", "halyardaudit", "halyarddocsprivate", "halyardetlstage",
         "halyardcrmexports", "halyardtelemetry"]
for i, a in enumerate(accts):
    sid = azid("halyard-data-rg", "Microsoft.Storage", "storageAccounts/" + a)
    pe = azid("halyard-data-rg", "Microsoft.Network", "privateEndpoints/%s-blob-pe" % a)
    res("NZ11", pe, "azure", AZ, "azure_private_endpoint", "%s-blob-pe" % a,
        {"subresource": "blob", "subnet": "halyard-hub-vnet/private-endpoints"}, [rel("attached_to", vnet), rel("allows_traffic_to", sid, "private link blob")],
        region="eastus", why="Private link endpoint inside the hub VNet.")
    attrs = {"allow_blob_public_access": False, "public_network_access": "Disabled", "shared_key_access": False,
             "min_tls_version": "TLS1_2" if i not in (2, 6) else "TLS1_1", "https_only": True,
             "tags": {"data_classification": "confidential" if a in ("halyardinvoices", "halyardcrmexports") else "internal", "environment": "production"}}
    res("NZ11", sid, "azure", AZ, "azure_storage_account", a, attrs, region="eastus",
        why="No public blob, public network access disabled, reachable only through its private endpoint.")
    if i in (2, 6):
        # Prowler alias storage_ensure_minimum_tls_version_12 is catalogued under AZ_STORAGE_PUBLIC_BLOB; the account is not public.
        weak(sid, "storage_ensure_minimum_tls_version_12", "MEDIUM", ["PUBLIC_DATA_STORE"],
             "Storage account %s minimum TLS version is 1.1" % a)
mis = {}
for name, role, scope in [("app-reader-mi", "Storage Blob Data Reader", "storageAccounts/halyardmlfeatures"),
                          ("ops-monitor-mi", "Monitoring Reader", "resourceGroups/halyard-app-rg")]:
    mis[name] = res("NZ11", azid("halyard-app-rg", "Microsoft.ManagedIdentity", "userAssignedIdentities/" + name), "azure", AZ,
                    "azure_user_assigned_identity", name, {"role_assignments": [{"role": role, "scope": scope}]}, region="eastus",
                    why="Data-plane reader / monitoring reader on a single scope.")
nsg_fd = azid("halyard-app-rg", "Microsoft.Network", "networkSecurityGroups/app-frontdoor-nsg")
nsg_int = azid("halyard-app-rg", "Microsoft.Network", "networkSecurityGroups/app-internal-nsg")
vms = [("app-web-01", "app-reader-mi", nsg_fd), ("app-web-02", "app-reader-mi", nsg_fd), ("ops-agent-01", "ops-monitor-mi", nsg_int), ("ops-agent-02", "ops-monitor-mi", nsg_int)]
vm_ids = {v: azid("halyard-app-rg", "Microsoft.Compute", "virtualMachines/" + v) for v, _, _ in vms}
res("NZ11", nsg_fd, "azure", AZ, "azure_network_security_group", "app-frontdoor-nsg",
    {"rules": [{"name": "allow-https-frontdoor", "port": 443, "source": "AzureFrontDoor.Backend", "access": "Allow", "priority": 100},
               {"name": "deny-all-inbound", "port": "*", "source": "*", "access": "Deny", "priority": 4096}]},
    [rel("allows_traffic_to", vm_ids[v], "tcp/443 from AzureFrontDoor.Backend") for v, _, n in vms if n == nsg_fd], region="eastus",
    why="443 only from the Front Door service tag; Front Door has WAF.")
res("NZ11", nsg_int, "azure", AZ, "azure_network_security_group", "app-internal-nsg",
    {"rules": [{"name": "allow-vnet", "port": "*", "source": "VirtualNetwork", "access": "Allow", "priority": 100}]},
    [rel("allows_traffic_to", vm_ids[v], "VirtualNetwork only") for v, _, n in vms if n == nsg_int], region="eastus",
    why="VNet-internal traffic only.")
for v, mi, n in vms:
    res("NZ11", vm_ids[v], "azure", AZ, "azure_virtual_machine", v,
        {"public_ip": None, "os": "linux", "disk_encryption": "platform-managed", "tags": {"environment": "production"}},
        [rel("attached_to", n), rel("runs_as", mis[mi])], region="eastus",
        why="No public IP; reachable only via Front Door or the VNet; identity is a single-scope reader.")
kv = res("NZ11", azid("halyard-sec-rg", "Microsoft.KeyVault", "vaults/halyard-app-kv"), "azure", AZ, "azure_key_vault", "halyard-app-kv",
         {"public_network_access": "Disabled", "rbac_authorization": True, "soft_delete": True, "purge_protection": True}, region="eastus",
         why="Private key vault with RBAC, purge protection.")

# ------------------------------------------------------------------ NZ12 GitHub protected repos + pinned OIDC deploy roles
repos = ["storefront", "checkout", "account-portal", "search", "partner-api", "notifications-api", "pricing-api", "data-pipelines",
         "terraform-live", "terraform-modules", "eks-platform", "observability", "design-system", "public-sdk", "docs-site"]
deploy_roles = {}
for r_ in ["storefront", "checkout", "data-pipelines", "terraform-live", "eks-platform"]:
    acct = DATA if r_ == "data-pipelines" else PROD
    deploy_roles[r_] = res("NZ12", role_arn(acct, "gha-%s-deploy" % r_), "aws", acct, "aws_iam_role", "gha-%s-deploy" % r_,
                           {"trust": "token.actions.githubusercontent.com sub=repo:halyard/%s:environment:production, aud=sts.amazonaws.com" % r_,
                            "inline_policy": ("plan/apply limited by permissions boundary deploy-boundary; no iam:CreateUser, no organizations:*"
                                              if r_ == "terraform-live" else "ecr:PushImage on %s; ecs:UpdateService on %s; cloudformation on app-%s-*" % (r_, r_, r_)),
                            "permissions_boundary": "arn:aws:iam::%s:policy/deploy-boundary" % acct},
                           why="OIDC trust pinned to the repo's protected 'production' environment (required reviewers), not to any branch.")
for r_ in repos:
    public = r_ in ("public-sdk", "docs-site")
    rid = res("NZ12", "github.com/halyard/" + r_, "github", GH, "github_repository", "halyard/" + r_,
              {"default_branch": "main", "branch_protection": True, "required_approving_reviews": 2, "require_code_owner_reviews": True,
               "dismiss_stale_reviews": True, "enforce_admins": True, "allow_force_pushes": False, "required_signatures": r_ in ("terraform-live", "eks-platform"),
               "environments": ({"production": {"required_reviewers": ["@halyard/release-managers"], "deployment_branch_policy": "protected"}}
                                if r_ in deploy_roles else {}),
               "visibility": "public" if public else "private", "secret_scanning": True, "dependabot": r_ not in ("design-system", "observability", "search")},
              [rel("can_assume", deploy_roles[r_], "GitHub OIDC sub repo:halyard/%s:environment:production" % r_)] if r_ in deploy_roles else None,
              why="Branch protection with 2 reviews, CODEOWNERS, admins enforced; deploys gated by a protected environment.")
    if public:
        weak(rid, "repository_private", "MEDIUM", ["PUBLIC_DATA_STORE"], "Repository halyard/%s is public" % r_)
    if r_ in ("design-system", "observability", "search"):
        weak(rid, "repository_dependabot_enabled", "LOW", ["SECRET_EXPOSURE"], "Dependabot alerts disabled on halyard/%s" % r_)

# ------------------------------------------------------------------ NZ13 IAM users with MFA and rotated keys
users = ["alice.ng", "bruno.costa", "chen.wei", "dana.okafor", "eli.schwartz", "farah.haddad", "gus.lindqvist", "hana.sato",
         "ivan.petrov", "jo.mensah", "kai.andersen", "lena.morel", "svc-backup-agent", "svc-metrics-pusher", "ops-admin-mfa"]
grp_dev = res("NZ13", "arn:aws:iam::%s:group/engineers" % PROD, "aws", PROD, "aws_iam_group", "engineers",
              {"attached_policies": ["arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"], "inline_policy": "sts:AssumeRole on SSO-provisioned roles only with MFA"},
              why="View-only group; anything more requires MFA-conditioned role assumption.")
grp_svc = res("NZ13", "arn:aws:iam::%s:group/service-agents" % PROD, "aws", PROD, "aws_iam_group", "service-agents",
              {"inline_policy": "cloudwatch:PutMetricData; s3:PutObject on halyard-backup-drop/* with aws:SourceIp 10.0.0.0/8"},
              why="Write-only metrics/backup drop, source-IP restricted to the VPC.")
for i, u in enumerate(users):
    svc = u.startswith("svc-")
    attrs = {"mfa_active": not svc, "mfa_type": None if svc else ("hardware" if i % 3 == 0 else "virtual"),
             "console_access": not svc, "access_key_1_active": svc or i % 4 == 1,
             "access_key_1_age_days": [12, 47, 63, 29, 81, 5, 33, 70, 18, 55, 41, 88, 22, 37, 9][i], "password_age_days": 30 + 3 * i,
             "groups": ["service-agents"] if svc else ["engineers"]}
    rels = [rel("member_of", grp_svc if svc else grp_dev)]
    if u == "ops-admin-mfa":
        attrs.update({"attached_policies": ["arn:aws:iam::aws:policy/AdministratorAccess"], "access_key_1_active": False, "mfa_type": "hardware",
                      "console_access": True, "conditions": "aws:MultiFactorAuthPresent required by account SCP"})
    if svc:
        attrs["access_key_source_ip_condition"] = "10.0.0.0/8"
    rid = res("NZ13", user_arn(PROD, u), "aws", PROD, "aws_iam_user", u, attrs, rels,
              why="MFA on (or no console for service users), keys under 90 days, view-only or IP-restricted write.")
    if attrs["mfa_type"] == "virtual" and i in (1, 4, 7):
        weak(rid, "iam_user_hardware_mfa_enabled", "LOW", ["NO_MFA"], "IAM user %s uses virtual (not hardware) MFA" % u,
             {"mfa_active": True})
    if u == "ops-admin-mfa":
        weak(rid, "iam_aws_attached_policy_no_administrative_privileges", "HIGH", ["OVERPRIVILEGED_IDENTITY"], "IAM user ops-admin-mfa has AdministratorAccess")
    if u == "svc-metrics-pusher":
        weak(rid, "iam_user_no_setup_initial_access_key", "LOW", ["STALE_CREDENTIALS"], "Access key created at user setup", {"access_key_1_age_days": attrs["access_key_1_age_days"]})

# ------------------------------------------------------------------ NZ14 non-KEV low-EPSS CVEs on private hosts
cves = [("CVE-2023-5678", "openssl", 5.3, 0.0021), ("CVE-2024-0727", "openssl", 5.5, 0.0012), ("CVE-2023-6129", "openssl", 6.5, 0.0009),
        ("CVE-2024-2511", "openssl", 5.9, 0.0015), ("CVE-2023-7008", "systemd", 5.9, 0.0007), ("CVE-2024-28182", "nghttp2", 5.3, 0.0031),
        ("CVE-2023-50495", "ncurses", 6.5, 0.0006), ("CVE-2023-39804", "tar", 6.2, 0.0004), ("CVE-2022-48522", "perl", 7.5, 0.0019),
        ("CVE-2024-26458", "krb5", 5.3, 0.0005), ("CVE-2023-4641", "shadow-utils", 4.7, 0.0004), ("CVE-2024-22365", "pam", 5.5, 0.0005)]
wsg = sg_arn(PROD, "workers-internal-sg"); bsg = sg_arn(DATA, "etl-internal-sg")
wrole = role_arn(PROD, "workers-instance-role"); brole = role_arn(DATA, "etl-instance-role")
hosts = [("worker-%02d" % n, PROD, wsg, wrole) for n in range(1, 8)] + [("etl-%02d" % n, DATA, bsg, brole) for n in range(1, 6)]
res("NZ14", wsg, "aws", PROD, "aws_security_group", "workers-internal-sg",
    {"ingress": [{"protocol": "tcp", "from_port": 9100, "to_port": 9100, "cidr": "10.0.0.0/16", "description": "metrics scrape"}]},
    [rel("allows_traffic_to", inst_arn(PROD, h_[0]), "tcp/9100 from 10.0.0.0/16") for h_ in hosts if h_[1] == PROD], region=R,
    why="RFC1918 ingress only.")
res("NZ14", bsg, "aws", DATA, "aws_security_group", "etl-internal-sg", {"ingress": []}, region=R, why="No ingress at all (SSM only).")
res("NZ14", wrole, "aws", PROD, "aws_iam_role", "workers-instance-role",
    {"attached_policies": ["arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"], "inline_policy": "sqs:ReceiveMessage,DeleteMessage on jobs-*"},
    why="Queue consumer role.")
res("NZ14", brole, "aws", DATA, "aws_iam_role", "etl-instance-role",
    {"attached_policies": ["arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"], "inline_policy": "read on halyard-analytics-raw via VPC endpoint"},
    [rel("grants_access_to", data_stores["halyard-analytics-raw"], "VPC-endpoint conditioned read")],
    why="ETL role reading analytics data; hosts have no ingress at all.")
for i, (name, acct, sg, role) in enumerate(hosts):
    rid = res("NZ14", inst_arn(acct, name), "aws", acct, "aws_instance", name,
              {"tags": {"environment": "production", "tier": "worker"}, "public_ip": None, "subnet": "private-worker",
               "metadata_http_tokens": "required", "metadata_hop_limit": 1},
              [rel("attached_to", sg), rel("runs_as", role)], region=R,
              why="Private host (no public IP, RFC1918/no ingress), IMDSv2; CVEs are local/low-impact, not in KEV, EPSS < 1%.")
    for c in ([cves[i]] + ([cves[(i + 5) % len(cves)]] if i % 3 == 0 else [])):
        cid, pkg, cvss, epss = c
        weak(rid, cid, "MEDIUM" if cvss >= 6 else "LOW", ["UNPATCHED"], "%s in %s on %s" % (cid, pkg, name),
             {"cve": cid, "package": pkg, "cvss": cvss, "epss": epss, "epss_percentile": round(epss * 30, 3), "kev": False,
              "network_reachable": False, "exploit_maturity": "none-known"})

# ------------------------------------------------------------------ NZ15 dev / sandbox (tagged)
devtags = {"environment": "dev", "data_classification": "synthetic", "owner": "eng-productivity"}
dsg = sg_arn(DEV, "dev-vpn-only"); dlegacy = sg_arn(DEV, "legacy-default-ssh"); drole = role_arn(DEV, "dev-app-role")
dinsts = [inst_arn(DEV, "dev-app-%02d" % n) for n in (1, 2, 3)]
dbuckets = ["halyard-dev-fixtures", "halyard-dev-build-cache", "halyard-dev-scratch"]
res("NZ15", dsg, "aws", DEV, "aws_security_group", "dev-vpn-only",
    {"ingress": [{"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr": "10.20.0.0/16", "description": "corp VPN pool"}]},
    [rel("allows_traffic_to", i, "tcp/22 from VPN pool") for i in dinsts], region=R, why="VPN-only.")
rid = res("NZ15", dlegacy, "aws", DEV, "aws_security_group", "legacy-default-ssh",
          {"ingress": [{"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr": "0.0.0.0/0"}], "attached_network_interfaces": 0,
           "tags": devtags}, region=R, why="Open SSH rule but attached to nothing (0 ENIs).")
weak(rid, "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22", "HIGH", ["PUBLIC_NETWORK_EXPOSURE"],
     "Security group legacy-default-ssh allows SSH from 0.0.0.0/0", {"exposure_cidrs": ["0.0.0.0/0"], "exposure_ports": [22]})
res("NZ15", drole, "aws", DEV, "aws_iam_role", "dev-app-role",
    {"inline_policy": "s3:* on halyard-dev-* buckets", "trust_principals": ["ec2.amazonaws.com"], "tags": devtags},
    [rel("grants_access_to", s3(b), "dev buckets only") for b in dbuckets], why="Dev-only data, synthetic.")
for n, i in enumerate(dinsts, 1):
    rid = res("NZ15", i, "aws", DEV, "aws_instance", "dev-app-%02d" % n,
              {"tags": devtags, "public_ip": None, "metadata_http_tokens": "optional", "subnet": "dev-private"},
              [rel("attached_to", dsg), rel("runs_as", drole)], region=R,
              why="IMDSv1 but private, VPN-only, dev role touches only synthetic dev buckets.")
    weak(rid, "ec2_instance_imdsv2_enabled", "MEDIUM", ["IMDSV1_ENABLED"], "EC2 instance dev-app-%02d allows IMDSv1" % n)
for b in dbuckets:
    rid = res("NZ15", s3(b), "aws", DEV, "aws_s3_bucket", b, {"tags": devtags, "public_access_block": True, "encryption": None}, region=R,
              why="Private dev bucket with synthetic data.")
    weak(rid, "s3_bucket_default_encryption", "MEDIUM", ["UNENCRYPTED_AT_REST"], "S3 bucket %s has no default encryption" % b)
rid = res("NZ15", rds(DEV, "dev-orders-db"), "aws", DEV, "aws_db_instance", "dev-orders-db",
          {"tags": devtags, "publicly_accessible": False, "storage_encrypted": False, "multi_az": False, "engine": "postgres"}, region=R,
          why="Private dev database with synthetic data.")
weak(rid, "rds_instance_storage_encrypted", "MEDIUM", ["UNENCRYPTED_AT_REST", "DATABASE"], "RDS instance dev-orders-db is not encrypted")
weak(rid, "rds_instance_multi_az", "LOW", ["NO_BACKUP", "DATABASE"], "RDS instance dev-orders-db is not Multi-AZ")
sbtags = {"environment": "sandbox", "data_classification": "none", "owner": "eng-sandbox", "auto_delete_after_days": "14"}
ssg = sg_arn(SBX, "sandbox-ssh"); srole = role_arn(SBX, "sandbox-ssm-only"); sinst = inst_arn(SBX, "sandbox-bastion-test")
res("NZ15", ssg, "aws", SBX, "aws_security_group", "sandbox-ssh",
    {"ingress": [{"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr": "0.0.0.0/0"}], "tags": sbtags},
    [rel("allows_traffic_to", sinst, "tcp/22")], region=R, why="Sandbox SSH test; host has nothing behind it.")
weak(ssg, "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22", "HIGH", ["PUBLIC_NETWORK_EXPOSURE"],
     "Security group sandbox-ssh allows SSH from 0.0.0.0/0", {"exposure_cidrs": ["0.0.0.0/0"], "exposure_ports": [22]})
res("NZ15", srole, "aws", SBX, "aws_iam_role", "sandbox-ssm-only",
    {"attached_policies": ["arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"], "tags": sbtags}, why="SSM core only; no data access.")
rid = res("NZ15", sinst, "aws", SBX, "aws_instance", "sandbox-bastion-test",
          {"tags": sbtags, "public_ip": "198.51.100.77", "metadata_http_tokens": "required", "key_pair": None, "ssh_password_auth": False},
          [rel("attached_to", ssg), rel("runs_as", srole)], region=R,
          why="Public SSH in sandbox, key-only auth with no key pair installed, IMDSv2, role is SSM-only: no impact reachable.")
weak(rid, "ec2_instance_port_ssh_exposed_to_internet", "HIGH", ["PUBLIC_NETWORK_EXPOSURE"], "EC2 instance sandbox-bastion-test reachable on SSH from 0.0.0.0/0",
     {"exposure_cidrs": ["0.0.0.0/0"], "exposure_ports": [22]})
weak(rid, "ec2_instance_public_ip", "MEDIUM", ["PUBLIC_NETWORK_EXPOSURE"], "EC2 instance sandbox-bastion-test has a public IP")
rid = res("NZ15", role_arn(SBX, "sandbox-poweruser"), "aws", SBX, "aws_iam_role", "sandbox-poweruser",
          {"attached_policies": ["arn:aws:iam::aws:policy/PowerUserAccess"], "trust": SSO_TRUST, "tags": sbtags,
           "scp": "sandbox OU: deny sts:AssumeRole to any non-sandbox account; deny vpc peering"}, [rel("trusts", SSO)],
          why="Sandbox power user via SSO+MFA; SCP blocks pivoting out of sandbox.")
weak(rid, "iam_policy_allows_privilege_escalation", "HIGH", ["OVERPRIVILEGED_IDENTITY"], "Role sandbox-poweruser has PowerUserAccess")
rid = res("NZ15", s3("halyard-sandbox-public-fixtures"), "aws", SBX, "aws_s3_bucket", "halyard-sandbox-public-fixtures",
          {"tags": sbtags, "public_access_block": False, "bucket_policy_principal": "*", "bucket_policy_actions": ["s3:GetObject"],
           "object_prefixes": ["fixtures/lorem/", "fixtures/images/"]}, region=R, why="Public sandbox fixtures; lorem-ipsum data.")
weak(rid, "s3_bucket_public_access", "HIGH", ["PUBLIC_DATA_STORE"], "S3 bucket halyard-sandbox-public-fixtures allows public read")
eks_dev = "arn:aws:eks:%s:%s:cluster/halyard-eks-dev" % (R, DEV)
rid = res("NZ15", eks_dev, "aws", DEV, "aws_eks_cluster", "halyard-eks-dev",
          {"endpoint_public_access": True, "endpoint_private_access": True, "public_access_cidrs": ["203.0.113.0/24"], "tags": devtags},
          region=R, why="Public endpoint restricted to the corporate egress /24; dev cluster; auth via SSO access entries.")
weak(rid, "eks_control_plane_endpoint_access_publicly_accessible", "MEDIUM", ["PUBLIC_NETWORK_EXPOSURE", "K8S_API"],
     "EKS dev API endpoint is public (restricted to 203.0.113.0/24)", {"exposure_cidrs": ["203.0.113.0/24"]})
rid = res("NZ15", "dev-tools/pod/devbox-0", "kubernetes", EKSDEV, "k8s_pod", "devbox-0",
          {"namespace": "dev-tools", "service_account": "default", "run_as_non_root": False, "image": "ghcr.io/halyard/devbox:2026.09"},
          region=None, why="Dev cluster pod running as root, no exposure, default SA with no bindings.")
weak(rid, "core_minimize_root_containers_admission", "MEDIUM", ["RUNS_AS_ROOT"], "Pod devbox-0 runs as root")
dsa = res("NZ15", gsa(GCPDEV, "dev-runner-sa"), "gcp", GCPDEV, "gcp_service_account", "dev-runner-sa@%s.iam.gserviceaccount.com" % GCPDEV,
          {"project_roles": ["roles/editor"], "project_labels": {"env": "dev", "data": "synthetic"}},
          why="Editor on a dev project with synthetic data; project has no shared VPC or IAM bindings into prod.")
weak(dsa, "iam_role_assigned_to_user_or_sa_primitive", "MEDIUM", ["OVERPRIVILEGED_IDENTITY"], "dev-runner-sa holds roles/editor on halyard-dev-gcp")
res("NZ15", gce(GCPDEV, "us-central1-b", "dev-runner-1"), "gcp", GCPDEV, "gcp_compute_instance", "dev-runner-1",
    {"external_ip": None, "service_account": dsa.split("/")[-1], "labels": {"env": "dev"}}, [rel("runs_as", dsa)], region="us-central1",
    why="No external IP; IAP-only; dev project.")

# ------------------------------------------------------------------ NZ90 near-misses (alarming names, benign attributes)
nm = []
def near(rid, provider, acct, rtype, name, attrs, why, rels=None, region=R, w=None):
    res("NZ90", rid, provider, acct, rtype, name, attrs, rels, region=region, why=why, near=True)
    if w: weak(rid, *w)
    nm.append(rid)
near(s3("prod-admin-backup"), "aws", PROD, "aws_s3_bucket", "prod-admin-backup",
     {"tags": {"environment": "production", "data_classification": "internal", "contents": "admin-console UI build artefacts"},
      "public_access_block": True, "encryption": "aws:kms", "object_lock": "COMPLIANCE 30d", "versioning": True},
     "Private, KMS, object-locked; contains UI build artefacts, not credentials.")
near(s3("pii-export-test"), "aws", DEV, "aws_s3_bucket", "pii-export-test",
     {"tags": {"environment": "dev", "data_classification": "synthetic", "generator": "faker 24.x"}, "public_access_block": True, "encryption": "AES256"},
     "Dev bucket of Faker-generated records used to test the PII export job; private.")
near(s3("public-pii-redacted-reports"), "aws", PROD, "aws_s3_bucket", "public-pii-redacted-reports",
     {"tags": {"environment": "production", "data_classification": "public", "contents": "aggregate transparency reports (k-anonymised)"},
      "public_access_block": False, "bucket_policy_principal": "*", "bucket_policy_actions": ["s3:GetObject"], "object_prefixes": ["reports/2025/", "reports/2026/"]},
     "Public by design: published transparency reports, tagged public, no row-level data.",
     w=("s3_bucket_public_access", "HIGH", ["PUBLIC_DATA_STORE"], "S3 bucket public-pii-redacted-reports allows public read"))
pa_role = role_arn(PROD, "prod-admin-api-role")
near(fn_arn(PROD, "prod-admin-api"), "aws", PROD, "aws_lambda_function", "prod-admin-api",
     {"function_url_auth_type": "AWS_IAM", "invoked_by": "SSO-authenticated admin console via SigV4"},
     "Admin API URL requires SigV4; role is read-only.", [rel("runs_as", pa_role)])
near(pa_role, "aws", PROD, "aws_iam_role", "prod-admin-api-role",
     {"trust_principals": ["lambda.amazonaws.com"], "attached_policies": ["arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"]},
     "Despite the name, view-only.", region=None)
cplb_sg = sg_arn(PROD, "customer-portal-lb-sg"); cplb = alb_arn(PROD, "customer-portal-lb"); cp_ecs = "arn:aws:ecs:%s:%s:service/halyard-prod/customer-portal" % (R, PROD)
near(cplb_sg, "aws", PROD, "aws_security_group", "customer-portal-lb-sg",
     {"ingress": [{"protocol": "tcp", "from_port": 443, "to_port": 443, "cidr": "0.0.0.0/0"}]}, "443 to the portal ALB, by design.",
     [rel("allows_traffic_to", cplb, "tcp/443")],
     w=("ec2_securitygroup_allow_wide_open_public_ipv4", "MEDIUM", ["PUBLIC_NETWORK_EXPOSURE"], "Security group customer-portal-lb-sg allows ingress from 0.0.0.0/0", {"exposure_cidrs": ["0.0.0.0/0"], "exposure_ports": [443]}))
near(cplb, "aws", PROD, "aws_lb", "customer-portal-lb",
     {"scheme": "internet-facing", "listeners": [{"port": 443, "protocol": "HTTPS"}], "authentication": "OIDC (customer IdP)", "waf_web_acl": "halyard-regional-waf"},
     "Customer portal front door; OIDC authenticated at the ALB.", [rel("attached_to", cplb_sg), rel("allows_traffic_to", cp_ecs, "443 -> 8443")])
near(cp_ecs, "aws", PROD, "aws_ecs_service", "customer-portal",
     {"launch_type": "FARGATE", "assign_public_ip": False}, "Fargate private; task role reads only the portal's own session table.",
     [rel("runs_as", role_arn(PROD, "customer-portal-task-role"))])
near(role_arn(PROD, "customer-portal-task-role"), "aws", PROD, "aws_iam_role", "customer-portal-task-role",
     {"trust_principals": ["ecs-tasks.amazonaws.com"], "inline_policy": "dynamodb:GetItem,PutItem on halyard-sessions with LeadingKeys = ${aws:PrincipalTag/tenant}"},
     "Tenant-scoped session access only.", [rel("grants_access_to", data_stores["halyard-sessions"], "tenant-scoped")], region=None)
near(role_arn(SEC, "root-access-audit"), "aws", SEC, "aws_iam_role", "root-access-audit",
     {"attached_policies": ["arn:aws:iam::aws:policy/SecurityAudit"], "purpose": "reviews root account usage alerts", "trust": SSO_TRUST},
     "Audits root usage; read-only; SSO+MFA.", [rel("trusts", SSO)], region=None)
near(role_arn(PROD, "breakglass-admin"), "aws", PROD, "aws_iam_role", "breakglass-admin",
     {"attached_policies": ["arn:aws:iam::aws:policy/AdministratorAccess"], "trust": SSO_TRUST, "last_used_days": 212,
      "alarm": "EventBridge -> PagerDuty on AssumeRole", "approval": "two-person rule in Okta workflow"},
     "Break-glass admin reachable only via SSO+MFA with two-person approval and paging.", [rel("trusts", SSO)], region=None,
     w=("iam_aws_attached_policy_no_administrative_privileges", "HIGH", ["OVERPRIVILEGED_IDENTITY"], "Role breakglass-admin has AdministratorAccess"))
srl_role = role_arn(PROD, "secrets-rotation-lambda-role")
near(fn_arn(PROD, "secrets-rotation-lambda"), "aws", PROD, "aws_lambda_function", "secrets-rotation-lambda",
     {"function_url_auth_type": None, "triggers": ["secretsmanager rotation schedule"], "vpc_config": "private"},
     "No URL, invoked only by Secrets Manager rotation.", [rel("runs_as", srl_role)])
near(srl_role, "aws", PROD, "aws_iam_role", "secrets-rotation-lambda-role",
     {"trust_principals": ["lambda.amazonaws.com"], "inline_policy": "secretsmanager:RotateSecret,PutSecretValue on secret:prod/db/orders-*"},
     "Rotation rights on one secret family; function is not externally invocable.", region=None)
near(inst_arn(PROD, "admin-jumphost"), "aws", PROD, "aws_instance", "admin-jumphost",
     {"public_ip": None, "metadata_http_tokens": "required", "access": "SSM Session Manager only", "ssh_daemon": "disabled", "tags": {"environment": "production"}},
     "No public IP, no SSH, SSM with SSO only; no instance role beyond SSM core.")
near(user_arn(PROD, "svc-prod-admin-legacy"), "aws", PROD, "aws_iam_user", "svc-prod-admin-legacy",
     {"console_access": False, "access_key_1_active": False, "access_key_2_active": False, "attached_policies": [], "groups": [], "mfa_active": False},
     "Orphaned user with no credentials and no policies: cannot authenticate or do anything.", region=None,
     w=("iam_user_mfa_enabled_console_access", "LOW", ["NO_MFA"], "IAM user svc-prod-admin-legacy has no MFA device", {"console_access": False}))
near(role_arn(PROD, "wildcard-trust-role"), "aws", PROD, "aws_iam_role", "wildcard-trust-role",
     {"trust_principals": ["lambda.amazonaws.com"], "trust_conditions": {"ArnLike": {"aws:SourceArn": "arn:aws:lambda:us-east-1:%s:function:report-renderer" % PROD}},
      "inline_policy": "logs:CreateLogStream,PutLogEvents"}, "Name is historical; trust is service-only with SourceArn pin; logs only.", region=None)
near("arn:aws:kms:%s:%s:key/%s" % (R, PROD, "mrk-" + h("kms-admin-key", 32)), "aws", PROD, "aws_kms_key", "kms-admin-key",
     {"key_policy_admins": ["arn:aws:iam::%s:role/org-admin-sso" % PROD], "key_users": ["arn:aws:iam::%s:role/checkout-instance-role" % PROD], "rotation": True},
     "Key administered by the SSO-only admin role; rotation on.")
near("arn:aws:ssm:%s:%s:parameter/prod/db/master-password" % (R, PROD), "aws", PROD, "aws_ssm_parameter", "/prod/db/master-password",
     {"type": "SecureString", "kms_key": "alias/halyard-data", "readers": ["checkout-instance-role"], "tier": "Standard"},
     "Encrypted parameter readable only by a private, IMDSv2-only workload role.")
near("cluster/clusterrolebinding/cluster-admin-viewer", "kubernetes", EKS, "k8s_cluster_role_binding", "cluster-admin-viewer",
     {"role_ref": "ClusterRole/view", "subjects": ["Group:sso:platform-oncall"]},
     "Binds the built-in read-only 'view' ClusterRole (not cluster-admin) to an SSO group.", [rel("bound_to", "cluster/clusterrole/view")], region=None)
near("cluster/clusterrole/view", "kubernetes", EKS, "k8s_cluster_role", "view",
     {"aggregated": True, "verbs": ["get", "list", "watch"], "excludes": ["secrets"]}, "Built-in read-only role; no secrets.", region=None)
near("sandbox/serviceaccount/root-deployer", "kubernetes", EKSDEV, "k8s_service_account", "root-deployer",
     {"namespace": "sandbox", "automount_service_account_token": False, "bindings": "Role/sandbox-deploy (namespace sandbox: deployments, services)"},
     "Namespaced deploy rights in a dev sandbox namespace; no cluster scope.", region=None)
near(gsa(GCP, "owner-sa-legacy"), "gcp", GCP, "gcp_service_account", "owner-sa-legacy@%s.iam.gserviceaccount.com" % GCP,
     {"disabled": True, "project_roles": [], "user_managed_keys": 0, "note": "roles removed 2025-11; kept for audit trail"},
     "Disabled, no roles, no keys.", region=None)
near(gsa(GCP, "pii-warehouse-reader"), "gcp", GCP, "gcp_service_account", "pii-warehouse-reader@%s.iam.gserviceaccount.com" % GCP,
     {"project_roles": [], "dataset_roles": [{"role": "roles/bigquery.dataViewer", "dataset": "public_aggregates"}], "user_managed_keys": 0,
      "attached_to": "no workloads (Workload Identity for a scheduled query only)"},
     "Reads an aggregate (non-PII) dataset; no keys; not attached to any exposed workload.", region=None)
near(azid("halyard-sec-rg", "Microsoft.KeyVault", "vaults/prodadminsecrets"), "azure", AZ, "azure_key_vault", "prodadminsecrets",
     {"public_network_access": "Disabled", "private_endpoint": True, "rbac_authorization": True, "purge_protection": True},
     "Private key vault, RBAC-only, no public network.", region="eastus")
near(azid("halyard-data-rg", "Microsoft.Storage", "storageAccounts/customerpiiarchive"), "azure", AZ, "azure_storage_account", "customerpiiarchive",
     {"allow_blob_public_access": False, "public_network_access": "Disabled", "immutability": "time-based 7y", "shared_key_access": False,
      "tags": {"data_classification": "pii", "environment": "production"}},
     "Sensitive but locked down: no public blob, no public network, no shared keys; no principal in the estate is granted access.", region="eastus")
near("github.com/halyard/infra-prod-admin", "github", GH, "github_repository", "halyard/infra-prod-admin",
     {"default_branch": "main", "branch_protection": True, "required_approving_reviews": 2, "require_code_owner_reviews": True, "enforce_admins": True,
      "visibility": "private", "oidc_roles": []}, "Protected, private, no cloud trust.", region=None)

# ------------------------------------------------------------------ NZT1 deliberate true positives (labelled)
tp_paths = []
# TP1: internet SSH -> IMDSv1 instance -> role -> confidential bucket
t1sg = sg_arn(PROD, "legacy-reports-ssh"); t1i = inst_arn(PROD, "legacy-reports-01"); t1r = role_arn(PROD, "legacy-reports-role"); t1b = s3("halyard-finance-ledger")
res("NZT1", t1sg, "aws", PROD, "aws_security_group", "legacy-reports-ssh",
    {"ingress": [{"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr": "0.0.0.0/0"}]}, [rel("allows_traffic_to", t1i, "tcp/22")], region=R,
    why="TRUE POSITIVE TP1 entry.", tp="TP1")
w1 = weak(t1sg, "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22", "HIGH", ["PUBLIC_NETWORK_EXPOSURE"],
          "Security group legacy-reports-ssh allows SSH from 0.0.0.0/0", {"exposure_cidrs": ["0.0.0.0/0"], "exposure_ports": [22]})
res("NZT1", t1i, "aws", PROD, "aws_instance", "legacy-reports-01",
    {"tags": {"environment": "production", "owner": "finance-eng"}, "public_ip": "198.51.100.140", "metadata_http_tokens": "optional",
     "ssh_password_auth": True, "instance_profile": "legacy-reports-profile"},
    [rel("attached_to", t1sg), rel("runs_as", t1r, "instance profile legacy-reports-profile")], region=R, why="TRUE POSITIVE TP1 foothold.", tp="TP1")
w2 = weak(t1i, "ec2_instance_port_ssh_exposed_to_internet", "HIGH", ["PUBLIC_NETWORK_EXPOSURE"], "EC2 instance legacy-reports-01 reachable on SSH from 0.0.0.0/0",
          {"exposure_cidrs": ["0.0.0.0/0"], "exposure_ports": [22]})
w3 = weak(t1i, "ec2_instance_imdsv2_enabled", "HIGH", ["IMDSV1_ENABLED"], "EC2 instance legacy-reports-01 allows IMDSv1")
res("NZT1", t1r, "aws", PROD, "aws_iam_role", "legacy-reports-role",
    {"trust_principals": ["ec2.amazonaws.com"], "inline_policy": "s3:GetObject, s3:ListBucket on halyard-finance-ledger/*"},
    [rel("grants_access_to", t1b, "inline policy LedgerRead")], why="TRUE POSITIVE TP1 credential.", tp="TP1")
res("NZT1", t1b, "aws", PROD, "aws_s3_bucket", "halyard-finance-ledger",
    {"tags": {"data_classification": "confidential", "environment": "production", "owner": "finance"}, "public_access_block": True, "encryption": "aws:kms"},
    region=R, why="TRUE POSITIVE TP1 target.", tp="TP1")
tp_paths.append({"id": "TP1", "expected_paths": 1, "kind": "internet -> host (SSH, IMDSv1) -> instance role -> confidential data",
                 "entry": t1sg, "target": t1b, "chain": [t1sg, t1i, t1r, t1b], "findings": [w1, w2, w3],
                 "rationale": "SSH (password auth) open to 0.0.0.0/0 on a public-IP host with IMDSv1; its role can read the confidential finance ledger."})
# TP2: unprotected repo -> OIDC (any ref) -> admin role in prod
t2repo = "github.com/halyard/release-tools"; t2role = role_arn(PROD, "gha-release-tools")
res("NZT1", t2repo, "github", GH, "github_repository", "halyard/release-tools",
    {"default_branch": "main", "branch_protection": False, "visibility": "private", "outside_collaborators": 4},
    [rel("can_assume", t2role, "GitHub OIDC sub repo:halyard/release-tools:*")], why="TRUE POSITIVE TP2 entry.", tp="TP2")
w4 = weak(t2repo, "repository_default_branch_protection_enabled", "HIGH", ["BRANCH_UNPROTECTED"], "Default branch main of halyard/release-tools has no protection")
res("NZT1", t2role, "aws", PROD, "aws_iam_role", "gha-release-tools",
    {"trust": "token.actions.githubusercontent.com sub=repo:halyard/release-tools:*", "attached_policies": ["arn:aws:iam::aws:policy/AdministratorAccess"]},
    why="TRUE POSITIVE TP2 target.", tp="TP2")
w5 = weak(t2role, "iam_aws_attached_policy_no_administrative_privileges", "HIGH", ["OVERPRIVILEGED_IDENTITY"], "GitHub OIDC role gha-release-tools has AdministratorAccess")
tp_paths.append({"id": "TP2", "expected_paths": 1, "kind": "unprotected repo -> OIDC wildcard sub -> prod admin role",
                 "entry": t2repo, "target": t2role, "chain": [t2repo, t2role], "findings": [w4, w5],
                 "rationale": "Any push to any branch (4 outside collaborators, no protection) can mint OIDC tokens accepted by a prod AdministratorAccess role."})
# TP3: public Lambda URL -> role -> PII table
t3fn = fn_arn(PROD, "partner-webhook-debug"); t3r = role_arn(PROD, "partner-webhook-debug-role"); t3t = ddb(PROD, "halyard-customer-contacts")
res("NZT1", t3fn, "aws", PROD, "aws_lambda_function", "partner-webhook-debug",
    {"function_url_auth_type": "NONE", "handler": "debug echo + lookup by email", "exposure_cidrs": ["0.0.0.0/0"]},
    [rel("runs_as", t3r)], region=R, why="TRUE POSITIVE TP3 entry.", tp="TP3")
w6 = weak(t3fn, "awslambda_function_url_public", "HIGH", ["PUBLIC_NETWORK_EXPOSURE"], "Lambda function URL partner-webhook-debug has AuthType NONE",
          {"exposure_cidrs": ["0.0.0.0/0"]})
res("NZT1", t3r, "aws", PROD, "aws_iam_role", "partner-webhook-debug-role",
    {"trust_principals": ["lambda.amazonaws.com"], "inline_policy": "dynamodb:Query,Scan,GetItem on halyard-customer-contacts"},
    [rel("grants_access_to", t3t, "inline policy ContactsRead")], why="TRUE POSITIVE TP3 credential.", tp="TP3")
res("NZT1", t3t, "aws", PROD, "aws_dynamodb_table", "halyard-customer-contacts",
    {"tags": {"data_classification": "pii", "environment": "production", "owner": "crm"}, "sse": "aws:kms"},
    region=R, why="TRUE POSITIVE TP3 target.", tp="TP3")
tp_paths.append({"id": "TP3", "expected_paths": 1, "kind": "unauthenticated function URL -> execution role -> PII table",
                 "entry": t3fn, "target": t3t, "chain": [t3fn, t3r, t3t], "findings": [w6],
                 "rationale": "Unauthenticated function URL whose role can Scan the customer contacts (PII) table."})

# ------------------------------------------------------------------ emit
def q(s):
    return json.dumps(s, ensure_ascii=False)
def key(k):
    return k if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*", k) and k not in ("y", "n", "yes", "no", "on", "off", "true", "false", "null") else q(k)
def flow(v):
    if isinstance(v, dict):
        return "{" + ", ".join("%s: %s" % (key(k), flow(x)) for k, x in v.items()) + "}"
    if isinstance(v, list):
        return "[" + ", ".join(flow(x) for x in v) + "]"
    if v is None: return "null"
    if isinstance(v, bool): return "true" if v else "false"
    if isinstance(v, (int, float)): return repr(v)
    return q(v)

hdr = """# nimbus NOISE estate (P0-NOISE): a realistic, benign-but-noisy multi-cloud estate for the fictional org "halyard".
#
# Authored independently of the attack-path engine (see lab/local/noise/AUTHOR_LOG.md for the files the author read).
# A precise engine must NOT turn any of this into an attack path, except the three labelled chains in scenario NZT1
# (TP1..TP3). Labels and per-resource reasons live in lab/noise_truth.yaml, not here; scenario codes NZxx are neutral
# so the generated findings (attribute lab_scenario) do not leak the label to the engine.
#
# Generate (existing generator, no code change; it already takes -in/-out):
#   go run ./lab/local/gen -in lab/local/noise/estate.yaml -out lab/local/out/noise.findings.json
#
# Weakness ids are N001..; their findings get stable ids lab-N001.. Inventory records reuse the generator's
# lab-inv-NN scheme, which collides with the main lab estate's inventory ids: ingest the two estates separately.
# CVE KEV/EPSS values in weakness attributes are asserted by this estate as of authoring (2026-10), not live lookups.
"""
out = [hdr, "version: 1", "name: nimbus-lab-noise", "source: nimbus-lab-noise", "", "accounts:"]
for p, i, l, n in ACCOUNTS:
    d = {"provider": p, "id": i, "label": l}
    if n: d["note"] = n
    out.append("  - " + flow(d))
out += ["", "resources:"]
last = None
for r in resources:
    if r["scenario"] != last:
        out.append("  # ---------------------------------------------------------------- %s" % r["scenario"])
        last = r["scenario"]
    out.append("  - id: %s" % q(r["id"]))
    for k in ("scenario", "provider", "account", "region", "type", "name"):
        if k in r: out.append("    %s: %s" % (k, q(r[k]) if k in ("account", "name") else r[k] if re.fullmatch(r"[A-Za-z0-9_.-]+", r[k]) else q(r[k])))
    if "attributes" in r: out.append("    attributes: " + flow(r["attributes"]))
    if "relationships" in r and r["relationships"]:
        out.append("    relationships:")
        for x in r["relationships"]: out.append("      - " + flow(x))
out += ["", "weaknesses:"]
for w in weaknesses:
    out.append("  - " + flow(w))
os.makedirs(os.path.join(ROOT, "lab/local/noise"), exist_ok=True)
open(os.path.join(ROOT, "lab/local/noise/estate.yaml"), "w").write("\n".join(out) + "\n")

# truth
from collections import Counter, OrderedDict
cc = Counter(truth[r["id"]]["class"] for r in resources)
fc = Counter(truth[w["resource"]]["class"] for w in weaknesses)
T = ["""# Ground truth for the nimbus NOISE estate (lab/local/noise/estate.yaml). Authored with it, independently of the engine.
#
# Semantics
#   expected_paths (per resource): number of attack paths a precise engine should report in which this resource
#     appears as a step. 0 for every decoy and near-miss. Only the members of the three labelled true-positive
#     chains (true_positives below) carry 1.
#   expected_paths_total: the exact number of attack paths a precise engine should report for the whole estate (3).
#     Any reported path whose resource set is not one of the true_positives chains (or a sub-chain of one, sharing its
#     entry and target) is a false positive.
#   findings: the seeded scanner findings (weakness ids; generated finding id = "lab-" + id) on that resource. They are
#     realistic scanner noise: present and individually "true" as scanner output, but not a path.
#   near_miss: the resource name is designed to look alarming (admin/prod/pii/customer/root/secret); attributes are benign.
#   why: the attribute-level reason it is benign (or, for true positives, its role in the chain).
""",
     "version: 1", "estate: lab/local/noise/estate.yaml", "findings_json: lab/local/out/noise.findings.json",
     "author: independent noise-estate author (P0-NOISE); file-read log in lab/local/noise/AUTHOR_LOG.md",
     "authored: 2026-10-09", "expected_paths_total: %d" % len(tp_paths), ""]
T.append("summary:")
T.append("  resources: %d" % len(resources))
T.append("  seeded_findings: %d" % len(weaknesses))
T.append("  near_misses: %d" % sum(1 for v in truth.values() if v["near_miss"]))
T.append("  true_positive_chains: %d" % len(tp_paths))
T.append("  true_positive_resources: %d" % sum(1 for v in truth.values() if v["tp"]))
T.append("  benign_resources: %d" % sum(1 for v in truth.values() if not v["tp"]))
T += ["", "classes:"]
for c, (slug, desc) in CLASSES.items():
    T.append("  %s: %s" % (c, flow({"slug": slug, "resources": cc.get(c, 0), "findings": fc.get(c, 0), "description": desc})))
T += ["", "true_positives:"]
for t in tp_paths:
    T.append("  - id: %s" % t["id"])
    for k in ("expected_paths", "kind", "entry", "target", "chain", "findings", "rationale"):
        T.append("    %s: %s" % (k, flow(t[k])))
T += ["", "resources:"]
for r in resources:
    v = truth[r["id"]]
    d = OrderedDict([("id", r["id"]), ("class", v["class"]), ("expected_paths", 1 if v["tp"] else 0)])
    if v["tp"]: d["true_positive"] = v["tp"]
    if v["near_miss"]: d["near_miss"] = True
    if v["findings"]: d["findings"] = v["findings"]
    d["why"] = v["why"]
    T.append("  - " + flow(d))
open(os.path.join(ROOT, "lab/noise_truth.yaml"), "w").write("\n".join(T) + "\n")
print("resources", len(resources), "weaknesses", len(weaknesses), "near", sum(1 for v in truth.values() if v["near_miss"]))
for c in CLASSES: print(c, cc.get(c, 0), fc.get(c, 0))
