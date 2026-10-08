from .conftest import REGION, by_id, run, status_of

AMI = "ami-12c6146b"


def default_vpc(ec2):
    return [v for v in ec2.describe_vpcs()["Vpcs"] if v.get("IsDefault")][0]["VpcId"]


def make_sg(ec2, name, perms):
    gid = ec2.create_security_group(GroupName=name, Description=name, VpcId=default_vpc(ec2))["GroupId"]
    if perms:
        ec2.authorize_security_group_ingress(GroupId=gid, IpPermissions=perms)
    return gid


def tcp(port, cidr="0.0.0.0/0", to=None):
    return {"IpProtocol": "tcp", "FromPort": port, "ToPort": to or port, "IpRanges": [{"CidrIp": cidr}]}


def test_ebs_volume_encryption(ctx):
    ec2 = ctx.client("ec2")
    plain = ec2.create_volume(AvailabilityZone=f"{REGION}a", Size=8)["VolumeId"]
    enc = ec2.create_volume(AvailabilityZone=f"{REGION}a", Size=8, Encrypted=True)["VolumeId"]
    res = run("ec2_ebs_volume_encryption", ctx)
    assert status_of(res, plain) == "FAIL"
    assert status_of(res, enc) == "PASS"


def test_ebs_default_encryption(ctx):
    assert run("ec2_ebs_default_encryption", ctx)[0].status == "FAIL"
    ctx.client("ec2").enable_ebs_encryption_by_default()
    assert run("ec2_ebs_default_encryption", ctx)[0].status == "PASS"


def test_sg_port_22(ctx):
    ec2 = ctx.client("ec2")
    open22 = make_sg(ec2, "open-ssh", [tcp(22)])
    open_range = make_sg(ec2, "open-range", [tcp(20, to=30)])
    v6 = make_sg(ec2, "open-ssh-v6", [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}])
    private = make_sg(ec2, "private-ssh", [tcp(22, "10.0.0.0/8")])
    web = make_sg(ec2, "web", [tcp(443)])
    res = run("ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22", ctx)
    assert status_of(res, open22) == "FAIL"
    assert status_of(res, open_range) == "FAIL"
    assert status_of(res, v6) == "FAIL"
    assert status_of(res, private) == "PASS"
    assert status_of(res, web) == "PASS"


def test_sg_port_3389(ctx):
    ec2 = ctx.client("ec2")
    rdp = make_sg(ec2, "open-rdp", [tcp(3389)])
    ssh = make_sg(ec2, "open-ssh", [tcp(22)])
    res = run("ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_3389", ctx)
    assert status_of(res, rdp) == "FAIL"
    assert status_of(res, ssh) == "PASS"


def test_sg_any_port(ctx):
    ec2 = ctx.client("ec2")
    allp = make_sg(ec2, "all-traffic", [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    full = make_sg(ec2, "full-range", [tcp(0, to=65535)])
    one = make_sg(ec2, "one-port", [tcp(443)])
    res = run("ec2_securitygroup_allow_ingress_from_internet_to_any_port", ctx)
    assert status_of(res, allp) == "FAIL"
    assert status_of(res, full) == "FAIL"
    assert status_of(res, one) == "PASS"


def test_default_sg_restrict(ctx):
    ec2 = ctx.client("ec2")
    sg = [g for g in ec2.describe_security_groups()["SecurityGroups"] if g["GroupName"] == "default"][0]
    gid = sg["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=gid, IpPermissions=[tcp(80)])
    assert status_of(run("ec2_securitygroup_default_restrict_traffic", ctx), gid) == "FAIL"
    ctx.clear_cache()
    sg = ec2.describe_security_groups(GroupIds=[gid])["SecurityGroups"][0]
    if sg["IpPermissions"]:
        ec2.revoke_security_group_ingress(GroupId=gid, IpPermissions=sg["IpPermissions"])
    if sg["IpPermissionsEgress"]:
        ec2.revoke_security_group_egress(GroupId=gid, IpPermissions=sg["IpPermissionsEgress"])
    assert status_of(run("ec2_securitygroup_default_restrict_traffic", ctx), gid) == "PASS"


def test_imdsv2(ctx):
    ec2 = ctx.client("ec2")
    v1 = ec2.run_instances(ImageId=AMI, MinCount=1, MaxCount=1, MetadataOptions={"HttpTokens": "optional"})["Instances"][0]["InstanceId"]
    v2 = ec2.run_instances(ImageId=AMI, MinCount=1, MaxCount=1, MetadataOptions={"HttpTokens": "required"})["Instances"][0]["InstanceId"]
    res = run("ec2_instance_imdsv2_enabled", ctx)
    assert status_of(res, v1) == "FAIL"
    assert status_of(res, v2) == "PASS"


def test_instance_public_ip(ctx):
    ec2 = ctx.client("ec2")
    public = ec2.run_instances(ImageId=AMI, MinCount=1, MaxCount=1)["Instances"][0]["InstanceId"]  # default subnet maps public IPs
    vpc = ec2.create_vpc(CidrBlock="10.10.0.0/16")["Vpc"]["VpcId"]
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.10.1.0/24")["Subnet"]["SubnetId"]
    private = ec2.run_instances(ImageId=AMI, MinCount=1, MaxCount=1, SubnetId=subnet)["Instances"][0]["InstanceId"]
    res = run("ec2_instance_public_ip", ctx)
    assert status_of(res, public) == "FAIL"
    assert status_of(res, private) == "PASS"


def test_networkacl_port_22(ctx):
    ec2 = ctx.client("ec2")
    default_acl = [a for a in ec2.describe_network_acls()["NetworkAcls"] if a.get("IsDefault")][0]["NetworkAclId"]
    vpc = ec2.create_vpc(CidrBlock="10.20.0.0/16")["Vpc"]["VpcId"]
    closed = ec2.create_network_acl(VpcId=vpc)["NetworkAcl"]["NetworkAclId"]
    deny_first = ec2.create_network_acl(VpcId=vpc)["NetworkAcl"]["NetworkAclId"]
    ec2.create_network_acl_entry(NetworkAclId=deny_first, RuleNumber=50, Protocol="6", RuleAction="deny", Egress=False,
                                 CidrBlock="0.0.0.0/0", PortRange={"From": 22, "To": 22})
    ec2.create_network_acl_entry(NetworkAclId=deny_first, RuleNumber=100, Protocol="-1", RuleAction="allow", Egress=False, CidrBlock="0.0.0.0/0")
    res = run("ec2_networkacl_allow_ingress_tcp_port_22", ctx)
    assert status_of(res, default_acl) == "FAIL"
    assert status_of(res, closed) == "PASS"
    assert status_of(res, deny_first) == "PASS"


def test_elastic_ip_unassigned(ctx):
    ec2 = ctx.client("ec2")
    free = ec2.allocate_address(Domain="vpc")["AllocationId"]
    used = ec2.allocate_address(Domain="vpc")["AllocationId"]
    iid = ec2.run_instances(ImageId=AMI, MinCount=1, MaxCount=1)["Instances"][0]["InstanceId"]
    ec2.associate_address(AllocationId=used, InstanceId=iid)
    res = run("ec2_elastic_ip_unassigned", ctx)
    assert status_of(res, free) == "FAIL"
    assert status_of(res, used) == "PASS"
    assert iid in by_id(res, used).related


def test_vpc_flow_logs(ctx):
    ec2 = ctx.client("ec2")
    no_logs = default_vpc(ec2)
    logged = ec2.create_vpc(CidrBlock="10.30.0.0/16")["Vpc"]["VpcId"]
    ctx.client("logs").create_log_group(logGroupName="flow")
    ec2.create_flow_logs(ResourceIds=[logged], ResourceType="VPC", TrafficType="ALL", LogGroupName="flow",
                         DeliverLogsPermissionArn="arn:aws:iam::123456789012:role/flow")
    res = run("vpc_flow_logs_enabled", ctx)
    assert status_of(res, no_logs) == "FAIL"
    assert status_of(res, logged) == "PASS"
