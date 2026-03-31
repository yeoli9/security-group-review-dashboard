"""AWS Security Group data collector using boto3."""

import boto3
import traceback
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed


def get_session(profile_name=None, region_name=None):
    kwargs = {}
    if profile_name:
        kwargs["profile_name"] = profile_name
    if region_name:
        kwargs["region_name"] = region_name
    return boto3.Session(**kwargs)


def collect_security_groups(session):
    ec2 = session.client("ec2")
    sgs = []
    paginator = ec2.get_paginator("describe_security_groups")
    for page in paginator.paginate():
        sgs.extend(page["SecurityGroups"])
    return sgs


def collect_enis(session):
    """Collect all ENIs - the most comprehensive way to find SG usage."""
    ec2 = session.client("ec2")
    enis = []
    paginator = ec2.get_paginator("describe_network_interfaces")
    for page in paginator.paginate():
        enis.extend(page["NetworkInterfaces"])
    return enis


def collect_ec2_instances(session):
    ec2 = session.client("ec2")
    instances = []
    paginator = ec2.get_paginator("describe_instances")
    for page in paginator.paginate():
        for reservation in page["Reservations"]:
            instances.extend(reservation["Instances"])
    return instances


def collect_rds_instances(session):
    rds = session.client("rds")
    instances = []
    paginator = rds.get_paginator("describe_db_instances")
    for page in paginator.paginate():
        instances.extend(page["DBInstances"])
    return instances


def collect_load_balancers(session):
    """Collect ALB/NLB."""
    elbv2 = session.client("elbv2")
    lbs = []
    paginator = elbv2.get_paginator("describe_load_balancers")
    for page in paginator.paginate():
        lbs.extend(page["LoadBalancers"])
    return lbs


def collect_classic_lbs(session):
    elb = session.client("elb")
    lbs = []
    paginator = elb.get_paginator("describe_load_balancers")
    for page in paginator.paginate():
        lbs.extend(page["LoadBalancerDescriptions"])
    return lbs


def collect_vpc_endpoints(session):
    ec2 = session.client("ec2")
    endpoints = []
    paginator = ec2.get_paginator("describe_vpc_endpoints")
    for page in paginator.paginate():
        endpoints.extend(page["VpcEndpoints"])
    return endpoints


def collect_lambda_functions(session):
    lam = session.client("lambda")
    functions = []
    paginator = lam.get_paginator("list_functions")
    for page in paginator.paginate():
        functions.extend(page["Functions"])
    return functions


def collect_ecs_services(session):
    ecs = session.client("ecs")
    services = []
    cluster_paginator = ecs.get_paginator("list_clusters")
    for cluster_page in cluster_paginator.paginate():
        for cluster in cluster_page["clusterArns"]:
            svc_paginator = ecs.get_paginator("list_services")
            for page in svc_paginator.paginate(cluster=cluster):
                arns = page.get("serviceArns", [])
                # describe_services accepts max 10 at a time
                for i in range(0, len(arns), 10):
                    batch = arns[i:i+10]
                    descs = ecs.describe_services(
                        cluster=cluster, services=batch
                    )["services"]
                    services.extend(descs)
    return services


def collect_rds_clusters(session):
    """Collect Aurora/RDS clusters (cluster-level SGs separate from instance-level)."""
    rds = session.client("rds")
    clusters = []
    paginator = rds.get_paginator("describe_db_clusters")
    for page in paginator.paginate():
        clusters.extend(page["DBClusters"])
    return clusters


def collect_elasticache_clusters(session):
    ec = session.client("elasticache")
    clusters = []
    paginator = ec.get_paginator("describe_cache_clusters")
    for page in paginator.paginate():
        clusters.extend(page["CacheClusters"])
    return clusters


def collect_redshift_clusters(session):
    rs = session.client("redshift")
    clusters = []
    paginator = rs.get_paginator("describe_clusters")
    for page in paginator.paginate():
        clusters.extend(page["Clusters"])
    return clusters


def collect_opensearch_domains(session):
    os_client = session.client("opensearch")
    names = os_client.list_domain_names().get("DomainNames", [])
    if not names:
        return []
    domain_names = [d["DomainName"] for d in names]
    # describe_domains accepts max 5 at a time
    domains = []
    for i in range(0, len(domain_names), 5):
        batch = domain_names[i:i+5]
        resp = os_client.describe_domains(DomainNames=batch)
        domains.extend(resp.get("DomainStatusList", []))
    return domains


def collect_eks_clusters(session):
    eks = session.client("eks")
    clusters = []
    paginator = eks.get_paginator("list_clusters")
    for page in paginator.paginate():
        for name in page["clusters"]:
            detail = eks.describe_cluster(name=name)["cluster"]
            clusters.append(detail)
    return clusters


def collect_documentdb_clusters(session):
    docdb = session.client("docdb")
    clusters = []
    paginator = docdb.get_paginator("describe_db_clusters")
    for page in paginator.paginate():
        clusters.extend(page["DBClusters"])
    return clusters


def collect_msk_clusters(session):
    kafka = session.client("kafka")
    clusters = []
    try:
        paginator = kafka.get_paginator("list_clusters_v2")
        for page in paginator.paginate():
            clusters.extend(page.get("ClusterInfoList", []))
    except Exception:
        # Fallback to v1 API
        paginator = kafka.get_paginator("list_clusters")
        for page in paginator.paginate():
            clusters.extend(page.get("ClusterInfoList", []))
    return clusters


def collect_emr_clusters(session):
    emr = session.client("emr")
    clusters = []
    paginator = emr.get_paginator("list_clusters")
    for page in paginator.paginate(ClusterStates=["STARTING", "BOOTSTRAPPING", "RUNNING", "WAITING"]):
        for c in page.get("Clusters", []):
            detail = emr.describe_cluster(ClusterId=c["Id"])["Cluster"]
            clusters.append(detail)
    return clusters


def collect_sagemaker_notebooks(session):
    sm = session.client("sagemaker")
    notebooks = []
    paginator = sm.get_paginator("list_notebook_instances")
    for page in paginator.paginate():
        for nb in page.get("NotebookInstances", []):
            detail = sm.describe_notebook_instance(
                NotebookInstanceName=nb["NotebookInstanceName"]
            )
            notebooks.append(detail)
    return notebooks


def collect_mwaa_environments(session):
    mwaa = session.client("mwaa")
    envs = []
    paginator = mwaa.get_paginator("list_environments")
    for page in paginator.paginate():
        for name in page.get("Environments", []):
            detail = mwaa.get_environment(Name=name)["Environment"]
            envs.append(detail)
    return envs


def collect_dms_instances(session):
    dms = session.client("dms")
    instances = []
    paginator = dms.get_paginator("describe_replication_instances")
    for page in paginator.paginate():
        instances.extend(page.get("ReplicationInstances", []))
    return instances


def collect_efs_mount_targets(session):
    efs = session.client("efs")
    mount_targets = []
    fs_paginator = efs.get_paginator("describe_file_systems")
    for page in fs_paginator.paginate():
        for fs in page["FileSystems"]:
            mt_resp = efs.describe_mount_targets(FileSystemId=fs["FileSystemId"])
            for mt in mt_resp.get("MountTargets", []):
                sg_resp = efs.describe_mount_target_security_groups(
                    MountTargetId=mt["MountTargetId"]
                )
                mt["SecurityGroups"] = sg_resp.get("SecurityGroups", [])
                mt["FileSystemName"] = fs.get("Name", "")
                mt["FileSystemId"] = fs["FileSystemId"]
                mount_targets.append(mt)
    return mount_targets


def collect_dax_clusters(session):
    dax = session.client("dax")
    clusters = []
    next_token = None
    while True:
        kwargs = {}
        if next_token:
            kwargs["NextToken"] = next_token
        resp = dax.describe_clusters(**kwargs)
        clusters.extend(resp.get("Clusters", []))
        next_token = resp.get("NextToken")
        if not next_token:
            break
    return clusters


def collect_neptune_clusters(session):
    neptune = session.client("neptune")
    clusters = []
    paginator = neptune.get_paginator("describe_db_clusters")
    for page in paginator.paginate():
        clusters.extend(page["DBClusters"])
    return clusters


def collect_memorydb_clusters(session):
    mdb = session.client("memorydb")
    clusters = []
    next_token = None
    while True:
        kwargs = {}
        if next_token:
            kwargs["NextToken"] = next_token
        resp = mdb.describe_clusters(**kwargs)
        clusters.extend(resp.get("Clusters", []))
        next_token = resp.get("NextToken")
        if not next_token:
            break
    return clusters


def collect_vpcs(session):
    ec2 = session.client("ec2")
    vpcs = []
    paginator = ec2.get_paginator("describe_vpcs")
    for page in paginator.paginate():
        vpcs.extend(page["Vpcs"])
    return vpcs


def get_name_tag(tags):
    if not tags:
        return ""
    for tag in tags:
        if tag["Key"] == "Name":
            return tag["Value"]
    return ""


def build_sg_resource_map(
    enis, ec2_instances, rds_instances, load_balancers, classic_lbs,
    vpc_endpoints, lambda_functions, ecs_services,
    rds_clusters=None, elasticache_clusters=None, redshift_clusters=None,
    opensearch_domains=None, eks_clusters=None, documentdb_clusters=None,
    msk_clusters=None, emr_clusters=None, sagemaker_notebooks=None,
    mwaa_environments=None, dms_instances=None, efs_mount_targets=None,
    dax_clusters=None, neptune_clusters=None, memorydb_clusters=None,
):
    """Build a map of SG ID -> list of resources using it."""
    sg_resources = defaultdict(list)

    # EC2 instances
    for inst in ec2_instances:
        name = get_name_tag(inst.get("Tags"))
        for sg in inst.get("SecurityGroups", []):
            sg_resources[sg["GroupId"]].append({
                "type": "EC2",
                "id": inst["InstanceId"],
                "name": name,
                "state": inst["State"]["Name"],
                "private_ip": inst.get("PrivateIpAddress", ""),
            })

    # RDS instances
    for rds in rds_instances:
        for sg in rds.get("VpcSecurityGroups", []):
            sg_resources[sg["VpcSecurityGroupId"]].append({
                "type": "RDS",
                "id": rds["DBInstanceIdentifier"],
                "name": rds["DBInstanceIdentifier"],
                "state": rds["DBInstanceStatus"],
                "engine": rds.get("Engine", ""),
            })

    # ALB/NLB
    for lb in load_balancers:
        for sg_id in lb.get("SecurityGroups", []):
            sg_resources[sg_id].append({
                "type": "ALB/NLB",
                "id": lb["LoadBalancerArn"].split("/")[-1],
                "name": lb["LoadBalancerName"],
                "state": lb.get("State", {}).get("Code", ""),
                "dns": lb.get("DNSName", ""),
                "lb_type": lb.get("Type", ""),
            })

    # Classic LB
    for lb in classic_lbs:
        for sg_id in lb.get("SecurityGroups", []):
            sg_resources[sg_id].append({
                "type": "CLB",
                "id": lb["LoadBalancerName"],
                "name": lb["LoadBalancerName"],
                "dns": lb.get("DNSName", ""),
            })

    # VPC Endpoints
    for ep in vpc_endpoints:
        for sg_id in ep.get("Groups", []):
            gid = sg_id if isinstance(sg_id, str) else sg_id.get("GroupId", "")
            sg_resources[gid].append({
                "type": "VPCEndpoint",
                "id": ep["VpcEndpointId"],
                "name": ep.get("ServiceName", "").split(".")[-1],
                "state": ep.get("State", ""),
                "service": ep.get("ServiceName", ""),
            })

    # Lambda
    for fn in lambda_functions:
        vpc_config = fn.get("VpcConfig", {})
        for sg_id in vpc_config.get("SecurityGroupIds", []):
            sg_resources[sg_id].append({
                "type": "Lambda",
                "id": fn["FunctionName"],
                "name": fn["FunctionName"],
                "runtime": fn.get("Runtime", ""),
            })

    # ECS Services
    for svc in ecs_services:
        net_config = svc.get("networkConfiguration", {}).get("awsvpcConfiguration", {})
        for sg_id in net_config.get("securityGroups", []):
            sg_resources[sg_id].append({
                "type": "ECS",
                "id": svc["serviceName"],
                "name": svc["serviceName"],
                "cluster": svc.get("clusterArn", "").split("/")[-1],
                "desiredCount": svc.get("desiredCount", 0),
            })

    # RDS Aurora Clusters
    for cluster in (rds_clusters or []):
        for sg in cluster.get("VpcSecurityGroups", []):
            sg_resources[sg["VpcSecurityGroupId"]].append({
                "type": "Aurora",
                "id": cluster["DBClusterIdentifier"],
                "name": cluster["DBClusterIdentifier"],
                "state": cluster.get("Status", ""),
                "engine": cluster.get("Engine", ""),
            })

    # ElastiCache
    for cluster in (elasticache_clusters or []):
        for sg in cluster.get("SecurityGroups", []):
            sg_resources[sg["SecurityGroupId"]].append({
                "type": "ElastiCache",
                "id": cluster["CacheClusterId"],
                "name": cluster["CacheClusterId"],
                "state": cluster.get("CacheClusterStatus", ""),
                "engine": cluster.get("Engine", ""),
            })

    # Redshift
    for cluster in (redshift_clusters or []):
        for sg in cluster.get("VpcSecurityGroups", []):
            sg_resources[sg["VpcSecurityGroupId"]].append({
                "type": "Redshift",
                "id": cluster["ClusterIdentifier"],
                "name": cluster["ClusterIdentifier"],
                "state": cluster.get("ClusterStatus", ""),
            })

    # OpenSearch
    for domain in (opensearch_domains or []):
        vpc_opts = domain.get("VPCOptions", {})
        for sg_id in vpc_opts.get("SecurityGroupIds", []):
            sg_resources[sg_id].append({
                "type": "OpenSearch",
                "id": domain["DomainName"],
                "name": domain["DomainName"],
                "engine_version": domain.get("EngineVersion", ""),
            })

    # EKS
    for cluster in (eks_clusters or []):
        vpc_config = cluster.get("resourcesVpcConfig", {})
        for sg_id in vpc_config.get("securityGroupIds", []):
            sg_resources[sg_id].append({
                "type": "EKS",
                "id": cluster["name"],
                "name": cluster["name"],
                "state": cluster.get("status", ""),
            })
        cluster_sg = vpc_config.get("clusterSecurityGroupId")
        if cluster_sg:
            sg_resources[cluster_sg].append({
                "type": "EKS",
                "id": cluster["name"],
                "name": f"{cluster['name']} (cluster SG)",
                "state": cluster.get("status", ""),
            })

    # DocumentDB
    for cluster in (documentdb_clusters or []):
        for sg in cluster.get("VpcSecurityGroups", []):
            sg_resources[sg["VpcSecurityGroupId"]].append({
                "type": "DocumentDB",
                "id": cluster["DBClusterIdentifier"],
                "name": cluster["DBClusterIdentifier"],
                "state": cluster.get("Status", ""),
                "engine": cluster.get("Engine", ""),
            })

    # MSK (Kafka)
    for cluster in (msk_clusters or []):
        broker_info = cluster.get("BrokerNodeGroupInfo", cluster.get("Provisioned", {}).get("BrokerNodeGroupInfo", {}))
        for sg_id in broker_info.get("SecurityGroups", []):
            sg_resources[sg_id].append({
                "type": "MSK",
                "id": cluster.get("ClusterName", cluster.get("ClusterArn", "").split("/")[-1]),
                "name": cluster.get("ClusterName", ""),
                "state": cluster.get("State", ""),
            })

    # EMR
    for cluster in (emr_clusters or []):
        ec2_attrs = cluster.get("Ec2InstanceAttributes", {})
        emr_sgs = set()
        for key in ["EmrManagedMasterSecurityGroup", "EmrManagedSlaveSecurityGroup", "ServiceAccessSecurityGroup"]:
            sg_id = ec2_attrs.get(key)
            if sg_id:
                emr_sgs.add(sg_id)
        for key in ["AdditionalMasterSecurityGroups", "AdditionalSlaveSecurityGroups"]:
            for sg_id in ec2_attrs.get(key, []):
                emr_sgs.add(sg_id)
        for sg_id in emr_sgs:
            sg_resources[sg_id].append({
                "type": "EMR",
                "id": cluster["Id"],
                "name": cluster.get("Name", cluster["Id"]),
                "state": cluster.get("Status", {}).get("State", ""),
            })

    # SageMaker Notebooks
    for nb in (sagemaker_notebooks or []):
        for sg_id in nb.get("SecurityGroups", []):
            sg_resources[sg_id].append({
                "type": "SageMaker",
                "id": nb["NotebookInstanceName"],
                "name": nb["NotebookInstanceName"],
                "state": nb.get("NotebookInstanceStatus", ""),
            })

    # MWAA (Managed Airflow)
    for env in (mwaa_environments or []):
        net_config = env.get("NetworkConfiguration", {})
        for sg_id in net_config.get("SecurityGroupIds", []):
            sg_resources[sg_id].append({
                "type": "MWAA",
                "id": env.get("Name", ""),
                "name": env.get("Name", ""),
                "state": env.get("Status", ""),
            })

    # DMS Replication Instances
    for inst in (dms_instances or []):
        for sg in inst.get("VpcSecurityGroups", []):
            sg_resources[sg["VpcSecurityGroupId"]].append({
                "type": "DMS",
                "id": inst.get("ReplicationInstanceIdentifier", ""),
                "name": inst.get("ReplicationInstanceIdentifier", ""),
                "state": inst.get("ReplicationInstanceStatus", ""),
            })

    # EFS Mount Targets
    for mt in (efs_mount_targets or []):
        for sg_id in mt.get("SecurityGroups", []):
            sg_resources[sg_id].append({
                "type": "EFS",
                "id": mt["FileSystemId"],
                "name": mt.get("FileSystemName") or mt["FileSystemId"],
                "mount_target_id": mt["MountTargetId"],
            })

    # DAX
    for cluster in (dax_clusters or []):
        for sg in cluster.get("SecurityGroups", []):
            sg_resources[sg["SecurityGroupIdentifier"]].append({
                "type": "DAX",
                "id": cluster.get("ClusterName", ""),
                "name": cluster.get("ClusterName", ""),
                "state": cluster.get("Status", ""),
            })

    # Neptune
    for cluster in (neptune_clusters or []):
        for sg in cluster.get("VpcSecurityGroups", []):
            sg_resources[sg["VpcSecurityGroupId"]].append({
                "type": "Neptune",
                "id": cluster["DBClusterIdentifier"],
                "name": cluster["DBClusterIdentifier"],
                "state": cluster.get("Status", ""),
            })

    # MemoryDB
    for cluster in (memorydb_clusters or []):
        for sg_id in cluster.get("SecurityGroups", []):
            gid = sg_id if isinstance(sg_id, str) else sg_id.get("SecurityGroupId", "")
            sg_resources[gid].append({
                "type": "MemoryDB",
                "id": cluster.get("Name", ""),
                "name": cluster.get("Name", ""),
                "state": cluster.get("Status", ""),
            })

    # ENIs (catch-all for anything not covered above)
    eni_resource_ids = set()
    for eni in enis:
        attachment = eni.get("Attachment", {})
        instance_id = attachment.get("InstanceId", "")
        desc = eni.get("Description", "")
        eni_type = eni.get("InterfaceType", "interface")

        # Skip ENIs already covered by specific resource types
        if instance_id:
            continue

        resource_info = {
            "type": "ENI",
            "id": eni["NetworkInterfaceId"],
            "name": desc or eni["NetworkInterfaceId"],
            "status": eni.get("Status", ""),
            "interface_type": eni_type,
            "private_ip": eni.get("PrivateIpAddress", ""),
        }

        # Try to identify what owns this ENI
        if "ELB" in desc:
            resource_info["type"] = "ELB-ENI"
        elif "RDSNetworkInterface" in desc:
            resource_info["type"] = "RDS-ENI"
        elif "lambda" in desc.lower():
            resource_info["type"] = "Lambda-ENI"
        elif "ecs" in desc.lower():
            resource_info["type"] = "ECS-ENI"
        elif eni_type == "vpc_endpoint":
            resource_info["type"] = "VPCEndpoint-ENI"
        elif eni_type == "nat_gateway":
            resource_info["type"] = "NATGateway"

        for sg in eni.get("Groups", []):
            key = (sg["GroupId"], resource_info["id"])
            if key not in eni_resource_ids:
                eni_resource_ids.add(key)
                sg_resources[sg["GroupId"]].append(resource_info)

    return dict(sg_resources)


def collect_all(profile_name=None, region_name=None):
    """Collect all data and return structured result.

    Uses parallel collection for performance and tracks errors per service.
    """
    import datetime

    session = get_session(profile_name, region_name)
    region = session.region_name or "ap-northeast-2"
    account_id = session.client("sts").get_caller_identity()["Account"]

    print(f"Collecting data for account {account_id}, region {region}...")

    # Define all collection tasks: (key, display_name, collect_function)
    tasks = [
        ("security_groups", "Security Groups", collect_security_groups),
        ("vpcs", "VPCs", collect_vpcs),
        ("enis", "ENIs", collect_enis),
        ("ec2_instances", "EC2 Instances", collect_ec2_instances),
        ("rds_instances", "RDS Instances", collect_rds_instances),
        ("load_balancers", "ALB/NLB", collect_load_balancers),
        ("classic_lbs", "Classic LB", collect_classic_lbs),
        ("vpc_endpoints", "VPC Endpoints", collect_vpc_endpoints),
        ("lambda_functions", "Lambda Functions", collect_lambda_functions),
        ("ecs_services", "ECS Services", collect_ecs_services),
        ("rds_clusters", "RDS/Aurora Clusters", collect_rds_clusters),
        ("elasticache_clusters", "ElastiCache", collect_elasticache_clusters),
        ("redshift_clusters", "Redshift", collect_redshift_clusters),
        ("opensearch_domains", "OpenSearch", collect_opensearch_domains),
        ("eks_clusters", "EKS", collect_eks_clusters),
        ("documentdb_clusters", "DocumentDB", collect_documentdb_clusters),
        ("msk_clusters", "MSK (Kafka)", collect_msk_clusters),
        ("emr_clusters", "EMR", collect_emr_clusters),
        ("sagemaker_notebooks", "SageMaker", collect_sagemaker_notebooks),
        ("mwaa_environments", "MWAA (Airflow)", collect_mwaa_environments),
        ("dms_instances", "DMS", collect_dms_instances),
        ("efs_mount_targets", "EFS", collect_efs_mount_targets),
        ("dax_clusters", "DAX", collect_dax_clusters),
        ("neptune_clusters", "Neptune", collect_neptune_clusters),
        ("memorydb_clusters", "MemoryDB", collect_memorydb_clusters),
    ]

    results = {}
    errors = []

    # Parallel collection using ThreadPoolExecutor
    # Each thread creates its own session for thread safety
    def _run_task(key, name, func):
        try:
            thread_session = get_session(profile_name, region_name)
            data = func(thread_session)
            print(f"  ✓ {name}: {len(data)}")
            return key, data, None
        except Exception as e:
            err_msg = str(e)
            # Truncate long error messages
            if len(err_msg) > 200:
                err_msg = err_msg[:200] + "..."
            print(f"  ✗ {name}: {err_msg}")
            return key, [], {"service": name, "error": err_msg}

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {
            executor.submit(_run_task, key, name, func): key
            for key, name, func in tasks
        }
        for future in as_completed(futures):
            key, data, error = future.result()
            results[key] = data
            if error:
                errors.append(error)

    sgs = results["security_groups"]
    vpcs_raw = results["vpcs"]

    # Build resource map
    sg_resource_map = build_sg_resource_map(
        results["enis"],
        results["ec2_instances"],
        results["rds_instances"],
        results["load_balancers"],
        results["classic_lbs"],
        results["vpc_endpoints"],
        results["lambda_functions"],
        results["ecs_services"],
        rds_clusters=results["rds_clusters"],
        elasticache_clusters=results["elasticache_clusters"],
        redshift_clusters=results["redshift_clusters"],
        opensearch_domains=results["opensearch_domains"],
        eks_clusters=results["eks_clusters"],
        documentdb_clusters=results["documentdb_clusters"],
        msk_clusters=results["msk_clusters"],
        emr_clusters=results["emr_clusters"],
        sagemaker_notebooks=results["sagemaker_notebooks"],
        mwaa_environments=results["mwaa_environments"],
        dms_instances=results["dms_instances"],
        efs_mount_targets=results["efs_mount_targets"],
        dax_clusters=results["dax_clusters"],
        neptune_clusters=results["neptune_clusters"],
        memorydb_clusters=results["memorydb_clusters"],
    )

    # Build VPC map
    vpc_map = {}
    for vpc in vpcs_raw:
        vpc_id = vpc["VpcId"]
        vpc_map[vpc_id] = {
            "id": vpc_id,
            "name": get_name_tag(vpc.get("Tags")),
            "cidr": vpc.get("CidrBlock", ""),
            "is_default": vpc.get("IsDefault", False),
        }

    # Process security groups
    sg_data = []
    for sg in sgs:
        sg_id = sg["GroupId"]
        resources = sg_resource_map.get(sg_id, [])

        # Find SG-to-SG references in rules
        sg_refs = set()
        for rule in sg.get("IpPermissions", []) + sg.get("IpPermissionsEgress", []):
            for pair in rule.get("UserIdGroupPairs", []):
                ref_sg = pair.get("GroupId", "")
                if ref_sg and ref_sg != sg_id:
                    sg_refs.add(ref_sg)

        sg_data.append({
            "id": sg_id,
            "name": sg.get("GroupName", ""),
            "description": sg.get("Description", ""),
            "vpc_id": sg.get("VpcId", ""),
            "tags": sg.get("Tags", []),
            "inbound_rules": _format_rules(sg.get("IpPermissions", [])),
            "outbound_rules": _format_rules(sg.get("IpPermissionsEgress", [])),
            "resources": resources,
            "resource_count": len(resources),
            "is_used": len(resources) > 0,
            "sg_references": list(sg_refs),
        })

    print(f"Collection complete: {len(sgs)} SGs, {len(errors)} errors")

    return {
        "account_id": account_id,
        "region": region,
        "vpcs": vpc_map,
        "security_groups": sg_data,
        "collection_time": datetime.datetime.utcnow().isoformat() + "Z",
        "collection_errors": errors,
    }


def _format_rules(permissions):
    rules = []
    for perm in permissions:
        protocol = perm.get("IpProtocol", "-1")
        from_port = perm.get("FromPort", 0)
        to_port = perm.get("ToPort", 0)

        if protocol == "-1":
            protocol_display = "All Traffic"
            port_display = "All"
        elif protocol == "tcp":
            protocol_display = "TCP"
            if from_port == to_port:
                port_display = str(from_port)
            else:
                port_display = f"{from_port}-{to_port}"
        elif protocol == "udp":
            protocol_display = "UDP"
            if from_port == to_port:
                port_display = str(from_port)
            else:
                port_display = f"{from_port}-{to_port}"
        elif protocol == "icmp":
            protocol_display = "ICMP"
            port_display = "N/A"
        else:
            protocol_display = protocol
            port_display = f"{from_port}-{to_port}"

        sources = []
        for cidr in perm.get("IpRanges", []):
            sources.append({
                "type": "cidr",
                "value": cidr["CidrIp"],
                "description": cidr.get("Description", ""),
            })
        for cidr in perm.get("Ipv6Ranges", []):
            sources.append({
                "type": "cidr_v6",
                "value": cidr["CidrIpv6"],
                "description": cidr.get("Description", ""),
            })
        for pair in perm.get("UserIdGroupPairs", []):
            sources.append({
                "type": "sg",
                "value": pair.get("GroupId", ""),
                "description": pair.get("Description", ""),
            })
        for prefix in perm.get("PrefixListIds", []):
            sources.append({
                "type": "prefix_list",
                "value": prefix.get("PrefixListId", ""),
                "description": prefix.get("Description", ""),
            })

        rules.append({
            "protocol": protocol_display,
            "port": port_display,
            "from_port": from_port,
            "to_port": to_port,
            "raw_protocol": perm.get("IpProtocol", "-1"),
            "sources": sources,
        })

    return rules
