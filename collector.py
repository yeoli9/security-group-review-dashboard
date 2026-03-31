"""AWS Security Group data collector using boto3."""

import boto3
from collections import defaultdict


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
    try:
        return elb.describe_load_balancers()["LoadBalancerDescriptions"]
    except Exception:
        return []


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
    clusters = ecs.list_clusters()["clusterArns"]
    for cluster in clusters:
        paginator = ecs.get_paginator("list_services")
        for page in paginator.paginate(cluster=cluster):
            if page["serviceArns"]:
                descs = ecs.describe_services(
                    cluster=cluster, services=page["serviceArns"]
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
        try:
            paginator = kafka.get_paginator("list_clusters")
            for page in paginator.paginate():
                clusters.extend(page.get("ClusterInfoList", []))
        except Exception:
            pass
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
    try:
        paginator = mwaa.get_paginator("list_environments")
        for page in paginator.paginate():
            for name in page.get("Environments", []):
                detail = mwaa.get_environment(Name=name)["Environment"]
                envs.append(detail)
    except Exception:
        pass
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
    try:
        resp = dax.describe_clusters()
        clusters.extend(resp.get("Clusters", []))
    except Exception:
        pass
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
    try:
        resp = mdb.describe_clusters()
        clusters.extend(resp.get("Clusters", []))
    except Exception:
        pass
    return clusters


def collect_vpcs(session):
    ec2 = session.client("ec2")
    return ec2.describe_vpcs()["Vpcs"]


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
    """Collect all data and return structured result."""
    session = get_session(profile_name, region_name)
    region = session.region_name or "ap-northeast-2"
    account_id = session.client("sts").get_caller_identity()["Account"]

    print(f"Collecting data for account {account_id}, region {region}...")

    print("  - Security Groups...")
    sgs = collect_security_groups(session)
    print(f"    Found {len(sgs)} security groups")

    print("  - VPCs...")
    vpcs = collect_vpcs(session)

    print("  - ENIs...")
    enis = collect_enis(session)
    print(f"    Found {len(enis)} ENIs")

    print("  - EC2 Instances...")
    ec2_instances = collect_ec2_instances(session)
    print(f"    Found {len(ec2_instances)} instances")

    print("  - RDS Instances...")
    rds_instances = collect_rds_instances(session)
    print(f"    Found {len(rds_instances)} RDS instances")

    print("  - Load Balancers (ALB/NLB)...")
    load_balancers = collect_load_balancers(session)
    print(f"    Found {len(load_balancers)} ALB/NLB")

    print("  - Classic Load Balancers...")
    classic_lbs = collect_classic_lbs(session)
    print(f"    Found {len(classic_lbs)} CLB")

    print("  - VPC Endpoints...")
    vpc_endpoints = collect_vpc_endpoints(session)
    print(f"    Found {len(vpc_endpoints)} VPC endpoints")

    print("  - Lambda Functions...")
    lambda_functions = collect_lambda_functions(session)
    print(f"    Found {len(lambda_functions)} Lambda functions")

    print("  - ECS Services...")
    ecs_services = collect_ecs_services(session)
    print(f"    Found {len(ecs_services)} ECS services")

    print("  - RDS/Aurora Clusters...")
    rds_clusters = collect_rds_clusters(session)
    print(f"    Found {len(rds_clusters)} RDS clusters")

    print("  - ElastiCache...")
    elasticache_clusters = collect_elasticache_clusters(session)
    print(f"    Found {len(elasticache_clusters)} ElastiCache clusters")

    print("  - Redshift...")
    redshift_clusters = collect_redshift_clusters(session)
    print(f"    Found {len(redshift_clusters)} Redshift clusters")

    print("  - OpenSearch...")
    opensearch_domains = collect_opensearch_domains(session)
    print(f"    Found {len(opensearch_domains)} OpenSearch domains")

    print("  - EKS...")
    eks_clusters = collect_eks_clusters(session)
    print(f"    Found {len(eks_clusters)} EKS clusters")

    print("  - DocumentDB...")
    documentdb_clusters = collect_documentdb_clusters(session)
    print(f"    Found {len(documentdb_clusters)} DocumentDB clusters")

    print("  - MSK (Kafka)...")
    msk_clusters = collect_msk_clusters(session)
    print(f"    Found {len(msk_clusters)} MSK clusters")

    print("  - EMR...")
    emr_clusters = collect_emr_clusters(session)
    print(f"    Found {len(emr_clusters)} EMR clusters")

    print("  - SageMaker Notebooks...")
    sagemaker_notebooks = collect_sagemaker_notebooks(session)
    print(f"    Found {len(sagemaker_notebooks)} SageMaker notebooks")

    print("  - MWAA (Airflow)...")
    mwaa_environments = collect_mwaa_environments(session)
    print(f"    Found {len(mwaa_environments)} MWAA environments")

    print("  - DMS...")
    dms_instances = collect_dms_instances(session)
    print(f"    Found {len(dms_instances)} DMS instances")

    print("  - EFS...")
    efs_mount_targets = collect_efs_mount_targets(session)
    print(f"    Found {len(efs_mount_targets)} EFS mount targets")

    print("  - DAX...")
    dax_clusters = collect_dax_clusters(session)
    print(f"    Found {len(dax_clusters)} DAX clusters")

    print("  - Neptune...")
    neptune_clusters = collect_neptune_clusters(session)
    print(f"    Found {len(neptune_clusters)} Neptune clusters")

    print("  - MemoryDB...")
    memorydb_clusters = collect_memorydb_clusters(session)
    print(f"    Found {len(memorydb_clusters)} MemoryDB clusters")

    # Build resource map
    sg_resource_map = build_sg_resource_map(
        enis, ec2_instances, rds_instances, load_balancers, classic_lbs,
        vpc_endpoints, lambda_functions, ecs_services,
        rds_clusters=rds_clusters,
        elasticache_clusters=elasticache_clusters,
        redshift_clusters=redshift_clusters,
        opensearch_domains=opensearch_domains,
        eks_clusters=eks_clusters,
        documentdb_clusters=documentdb_clusters,
        msk_clusters=msk_clusters,
        emr_clusters=emr_clusters,
        sagemaker_notebooks=sagemaker_notebooks,
        mwaa_environments=mwaa_environments,
        dms_instances=dms_instances,
        efs_mount_targets=efs_mount_targets,
        dax_clusters=dax_clusters,
        neptune_clusters=neptune_clusters,
        memorydb_clusters=memorydb_clusters,
    )

    # Build VPC map
    vpc_map = {}
    for vpc in vpcs:
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

    return {
        "account_id": account_id,
        "region": region,
        "vpcs": vpc_map,
        "security_groups": sg_data,
        "collection_time": __import__("datetime").datetime.utcnow().isoformat() + "Z",
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
