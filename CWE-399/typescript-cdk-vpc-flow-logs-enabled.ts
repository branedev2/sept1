import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as iam from 'aws-cdk-lib/aws-iam';

// True Positives (vulnerable code that should be detected)

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_1(scope: Construct) {
  // Creating a VPC without flow logs
  // ruleid: typescript-cdk-vpc-flow-logs-enabled
  const vpc = new ec2.Vpc(scope, 'MyVpcWithoutFlowLogs', {
    maxAzs: 2,
    natGateways: 1
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_2(scope: Construct) {
  // Creating a VPC with minimal configuration and no flow logs
  // ruleid: typescript-cdk-vpc-flow-logs-enabled
  const vpc = new ec2.Vpc(scope, 'MinimalVpc', {
    cidr: '10.0.0.0/16',
    subnetConfiguration: []
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_3(scope: Construct) {
  // Creating a VPC with custom subnets but no flow logs
  // ruleid: typescript-cdk-vpc-flow-logs-enabled
  const vpc = new ec2.Vpc(scope, 'CustomSubnetVpc', {
    cidr: '10.0.0.0/16',
    subnetConfiguration: [
      {
        name: 'public',
        subnetType: ec2.SubnetType.PUBLIC,
        cidrMask: 24,
      },
      {
        name: 'private',
        subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
        cidrMask: 24,
      }
    ]
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_4(scope: Construct) {
  // Creating a VPC with NAT gateway configuration but no flow logs
  // ruleid: typescript-cdk-vpc-flow-logs-enabled
  const vpc = new ec2.Vpc(scope, 'NatGatewayVpc', {
    maxAzs: 3,
    natGateways: 2,
    natGatewayProvider: ec2.NatProvider.gateway(),
    subnetConfiguration: [
      {
        name: 'public',
        subnetType: ec2.SubnetType.PUBLIC,
        cidrMask: 24,
      },
      {
        name: 'private',
        subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
        cidrMask: 24,
      }
    ]
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_5(scope: Construct) {
  // Creating a VPC with IPv6 support but no flow logs
  // ruleid: typescript-cdk-vpc-flow-logs-enabled
  const vpc = new ec2.Vpc(scope, 'Ipv6Vpc', {
    maxAzs: 2,
    ipAddresses: ec2.IpAddresses.cidr('10.0.0.0/16'),
    enableDnsHostnames: true,
    enableDnsSupport: true,
    subnetConfiguration: [
      {
        name: 'public',
        subnetType: ec2.SubnetType.PUBLIC,
        cidrMask: 24,
      }
    ]
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_6(scope: Construct) {
  // Creating a VPC with VPN gateway but no flow logs
  // ruleid: typescript-cdk-vpc-flow-logs-enabled
  const vpc = new ec2.Vpc(scope, 'VpnVpc', {
    maxAzs: 2,
    vpnGateway: true,
    vpnGatewayAsn: 65000
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_7(scope: Construct) {
  // Creating a VPC with DNS settings but no flow logs
  // ruleid: typescript-cdk-vpc-flow-logs-enabled
  const vpc = new ec2.Vpc(scope, 'DnsVpc', {
    maxAzs: 2,
    enableDnsHostnames: true,
    enableDnsSupport: true
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_8(scope: Construct) {
  // Creating a VPC with flow logs but not enabling them (commented out)
  // ruleid: typescript-cdk-vpc-flow-logs-enabled
  const vpc = new ec2.Vpc(scope, 'CommentedFlowLogsVpc', {
    maxAzs: 2
  });
  
  // Flow logs are commented out and not implemented
  // const flowLog = new ec2.FlowLog(scope, 'FlowLog', {
  //   resourceType: ec2.FlowLogResourceType.fromVpc(vpc),
  //   destination: ec2.FlowLogDestination.toCloudWatchLogs()
  // });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_9(scope: Construct) {
  // Creating a VPC with incomplete flow log setup
  // ruleid: typescript-cdk-vpc-flow-logs-enabled
  const vpc = new ec2.Vpc(scope, 'IncompleteFlowLogsVpc', {
    maxAzs: 2
  });
  
  // Creating log group but not attaching it to VPC flow logs
  const logGroup = new logs.LogGroup(scope, 'VpcFlowLogGroup', {
    retention: logs.RetentionDays.ONE_WEEK
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_10(scope: Construct) {
  // Creating a VPC and then trying to use a different API that doesn't actually enable flow logs
  // ruleid: typescript-cdk-vpc-flow-logs-enabled
  const vpc = new ec2.Vpc(scope, 'MisunderstoodFlowLogsVpc', {
    maxAzs: 2
  });
  
  // This doesn't actually enable flow logs, just creates a security group
  const securityGroup = new ec2.SecurityGroup(scope, 'SG', {
    vpc,
    description: 'Allow traffic',
    allowAllOutbound: true
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_11(scope: Construct) {
  // Creating a VPC with conditional logic that doesn't enable flow logs
  // ruleid: typescript-cdk-vpc-flow-logs-enabled
  const enableFlowLogs = false;
  
  const vpc = new ec2.Vpc(scope, 'ConditionalVpc', {
    maxAzs: 2
  });
  
  if (enableFlowLogs) {
    // This code never executes
    const logGroup = new logs.LogGroup(scope, 'FlowLogsGroup');
    new ec2.FlowLog(scope, 'FlowLog', {
      resourceType: ec2.FlowLogResourceType.fromVpc(vpc),
      destination: ec2.FlowLogDestination.toCloudWatchLogs(
        new iam.Role(scope, 'FlowLogRole', {
          assumedBy: new iam.ServicePrincipal('vpc-flow-logs.amazonaws.com')
        }),
        logGroup
      )
    });
  }
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_12(scope: Construct) {
  // Creating a VPC with flow logs object but incorrect resource type
  // ruleid: typescript-cdk-vpc-flow-logs-enabled
  const vpc = new ec2.Vpc(scope, 'WrongResourceTypeVpc', {
    maxAzs: 2
  });
  
  // Creating a subnet to use instead of the VPC
  const subnet = vpc.selectSubnets({
    subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS
  }).subnets[0];
  
  // Flow log is attached to subnet, not VPC
  new ec2.FlowLog(scope, 'SubnetFlowLog', {
    resourceType: ec2.FlowLogResourceType.fromSubnet(subnet),
    destination: ec2.FlowLogDestination.toCloudWatchLogs()
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_13(scope: Construct) {
  // Creating multiple VPCs but only enabling flow logs for one
  // ruleid: typescript-cdk-vpc-flow-logs-enabled
  const vpc1 = new ec2.Vpc(scope, 'Vpc1', {
    maxAzs: 2
  });
  
  const vpc2 = new ec2.Vpc(scope, 'Vpc2', {
    maxAzs: 2
  });
  
  // Only vpc2 has flow logs
  new ec2.FlowLog(scope, 'Vpc2FlowLog', {
    resourceType: ec2.FlowLogResourceType.fromVpc(vpc2),
    destination: ec2.FlowLogDestination.toCloudWatchLogs()
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_14(scope: Construct) {
  // Creating a VPC with flow logs but incorrect destination
  // ruleid: typescript-cdk-vpc-flow-logs-enabled
  const vpc = new ec2.Vpc(scope, 'InvalidDestinationVpc', {
    maxAzs: 2
  });
  
  // Creating a variable but not using it for flow logs
  const logGroup = new logs.LogGroup(scope, 'UnusedLogGroup');
  
  // No actual flow logs created
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_15(scope: Construct) {
  // Creating a VPC using a factory function but not enabling flow logs
  // ruleid: typescript-cdk-vpc-flow-logs-enabled
  function createVpc(id: string): ec2.Vpc {
    return new ec2.Vpc(scope, id, {
      maxAzs: 2,
      natGateways: 1
    });
  }
  
  const vpc = createVpc('FactoryVpc');
}
// {/fact}

// True Negatives (secure code that should not be detected)

// {fact rule=object-presence@v1.0 defects=0}
function good_case_1(scope: Construct) {
  // Creating a VPC with flow logs enabled using CloudWatch Logs
  const vpc = new ec2.Vpc(scope, 'VpcWithFlowLogs', {
    maxAzs: 2
  });
  
  // ok: typescript-cdk-vpc-flow-logs-enabled
  new ec2.FlowLog(scope, 'FlowLog', {
    resourceType: ec2.FlowLogResourceType.fromVpc(vpc),
    destination: ec2.FlowLogDestination.toCloudWatchLogs()
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_2(scope: Construct) {
  // Creating a VPC with flow logs enabled using S3
  const vpc = new ec2.Vpc(scope, 'VpcWithS3FlowLogs', {
    maxAzs: 2
  });
  
  // ok: typescript-cdk-vpc-flow-logs-enabled
  new ec2.FlowLog(scope, 'S3FlowLog', {
    resourceType: ec2.FlowLogResourceType.fromVpc(vpc),
    destination: ec2.FlowLogDestination.toS3()
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_3(scope: Construct) {
  // Creating a VPC with flow logs enabled with custom IAM role
  const vpc = new ec2.Vpc(scope, 'VpcWithCustomRoleFlowLogs', {
    maxAzs: 2
  });
  
  const role = new iam.Role(scope, 'FlowLogRole', {
    assumedBy: new iam.ServicePrincipal('vpc-flow-logs.amazonaws.com')
  });
  
  // ok: typescript-cdk-vpc-flow-logs-enabled
  new ec2.FlowLog(scope, 'CustomRoleFlowLog', {
    resourceType: ec2.FlowLogResourceType.fromVpc(vpc),
    destination: ec2.FlowLogDestination.toCloudWatchLogs(role)
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_4(scope: Construct) {
  // Creating a VPC with flow logs enabled with custom log group
  const vpc = new ec2.Vpc(scope, 'VpcWithCustomLogGroupFlowLogs', {
    maxAzs: 2
  });
  
  const logGroup = new logs.LogGroup(scope, 'FlowLogsGroup', {
    retention: logs.RetentionDays.ONE_WEEK
  });
  
  const role = new iam.Role(scope, 'FlowLogRole', {
    assumedBy: new iam.ServicePrincipal('vpc-flow-logs.amazonaws.com')
  });
  
  // ok: typescript-cdk-vpc-flow-logs-enabled
  new ec2.FlowLog(scope, 'CustomLogGroupFlowLog', {
    resourceType: ec2.FlowLogResourceType.fromVpc(vpc),
    destination: ec2.FlowLogDestination.toCloudWatchLogs(role, logGroup)
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_5(scope: Construct) {
  // Creating a VPC with flow logs enabled with traffic type specified
  const vpc = new ec2.Vpc(scope, 'VpcWithTrafficTypeFlowLogs', {
    maxAzs: 2
  });
  
  // ok: typescript-cdk-vpc-flow-logs-enabled
  new ec2.FlowLog(scope, 'TrafficTypeFlowLog', {
    resourceType: ec2.FlowLogResourceType.fromVpc(vpc),
    destination: ec2.FlowLogDestination.toCloudWatchLogs(),
    trafficType: ec2.FlowLogTrafficType.ALL
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_6(scope: Construct) {
  // Creating a VPC with flow logs enabled with maximum aggregation interval
  const vpc = new ec2.Vpc(scope, 'VpcWithAggregationIntervalFlowLogs', {
    maxAzs: 2
  });
  
  // ok: typescript-cdk-vpc-flow-logs-enabled
  new ec2.FlowLog(scope, 'AggregationIntervalFlowLog', {
    resourceType: ec2.FlowLogResourceType.fromVpc(vpc),
    destination: ec2.FlowLogDestination.toCloudWatchLogs(),
    maxAggregationInterval: ec2.FlowLogMaxAggregationInterval.ONE_MINUTE
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_7(scope: Construct) {
  // Creating a VPC with flow logs enabled with custom format
  const vpc = new ec2.Vpc(scope, 'VpcWithCustomFormatFlowLogs', {
    maxAzs: 2
  });
  
  // ok: typescript-cdk-vpc-flow-logs-enabled
  new ec2.FlowLog(scope, 'CustomFormatFlowLog', {
    resourceType: ec2.FlowLogResourceType.fromVpc(vpc),
    destination: ec2.FlowLogDestination.toCloudWatchLogs(),
    trafficType: ec2.FlowLogTrafficType.REJECT,
    logFormat: '${version} ${account-id} ${interface-id}'
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_8(scope: Construct) {
  // Creating a VPC with flow logs enabled conditionally
  const vpc = new ec2.Vpc(scope, 'ConditionalFlowLogsVpc', {
    maxAzs: 2
  });
  
  const enableFlowLogs = true;
  
  if (enableFlowLogs) {
    // ok: typescript-cdk-vpc-flow-logs-enabled
    new ec2.FlowLog(scope, 'ConditionalFlowLog', {
      resourceType: ec2.FlowLogResourceType.fromVpc(vpc),
      destination: ec2.FlowLogDestination.toCloudWatchLogs()
    });
  }
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_9(scope: Construct) {
  // Creating multiple VPCs with flow logs enabled for all
  const vpc1 = new ec2.Vpc(scope, 'MultiVpc1', {
    maxAzs: 2
  });
  
  const vpc2 = new ec2.Vpc(scope, 'MultiVpc2', {
    maxAzs: 2
  });
  
  // ok: typescript-cdk-vpc-flow-logs-enabled
  new ec2.FlowLog(scope, 'Vpc1FlowLog', {
    resourceType: ec2.FlowLogResourceType.fromVpc(vpc1),
    destination: ec2.FlowLogDestination.toCloudWatchLogs()
  });
  
  // ok: typescript-cdk-vpc-flow-logs-enabled
  new ec2.FlowLog(scope, 'Vpc2FlowLog', {
    resourceType: ec2.FlowLogResourceType.fromVpc(vpc2),
    destination: ec2.FlowLogDestination.toCloudWatchLogs()
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_10(scope: Construct) {
  // Creating a VPC with flow logs enabled using a factory function
  function createVpcWithFlowLogs(id: string): ec2.Vpc {
    const vpc = new ec2.Vpc(scope, id, {
      maxAzs: 2
    });
    
    // ok: typescript-cdk-vpc-flow-logs-enabled
    new ec2.FlowLog(scope, `${id}FlowLog`, {
      resourceType: ec2.FlowLogResourceType.fromVpc(vpc),
      destination: ec2.FlowLogDestination.toCloudWatchLogs()
    });
    
    return vpc;
  }
  
  const vpc = createVpcWithFlowLogs('FactoryVpcWithLogs');
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_11(scope: Construct) {
  // Creating a VPC with flow logs enabled using a complex setup
  const vpc = new ec2.Vpc(scope, 'ComplexVpc', {
    maxAzs: 3,
    cidr: '10.0.0.0/16',
    natGateways: 3,
    subnetConfiguration: [
      {
        name: 'public',
        subnetType: ec2.SubnetType.PUBLIC,
        cidrMask: 24,
      },
      {
        name: 'private',
        subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
        cidrMask: 24,
      },
      {
        name: 'isolated',
        subnetType: ec2.SubnetType.PRIVATE_ISOLATED,
        cidrMask: 28,
      }
    ]
  });
  
  // ok: typescript-cdk-vpc-flow-logs-enabled
  new ec2.FlowLog(scope, 'ComplexVpcFlowLog', {
    resourceType: ec2.FlowLogResourceType.fromVpc(vpc),
    destination: ec2.FlowLogDestination.toCloudWatchLogs()
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_12(scope: Construct) {
  // Creating a VPC with flow logs enabled for both VPC and subnet
  const vpc = new ec2.Vpc(scope, 'VpcAndSubnetFlowLogsVpc', {
    maxAzs: 2
  });
  
  // ok: typescript-cdk-vpc-flow-logs-enabled
  new ec2.FlowLog(scope, 'VpcFlowLog', {
    resourceType: ec2.FlowLogResourceType.fromVpc(vpc),
    destination: ec2.FlowLogDestination.toCloudWatchLogs()
  });
  
  const subnet = vpc.selectSubnets({
    subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS
  }).subnets[0];
  
  new ec2.FlowLog(scope, 'SubnetFlowLog', {
    resourceType: ec2.FlowLogResourceType.fromSubnet(subnet),
    destination: ec2.FlowLogDestination.toCloudWatchLogs()
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_13(scope: Construct) {
  // Creating a VPC with flow logs enabled using a helper function
  const vpc = new ec2.Vpc(scope, 'HelperFunctionVpc', {
    maxAzs: 2
  });
  
  function enableFlowLogs(targetVpc: ec2.Vpc) {
    // ok: typescript-cdk-vpc-flow-logs-enabled
    new ec2.FlowLog(scope, 'HelperFlowLog', {
      resourceType: ec2.FlowLogResourceType.fromVpc(targetVpc),
      destination: ec2.FlowLogDestination.toCloudWatchLogs()
    });
  }
  
  enableFlowLogs(vpc);
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_14(scope: Construct) {
  // Creating a VPC with flow logs enabled with custom tags
  const vpc = new ec2.Vpc(scope, 'TaggedVpc', {
    maxAzs: 2
  });
  
  // ok: typescript-cdk-vpc-flow-logs-enabled
  const flowLog = new ec2.FlowLog(scope, 'TaggedFlowLog', {
    resourceType: ec2.FlowLogResourceType.fromVpc(vpc),
    destination: ec2.FlowLogDestination.toCloudWatchLogs()
  });
  
  cdk.Tags.of(flowLog).add('Environment', 'Production');
  cdk.Tags.of(flowLog).add('Purpose', 'SecurityMonitoring');
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_15(scope: Construct) {
  // Creating a VPC with flow logs enabled with both S3 and CloudWatch destinations
  const vpc = new ec2.Vpc(scope, 'DualDestinationVpc', {
    maxAzs: 2
  });
  
  // ok: typescript-cdk-vpc-flow-logs-enabled
  new ec2.FlowLog(scope, 'CloudWatchFlowLog', {
    resourceType: ec2.FlowLogResourceType.fromVpc(vpc),
    destination: ec2.FlowLogDestination.toCloudWatchLogs(),
    trafficType: ec2.FlowLogTrafficType.ACCEPT
  });
  
  new ec2.FlowLog(scope, 'S3FlowLog', {
    resourceType: ec2.FlowLogResourceType.fromVpc(vpc),
    destination: ec2.FlowLogDestination.toS3(),
    trafficType: ec2.FlowLogTrafficType.REJECT
  });
}
// {/fact}