import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as neptune from 'aws-cdk-lib/aws-neptune';
import * as rds from 'aws-cdk-lib/aws-rds';
import * as ec2 from 'aws-cdk-lib/aws-ec2';

// True Positives (Vulnerable Code Examples)

// {fact rule=coding-standards-violation@v1.0 defects=1}
function bad_case_1(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript-cdk-neptune-cluster-multi-az
  const cluster = new neptune.DatabaseCluster(scope, 'NeptuneCluster', {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
    multiAz: false, // Explicitly setting multiAz to false
  });
}
// {/fact}

// {fact rule=coding-standards-violation@v1.0 defects=1}
function bad_case_2(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript-cdk-neptune-cluster-multi-az
  const cluster = new neptune.DatabaseCluster(scope, 'NeptuneCluster', {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
    // multiAz not specified, defaults to false
  });
}
// {/fact}

// {fact rule=coding-standards-violation@v1.0 defects=1}
function bad_case_3(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  const subnetGroup = new neptune.SubnetGroup(scope, 'NeptuneSubnetGroup', {
    vpc,
    description: 'Subnet group for Neptune database',
  });
  
  // ruleid: typescript-cdk-neptune-cluster-multi-az
  const cluster = new neptune.DatabaseCluster(scope, 'NeptuneCluster', {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
    subnetGroup,
    multiAz: false,
    deletionProtection: true, // Even with deletion protection, still vulnerable without multiAz
  });
}
// {/fact}

// {fact rule=coding-standards-violation@v1.0 defects=1}
function bad_case_4(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript-cdk-neptune-cluster-multi-az
  const cluster = new neptune.CfnDBCluster(scope, 'NeptuneCluster', {
    dbSubnetGroupName: 'my-subnet-group',
    // No availabilityZones specified, which is needed for proper Multi-AZ
  });
  
  const instance = new neptune.CfnDBInstance(scope, 'NeptuneInstance', {
    dbClusterIdentifier: cluster.ref,
    dbInstanceClass: 'db.r5.large',
  });
}
// {/fact}

// {fact rule=coding-standards-violation@v1.0 defects=1}
function bad_case_5(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript-cdk-neptune-cluster-multi-az
  const cluster = new neptune.DatabaseCluster(scope, 'NeptuneCluster', {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
    multiAz: false,
    backupRetention: cdk.Duration.days(7), // Even with backup retention, still vulnerable without multiAz
  });
}
// {/fact}

// {fact rule=coding-standards-violation@v1.0 defects=1}
function bad_case_6(scope: Construct, stackProps: cdk.StackProps) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  const securityGroup = new ec2.SecurityGroup(scope, 'SecurityGroup', { vpc });
  
  // ruleid: typescript-cdk-neptune-cluster-multi-az
  const cluster = new neptune.DatabaseCluster(scope, 'NeptuneCluster', {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
    securityGroups: [securityGroup],
    multiAz: false,
  });
}
// {/fact}

// {fact rule=coding-standards-violation@v1.0 defects=1}
function bad_case_7(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript-cdk-neptune-cluster-multi-az
  const cluster = new neptune.DatabaseCluster(scope, 'NeptuneCluster', {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
    multiAz: false,
    removalPolicy: cdk.RemovalPolicy.SNAPSHOT, // Even with snapshot on removal, still vulnerable without multiAz
  });
}
// {/fact}

// {fact rule=coding-standards-violation@v1.0 defects=1}
function bad_case_8(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript-cdk-neptune-cluster-multi-az
  const dbClusterParams = {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
    multiAz: false,
  };
  
  const cluster = new neptune.DatabaseCluster(scope, 'NeptuneCluster', dbClusterParams);
}
// {/fact}

// {fact rule=coding-standards-violation@v1.0 defects=1}
function bad_case_9(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  const multiAzSetting = false;
  
  // ruleid: typescript-cdk-neptune-cluster-multi-az
  const cluster = new neptune.DatabaseCluster(scope, 'NeptuneCluster', {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
    multiAz: multiAzSetting,
  });
}
// {/fact}

// {fact rule=coding-standards-violation@v1.0 defects=1}
function bad_case_10(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript-cdk-neptune-cluster-multi-az
  const cluster = new neptune.DatabaseCluster(scope, 'NeptuneCluster', {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
    multiAz: process.env.NODE_ENV === 'production' ? false : false, // Always false regardless of condition
  });
}
// {/fact}

// {fact rule=coding-standards-violation@v1.0 defects=1}
function bad_case_11(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript-cdk-neptune-cluster-multi-az
  const cluster = new neptune.DatabaseCluster(scope, 'NeptuneCluster', {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
    multiAz: false,
    port: 8182, // Custom port, but still vulnerable without multiAz
  });
}
// {/fact}

// {fact rule=coding-standards-violation@v1.0 defects=1}
function bad_case_12(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript-cdk-neptune-cluster-multi-az
  const cluster = new neptune.CfnDBCluster(scope, 'NeptuneCluster', {
    dbSubnetGroupName: 'my-subnet-group',
    engineVersion: '1.2.0.0',
    // Missing availabilityZones configuration
  });
}
// {/fact}

// {fact rule=coding-standards-violation@v1.0 defects=1}
function bad_case_13(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript-cdk-neptune-cluster-multi-az
  const cluster = new neptune.DatabaseCluster(scope, 'NeptuneCluster', {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
    multiAz: false,
    storageEncrypted: true, // Even with encryption, still vulnerable without multiAz
  });
}
// {/fact}

// {fact rule=coding-standards-violation@v1.0 defects=1}
function bad_case_14(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript-cdk-neptune-cluster-multi-az
  const neptuneProps = {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
    multiAz: false,
  };
  
  for (let i = 0; i < 3; i++) {
    const cluster = new neptune.DatabaseCluster(scope, `NeptuneCluster-${i}`, neptuneProps);
  }
}
// {/fact}

// {fact rule=coding-standards-violation@v1.0 defects=1}
function bad_case_15(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  const createNeptuneCluster = () => {
    // ruleid: typescript-cdk-neptune-cluster-multi-az
    return new neptune.DatabaseCluster(scope, 'NeptuneCluster', {
      vpc,
      instanceType: neptune.InstanceType.R5_LARGE,
      multiAz: false,
    });
  };
  
  const cluster = createNeptuneCluster();
}
// {/fact}

// True Negatives (Secure Code Examples)

// {fact rule=coding-standards-violation@v1.0 defects=0}
function good_case_1(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript-cdk-neptune-cluster-multi-az
  const cluster = new neptune.DatabaseCluster(scope, 'NeptuneCluster', {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
    multiAz: true, // Properly setting multiAz to true
  });
}
// {/fact}

// {fact rule=coding-standards-violation@v1.0 defects=0}
function good_case_2(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript-cdk-neptune-cluster-multi-az
  const cluster = new neptune.CfnDBCluster(scope, 'NeptuneCluster', {
    dbSubnetGroupName: 'my-subnet-group',
    availabilityZones: ['us-east-1a', 'us-east-1b', 'us-east-1c'], // Properly specifying multiple AZs
  });
  
  const instance = new neptune.CfnDBInstance(scope, 'NeptuneInstance', {
    dbClusterIdentifier: cluster.ref,
    dbInstanceClass: 'db.r5.large',
  });
}
// {/fact}

// {fact rule=coding-standards-violation@v1.0 defects=0}
function good_case_3(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  const subnetGroup = new neptune.SubnetGroup(scope, 'NeptuneSubnetGroup', {
    vpc,
    description: 'Subnet group for Neptune database',
  });
  
  // ok: typescript-cdk-neptune-cluster-multi-az
  const cluster = new neptune.DatabaseCluster(scope, 'NeptuneCluster', {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
    subnetGroup,
    multiAz: true,
    deletionProtection: true,
  });
}
// {/fact}

// {fact rule=coding-standards-violation@v1.0 defects=0}
function good_case_4(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript-cdk-neptune-cluster-multi-az
  const cluster = new neptune.DatabaseCluster(scope, 'NeptuneCluster', {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
    multiAz: true,
    backupRetention: cdk.Duration.days(7),
  });
}
// {/fact}

// {fact rule=coding-standards-violation@v1.0 defects=0}
function good_case_5(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  const securityGroup = new ec2.SecurityGroup(scope, 'SecurityGroup', { vpc });
  
  // ok: typescript-cdk-neptune-cluster-multi-az
  const cluster = new neptune.DatabaseCluster(scope, 'NeptuneCluster', {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
    securityGroups: [securityGroup],
    multiAz: true,
  });
}
// {/fact}

// {fact rule=coding-standards-violation@v1.0 defects=0}
function good_case_6(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript-cdk-neptune-cluster-multi-az
  const cluster = new neptune.DatabaseCluster(scope, 'NeptuneCluster', {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
    multiAz: true,
    removalPolicy: cdk.RemovalPolicy.SNAPSHOT,
  });
}
// {/fact}

// {fact rule=coding-standards-violation@v1.0 defects=0}
function good_case_7(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript-cdk-neptune-cluster-multi-az
  const dbClusterParams = {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
    multiAz: true,
  };
  
  const cluster = new neptune.DatabaseCluster(scope, 'NeptuneCluster', dbClusterParams);
}
// {/fact}

// {fact rule=coding-standards-violation@v1.0 defects=0}
function good_case_8(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  const multiAzSetting = true;
  
  // ok: typescript-cdk-neptune-cluster-multi-az
  const cluster = new neptune.DatabaseCluster(scope, 'NeptuneCluster', {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
    multiAz: multiAzSetting,
  });
}
// {/fact}

// {fact rule=coding-standards-violation@v1.0 defects=0}
function good_case_9(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript-cdk-neptune-cluster-multi-az
  const cluster = new neptune.DatabaseCluster(scope, 'NeptuneCluster', {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
    multiAz: process.env.NODE_ENV === 'production' ? true : false, // True in production
    // This is considered secure because it enables multiAz in production
  });
}
// {/fact}

// {fact rule=coding-standards-violation@v1.0 defects=0}
function good_case_10(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript-cdk-neptune-cluster-multi-az
  const cluster = new neptune.DatabaseCluster(scope, 'NeptuneCluster', {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
    multiAz: true,
    port: 8182,
  });
}
// {/fact}

// {fact rule=coding-standards-violation@v1.0 defects=0}
function good_case_11(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript-cdk-neptune-cluster-multi-az
  const cluster = new neptune.CfnDBCluster(scope, 'NeptuneCluster', {
    dbSubnetGroupName: 'my-subnet-group',
    engineVersion: '1.2.0.0',
    availabilityZones: ['us-west-2a', 'us-west-2b'], // Properly specifying multiple AZs
  });
}
// {/fact}

// {fact rule=coding-standards-violation@v1.0 defects=0}
function good_case_12(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript-cdk-neptune-cluster-multi-az
  const cluster = new neptune.DatabaseCluster(scope, 'NeptuneCluster', {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
    multiAz: true,
    storageEncrypted: true,
  });
}
// {/fact}

// {fact rule=coding-standards-violation@v1.0 defects=0}
function good_case_13(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript-cdk-neptune-cluster-multi-az
  const neptuneProps = {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
    multiAz: true,
  };
  
  for (let i = 0; i < 3; i++) {
    const cluster = new neptune.DatabaseCluster(scope, `NeptuneCluster-${i}`, neptuneProps);
  }
}
// {/fact}

// {fact rule=coding-standards-violation@v1.0 defects=0}
function good_case_14(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  const createNeptuneCluster = () => {
    // ok: typescript-cdk-neptune-cluster-multi-az
    return new neptune.DatabaseCluster(scope, 'NeptuneCluster', {
      vpc,
      instanceType: neptune.InstanceType.R5_LARGE,
      multiAz: true,
    });
  };
  
  const cluster = createNeptuneCluster();
}
// {/fact}

// {fact rule=coding-standards-violation@v1.0 defects=0}
function good_case_15(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript-cdk-neptune-cluster-multi-az
  const cluster = new neptune.DatabaseCluster(scope, 'NeptuneCluster', {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
    multiAz: true,
    preferredMaintenanceWindow: 'sun:23:45-mon:00:15', // Setting maintenance window with multiAz enabled
  });
}
// {/fact}