import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as redshift from 'aws-cdk-lib/aws-redshift';
import * as ec2 from 'aws-cdk-lib/aws-ec2';

// True Positive Examples (Vulnerable Code)

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_1(scope: Construct) {
  // Creating a Redshift cluster without specifying port (defaults to 5439)
  // ruleid: typescript_cdk_redshift_cluster_usage_of_default_port
  new redshift.CfnCluster(scope, 'MyRedshiftCluster', {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    dbName: 'mydb',
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_2(scope: Construct) {
  // Explicitly setting the default port 5439
  // ruleid: typescript_cdk_redshift_cluster_usage_of_default_port
  new redshift.CfnCluster(scope, 'ExplicitDefaultPort', {
    clusterType: 'multi-node',
    nodeType: 'dc2.large',
    numberOfNodes: 2,
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    dbName: 'mydb',
    port: 5439,
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_3(scope: Construct) {
  // Using a variable that equals the default port
  const defaultPort = 5439;
  // ruleid: typescript_cdk_redshift_cluster_usage_of_default_port
  new redshift.CfnCluster(scope, 'VariableDefaultPort', {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    dbName: 'mydb',
    port: defaultPort,
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_4(scope: Construct, vpc: ec2.Vpc) {
  // Using the default port with VPC configuration
  // ruleid: typescript_cdk_redshift_cluster_usage_of_default_port
  new redshift.CfnCluster(scope, 'VpcDefaultPort', {
    clusterType: 'multi-node',
    nodeType: 'dc2.large',
    numberOfNodes: 3,
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    dbName: 'mydb',
    clusterSubnetGroupName: 'subnet-group',
    vpcSecurityGroupIds: ['sg-12345'],
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_5(scope: Construct) {
  // Using the default port with encryption enabled
  // ruleid: typescript_cdk_redshift_cluster_usage_of_default_port
  new redshift.CfnCluster(scope, 'EncryptedDefaultPort', {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    dbName: 'mydb',
    encrypted: true,
    kmsKeyId: 'arn:aws:kms:region:account:key/key-id',
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_6(scope: Construct) {
  // Using the default port with enhanced VPC routing
  // ruleid: typescript_cdk_redshift_cluster_usage_of_default_port
  new redshift.CfnCluster(scope, 'EnhancedVpcDefaultPort', {
    clusterType: 'multi-node',
    nodeType: 'dc2.large',
    numberOfNodes: 2,
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    dbName: 'mydb',
    enhancedVpcRouting: true,
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_7(scope: Construct) {
  // Using the default port with snapshot configuration
  // ruleid: typescript_cdk_redshift_cluster_usage_of_default_port
  new redshift.CfnCluster(scope, 'SnapshotDefaultPort', {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    dbName: 'mydb',
    snapshotIdentifier: 'snapshot-id',
    automatedSnapshotRetentionPeriod: 7,
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_8(scope: Construct) {
  // Using the default port with maintenance window
  // ruleid: typescript_cdk_redshift_cluster_usage_of_default_port
  new redshift.CfnCluster(scope, 'MaintenanceDefaultPort', {
    clusterType: 'multi-node',
    nodeType: 'dc2.large',
    numberOfNodes: 2,
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    dbName: 'mydb',
    preferredMaintenanceWindow: 'sun:03:00-sun:04:00',
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_9(scope: Construct) {
  // Using the default port with parameter group
  // ruleid: typescript_cdk_redshift_cluster_usage_of_default_port
  new redshift.CfnCluster(scope, 'ParameterGroupDefaultPort', {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    dbName: 'mydb',
    clusterParameterGroupName: 'my-parameter-group',
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_10(scope: Construct) {
  // Using the default port with tags
  // ruleid: typescript_cdk_redshift_cluster_usage_of_default_port
  new redshift.CfnCluster(scope, 'TaggedDefaultPort', {
    clusterType: 'multi-node',
    nodeType: 'dc2.large',
    numberOfNodes: 2,
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    dbName: 'mydb',
    tags: [
      { key: 'Environment', value: 'Production' },
      { key: 'Owner', value: 'DataTeam' }
    ],
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_11(scope: Construct) {
  // Using the default port with availability zone
  // ruleid: typescript_cdk_redshift_cluster_usage_of_default_port
  new redshift.CfnCluster(scope, 'AZDefaultPort', {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    dbName: 'mydb',
    availabilityZone: 'us-east-1a',
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_12(scope: Construct) {
  // Using the default port with publicly accessible setting
  // ruleid: typescript_cdk_redshift_cluster_usage_of_default_port
  new redshift.CfnCluster(scope, 'PublicDefaultPort', {
    clusterType: 'multi-node',
    nodeType: 'dc2.large',
    numberOfNodes: 2,
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    dbName: 'mydb',
    publiclyAccessible: false,
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_13(scope: Construct) {
  // Using the default port with IAM roles
  // ruleid: typescript_cdk_redshift_cluster_usage_of_default_port
  new redshift.CfnCluster(scope, 'IamRolesDefaultPort', {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    dbName: 'mydb',
    iamRoles: ['arn:aws:iam::123456789012:role/RedshiftRole'],
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_14(scope: Construct) {
  // Using the default port with logging enabled
  // ruleid: typescript_cdk_redshift_cluster_usage_of_default_port
  new redshift.CfnCluster(scope, 'LoggingDefaultPort', {
    clusterType: 'multi-node',
    nodeType: 'dc2.large',
    numberOfNodes: 2,
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    dbName: 'mydb',
    loggingProperties: {
      bucketName: 'my-logging-bucket',
      s3KeyPrefix: 'redshift-logs/'
    },
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_15(scope: Construct) {
  // Using the default port with HSM configuration
  // ruleid: typescript_cdk_redshift_cluster_usage_of_default_port
  new redshift.CfnCluster(scope, 'HsmDefaultPort', {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    dbName: 'mydb',
    hsmConfigurationIdentifier: 'hsm-config',
  });
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=code-injection@v1.0 defects=0}
function good_case_1(scope: Construct) {
  // Using a non-default port (5440)
  // ok: typescript_cdk_redshift_cluster_usage_of_default_port
  new redshift.CfnCluster(scope, 'NonDefaultPort', {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    dbName: 'mydb',
    port: 5440,
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_2(scope: Construct) {
  // Using a different non-default port (8192)
  // ok: typescript_cdk_redshift_cluster_usage_of_default_port
  new redshift.CfnCluster(scope, 'HigherNonDefaultPort', {
    clusterType: 'multi-node',
    nodeType: 'dc2.large',
    numberOfNodes: 2,
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    dbName: 'mydb',
    port: 8192,
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_3(scope: Construct) {
  // Using a variable with non-default port
  const securePort = 5441;
  // ok: typescript_cdk_redshift_cluster_usage_of_default_port
  new redshift.CfnCluster(scope, 'VariableNonDefaultPort', {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    dbName: 'mydb',
    port: securePort,
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_4(scope: Construct, vpc: ec2.Vpc) {
  // Using a non-default port with VPC configuration
  // ok: typescript_cdk_redshift_cluster_usage_of_default_port
  new redshift.CfnCluster(scope, 'VpcNonDefaultPort', {
    clusterType: 'multi-node',
    nodeType: 'dc2.large',
    numberOfNodes: 3,
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    dbName: 'mydb',
    port: 5442,
    clusterSubnetGroupName: 'subnet-group',
    vpcSecurityGroupIds: ['sg-12345'],
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_5(scope: Construct) {
  // Using a non-default port with encryption enabled
  // ok: typescript_cdk_redshift_cluster_usage_of_default_port
  new redshift.CfnCluster(scope, 'EncryptedNonDefaultPort', {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    dbName: 'mydb',
    port: 5443,
    encrypted: true,
    kmsKeyId: 'arn:aws:kms:region:account:key/key-id',
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_6(scope: Construct) {
  // Using a non-default port with enhanced VPC routing
  // ok: typescript_cdk_redshift_cluster_usage_of_default_port
  new redshift.CfnCluster(scope, 'EnhancedVpcNonDefaultPort', {
    clusterType: 'multi-node',
    nodeType: 'dc2.large',
    numberOfNodes: 2,
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    dbName: 'mydb',
    port: 5444,
    enhancedVpcRouting: true,
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_7(scope: Construct) {
  // Using a non-default port with snapshot configuration
  // ok: typescript_cdk_redshift_cluster_usage_of_default_port
  new redshift.CfnCluster(scope, 'SnapshotNonDefaultPort', {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    dbName: 'mydb',
    port: 5445,
    snapshotIdentifier: 'snapshot-id',
    automatedSnapshotRetentionPeriod: 7,
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_8(scope: Construct) {
  // Using a non-default port with maintenance window
  // ok: typescript_cdk_redshift_cluster_usage_of_default_port
  new redshift.CfnCluster(scope, 'MaintenanceNonDefaultPort', {
    clusterType: 'multi-node',
    nodeType: 'dc2.large',
    numberOfNodes: 2,
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    dbName: 'mydb',
    port: 5446,
    preferredMaintenanceWindow: 'sun:03:00-sun:04:00',
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_9(scope: Construct) {
  // Using a non-default port with parameter group
  // ok: typescript_cdk_redshift_cluster_usage_of_default_port
  new redshift.CfnCluster(scope, 'ParameterGroupNonDefaultPort', {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    dbName: 'mydb',
    port: 5447,
    clusterParameterGroupName: 'my-parameter-group',
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_10(scope: Construct) {
  // Using a non-default port with tags
  // ok: typescript_cdk_redshift_cluster_usage_of_default_port
  new redshift.CfnCluster(scope, 'TaggedNonDefaultPort', {
    clusterType: 'multi-node',
    nodeType: 'dc2.large',
    numberOfNodes: 2,
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    dbName: 'mydb',
    port: 5448,
    tags: [
      { key: 'Environment', value: 'Production' },
      { key: 'Owner', value: 'DataTeam' }
    ],
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_11(scope: Construct) {
  // Using a non-default port with availability zone
  // ok: typescript_cdk_redshift_cluster_usage_of_default_port
  new redshift.CfnCluster(scope, 'AZNonDefaultPort', {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    dbName: 'mydb',
    port: 5449,
    availabilityZone: 'us-east-1a',
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_12(scope: Construct) {
  // Using a non-default port with publicly accessible setting
  // ok: typescript_cdk_redshift_cluster_usage_of_default_port
  new redshift.CfnCluster(scope, 'PublicNonDefaultPort', {
    clusterType: 'multi-node',
    nodeType: 'dc2.large',
    numberOfNodes: 2,
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    dbName: 'mydb',
    port: 5450,
    publiclyAccessible: false,
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_13(scope: Construct) {
  // Using a non-default port with IAM roles
  // ok: typescript_cdk_redshift_cluster_usage_of_default_port
  new redshift.CfnCluster(scope, 'IamRolesNonDefaultPort', {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    dbName: 'mydb',
    port: 5451,
    iamRoles: ['arn:aws:iam::123456789012:role/RedshiftRole'],
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_14(scope: Construct) {
  // Using a non-default port with logging enabled
  // ok: typescript_cdk_redshift_cluster_usage_of_default_port
  new redshift.CfnCluster(scope, 'LoggingNonDefaultPort', {
    clusterType: 'multi-node',
    nodeType: 'dc2.large',
    numberOfNodes: 2,
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    dbName: 'mydb',
    port: 5452,
    loggingProperties: {
      bucketName: 'my-logging-bucket',
      s3KeyPrefix: 'redshift-logs/'
    },
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_15(scope: Construct) {
  // Using a non-default port with HSM configuration
  // ok: typescript_cdk_redshift_cluster_usage_of_default_port
  new redshift.CfnCluster(scope, 'HsmNonDefaultPort', {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    dbName: 'mydb',
    port: 5453,
    hsmConfigurationIdentifier: 'hsm-config',
  });
}
// {/fact}