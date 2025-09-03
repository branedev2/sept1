import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as redshift from 'aws-cdk-lib/aws-redshift';
import * as ec2 from 'aws-cdk-lib/aws-ec2';

// True Positive Examples (Vulnerable Code)

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_1(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript-cdk-redshift-backup-enabled
  new redshift.Cluster(scope, 'RedshiftCluster1', {
    masterUser: {
      masterUsername: 'admin',
      masterPassword: cdk.SecretValue.unsafePlainText('password'),
    },
    vpc,
    automatedSnapshotRetentionPeriod: 0, // Explicitly disabling automated snapshots
    nodeType: redshift.NodeType.RA3_4XLARGE,
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_2(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript-cdk-redshift-backup-enabled
  const cluster = new redshift.Cluster(scope, 'RedshiftCluster2', {
    masterUser: {
      masterUsername: 'admin',
      masterPassword: cdk.SecretValue.secretsManager('redshift/password'),
    },
    vpc,
    automatedSnapshotRetentionPeriod: 0,
    nodeType: redshift.NodeType.DC2_LARGE,
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_3(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript-cdk-redshift-backup-enabled
  const props = {
    masterUser: {
      masterUsername: 'admin',
      masterPassword: cdk.SecretValue.secretsManager('redshift/password'),
    },
    vpc,
    automatedSnapshotRetentionPeriod: 0,
    nodeType: redshift.NodeType.RA3_16XLARGE,
  };
  
  new redshift.Cluster(scope, 'RedshiftCluster3', props);
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_4(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  const snapshotRetention = 0;
  
  // ruleid: typescript-cdk-redshift-backup-enabled
  new redshift.Cluster(scope, 'RedshiftCluster4', {
    masterUser: {
      masterUsername: 'admin',
      masterPassword: cdk.SecretValue.secretsManager('redshift/password'),
    },
    vpc,
    automatedSnapshotRetentionPeriod: snapshotRetention,
    nodeType: redshift.NodeType.DC2_8XLARGE,
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_5(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript-cdk-redshift-backup-enabled
  const cluster = new redshift.CfnCluster(scope, 'RedshiftCluster5', {
    clusterType: 'multi-node',
    numberOfNodes: 2,
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    automatedSnapshotRetentionPeriod: 0,
    vpcSecurityGroupIds: ['sg-12345'],
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_6(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  const config = {
    retention: 0,
    nodeType: redshift.NodeType.RA3_4XLARGE,
  };
  
  // ruleid: typescript-cdk-redshift-backup-enabled
  new redshift.Cluster(scope, 'RedshiftCluster6', {
    masterUser: {
      masterUsername: 'admin',
      masterPassword: cdk.SecretValue.secretsManager('redshift/password'),
    },
    vpc,
    automatedSnapshotRetentionPeriod: config.retention,
    nodeType: config.nodeType,
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_7(scope: Construct, env: string) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript-cdk-redshift-backup-enabled
  new redshift.Cluster(scope, 'RedshiftCluster7', {
    masterUser: {
      masterUsername: 'admin',
      masterPassword: cdk.SecretValue.secretsManager('redshift/password'),
    },
    vpc,
    automatedSnapshotRetentionPeriod: env === 'dev' ? 0 : 7, // Disabling backups in dev environment
    nodeType: redshift.NodeType.DC2_LARGE,
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_8(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  const clusterProps: redshift.ClusterProps = {
    masterUser: {
      masterUsername: 'admin',
      masterPassword: cdk.SecretValue.secretsManager('redshift/password'),
    },
    vpc,
    nodeType: redshift.NodeType.RA3_4XLARGE,
    automatedSnapshotRetentionPeriod: 0,
  };
  
  // ruleid: typescript-cdk-redshift-backup-enabled
  new redshift.Cluster(scope, 'RedshiftCluster8', clusterProps);
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_9(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript-cdk-redshift-backup-enabled
  const cfnCluster = new redshift.CfnCluster(scope, 'RedshiftCluster9', {
    clusterType: 'single-node',
    nodeType: 'ra3.4xlarge',
    masterUsername: 'admin',
    masterUserPassword: 'SecurePassword123!',
    automatedSnapshotRetentionPeriod: 0,
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_10(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  function createCluster() {
    // ruleid: typescript-cdk-redshift-backup-enabled
    return new redshift.Cluster(scope, 'RedshiftCluster10', {
      masterUser: {
        masterUsername: 'admin',
        masterPassword: cdk.SecretValue.secretsManager('redshift/password'),
      },
      vpc,
      automatedSnapshotRetentionPeriod: 0,
      nodeType: redshift.NodeType.DC2_LARGE,
    });
  }
  
  const cluster = createCluster();
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_11(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript-cdk-redshift-backup-enabled
  const cluster = new redshift.Cluster(scope, 'RedshiftCluster11', {
    masterUser: {
      masterUsername: 'admin',
      masterPassword: cdk.SecretValue.secretsManager('redshift/password'),
    },
    vpc,
    nodeType: redshift.NodeType.RA3_4XLARGE,
    // Not specifying automatedSnapshotRetentionPeriod, which defaults to 1 (enabled)
  });
  
  // But then disabling it after creation
  cluster.addPropertyOverride('AutomatedSnapshotRetentionPeriod', 0);
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_12(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript-cdk-redshift-backup-enabled
  new redshift.CfnCluster(scope, 'RedshiftCluster12', {
    clusterType: 'multi-node',
    numberOfNodes: 4,
    nodeType: 'ra3.16xlarge',
    masterUsername: 'admin',
    masterUserPassword: 'Password123!',
    // Not specifying automatedSnapshotRetentionPeriod
  }).addPropertyOverride('AutomatedSnapshotRetentionPeriod', 0);
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_13(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  const retentionPeriod = process.env.IS_PRODUCTION === 'true' ? 7 : 0;
  
  // ruleid: typescript-cdk-redshift-backup-enabled
  new redshift.Cluster(scope, 'RedshiftCluster13', {
    masterUser: {
      masterUsername: 'admin',
      masterPassword: cdk.SecretValue.secretsManager('redshift/password'),
    },
    vpc,
    automatedSnapshotRetentionPeriod: retentionPeriod, // Could be 0 for non-production
    nodeType: redshift.NodeType.DC2_LARGE,
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_14(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript-cdk-redshift-backup-enabled
  const cfnCluster = new redshift.CfnCluster(scope, 'RedshiftCluster14', {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123!',
  });
  
  // Setting automated snapshot retention to 0 using CloudFormation properties
  cfnCluster.addPropertyOverride('AutomatedSnapshotRetentionPeriod', 0);
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_15(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  const clusterParams = {
    masterUsername: 'admin',
    masterPassword: 'Password123!',
    nodeType: 'ra3.4xlarge',
    clusterType: 'multi-node',
    numberOfNodes: 2,
    automatedSnapshotRetentionPeriod: 0,
  };
  
  // ruleid: typescript-cdk-redshift-backup-enabled
  new redshift.CfnCluster(scope, 'RedshiftCluster15', clusterParams);
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_1(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript-cdk-redshift-backup-enabled
  new redshift.Cluster(scope, 'RedshiftCluster1', {
    masterUser: {
      masterUsername: 'admin',
      masterPassword: cdk.SecretValue.secretsManager('redshift/password'),
    },
    vpc,
    automatedSnapshotRetentionPeriod: 7, // Enabling automated snapshots with 7-day retention
    nodeType: redshift.NodeType.RA3_4XLARGE,
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_2(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript-cdk-redshift-backup-enabled
  const cluster = new redshift.Cluster(scope, 'RedshiftCluster2', {
    masterUser: {
      masterUsername: 'admin',
      masterPassword: cdk.SecretValue.secretsManager('redshift/password'),
    },
    vpc,
    automatedSnapshotRetentionPeriod: 35, // Maximum retention period
    nodeType: redshift.NodeType.DC2_LARGE,
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_3(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript-cdk-redshift-backup-enabled
  const props = {
    masterUser: {
      masterUsername: 'admin',
      masterPassword: cdk.SecretValue.secretsManager('redshift/password'),
    },
    vpc,
    automatedSnapshotRetentionPeriod: 14,
    nodeType: redshift.NodeType.RA3_16XLARGE,
  };
  
  new redshift.Cluster(scope, 'RedshiftCluster3', props);
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_4(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  const snapshotRetention = 30;
  
  // ok: typescript-cdk-redshift-backup-enabled
  new redshift.Cluster(scope, 'RedshiftCluster4', {
    masterUser: {
      masterUsername: 'admin',
      masterPassword: cdk.SecretValue.secretsManager('redshift/password'),
    },
    vpc,
    automatedSnapshotRetentionPeriod: snapshotRetention,
    nodeType: redshift.NodeType.DC2_8XLARGE,
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_5(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript-cdk-redshift-backup-enabled
  const cluster = new redshift.CfnCluster(scope, 'RedshiftCluster5', {
    clusterType: 'multi-node',
    numberOfNodes: 2,
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    automatedSnapshotRetentionPeriod: 7,
    vpcSecurityGroupIds: ['sg-12345'],
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_6(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  const config = {
    retention: 14,
    nodeType: redshift.NodeType.RA3_4XLARGE,
  };
  
  // ok: typescript-cdk-redshift-backup-enabled
  new redshift.Cluster(scope, 'RedshiftCluster6', {
    masterUser: {
      masterUsername: 'admin',
      masterPassword: cdk.SecretValue.secretsManager('redshift/password'),
    },
    vpc,
    automatedSnapshotRetentionPeriod: config.retention,
    nodeType: config.nodeType,
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_7(scope: Construct, env: string) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript-cdk-redshift-backup-enabled
  new redshift.Cluster(scope, 'RedshiftCluster7', {
    masterUser: {
      masterUsername: 'admin',
      masterPassword: cdk.SecretValue.secretsManager('redshift/password'),
    },
    vpc,
    automatedSnapshotRetentionPeriod: env === 'prod' ? 35 : 7, // Different retention periods based on environment, but always enabled
    nodeType: redshift.NodeType.DC2_LARGE,
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_8(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  const clusterProps: redshift.ClusterProps = {
    masterUser: {
      masterUsername: 'admin',
      masterPassword: cdk.SecretValue.secretsManager('redshift/password'),
    },
    vpc,
    nodeType: redshift.NodeType.RA3_4XLARGE,
    automatedSnapshotRetentionPeriod: 3,
  };
  
  // ok: typescript-cdk-redshift-backup-enabled
  new redshift.Cluster(scope, 'RedshiftCluster8', clusterProps);
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_9(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript-cdk-redshift-backup-enabled
  const cfnCluster = new redshift.CfnCluster(scope, 'RedshiftCluster9', {
    clusterType: 'single-node',
    nodeType: 'ra3.4xlarge',
    masterUsername: 'admin',
    masterUserPassword: 'SecurePassword123!',
    automatedSnapshotRetentionPeriod: 5,
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_10(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  function createCluster() {
    // ok: typescript-cdk-redshift-backup-enabled
    return new redshift.Cluster(scope, 'RedshiftCluster10', {
      masterUser: {
        masterUsername: 'admin',
        masterPassword: cdk.SecretValue.secretsManager('redshift/password'),
      },
      vpc,
      automatedSnapshotRetentionPeriod: 7,
      nodeType: redshift.NodeType.DC2_LARGE,
    });
  }
  
  const cluster = createCluster();
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_11(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript-cdk-redshift-backup-enabled
  const cluster = new redshift.Cluster(scope, 'RedshiftCluster11', {
    masterUser: {
      masterUsername: 'admin',
      masterPassword: cdk.SecretValue.secretsManager('redshift/password'),
    },
    vpc,
    nodeType: redshift.NodeType.RA3_4XLARGE,
    // Not specifying automatedSnapshotRetentionPeriod, which defaults to 1 (enabled)
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_12(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript-cdk-redshift-backup-enabled
  new redshift.CfnCluster(scope, 'RedshiftCluster12', {
    clusterType: 'multi-node',
    numberOfNodes: 4,
    nodeType: 'ra3.16xlarge',
    masterUsername: 'admin',
    masterUserPassword: 'Password123!',
    // Not specifying automatedSnapshotRetentionPeriod, which defaults to 1 (enabled)
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_13(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript-cdk-redshift-backup-enabled
  new redshift.Cluster(scope, 'RedshiftCluster13', {
    masterUser: {
      masterUsername: 'admin',
      masterPassword: cdk.SecretValue.secretsManager('redshift/password'),
    },
    vpc,
    automatedSnapshotRetentionPeriod: 1, // Minimum non-zero value
    nodeType: redshift.NodeType.DC2_LARGE,
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_14(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript-cdk-redshift-backup-enabled
  const cfnCluster = new redshift.CfnCluster(scope, 'RedshiftCluster14', {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123!',
  });
  
  // Setting automated snapshot retention to a positive value using CloudFormation properties
  cfnCluster.addPropertyOverride('AutomatedSnapshotRetentionPeriod', 10);
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_15(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  const clusterParams = {
    masterUsername: 'admin',
    masterPassword: 'Password123!',
    nodeType: 'ra3.4xlarge',
    clusterType: 'multi-node',
    numberOfNodes: 2,
    automatedSnapshotRetentionPeriod: 21,
  };
  
  // ok: typescript-cdk-redshift-backup-enabled
  new redshift.CfnCluster(scope, 'RedshiftCluster15', clusterParams);
}
// {/fact}