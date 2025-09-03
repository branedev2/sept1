import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as redshift from 'aws-cdk-lib/aws-redshift';

// True Positives (Vulnerable Code - Missing Audit Logging)

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_1(scope: Construct) {
  // Creating a Redshift cluster without logging properties
  // ruleid: typescript_cdk_redshift_cluster_audit_logging
  new redshift.CfnCluster(scope, 'RedshiftCluster1', {
    clusterType: 'multi-node',
    numberOfNodes: 2,
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    dbName: 'mydb',
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_2(scope: Construct) {
  // Creating a Redshift cluster with empty properties object but no logging
  const props = {
    clusterType: 'multi-node',
    numberOfNodes: 2,
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
  };
  
  // ruleid: typescript_cdk_redshift_cluster_audit_logging
  new redshift.CfnCluster(scope, 'RedshiftCluster2', props);
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_3(scope: Construct) {
  // Creating a Redshift cluster with null logging properties
  // ruleid: typescript_cdk_redshift_cluster_audit_logging
  new redshift.CfnCluster(scope, 'RedshiftCluster3', {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    dbName: 'mydb',
    loggingProperties: null,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_4(scope: Construct) {
  // Creating a Redshift cluster with undefined logging properties
  const loggingProps = undefined;
  
  // ruleid: typescript_cdk_redshift_cluster_audit_logging
  new redshift.CfnCluster(scope, 'RedshiftCluster4', {
    clusterType: 'multi-node',
    numberOfNodes: 3,
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    dbName: 'mydb',
    loggingProperties: loggingProps,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_5(scope: Construct) {
  // Creating a Redshift cluster with empty logging properties object
  // ruleid: typescript_cdk_redshift_cluster_audit_logging
  new redshift.CfnCluster(scope, 'RedshiftCluster5', {
    clusterType: 'multi-node',
    numberOfNodes: 2,
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    dbName: 'mydb',
    loggingProperties: {},
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_6(scope: Construct, stackProps: cdk.StackProps) {
  // Creating a Redshift cluster in a production environment without logging
  const isProd = stackProps.tags && stackProps.tags['environment'] === 'production';
  
  // ruleid: typescript_cdk_redshift_cluster_audit_logging
  new redshift.CfnCluster(scope, 'RedshiftCluster6', {
    clusterType: isProd ? 'multi-node' : 'single-node',
    numberOfNodes: isProd ? 4 : 1,
    nodeType: isProd ? 'dc2.8xlarge' : 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    dbName: 'proddb',
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_7(scope: Construct) {
  // Creating a Redshift cluster with conditional properties but missing logging
  const config = {
    clusterType: 'multi-node',
    numberOfNodes: 2,
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    dbName: 'mydb',
  };
  
  // ruleid: typescript_cdk_redshift_cluster_audit_logging
  new redshift.CfnCluster(scope, 'RedshiftCluster7', config);
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_8(scope: Construct) {
  // Creating a Redshift cluster with incorrect logging properties structure
  // ruleid: typescript_cdk_redshift_cluster_audit_logging
  new redshift.CfnCluster(scope, 'RedshiftCluster8', {
    clusterType: 'multi-node',
    numberOfNodes: 2,
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    dbName: 'mydb',
    loggingEnabled: true, // Incorrect property name
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_9(scope: Construct) {
  // Creating a Redshift cluster with logging properties that don't enable bucket logging
  // ruleid: typescript_cdk_redshift_cluster_audit_logging
  new redshift.CfnCluster(scope, 'RedshiftCluster9', {
    clusterType: 'multi-node',
    numberOfNodes: 2,
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    dbName: 'mydb',
    loggingProperties: {
      // Missing bucketName and s3KeyPrefix
    },
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_10(scope: Construct) {
  // Creating a Redshift cluster with partial logging properties
  // ruleid: typescript_cdk_redshift_cluster_audit_logging
  new redshift.CfnCluster(scope, 'RedshiftCluster10', {
    clusterType: 'multi-node',
    numberOfNodes: 2,
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    dbName: 'mydb',
    loggingProperties: {
      bucketName: 'my-logs-bucket',
      // Missing s3KeyPrefix
    },
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_11(scope: Construct) {
  // Creating multiple Redshift clusters in a loop, all without logging
  const clusterConfigs = [
    { id: 'Cluster1', nodes: 2 },
    { id: 'Cluster2', nodes: 3 },
  ];
  
  for (const config of clusterConfigs) {
    // ruleid: typescript_cdk_redshift_cluster_audit_logging
    new redshift.CfnCluster(scope, config.id, {
      clusterType: 'multi-node',
      numberOfNodes: config.nodes,
      nodeType: 'dc2.large',
      masterUsername: 'admin',
      masterUserPassword: 'Password123',
      dbName: 'mydb',
    });
  }
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_12(scope: Construct) {
  // Creating a Redshift cluster with logging properties that have empty strings
  // ruleid: typescript_cdk_redshift_cluster_audit_logging
  new redshift.CfnCluster(scope, 'RedshiftCluster12', {
    clusterType: 'multi-node',
    numberOfNodes: 2,
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    dbName: 'mydb',
    loggingProperties: {
      bucketName: '',
      s3KeyPrefix: '',
    },
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_13(scope: Construct) {
  // Creating a Redshift cluster with a factory function but no logging
  function createClusterProps() {
    return {
      clusterType: 'multi-node',
      numberOfNodes: 2,
      nodeType: 'dc2.large',
      masterUsername: 'admin',
      masterUserPassword: 'Password123',
      dbName: 'mydb',
    };
  }
  
  // ruleid: typescript_cdk_redshift_cluster_audit_logging
  new redshift.CfnCluster(scope, 'RedshiftCluster13', createClusterProps());
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_14(scope: Construct) {
  // Creating a Redshift cluster with a try-catch but no logging
  try {
    // ruleid: typescript_cdk_redshift_cluster_audit_logging
    new redshift.CfnCluster(scope, 'RedshiftCluster14', {
      clusterType: 'multi-node',
      numberOfNodes: 2,
      nodeType: 'dc2.large',
      masterUsername: 'admin',
      masterUserPassword: 'Password123',
      dbName: 'mydb',
    });
  } catch (error) {
    console.error('Failed to create Redshift cluster', error);
  }
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_15(scope: Construct) {
  // Creating a Redshift cluster with conditional logic but no logging in any branch
  const isHighPerformance = true;
  
  // ruleid: typescript_cdk_redshift_cluster_audit_logging
  new redshift.CfnCluster(scope, 'RedshiftCluster15', {
    clusterType: 'multi-node',
    numberOfNodes: isHighPerformance ? 4 : 2,
    nodeType: isHighPerformance ? 'dc2.8xlarge' : 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    dbName: 'mydb',
  });
}
// {/fact}

// True Negatives (Secure Code - With Audit Logging)

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_1(scope: Construct) {
  // Creating a Redshift cluster with proper logging properties
  // ok: typescript_cdk_redshift_cluster_audit_logging
  new redshift.CfnCluster(scope, 'RedshiftCluster1', {
    clusterType: 'multi-node',
    numberOfNodes: 2,
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    dbName: 'mydb',
    loggingProperties: {
      bucketName: 'my-logs-bucket',
      s3KeyPrefix: 'redshift-logs/',
    },
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_2(scope: Construct) {
  // Creating a Redshift cluster with logging properties from variables
  const logBucket = 'audit-logs-bucket';
  const logPrefix = 'redshift/cluster2/';
  
  // ok: typescript_cdk_redshift_cluster_audit_logging
  new redshift.CfnCluster(scope, 'RedshiftCluster2', {
    clusterType: 'multi-node',
    numberOfNodes: 2,
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    dbName: 'mydb',
    loggingProperties: {
      bucketName: logBucket,
      s3KeyPrefix: logPrefix,
    },
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_3(scope: Construct) {
  // Creating a Redshift cluster with logging properties in a separate object
  const loggingProps = {
    bucketName: 'redshift-audit-logs',
    s3KeyPrefix: 'cluster3/',
  };
  
  // ok: typescript_cdk_redshift_cluster_audit_logging
  new redshift.CfnCluster(scope, 'RedshiftCluster3', {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    dbName: 'mydb',
    loggingProperties: loggingProps,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_4(scope: Construct) {
  // Creating a Redshift cluster with conditional logging properties
  const isProd = true;
  const logBucket = isProd ? 'prod-audit-logs' : 'dev-audit-logs';
  const logPrefix = isProd ? 'prod/redshift/' : 'dev/redshift/';
  
  // ok: typescript_cdk_redshift_cluster_audit_logging
  new redshift.CfnCluster(scope, 'RedshiftCluster4', {
    clusterType: 'multi-node',
    numberOfNodes: isProd ? 3 : 1,
    nodeType: isProd ? 'dc2.8xlarge' : 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    dbName: 'mydb',
    loggingProperties: {
      bucketName: logBucket,
      s3KeyPrefix: logPrefix,
    },
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_5(scope: Construct) {
  // Creating a Redshift cluster with all properties in a config object
  const clusterConfig = {
    clusterType: 'multi-node',
    numberOfNodes: 2,
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    dbName: 'mydb',
    loggingProperties: {
      bucketName: 'centralized-logs',
      s3KeyPrefix: 'redshift/cluster5/',
    },
  };
  
  // ok: typescript_cdk_redshift_cluster_audit_logging
  new redshift.CfnCluster(scope, 'RedshiftCluster5', clusterConfig);
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_6(scope: Construct) {
  // Creating a Redshift cluster with logging properties in a factory function
  function createLoggingProps() {
    return {
      bucketName: 'audit-logs-' + new Date().getFullYear(),
      s3KeyPrefix: 'redshift/cluster6/',
    };
  }
  
  // ok: typescript_cdk_redshift_cluster_audit_logging
  new redshift.CfnCluster(scope, 'RedshiftCluster6', {
    clusterType: 'multi-node',
    numberOfNodes: 2,
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    dbName: 'mydb',
    loggingProperties: createLoggingProps(),
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_7(scope: Construct) {
  // Creating multiple Redshift clusters in a loop, all with logging
  const clusterConfigs = [
    { id: 'Cluster7A', nodes: 2, prefix: 'cluster7a/' },
    { id: 'Cluster7B', nodes: 3, prefix: 'cluster7b/' },
  ];
  
  for (const config of clusterConfigs) {
    // ok: typescript_cdk_redshift_cluster_audit_logging
    new redshift.CfnCluster(scope, config.id, {
      clusterType: 'multi-node',
      numberOfNodes: config.nodes,
      nodeType: 'dc2.large',
      masterUsername: 'admin',
      masterUserPassword: 'Password123',
      dbName: 'mydb',
      loggingProperties: {
        bucketName: 'multi-cluster-logs',
        s3KeyPrefix: config.prefix,
      },
    });
  }
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_8(scope: Construct) {
  // Creating a Redshift cluster with try-catch and logging properties
  try {
    // ok: typescript_cdk_redshift_cluster_audit_logging
    new redshift.CfnCluster(scope, 'RedshiftCluster8', {
      clusterType: 'multi-node',
      numberOfNodes: 2,
      nodeType: 'dc2.large',
      masterUsername: 'admin',
      masterUserPassword: 'Password123',
      dbName: 'mydb',
      loggingProperties: {
        bucketName: 'secure-audit-logs',
        s3KeyPrefix: 'redshift/cluster8/',
      },
    });
  } catch (error) {
    console.error('Failed to create Redshift cluster', error);
  }
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_9(scope: Construct) {
  // Creating a Redshift cluster with environment-specific logging
  const env = process.env.ENVIRONMENT || 'dev';
  const logBucket = `${env}-audit-logs`;
  const logPrefix = `${env}/redshift/cluster9/`;
  
  // ok: typescript_cdk_redshift_cluster_audit_logging
  new redshift.CfnCluster(scope, 'RedshiftCluster9', {
    clusterType: env === 'prod' ? 'multi-node' : 'single-node',
    numberOfNodes: env === 'prod' ? 3 : 1,
    nodeType: env === 'prod' ? 'dc2.8xlarge' : 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    dbName: 'mydb',
    loggingProperties: {
      bucketName: logBucket,
      s3KeyPrefix: logPrefix,
    },
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_10(scope: Construct) {
  // Creating a Redshift cluster with detailed logging properties
  const timestamp = new Date().toISOString().split('T')[0];
  
  // ok: typescript_cdk_redshift_cluster_audit_logging
  new redshift.CfnCluster(scope, 'RedshiftCluster10', {
    clusterType: 'multi-node',
    numberOfNodes: 2,
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    dbName: 'mydb',
    loggingProperties: {
      bucketName: 'detailed-audit-logs',
      s3KeyPrefix: `redshift/cluster10/${timestamp}/`,
    },
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_11(scope: Construct) {
  // Creating a Redshift cluster with logging properties and additional configuration
  // ok: typescript_cdk_redshift_cluster_audit_logging
  new redshift.CfnCluster(scope, 'RedshiftCluster11', {
    clusterType: 'multi-node',
    numberOfNodes: 2,
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    dbName: 'mydb',
    loggingProperties: {
      bucketName: 'comprehensive-logs',
      s3KeyPrefix: 'redshift/cluster11/',
    },
    clusterParameterGroupName: 'custom-params',
    vpcSecurityGroupIds: ['sg-12345'],
    enhancedVpcRouting: true,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_12(scope: Construct) {
  // Creating a Redshift cluster with logging properties and tags
  // ok: typescript_cdk_redshift_cluster_audit_logging
  new redshift.CfnCluster(scope, 'RedshiftCluster12', {
    clusterType: 'multi-node',
    numberOfNodes: 2,
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    dbName: 'mydb',
    loggingProperties: {
      bucketName: 'tagged-audit-logs',
      s3KeyPrefix: 'redshift/cluster12/',
    },
    tags: [
      { key: 'Environment', value: 'Production' },
      { key: 'Department', value: 'Analytics' },
    ],
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_13(scope: Construct) {
  // Creating a Redshift cluster with logging properties and encryption
  // ok: typescript_cdk_redshift_cluster_audit_logging
  new redshift.CfnCluster(scope, 'RedshiftCluster13', {
    clusterType: 'multi-node',
    numberOfNodes: 2,
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    dbName: 'mydb',
    loggingProperties: {
      bucketName: 'encrypted-audit-logs',
      s3KeyPrefix: 'redshift/cluster13/',
    },
    encrypted: true,
    kmsKeyId: 'arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab',
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_14(scope: Construct) {
  // Creating a Redshift cluster with logging properties and snapshot configuration
  // ok: typescript_cdk_redshift_cluster_audit_logging
  new redshift.CfnCluster(scope, 'RedshiftCluster14', {
    clusterType: 'multi-node',
    numberOfNodes: 2,
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    dbName: 'mydb',
    loggingProperties: {
      bucketName: 'snapshot-audit-logs',
      s3KeyPrefix: 'redshift/cluster14/',
    },
    automatedSnapshotRetentionPeriod: 7,
    snapshotCopyRetentionPeriod: 7,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_15(scope: Construct) {
  // Creating a Redshift cluster with logging properties and advanced networking
  // ok: typescript_cdk_redshift_cluster_audit_logging
  new redshift.CfnCluster(scope, 'RedshiftCluster15', {
    clusterType: 'multi-node',
    numberOfNodes: 2,
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    dbName: 'mydb',
    loggingProperties: {
      bucketName: 'network-audit-logs',
      s3KeyPrefix: 'redshift/cluster15/',
    },
    clusterSubnetGroupName: 'redshift-subnet-group',
    publiclyAccessible: false,
    enhancedVpcRouting: true,
  });
}
// {/fact}