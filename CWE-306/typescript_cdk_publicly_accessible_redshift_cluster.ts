import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as redshift from 'aws-cdk-lib/aws-redshift';
import * as ec2 from 'aws-cdk-lib/aws-ec2';

// True positive examples (vulnerable code)

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_1(scope: Construct) {
  // Creating a Redshift cluster with publiclyAccessible set to true explicitly
  // ruleid: typescript_cdk_publicly_accessible_redshift_cluster
  new redshift.CfnCluster(scope, 'VulnerableRedshiftCluster1', {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    publiclyAccessible: true,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_2(scope: Construct) {
  // Creating a Redshift cluster with publiclyAccessible set to true in a variable
  const clusterProps = {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    publiclyAccessible: true,
  };
  
  // ruleid: typescript_cdk_publicly_accessible_redshift_cluster
  new redshift.CfnCluster(scope, 'VulnerableRedshiftCluster2', clusterProps);
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_3(scope: Construct) {
  // Creating a Redshift cluster with publiclyAccessible set to true using a function
  function getClusterConfig() {
    return {
      clusterType: 'multi-node',
      numberOfNodes: 2,
      nodeType: 'dc2.large',
      masterUsername: 'admin',
      masterUserPassword: 'Password123',
      publiclyAccessible: true,
    };
  }
  
  // ruleid: typescript_cdk_publicly_accessible_redshift_cluster
  new redshift.CfnCluster(scope, 'VulnerableRedshiftCluster3', getClusterConfig());
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_4(scope: Construct, isPublic: boolean = true) {
  // Creating a Redshift cluster with publiclyAccessible set to true by default parameter
  // ruleid: typescript_cdk_publicly_accessible_redshift_cluster
  new redshift.CfnCluster(scope, 'VulnerableRedshiftCluster4', {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    publiclyAccessible: isPublic,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_5(scope: Construct) {
  // Creating a Redshift cluster with publiclyAccessible set to true in a conditional
  const isProduction = false;
  
  // ruleid: typescript_cdk_publicly_accessible_redshift_cluster
  new redshift.CfnCluster(scope, 'VulnerableRedshiftCluster5', {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    publiclyAccessible: isProduction ? false : true,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_6(scope: Construct) {
  // Creating a Redshift cluster with publiclyAccessible set to true using object spread
  const baseConfig = {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
  };
  
  // ruleid: typescript_cdk_publicly_accessible_redshift_cluster
  new redshift.CfnCluster(scope, 'VulnerableRedshiftCluster6', {
    ...baseConfig,
    publiclyAccessible: true,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_7(scope: Construct) {
  // Creating a Redshift cluster with publiclyAccessible set to true using ternary with boolean literal
  const enablePublicAccess = true;
  
  // ruleid: typescript_cdk_publicly_accessible_redshift_cluster
  new redshift.CfnCluster(scope, 'VulnerableRedshiftCluster7', {
    clusterType: 'multi-node',
    numberOfNodes: 3,
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    publiclyAccessible: enablePublicAccess ? true : false,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_8(scope: Construct) {
  // Creating a Redshift cluster with publiclyAccessible set to true using logical OR
  const defaultPublicAccess = null;
  
  // ruleid: typescript_cdk_publicly_accessible_redshift_cluster
  new redshift.CfnCluster(scope, 'VulnerableRedshiftCluster8', {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    publiclyAccessible: defaultPublicAccess || true,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_9(scope: Construct) {
  // Creating a Redshift cluster with publiclyAccessible set to true in a loop
  const environments = ['dev', 'test', 'prod'];
  
  for (const env of environments) {
    // ruleid: typescript_cdk_publicly_accessible_redshift_cluster
    new redshift.CfnCluster(scope, `VulnerableRedshiftCluster9-${env}`, {
      clusterType: 'single-node',
      nodeType: 'dc2.large',
      masterUsername: 'admin',
      masterUserPassword: 'Password123',
      publiclyAccessible: true,
      tags: [{ key: 'Environment', value: env }],
    });
  }
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_10(scope: Construct) {
  // Creating a Redshift cluster with publiclyAccessible set to true with additional security groups
  const vpc = new ec2.Vpc(scope, 'VPC');
  const securityGroup = new ec2.SecurityGroup(scope, 'RedshiftSG', { vpc });
  
  // ruleid: typescript_cdk_publicly_accessible_redshift_cluster
  new redshift.CfnCluster(scope, 'VulnerableRedshiftCluster10', {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    publiclyAccessible: true,
    vpcSecurityGroupIds: [securityGroup.securityGroupId],
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_11(scope: Construct) {
  // Creating a Redshift cluster with publiclyAccessible set to true with encryption enabled
  // ruleid: typescript_cdk_publicly_accessible_redshift_cluster
  new redshift.CfnCluster(scope, 'VulnerableRedshiftCluster11', {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    publiclyAccessible: true,
    encrypted: true,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_12(scope: Construct) {
  // Creating a Redshift cluster with publiclyAccessible set to true with enhanced VPC routing
  // ruleid: typescript_cdk_publicly_accessible_redshift_cluster
  new redshift.CfnCluster(scope, 'VulnerableRedshiftCluster12', {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    publiclyAccessible: true,
    enhancedVpcRouting: true,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_13(scope: Construct) {
  // Creating a Redshift cluster with publiclyAccessible set to true with snapshot configuration
  // ruleid: typescript_cdk_publicly_accessible_redshift_cluster
  new redshift.CfnCluster(scope, 'VulnerableRedshiftCluster13', {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    publiclyAccessible: true,
    automatedSnapshotRetentionPeriod: 7,
    snapshotCopyRetentionPeriod: 7,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_14(scope: Construct) {
  // Creating a Redshift cluster with publiclyAccessible set to true with logging enabled
  // ruleid: typescript_cdk_publicly_accessible_redshift_cluster
  new redshift.CfnCluster(scope, 'VulnerableRedshiftCluster14', {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    publiclyAccessible: true,
    loggingProperties: {
      bucketName: 'redshift-logs',
      s3KeyPrefix: 'logs/',
    },
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_15(scope: Construct) {
  // Creating a Redshift cluster with publiclyAccessible set to true with IAM roles
  // ruleid: typescript_cdk_publicly_accessible_redshift_cluster
  new redshift.CfnCluster(scope, 'VulnerableRedshiftCluster15', {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    publiclyAccessible: true,
    iamRoles: ['arn:aws:iam::123456789012:role/RedshiftRole'],
  });
}
// {/fact}

// True negative examples (secure code)

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_1(scope: Construct) {
  // Creating a Redshift cluster with publiclyAccessible set to false explicitly
  // ok: typescript_cdk_publicly_accessible_redshift_cluster
  new redshift.CfnCluster(scope, 'SecureRedshiftCluster1', {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    publiclyAccessible: false,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_2(scope: Construct) {
  // Creating a Redshift cluster with publiclyAccessible not specified (defaults to false)
  // ok: typescript_cdk_publicly_accessible_redshift_cluster
  new redshift.CfnCluster(scope, 'SecureRedshiftCluster2', {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_3(scope: Construct) {
  // Creating a Redshift cluster with publiclyAccessible set to false in a variable
  const clusterProps = {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    publiclyAccessible: false,
  };
  
  // ok: typescript_cdk_publicly_accessible_redshift_cluster
  new redshift.CfnCluster(scope, 'SecureRedshiftCluster3', clusterProps);
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_4(scope: Construct) {
  // Creating a Redshift cluster with publiclyAccessible set to false using a function
  function getClusterConfig() {
    return {
      clusterType: 'multi-node',
      numberOfNodes: 2,
      nodeType: 'dc2.large',
      masterUsername: 'admin',
      masterUserPassword: 'Password123',
      publiclyAccessible: false,
    };
  }
  
  // ok: typescript_cdk_publicly_accessible_redshift_cluster
  new redshift.CfnCluster(scope, 'SecureRedshiftCluster4', getClusterConfig());
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_5(scope: Construct, isPublic: boolean = false) {
  // Creating a Redshift cluster with publiclyAccessible set to false by default parameter
  // ok: typescript_cdk_publicly_accessible_redshift_cluster
  new redshift.CfnCluster(scope, 'SecureRedshiftCluster5', {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    publiclyAccessible: isPublic,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_6(scope: Construct) {
  // Creating a Redshift cluster with publiclyAccessible set to false in a conditional
  const isProduction = true;
  
  // ok: typescript_cdk_publicly_accessible_redshift_cluster
  new redshift.CfnCluster(scope, 'SecureRedshiftCluster6', {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    publiclyAccessible: isProduction ? false : true,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_7(scope: Construct) {
  // Creating a Redshift cluster with publiclyAccessible set to false using object spread
  const baseConfig = {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
  };
  
  // ok: typescript_cdk_publicly_accessible_redshift_cluster
  new redshift.CfnCluster(scope, 'SecureRedshiftCluster7', {
    ...baseConfig,
    publiclyAccessible: false,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_8(scope: Construct) {
  // Creating a Redshift cluster with publiclyAccessible set to false using ternary with boolean literal
  const enablePublicAccess = false;
  
  // ok: typescript_cdk_publicly_accessible_redshift_cluster
  new redshift.CfnCluster(scope, 'SecureRedshiftCluster8', {
    clusterType: 'multi-node',
    numberOfNodes: 3,
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    publiclyAccessible: enablePublicAccess ? true : false,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_9(scope: Construct) {
  // Creating a Redshift cluster with publiclyAccessible set to false using logical OR
  const defaultPublicAccess = false;
  
  // ok: typescript_cdk_publicly_accessible_redshift_cluster
  new redshift.CfnCluster(scope, 'SecureRedshiftCluster9', {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    publiclyAccessible: defaultPublicAccess || false,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_10(scope: Construct) {
  // Creating a Redshift cluster with publiclyAccessible set to false in a loop
  const environments = ['dev', 'test', 'prod'];
  
  for (const env of environments) {
    // ok: typescript_cdk_publicly_accessible_redshift_cluster
    new redshift.CfnCluster(scope, `SecureRedshiftCluster10-${env}`, {
      clusterType: 'single-node',
      nodeType: 'dc2.large',
      masterUsername: 'admin',
      masterUserPassword: 'Password123',
      publiclyAccessible: false,
      tags: [{ key: 'Environment', value: env }],
    });
  }
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_11(scope: Construct) {
  // Creating a Redshift cluster with publiclyAccessible set to false with additional security groups
  const vpc = new ec2.Vpc(scope, 'VPC');
  const securityGroup = new ec2.SecurityGroup(scope, 'RedshiftSG', { vpc });
  
  // ok: typescript_cdk_publicly_accessible_redshift_cluster
  new redshift.CfnCluster(scope, 'SecureRedshiftCluster11', {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    publiclyAccessible: false,
    vpcSecurityGroupIds: [securityGroup.securityGroupId],
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_12(scope: Construct) {
  // Creating a Redshift cluster with publiclyAccessible set to false with encryption enabled
  // ok: typescript_cdk_publicly_accessible_redshift_cluster
  new redshift.CfnCluster(scope, 'SecureRedshiftCluster12', {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    publiclyAccessible: false,
    encrypted: true,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_13(scope: Construct) {
  // Creating a Redshift cluster with publiclyAccessible set to false with enhanced VPC routing
  // ok: typescript_cdk_publicly_accessible_redshift_cluster
  new redshift.CfnCluster(scope, 'SecureRedshiftCluster13', {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    publiclyAccessible: false,
    enhancedVpcRouting: true,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_14(scope: Construct) {
  // Creating a Redshift cluster with publiclyAccessible set to false with snapshot configuration
  // ok: typescript_cdk_publicly_accessible_redshift_cluster
  new redshift.CfnCluster(scope, 'SecureRedshiftCluster14', {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    publiclyAccessible: false,
    automatedSnapshotRetentionPeriod: 7,
    snapshotCopyRetentionPeriod: 7,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_15(scope: Construct) {
  // Creating a Redshift cluster with publiclyAccessible set to false with IAM roles
  // ok: typescript_cdk_publicly_accessible_redshift_cluster
  new redshift.CfnCluster(scope, 'SecureRedshiftCluster15', {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    publiclyAccessible: false,
    iamRoles: ['arn:aws:iam::123456789012:role/RedshiftRole'],
  });
}
// {/fact}