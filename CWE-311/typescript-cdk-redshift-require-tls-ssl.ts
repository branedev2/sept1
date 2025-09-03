import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as redshift from 'aws-cdk-lib/aws-redshift';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as iam from 'aws-cdk-lib/aws-iam';

// True Positive Examples (Vulnerable Code)

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_1(scope: Construct) {
  // Creating a Redshift cluster without setting require_ssl
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript-cdk-redshift-require-tls-ssl
  new redshift.Cluster(scope, 'RedshiftCluster', {
    masterUser: {
      masterUsername: 'admin',
    },
    vpc,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_2(scope: Construct) {
  // Creating a Redshift cluster with require_ssl explicitly set to false
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript-cdk-redshift-require-tls-ssl
  new redshift.Cluster(scope, 'RedshiftCluster', {
    masterUser: {
      masterUsername: 'admin',
    },
    vpc,
    parameterGroup: redshift.ClusterParameterGroup.fromParameterGroupName(
      scope,
      'ParamGroup',
      'default.redshift-1.0'
    ),
    clusterType: redshift.ClusterType.SINGLE_NODE,
    encrypted: true,
    parameters: {
      require_ssl: 'false',
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_3(scope: Construct) {
  // Creating a Redshift cluster with parameters but missing require_ssl
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript-cdk-redshift-require-tls-ssl
  new redshift.Cluster(scope, 'RedshiftCluster', {
    masterUser: {
      masterUsername: 'admin',
    },
    vpc,
    parameters: {
      enable_user_activity_logging: 'true',
      max_concurrency_scaling_clusters: '3',
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_4(scope: Construct) {
  // Creating a Redshift cluster with require_ssl as a variable set to false
  const vpc = new ec2.Vpc(scope, 'VPC');
  const requireSsl = 'false';
  
  // ruleid: typescript-cdk-redshift-require-tls-ssl
  new redshift.Cluster(scope, 'RedshiftCluster', {
    masterUser: {
      masterUsername: 'admin',
    },
    vpc,
    parameters: {
      require_ssl: requireSsl,
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_5(scope: Construct) {
  // Creating a Redshift cluster with multiple parameters but require_ssl is false
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript-cdk-redshift-require-tls-ssl
  new redshift.Cluster(scope, 'RedshiftCluster', {
    masterUser: {
      masterUsername: 'admin',
    },
    vpc,
    parameters: {
      require_ssl: 'false',
      enable_user_activity_logging: 'true',
      auto_analyze: 'true',
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_6(scope: Construct) {
  // Creating a Redshift cluster with conditional require_ssl that evaluates to false
  const vpc = new ec2.Vpc(scope, 'VPC');
  const isProduction = false;
  
  // ruleid: typescript-cdk-redshift-require-tls-ssl
  new redshift.Cluster(scope, 'RedshiftCluster', {
    masterUser: {
      masterUsername: 'admin',
    },
    vpc,
    parameters: {
      require_ssl: isProduction ? 'true' : 'false',
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_7(scope: Construct) {
  // Creating a Redshift cluster with require_ssl as 0 (which means false)
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript-cdk-redshift-require-tls-ssl
  new redshift.Cluster(scope, 'RedshiftCluster', {
    masterUser: {
      masterUsername: 'admin',
    },
    vpc,
    parameters: {
      require_ssl: '0',
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_8(scope: Construct, stack: cdk.Stack) {
  // Creating a Redshift cluster with require_ssl from context that is false
  const vpc = new ec2.Vpc(scope, 'VPC');
  const requireSsl = stack.node.tryGetContext('require_ssl') || 'false';
  
  // ruleid: typescript-cdk-redshift-require-tls-ssl
  new redshift.Cluster(scope, 'RedshiftCluster', {
    masterUser: {
      masterUsername: 'admin',
    },
    vpc,
    parameters: {
      require_ssl: requireSsl,
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_9(scope: Construct) {
  // Creating a Redshift cluster with require_ssl as a boolean false
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript-cdk-redshift-require-tls-ssl
  new redshift.Cluster(scope, 'RedshiftCluster', {
    masterUser: {
      masterUsername: 'admin',
    },
    vpc,
    parameters: {
      require_ssl: false,
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_10(scope: Construct) {
  // Creating a Redshift cluster with parameters object created separately
  const vpc = new ec2.Vpc(scope, 'VPC');
  const params = {
    auto_analyze: 'true',
    query_group: 'default',
    // require_ssl is missing
  };
  
  // ruleid: typescript-cdk-redshift-require-tls-ssl
  new redshift.Cluster(scope, 'RedshiftCluster', {
    masterUser: {
      masterUsername: 'admin',
    },
    vpc,
    parameters: params,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_11(scope: Construct) {
  // Creating a Redshift cluster with require_ssl in wrong case (not recognized)
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript-cdk-redshift-require-tls-ssl
  new redshift.Cluster(scope, 'RedshiftCluster', {
    masterUser: {
      masterUsername: 'admin',
    },
    vpc,
    parameters: {
      REQUIRE_SSL: 'true', // Wrong case, won't be recognized
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_12(scope: Construct) {
  // Creating a Redshift cluster with require_ssl as an empty string
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript-cdk-redshift-require-tls-ssl
  new redshift.Cluster(scope, 'RedshiftCluster', {
    masterUser: {
      masterUsername: 'admin',
    },
    vpc,
    parameters: {
      require_ssl: '',
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_13(scope: Construct) {
  // Creating a Redshift cluster with a function that returns false for require_ssl
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  function getRequireSsl(): string {
    return 'false';
  }
  
  // ruleid: typescript-cdk-redshift-require-tls-ssl
  new redshift.Cluster(scope, 'RedshiftCluster', {
    masterUser: {
      masterUsername: 'admin',
    },
    vpc,
    parameters: {
      require_ssl: getRequireSsl(),
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_14(scope: Construct) {
  // Creating a Redshift cluster with a complex expression that evaluates to false
  const vpc = new ec2.Vpc(scope, 'VPC');
  const env = 'dev';
  
  // ruleid: typescript-cdk-redshift-require-tls-ssl
  new redshift.Cluster(scope, 'RedshiftCluster', {
    masterUser: {
      masterUsername: 'admin',
    },
    vpc,
    parameters: {
      require_ssl: env === 'prod' ? 'true' : 'false',
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_15(scope: Construct) {
  // Creating a Redshift cluster with parameters spread from an object missing require_ssl
  const vpc = new ec2.Vpc(scope, 'VPC');
  const baseParams = {
    enable_user_activity_logging: 'true',
    auto_analyze: 'true',
  };
  
  // ruleid: typescript-cdk-redshift-require-tls-ssl
  new redshift.Cluster(scope, 'RedshiftCluster', {
    masterUser: {
      masterUsername: 'admin',
    },
    vpc,
    parameters: {
      ...baseParams,
      // require_ssl is missing
    },
  });
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_1(scope: Construct) {
  // Creating a Redshift cluster with require_ssl set to true
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript-cdk-redshift-require-tls-ssl
  new redshift.Cluster(scope, 'RedshiftCluster', {
    masterUser: {
      masterUsername: 'admin',
    },
    vpc,
    parameters: {
      require_ssl: 'true',
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_2(scope: Construct) {
  // Creating a Redshift cluster with require_ssl as a boolean true
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript-cdk-redshift-require-tls-ssl
  new redshift.Cluster(scope, 'RedshiftCluster', {
    masterUser: {
      masterUsername: 'admin',
    },
    vpc,
    parameters: {
      require_ssl: true,
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_3(scope: Construct) {
  // Creating a Redshift cluster with require_ssl as a variable set to true
  const vpc = new ec2.Vpc(scope, 'VPC');
  const requireSsl = 'true';
  
  // ok: typescript-cdk-redshift-require-tls-ssl
  new redshift.Cluster(scope, 'RedshiftCluster', {
    masterUser: {
      masterUsername: 'admin',
    },
    vpc,
    parameters: {
      require_ssl: requireSsl,
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_4(scope: Construct) {
  // Creating a Redshift cluster with multiple parameters including require_ssl as true
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript-cdk-redshift-require-tls-ssl
  new redshift.Cluster(scope, 'RedshiftCluster', {
    masterUser: {
      masterUsername: 'admin',
    },
    vpc,
    parameters: {
      require_ssl: 'true',
      enable_user_activity_logging: 'true',
      auto_analyze: 'true',
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_5(scope: Construct) {
  // Creating a Redshift cluster with conditional require_ssl that evaluates to true
  const vpc = new ec2.Vpc(scope, 'VPC');
  const isProduction = true;
  
  // ok: typescript-cdk-redshift-require-tls-ssl
  new redshift.Cluster(scope, 'RedshiftCluster', {
    masterUser: {
      masterUsername: 'admin',
    },
    vpc,
    parameters: {
      require_ssl: isProduction ? 'true' : 'false',
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_6(scope: Construct) {
  // Creating a Redshift cluster with require_ssl as 1 (which means true)
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript-cdk-redshift-require-tls-ssl
  new redshift.Cluster(scope, 'RedshiftCluster', {
    masterUser: {
      masterUsername: 'admin',
    },
    vpc,
    parameters: {
      require_ssl: '1',
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_7(scope: Construct, stack: cdk.Stack) {
  // Creating a Redshift cluster with require_ssl from context that is true
  const vpc = new ec2.Vpc(scope, 'VPC');
  const requireSsl = stack.node.tryGetContext('require_ssl') || 'true';
  
  // ok: typescript-cdk-redshift-require-tls-ssl
  new redshift.Cluster(scope, 'RedshiftCluster', {
    masterUser: {
      masterUsername: 'admin',
    },
    vpc,
    parameters: {
      require_ssl: requireSsl,
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_8(scope: Construct) {
  // Creating a Redshift cluster with parameters object created separately including require_ssl as true
  const vpc = new ec2.Vpc(scope, 'VPC');
  const params = {
    require_ssl: 'true',
    auto_analyze: 'true',
    query_group: 'default',
  };
  
  // ok: typescript-cdk-redshift-require-tls-ssl
  new redshift.Cluster(scope, 'RedshiftCluster', {
    masterUser: {
      masterUsername: 'admin',
    },
    vpc,
    parameters: params,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_9(scope: Construct) {
  // Creating a Redshift cluster with a function that returns true for require_ssl
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  function getRequireSsl(): string {
    return 'true';
  }
  
  // ok: typescript-cdk-redshift-require-tls-ssl
  new redshift.Cluster(scope, 'RedshiftCluster', {
    masterUser: {
      masterUsername: 'admin',
    },
    vpc,
    parameters: {
      require_ssl: getRequireSsl(),
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_10(scope: Construct) {
  // Creating a Redshift cluster with a complex expression that evaluates to true
  const vpc = new ec2.Vpc(scope, 'VPC');
  const env = 'prod';
  
  // ok: typescript-cdk-redshift-require-tls-ssl
  new redshift.Cluster(scope, 'RedshiftCluster', {
    masterUser: {
      masterUsername: 'admin',
    },
    vpc,
    parameters: {
      require_ssl: env === 'prod' ? 'true' : 'false',
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_11(scope: Construct) {
  // Creating a Redshift cluster with parameters spread from an object that includes require_ssl as true
  const vpc = new ec2.Vpc(scope, 'VPC');
  const baseParams = {
    require_ssl: 'true',
    enable_user_activity_logging: 'true',
    auto_analyze: 'true',
  };
  
  // ok: typescript-cdk-redshift-require-tls-ssl
  new redshift.Cluster(scope, 'RedshiftCluster', {
    masterUser: {
      masterUsername: 'admin',
    },
    vpc,
    parameters: {
      ...baseParams,
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_12(scope: Construct) {
  // Creating a Redshift cluster with require_ssl set to true and additional security settings
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript-cdk-redshift-require-tls-ssl
  new redshift.Cluster(scope, 'RedshiftCluster', {
    masterUser: {
      masterUsername: 'admin',
    },
    vpc,
    encrypted: true,
    parameters: {
      require_ssl: 'true',
      enable_user_activity_logging: 'true',
    },
    securityGroups: [
      new ec2.SecurityGroup(scope, 'RedshiftSG', { vpc })
    ],
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_13(scope: Construct) {
  // Creating a Redshift cluster with require_ssl as true and using a parameter group
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  const parameterGroup = new redshift.ClusterParameterGroup(scope, 'RedshiftParams', {
    description: 'Custom parameter group',
    parameters: {
      require_ssl: 'true',
    },
  });
  
  // ok: typescript-cdk-redshift-require-tls-ssl
  new redshift.Cluster(scope, 'RedshiftCluster', {
    masterUser: {
      masterUsername: 'admin',
    },
    vpc,
    parameterGroup: parameterGroup,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_14(scope: Construct) {
  // Creating a Redshift cluster with require_ssl as true and using a custom parameter group
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript-cdk-redshift-require-tls-ssl
  new redshift.Cluster(scope, 'RedshiftCluster', {
    masterUser: {
      masterUsername: 'admin',
    },
    vpc,
    parameters: {
      require_ssl: 'true',
    },
    clusterType: redshift.ClusterType.MULTI_NODE,
    numberOfNodes: 2,
    nodeType: redshift.NodeType.DC2_LARGE,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_15(scope: Construct) {
  // Creating a Redshift cluster with require_ssl as true and using environment variables for other settings
  const vpc = new ec2.Vpc(scope, 'VPC');
  const username = process.env.REDSHIFT_USERNAME || 'admin';
  
  // ok: typescript-cdk-redshift-require-tls-ssl
  new redshift.Cluster(scope, 'RedshiftCluster', {
    masterUser: {
      masterUsername: username,
    },
    vpc,
    parameters: {
      require_ssl: 'true',
    },
    encrypted: true,
  });
}
// {/fact}