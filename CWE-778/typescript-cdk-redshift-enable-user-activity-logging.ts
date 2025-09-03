import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as redshift from 'aws-cdk-lib/aws-redshift';
import * as ec2 from 'aws-cdk-lib/aws-ec2';

// True Positive Examples (Vulnerable Code)

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_1(scope: Construct) {
  // Creating a Redshift cluster without enabling user activity logging
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript-cdk-redshift-enable-user-activity-logging
  const cluster = new redshift.Cluster(scope, 'Redshift', {
    masterUsername: 'admin',
    masterPassword: cdk.SecretValue.unsafePlainText('password'),
    vpc: vpc,
    nodeType: redshift.NodeType.RA3_XLPLUS,
    numberOfNodes: 2,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_2(scope: Construct) {
  // Creating a Redshift cluster with a parameter group but not enabling user activity logging
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  const parameterGroup = new redshift.ClusterParameterGroup(scope, 'RedshiftParams', {
    description: 'Custom parameter group for Redshift',
    parameters: {
      'require_ssl': 'true',
      'enable_case_sensitive_identifier': 'true',
    }
  });
  
  // ruleid: typescript-cdk-redshift-enable-user-activity-logging
  const cluster = new redshift.Cluster(scope, 'Redshift', {
    masterUsername: 'admin',
    masterPassword: cdk.SecretValue.unsafePlainText('password'),
    vpc: vpc,
    nodeType: redshift.NodeType.RA3_XLPLUS,
    parameterGroup: parameterGroup,
    numberOfNodes: 2,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_3(scope: Construct) {
  // Creating a Redshift cluster with parameter group but setting user activity logging to false
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  const parameterGroup = new redshift.ClusterParameterGroup(scope, 'RedshiftParams', {
    description: 'Custom parameter group for Redshift',
    parameters: {
      'enable_user_activity_logging': 'false',
      'require_ssl': 'true',
    }
  });
  
  // ruleid: typescript-cdk-redshift-enable-user-activity-logging
  const cluster = new redshift.Cluster(scope, 'Redshift', {
    masterUsername: 'admin',
    masterPassword: cdk.SecretValue.unsafePlainText('password'),
    vpc: vpc,
    nodeType: redshift.NodeType.RA3_XLPLUS,
    parameterGroup: parameterGroup,
    numberOfNodes: 2,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_4(scope: Construct) {
  // Creating a Redshift cluster with imported parameter group (unknown configuration)
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  const importedParameterGroup = redshift.ClusterParameterGroup.fromClusterParameterGroupName(
    scope,
    'ImportedParams',
    'default.redshift-1.0'
  );
  
  // ruleid: typescript-cdk-redshift-enable-user-activity-logging
  const cluster = new redshift.Cluster(scope, 'Redshift', {
    masterUsername: 'admin',
    masterPassword: cdk.SecretValue.unsafePlainText('password'),
    vpc: vpc,
    nodeType: redshift.NodeType.RA3_XLPLUS,
    parameterGroup: importedParameterGroup,
    numberOfNodes: 2,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_5(scope: Construct) {
  // Creating multiple Redshift clusters with the same insecure parameter group
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  const parameterGroup = new redshift.ClusterParameterGroup(scope, 'RedshiftParams', {
    description: 'Shared parameter group for Redshift clusters',
    parameters: {
      'wlm_json_configuration': '[{"user_group":["admin"],"query_group":["test"],"memory_percent":50}]',
    }
  });
  
  // ruleid: typescript-cdk-redshift-enable-user-activity-logging
  const cluster1 = new redshift.Cluster(scope, 'Redshift1', {
    masterUsername: 'admin',
    masterPassword: cdk.SecretValue.unsafePlainText('password1'),
    vpc: vpc,
    nodeType: redshift.NodeType.RA3_XLPLUS,
    parameterGroup: parameterGroup,
    numberOfNodes: 2,
  });
  
  // ruleid: typescript-cdk-redshift-enable-user-activity-logging
  const cluster2 = new redshift.Cluster(scope, 'Redshift2', {
    masterUsername: 'admin',
    masterPassword: cdk.SecretValue.unsafePlainText('password2'),
    vpc: vpc,
    nodeType: redshift.NodeType.RA3_XLPLUS,
    parameterGroup: parameterGroup,
    numberOfNodes: 2,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_6(scope: Construct) {
  // Creating a Redshift cluster with parameter group defined separately
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  const parameterGroup = new redshift.ClusterParameterGroup(scope, 'RedshiftParams', {
    description: 'Custom parameter group for Redshift',
    parameters: {
      'auto_analyze': 'true',
      'statement_timeout': '43200000',
    }
  });
  
  const clusterProps = {
    masterUsername: 'admin',
    masterPassword: cdk.SecretValue.unsafePlainText('password'),
    vpc: vpc,
    nodeType: redshift.NodeType.RA3_XLPLUS,
    parameterGroup: parameterGroup,
    numberOfNodes: 2,
  };
  
  // ruleid: typescript-cdk-redshift-enable-user-activity-logging
  const cluster = new redshift.Cluster(scope, 'Redshift', clusterProps);
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_7(scope: Construct) {
  // Creating a Redshift cluster with conditional parameter assignment but missing logging
  const vpc = new ec2.Vpc(scope, 'VPC');
  const isProduction = process.env.ENVIRONMENT === 'production';
  
  const parameterGroup = new redshift.ClusterParameterGroup(scope, 'RedshiftParams', {
    description: 'Environment-specific parameter group',
    parameters: {
      'require_ssl': isProduction ? 'true' : 'false',
      'max_concurrency_scaling_clusters': isProduction ? '10' : '1',
    }
  });
  
  // ruleid: typescript-cdk-redshift-enable-user-activity-logging
  const cluster = new redshift.Cluster(scope, 'Redshift', {
    masterUsername: 'admin',
    masterPassword: cdk.SecretValue.unsafePlainText('password'),
    vpc: vpc,
    nodeType: redshift.NodeType.RA3_XLPLUS,
    parameterGroup: parameterGroup,
    numberOfNodes: isProduction ? 4 : 2,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_8(scope: Construct) {
  // Creating a Redshift cluster with parameter group but setting user activity logging with wrong type
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  const parameterGroup = new redshift.ClusterParameterGroup(scope, 'RedshiftParams', {
    description: 'Custom parameter group for Redshift',
    parameters: {
      'enable_user_activity_logging': true, // Boolean instead of string
      'require_ssl': 'true',
    }
  });
  
  // ruleid: typescript-cdk-redshift-enable-user-activity-logging
  const cluster = new redshift.Cluster(scope, 'Redshift', {
    masterUsername: 'admin',
    masterPassword: cdk.SecretValue.unsafePlainText('password'),
    vpc: vpc,
    nodeType: redshift.NodeType.RA3_XLPLUS,
    parameterGroup: parameterGroup,
    numberOfNodes: 2,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_9(scope: Construct) {
  // Creating a Redshift cluster with parameter group but setting user activity logging with wrong value
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  const parameterGroup = new redshift.ClusterParameterGroup(scope, 'RedshiftParams', {
    description: 'Custom parameter group for Redshift',
    parameters: {
      'enable_user_activity_logging': '1', // Should be 'true'
      'require_ssl': 'true',
    }
  });
  
  // ruleid: typescript-cdk-redshift-enable-user-activity-logging
  const cluster = new redshift.Cluster(scope, 'Redshift', {
    masterUsername: 'admin',
    masterPassword: cdk.SecretValue.unsafePlainText('password'),
    vpc: vpc,
    nodeType: redshift.NodeType.RA3_XLPLUS,
    parameterGroup: parameterGroup,
    numberOfNodes: 2,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_10(scope: Construct) {
  // Creating a Redshift cluster with parameter group but with a typo in the parameter name
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  const parameterGroup = new redshift.ClusterParameterGroup(scope, 'RedshiftParams', {
    description: 'Custom parameter group for Redshift',
    parameters: {
      'enable_user_activity_log': 'true', // Typo in parameter name
      'require_ssl': 'true',
    }
  });
  
  // ruleid: typescript-cdk-redshift-enable-user-activity-logging
  const cluster = new redshift.Cluster(scope, 'Redshift', {
    masterUsername: 'admin',
    masterPassword: cdk.SecretValue.unsafePlainText('password'),
    vpc: vpc,
    nodeType: redshift.NodeType.RA3_XLPLUS,
    parameterGroup: parameterGroup,
    numberOfNodes: 2,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_11(scope: Construct) {
  // Creating a Redshift cluster with empty parameter group
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  const parameterGroup = new redshift.ClusterParameterGroup(scope, 'RedshiftParams', {
    description: 'Empty parameter group for Redshift',
    parameters: {}
  });
  
  // ruleid: typescript-cdk-redshift-enable-user-activity-logging
  const cluster = new redshift.Cluster(scope, 'Redshift', {
    masterUsername: 'admin',
    masterPassword: cdk.SecretValue.unsafePlainText('password'),
    vpc: vpc,
    nodeType: redshift.NodeType.RA3_XLPLUS,
    parameterGroup: parameterGroup,
    numberOfNodes: 2,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_12(scope: Construct) {
  // Creating a Redshift cluster with parameter group defined through a variable
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  const parameters = {
    'auto_analyze': 'true',
    'statement_timeout': '43200000',
    // Missing enable_user_activity_logging
  };
  
  const parameterGroup = new redshift.ClusterParameterGroup(scope, 'RedshiftParams', {
    description: 'Custom parameter group for Redshift',
    parameters: parameters
  });
  
  // ruleid: typescript-cdk-redshift-enable-user-activity-logging
  const cluster = new redshift.Cluster(scope, 'Redshift', {
    masterUsername: 'admin',
    masterPassword: cdk.SecretValue.unsafePlainText('password'),
    vpc: vpc,
    nodeType: redshift.NodeType.RA3_XLPLUS,
    parameterGroup: parameterGroup,
    numberOfNodes: 2,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_13(scope: Construct) {
  // Creating a Redshift cluster with parameter group but with user activity logging commented out
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  const parameterGroup = new redshift.ClusterParameterGroup(scope, 'RedshiftParams', {
    description: 'Custom parameter group for Redshift',
    parameters: {
      // 'enable_user_activity_logging': 'true', // Commented out
      'require_ssl': 'true',
    }
  });
  
  // ruleid: typescript-cdk-redshift-enable-user-activity-logging
  const cluster = new redshift.Cluster(scope, 'Redshift', {
    masterUsername: 'admin',
    masterPassword: cdk.SecretValue.unsafePlainText('password'),
    vpc: vpc,
    nodeType: redshift.NodeType.RA3_XLPLUS,
    parameterGroup: parameterGroup,
    numberOfNodes: 2,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_14(scope: Construct) {
  // Creating a Redshift cluster with parameter group but with user activity logging set to undefined
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  const loggingEnabled = undefined;
  
  const parameterGroup = new redshift.ClusterParameterGroup(scope, 'RedshiftParams', {
    description: 'Custom parameter group for Redshift',
    parameters: {
      'enable_user_activity_logging': loggingEnabled,
      'require_ssl': 'true',
    }
  });
  
  // ruleid: typescript-cdk-redshift-enable-user-activity-logging
  const cluster = new redshift.Cluster(scope, 'Redshift', {
    masterUsername: 'admin',
    masterPassword: cdk.SecretValue.unsafePlainText('password'),
    vpc: vpc,
    nodeType: redshift.NodeType.RA3_XLPLUS,
    parameterGroup: parameterGroup,
    numberOfNodes: 2,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_15(scope: Construct) {
  // Creating a Redshift cluster with parameter group but with user activity logging in a different case
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  const parameterGroup = new redshift.ClusterParameterGroup(scope, 'RedshiftParams', {
    description: 'Custom parameter group for Redshift',
    parameters: {
      'ENABLE_USER_ACTIVITY_LOGGING': 'true', // Wrong case
      'require_ssl': 'true',
    }
  });
  
  // ruleid: typescript-cdk-redshift-enable-user-activity-logging
  const cluster = new redshift.Cluster(scope, 'Redshift', {
    masterUsername: 'admin',
    masterPassword: cdk.SecretValue.unsafePlainText('password'),
    vpc: vpc,
    nodeType: redshift.NodeType.RA3_XLPLUS,
    parameterGroup: parameterGroup,
    numberOfNodes: 2,
  });
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_1(scope: Construct) {
  // Creating a Redshift cluster with user activity logging enabled
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  const parameterGroup = new redshift.ClusterParameterGroup(scope, 'RedshiftParams', {
    description: 'Custom parameter group for Redshift',
    parameters: {
      // ok: typescript-cdk-redshift-enable-user-activity-logging
      'enable_user_activity_logging': 'true',
      'require_ssl': 'true',
    }
  });
  
  const cluster = new redshift.Cluster(scope, 'Redshift', {
    masterUsername: 'admin',
    masterPassword: cdk.SecretValue.unsafePlainText('password'),
    vpc: vpc,
    nodeType: redshift.NodeType.RA3_XLPLUS,
    parameterGroup: parameterGroup,
    numberOfNodes: 2,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_2(scope: Construct) {
  // Creating a Redshift cluster with user activity logging enabled and other parameters
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  const parameterGroup = new redshift.ClusterParameterGroup(scope, 'RedshiftParams', {
    description: 'Custom parameter group for Redshift',
    parameters: {
      // ok: typescript-cdk-redshift-enable-user-activity-logging
      'enable_user_activity_logging': 'true',
      'require_ssl': 'true',
      'auto_analyze': 'true',
      'statement_timeout': '43200000',
    }
  });
  
  const cluster = new redshift.Cluster(scope, 'Redshift', {
    masterUsername: 'admin',
    masterPassword: cdk.SecretValue.unsafePlainText('password'),
    vpc: vpc,
    nodeType: redshift.NodeType.RA3_XLPLUS,
    parameterGroup: parameterGroup,
    numberOfNodes: 2,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_3(scope: Construct) {
  // Creating a Redshift cluster with user activity logging enabled through a variable
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  const loggingEnabled = 'true';
  
  const parameterGroup = new redshift.ClusterParameterGroup(scope, 'RedshiftParams', {
    description: 'Custom parameter group for Redshift',
    parameters: {
      // ok: typescript-cdk-redshift-enable-user-activity-logging
      'enable_user_activity_logging': loggingEnabled,
      'require_ssl': 'true',
    }
  });
  
  const cluster = new redshift.Cluster(scope, 'Redshift', {
    masterUsername: 'admin',
    masterPassword: cdk.SecretValue.unsafePlainText('password'),
    vpc: vpc,
    nodeType: redshift.NodeType.RA3_XLPLUS,
    parameterGroup: parameterGroup,
    numberOfNodes: 2,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_4(scope: Construct) {
  // Creating a Redshift cluster with user activity logging enabled through a conditional
  const vpc = new ec2.Vpc(scope, 'VPC');
  const isProduction = process.env.ENVIRONMENT === 'production';
  
  const parameterGroup = new redshift.ClusterParameterGroup(scope, 'RedshiftParams', {
    description: 'Environment-specific parameter group',
    parameters: {
      // ok: typescript-cdk-redshift-enable-user-activity-logging
      'enable_user_activity_logging': 'true',
      'require_ssl': isProduction ? 'true' : 'false',
      'max_concurrency_scaling_clusters': isProduction ? '10' : '1',
    }
  });
  
  const cluster = new redshift.Cluster(scope, 'Redshift', {
    masterUsername: 'admin',
    masterPassword: cdk.SecretValue.unsafePlainText('password'),
    vpc: vpc,
    nodeType: redshift.NodeType.RA3_XLPLUS,
    parameterGroup: parameterGroup,
    numberOfNodes: isProduction ? 4 : 2,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_5(scope: Construct) {
  // Creating multiple Redshift clusters with the same secure parameter group
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  const parameterGroup = new redshift.ClusterParameterGroup(scope, 'RedshiftParams', {
    description: 'Shared parameter group for Redshift clusters',
    parameters: {
      // ok: typescript-cdk-redshift-enable-user-activity-logging
      'enable_user_activity_logging': 'true',
      'wlm_json_configuration': '[{"user_group":["admin"],"query_group":["test"],"memory_percent":50}]',
    }
  });
  
  const cluster1 = new redshift.Cluster(scope, 'Redshift1', {
    masterUsername: 'admin',
    masterPassword: cdk.SecretValue.unsafePlainText('password1'),
    vpc: vpc,
    nodeType: redshift.NodeType.RA3_XLPLUS,
    parameterGroup: parameterGroup,
    numberOfNodes: 2,
  });
  
  const cluster2 = new redshift.Cluster(scope, 'Redshift2', {
    masterUsername: 'admin',
    masterPassword: cdk.SecretValue.unsafePlainText('password2'),
    vpc: vpc,
    nodeType: redshift.NodeType.RA3_XLPLUS,
    parameterGroup: parameterGroup,
    numberOfNodes: 2,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_6(scope: Construct) {
  // Creating a Redshift cluster with parameter group defined separately
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  const parameters = {
    // ok: typescript-cdk-redshift-enable-user-activity-logging
    'enable_user_activity_logging': 'true',
    'auto_analyze': 'true',
    'statement_timeout': '43200000',
  };
  
  const parameterGroup = new redshift.ClusterParameterGroup(scope, 'RedshiftParams', {
    description: 'Custom parameter group for Redshift',
    parameters: parameters
  });
  
  const clusterProps = {
    masterUsername: 'admin',
    masterPassword: cdk.SecretValue.unsafePlainText('password'),
    vpc: vpc,
    nodeType: redshift.NodeType.RA3_XLPLUS,
    parameterGroup: parameterGroup,
    numberOfNodes: 2,
  };
  
  const cluster = new redshift.Cluster(scope, 'Redshift', clusterProps);
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_7(scope: Construct) {
  // Creating a Redshift cluster with parameter group and user activity logging enabled with string template
  const vpc = new ec2.Vpc(scope, 'VPC');
  const enableLogging = 'true';
  
  const parameterGroup = new redshift.ClusterParameterGroup(scope, 'RedshiftParams', {
    description: 'Custom parameter group for Redshift',
    parameters: {
      // ok: typescript-cdk-redshift-enable-user-activity-logging
      'enable_user_activity_logging': `${enableLogging}`,
      'require_ssl': 'true',
    }
  });
  
  const cluster = new redshift.Cluster(scope, 'Redshift', {
    masterUsername: 'admin',
    masterPassword: cdk.SecretValue.unsafePlainText('password'),
    vpc: vpc,
    nodeType: redshift.NodeType.RA3_XLPLUS,
    parameterGroup: parameterGroup,
    numberOfNodes: 2,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_8(scope: Construct) {
  // Creating a Redshift cluster with parameter group and user activity logging enabled with function call
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  function getLoggingValue(): string {
    return 'true';
  }
  
  const parameterGroup = new redshift.ClusterParameterGroup(scope, 'RedshiftParams', {
    description: 'Custom parameter group for Redshift',
    parameters: {
      // ok: typescript-cdk-redshift-enable-user-activity-logging
      'enable_user_activity_logging': getLoggingValue(),
      'require_ssl': 'true',
    }
  });
  
  const cluster = new redshift.Cluster(scope, 'Redshift', {
    masterUsername: 'admin',
    masterPassword: cdk.SecretValue.unsafePlainText('password'),
    vpc: vpc,
    nodeType: redshift.NodeType.RA3_XLPLUS,
    parameterGroup: parameterGroup,
    numberOfNodes: 2,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_9(scope: Construct) {
  // Creating a Redshift cluster with parameter group and user activity logging enabled with object spread
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  const baseParameters = {
    'require_ssl': 'true',
    'auto_analyze': 'true',
  };
  
  const securityParameters = {
    // ok: typescript-cdk-redshift-enable-user-activity-logging
    'enable_user_activity_logging': 'true',
  };
  
  const parameterGroup = new redshift.ClusterParameterGroup(scope, 'RedshiftParams', {
    description: 'Custom parameter group for Redshift',
    parameters: {
      ...baseParameters,
      ...securityParameters,
    }
  });
  
  const cluster = new redshift.Cluster(scope, 'Redshift', {
    masterUsername: 'admin',
    masterPassword: cdk.SecretValue.unsafePlainText('password'),
    vpc: vpc,
    nodeType: redshift.NodeType.RA3_XLPLUS,
    parameterGroup: parameterGroup,
    numberOfNodes: 2,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_10(scope: Construct) {
  // Creating a Redshift cluster with parameter group and user activity logging enabled with environment variable
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  const loggingEnabled = process.env.ENABLE_LOGGING || 'true';
  
  const parameterGroup = new redshift.ClusterParameterGroup(scope, 'RedshiftParams', {
    description: 'Custom parameter group for Redshift',
    parameters: {
      // ok: typescript-cdk-redshift-enable-user-activity-logging
      'enable_user_activity_logging': loggingEnabled,
      'require_ssl': 'true',
    }
  });
  
  const cluster = new redshift.Cluster(scope, 'Redshift', {
    masterUsername: 'admin',
    masterPassword: cdk.SecretValue.unsafePlainText('password'),
    vpc: vpc,
    nodeType: redshift.NodeType.RA3_XLPLUS,
    parameterGroup: parameterGroup,
    numberOfNodes: 2,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_11(scope: Construct) {
  // Creating a Redshift cluster with parameter group and user activity logging enabled with ternary operator
  const vpc = new ec2.Vpc(scope, 'VPC');
  const isCompliant = true;
  
  const parameterGroup = new redshift.ClusterParameterGroup(scope, 'RedshiftParams', {
    description: 'Custom parameter group for Redshift',
    parameters: {
      // ok: typescript-cdk-redshift-enable-user-activity-logging
      'enable_user_activity_logging': isCompliant ? 'true' : 'false',
      'require_ssl': 'true',
    }
  });
  
  const cluster = new redshift.Cluster(scope, 'Redshift', {
    masterUsername: 'admin',
    masterPassword: cdk.SecretValue.unsafePlainText('password'),
    vpc: vpc,
    nodeType: redshift.NodeType.RA3_XLPLUS,
    parameterGroup: parameterGroup,
    numberOfNodes: 2,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_12(scope: Construct) {
  // Creating a Redshift cluster with parameter group and user activity logging enabled with logical OR
  const vpc = new ec2.Vpc(scope, 'VPC');
  const configuredLogging = undefined;
  
  const parameterGroup = new redshift.ClusterParameterGroup(scope, 'RedshiftParams', {
    description: 'Custom parameter group for Redshift',
    parameters: {
      // ok: typescript-cdk-redshift-enable-user-activity-logging
      'enable_user_activity_logging': configuredLogging || 'true',
      'require_ssl': 'true',
    }
  });
  
  const cluster = new redshift.Cluster(scope, 'Redshift', {
    masterUsername: 'admin',
    masterPassword: cdk.SecretValue.unsafePlainText('password'),
    vpc: vpc,
    nodeType: redshift.NodeType.RA3_XLPLUS,
    parameterGroup: parameterGroup,
    numberOfNodes: 2,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_13(scope: Construct) {
  // Creating a Redshift cluster with parameter group and user activity logging enabled with computed property name
  const vpc = new ec2.Vpc(scope, 'VPC');
  const loggingParam = 'enable_user_activity_logging';
  
  const parameterGroup = new redshift.ClusterParameterGroup(scope, 'RedshiftParams', {
    description: 'Custom parameter group for Redshift',
    parameters: {
      // ok: typescript-cdk-redshift-enable-user-activity-logging
      [loggingParam]: 'true',
      'require_ssl': 'true',
    }
  });
  
  const cluster = new redshift.Cluster(scope, 'Redshift', {
    masterUsername: 'admin',
    masterPassword: cdk.SecretValue.unsafePlainText('password'),
    vpc: vpc,
    nodeType: redshift.NodeType.RA3_XLPLUS,
    parameterGroup: parameterGroup,
    numberOfNodes: 2,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_14(scope: Construct) {
  // Creating a Redshift cluster with parameter group and user activity logging enabled with object assignment
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  const parameters: Record<string, string> = {};
  parameters['require_ssl'] = 'true';
  // ok: typescript-cdk-redshift-enable-user-activity-logging
  parameters['enable_user_activity_logging'] = 'true';
  
  const parameterGroup = new redshift.ClusterParameterGroup(scope, 'RedshiftParams', {
    description: 'Custom parameter group for Redshift',
    parameters: parameters
  });
  
  const cluster = new redshift.Cluster(scope, 'Redshift', {
    masterUsername: 'admin',
    masterPassword: cdk.SecretValue.unsafePlainText('password'),
    vpc: vpc,
    nodeType: redshift.NodeType.RA3_XLPLUS,
    parameterGroup: parameterGroup,
    numberOfNodes: 2,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_15(scope: Construct) {
  // Creating a Redshift cluster with parameter group and user activity logging enabled with if statement
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  const parameters: Record<string, string> = {
    'require_ssl': 'true',
  };
  
  const shouldEnableLogging = true;
  if (shouldEnableLogging) {
    // ok: typescript-cdk-redshift-enable-user-activity-logging
    parameters['enable_user_activity_logging'] = 'true';
  }
  
  const parameterGroup = new redshift.ClusterParameterGroup(scope, 'RedshiftParams', {
    description: 'Custom parameter group for Redshift',
    parameters: parameters
  });
  
  const cluster = new redshift.Cluster(scope, 'Redshift', {
    masterUsername: 'admin',
    masterPassword: cdk.SecretValue.unsafePlainText('password'),
    vpc: vpc,
    nodeType: redshift.NodeType.RA3_XLPLUS,
    parameterGroup: parameterGroup,
    numberOfNodes: 2,
  });
}
// {/fact}