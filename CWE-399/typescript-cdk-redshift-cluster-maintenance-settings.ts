import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as redshift from 'aws-cdk-lib/aws-redshift';
import * as ec2 from 'aws-cdk-lib/aws-ec2';

// True Positive Examples (Vulnerable Code)

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_1(scope: Construct) {
  // Basic case with allowVersionUpgrade explicitly set to false
  // ruleid: typescript-cdk-redshift-cluster-maintenance-settings
  new redshift.CfnCluster(scope, 'MyRedshiftCluster1', {
    clusterType: 'multi-node',
    numberOfNodes: 2,
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    allowVersionUpgrade: false,
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_2(scope: Construct) {
  // Using a variable to set allowVersionUpgrade to false
  const allowUpgrade = false;
  // ruleid: typescript-cdk-redshift-cluster-maintenance-settings
  new redshift.CfnCluster(scope, 'MyRedshiftCluster2', {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    allowVersionUpgrade: allowUpgrade,
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_3(scope: Construct) {
  // Using object spread to include properties with allowVersionUpgrade false
  const baseProps = {
    clusterType: 'multi-node',
    numberOfNodes: 3,
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
  };
  
  // ruleid: typescript-cdk-redshift-cluster-maintenance-settings
  new redshift.CfnCluster(scope, 'MyRedshiftCluster3', {
    ...baseProps,
    allowVersionUpgrade: false,
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_4(scope: Construct) {
  // Using a function that returns false for allowVersionUpgrade
  const getVersionUpgradeFlag = () => {
    return false;
  };
  
  // ruleid: typescript-cdk-redshift-cluster-maintenance-settings
  new redshift.CfnCluster(scope, 'MyRedshiftCluster4', {
    clusterType: 'multi-node',
    numberOfNodes: 2,
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    allowVersionUpgrade: getVersionUpgradeFlag(),
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_5(scope: Construct) {
  // Using a conditional expression that evaluates to false
  const isProduction = false;
  
  // ruleid: typescript-cdk-redshift-cluster-maintenance-settings
  new redshift.CfnCluster(scope, 'MyRedshiftCluster5', {
    clusterType: 'multi-node',
    numberOfNodes: 2,
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    allowVersionUpgrade: isProduction ? true : false,
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_6(scope: Construct, vpc: ec2.Vpc) {
  // With VPC configuration but still has allowVersionUpgrade false
  // ruleid: typescript-cdk-redshift-cluster-maintenance-settings
  new redshift.CfnCluster(scope, 'MyRedshiftCluster6', {
    clusterType: 'multi-node',
    numberOfNodes: 2,
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    vpcSecurityGroupIds: ['sg-12345'],
    clusterSubnetGroupName: 'subnet-group',
    allowVersionUpgrade: false,
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_7(scope: Construct) {
  // With additional configuration options but allowVersionUpgrade is false
  // ruleid: typescript-cdk-redshift-cluster-maintenance-settings
  new redshift.CfnCluster(scope, 'MyRedshiftCluster7', {
    clusterType: 'multi-node',
    numberOfNodes: 4,
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    clusterParameterGroupName: 'default.redshift-1.0',
    automatedSnapshotRetentionPeriod: 7,
    preferredMaintenanceWindow: 'sun:03:00-sun:04:00',
    allowVersionUpgrade: false,
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_8(scope: Construct) {
  // Using a complex object structure but still setting allowVersionUpgrade to false
  const clusterConfig = {
    basic: {
      clusterType: 'multi-node',
      numberOfNodes: 2,
      nodeType: 'dc2.large',
    },
    auth: {
      masterUsername: 'admin',
      masterUserPassword: 'Password123',
    },
    maintenance: {
      allowVersionUpgrade: false,
    }
  };
  
  // ruleid: typescript-cdk-redshift-cluster-maintenance-settings
  new redshift.CfnCluster(scope, 'MyRedshiftCluster8', {
    ...clusterConfig.basic,
    ...clusterConfig.auth,
    allowVersionUpgrade: clusterConfig.maintenance.allowVersionUpgrade,
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_9(scope: Construct) {
  // Using environment variables but defaulting to false when not available
  const allowUpgrade = process.env.ALLOW_UPGRADE === 'true' ? true : false;
  
  // Assuming process.env.ALLOW_UPGRADE is not set or not 'true'
  // ruleid: typescript-cdk-redshift-cluster-maintenance-settings
  new redshift.CfnCluster(scope, 'MyRedshiftCluster9', {
    clusterType: 'multi-node',
    numberOfNodes: 2,
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    allowVersionUpgrade: allowUpgrade,
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_10(scope: Construct) {
  // Using a class to configure the cluster but with allowVersionUpgrade false
  class RedshiftConfig {
    getClusterProps() {
      return {
        clusterType: 'multi-node',
        numberOfNodes: 2,
        nodeType: 'dc2.large',
        masterUsername: 'admin',
        masterUserPassword: 'Password123',
        allowVersionUpgrade: false,
      };
    }
  }
  
  const config = new RedshiftConfig();
  // ruleid: typescript-cdk-redshift-cluster-maintenance-settings
  new redshift.CfnCluster(scope, 'MyRedshiftCluster10', config.getClusterProps());
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_11(scope: Construct) {
  // Using a factory function pattern but with allowVersionUpgrade false
  function createRedshiftProps(env: string) {
    return {
      clusterType: env === 'prod' ? 'multi-node' : 'single-node',
      numberOfNodes: env === 'prod' ? 4 : 1,
      nodeType: env === 'prod' ? 'dc2.large' : 'dc2.small',
      masterUsername: 'admin',
      masterUserPassword: 'Password123',
      allowVersionUpgrade: false,
    };
  }
  
  // ruleid: typescript-cdk-redshift-cluster-maintenance-settings
  new redshift.CfnCluster(scope, 'MyRedshiftCluster11', createRedshiftProps('dev'));
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_12(scope: Construct) {
  // Using a ternary with both paths leading to false
  const isHighSecurity = true;
  
  // ruleid: typescript-cdk-redshift-cluster-maintenance-settings
  new redshift.CfnCluster(scope, 'MyRedshiftCluster12', {
    clusterType: 'multi-node',
    numberOfNodes: 2,
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    allowVersionUpgrade: isHighSecurity ? false : false, // Both paths lead to false
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_13(scope: Construct) {
  // Using logical operators that evaluate to false
  const enableUpgrades = true;
  const blockUpgrades = true;
  
  // ruleid: typescript-cdk-redshift-cluster-maintenance-settings
  new redshift.CfnCluster(scope, 'MyRedshiftCluster13', {
    clusterType: 'multi-node',
    numberOfNodes: 2,
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    allowVersionUpgrade: enableUpgrades && !blockUpgrades, // Evaluates to false
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_14(scope: Construct) {
  // Using a more complex configuration object with nested properties
  const config = {
    cluster: {
      type: 'multi-node',
      nodes: 2,
      nodeType: 'dc2.large',
    },
    security: {
      username: 'admin',
      password: 'Password123',
      maintenance: {
        allowUpgrade: false,
      }
    }
  };
  
  // ruleid: typescript-cdk-redshift-cluster-maintenance-settings
  new redshift.CfnCluster(scope, 'MyRedshiftCluster14', {
    clusterType: config.cluster.type,
    numberOfNodes: config.cluster.nodes,
    nodeType: config.cluster.nodeType,
    masterUsername: config.security.username,
    masterUserPassword: config.security.password,
    allowVersionUpgrade: config.security.maintenance.allowUpgrade,
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_15(scope: Construct) {
  // Using bitwise operations that result in 0 (falsy)
  const securityLevel = 1;
  const upgradeMask = 1;
  
  // ruleid: typescript-cdk-redshift-cluster-maintenance-settings
  new redshift.CfnCluster(scope, 'MyRedshiftCluster15', {
    clusterType: 'multi-node',
    numberOfNodes: 2,
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    allowVersionUpgrade: Boolean(securityLevel & ~upgradeMask), // Evaluates to false
  });
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=object-presence@v1.0 defects=0}
function good_case_1(scope: Construct) {
  // Basic case with allowVersionUpgrade explicitly set to true
  // ok: typescript-cdk-redshift-cluster-maintenance-settings
  new redshift.CfnCluster(scope, 'MyRedshiftCluster1', {
    clusterType: 'multi-node',
    numberOfNodes: 2,
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    allowVersionUpgrade: true,
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_2(scope: Construct) {
  // Using a variable to set allowVersionUpgrade to true
  const allowUpgrade = true;
  // ok: typescript-cdk-redshift-cluster-maintenance-settings
  new redshift.CfnCluster(scope, 'MyRedshiftCluster2', {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    allowVersionUpgrade: allowUpgrade,
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_3(scope: Construct) {
  // Using object spread to include properties with allowVersionUpgrade true
  const baseProps = {
    clusterType: 'multi-node',
    numberOfNodes: 3,
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
  };
  
  // ok: typescript-cdk-redshift-cluster-maintenance-settings
  new redshift.CfnCluster(scope, 'MyRedshiftCluster3', {
    ...baseProps,
    allowVersionUpgrade: true,
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_4(scope: Construct) {
  // Using a function that returns true for allowVersionUpgrade
  const getVersionUpgradeFlag = () => {
    return true;
  };
  
  // ok: typescript-cdk-redshift-cluster-maintenance-settings
  new redshift.CfnCluster(scope, 'MyRedshiftCluster4', {
    clusterType: 'multi-node',
    numberOfNodes: 2,
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    allowVersionUpgrade: getVersionUpgradeFlag(),
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_5(scope: Construct) {
  // Using a conditional expression that evaluates to true
  const isProduction = true;
  
  // ok: typescript-cdk-redshift-cluster-maintenance-settings
  new redshift.CfnCluster(scope, 'MyRedshiftCluster5', {
    clusterType: 'multi-node',
    numberOfNodes: 2,
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    allowVersionUpgrade: isProduction ? true : false,
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_6(scope: Construct, vpc: ec2.Vpc) {
  // With VPC configuration and allowVersionUpgrade true
  // ok: typescript-cdk-redshift-cluster-maintenance-settings
  new redshift.CfnCluster(scope, 'MyRedshiftCluster6', {
    clusterType: 'multi-node',
    numberOfNodes: 2,
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    vpcSecurityGroupIds: ['sg-12345'],
    clusterSubnetGroupName: 'subnet-group',
    allowVersionUpgrade: true,
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_7(scope: Construct) {
  // With additional configuration options and allowVersionUpgrade is true
  // ok: typescript-cdk-redshift-cluster-maintenance-settings
  new redshift.CfnCluster(scope, 'MyRedshiftCluster7', {
    clusterType: 'multi-node',
    numberOfNodes: 4,
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    clusterParameterGroupName: 'default.redshift-1.0',
    automatedSnapshotRetentionPeriod: 7,
    preferredMaintenanceWindow: 'sun:03:00-sun:04:00',
    allowVersionUpgrade: true,
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_8(scope: Construct) {
  // Using default value (not specifying allowVersionUpgrade defaults to true)
  // ok: typescript-cdk-redshift-cluster-maintenance-settings
  new redshift.CfnCluster(scope, 'MyRedshiftCluster8', {
    clusterType: 'multi-node',
    numberOfNodes: 2,
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    // allowVersionUpgrade is not specified, which defaults to true
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_9(scope: Construct) {
  // Using environment variables properly set to true
  const allowUpgrade = process.env.ALLOW_UPGRADE !== 'false';
  
  // ok: typescript-cdk-redshift-cluster-maintenance-settings
  new redshift.CfnCluster(scope, 'MyRedshiftCluster9', {
    clusterType: 'multi-node',
    numberOfNodes: 2,
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    allowVersionUpgrade: allowUpgrade,
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_10(scope: Construct) {
  // Using a class to configure the cluster with allowVersionUpgrade true
  class RedshiftConfig {
    getClusterProps() {
      return {
        clusterType: 'multi-node',
        numberOfNodes: 2,
        nodeType: 'dc2.large',
        masterUsername: 'admin',
        masterUserPassword: 'Password123',
        allowVersionUpgrade: true,
      };
    }
  }
  
  const config = new RedshiftConfig();
  // ok: typescript-cdk-redshift-cluster-maintenance-settings
  new redshift.CfnCluster(scope, 'MyRedshiftCluster10', config.getClusterProps());
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_11(scope: Construct) {
  // Using a factory function pattern with allowVersionUpgrade true
  function createRedshiftProps(env: string) {
    return {
      clusterType: env === 'prod' ? 'multi-node' : 'single-node',
      numberOfNodes: env === 'prod' ? 4 : 1,
      nodeType: env === 'prod' ? 'dc2.large' : 'dc2.small',
      masterUsername: 'admin',
      masterUserPassword: 'Password123',
      allowVersionUpgrade: true,
    };
  }
  
  // ok: typescript-cdk-redshift-cluster-maintenance-settings
  new redshift.CfnCluster(scope, 'MyRedshiftCluster11', createRedshiftProps('dev'));
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_12(scope: Construct) {
  // Using a ternary with both paths leading to true
  const isHighSecurity = true;
  
  // ok: typescript-cdk-redshift-cluster-maintenance-settings
  new redshift.CfnCluster(scope, 'MyRedshiftCluster12', {
    clusterType: 'multi-node',
    numberOfNodes: 2,
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    allowVersionUpgrade: isHighSecurity ? true : true, // Both paths lead to true
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_13(scope: Construct) {
  // Using logical operators that evaluate to true
  const enableUpgrades = true;
  const blockUpgrades = false;
  
  // ok: typescript-cdk-redshift-cluster-maintenance-settings
  new redshift.CfnCluster(scope, 'MyRedshiftCluster13', {
    clusterType: 'multi-node',
    numberOfNodes: 2,
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    allowVersionUpgrade: enableUpgrades && !blockUpgrades, // Evaluates to true
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_14(scope: Construct) {
  // Using a more complex configuration object with nested properties
  const config = {
    cluster: {
      type: 'multi-node',
      nodes: 2,
      nodeType: 'dc2.large',
    },
    security: {
      username: 'admin',
      password: 'Password123',
      maintenance: {
        allowUpgrade: true,
      }
    }
  };
  
  // ok: typescript-cdk-redshift-cluster-maintenance-settings
  new redshift.CfnCluster(scope, 'MyRedshiftCluster14', {
    clusterType: config.cluster.type,
    numberOfNodes: config.cluster.nodes,
    nodeType: config.cluster.nodeType,
    masterUsername: config.security.username,
    masterUserPassword: config.security.password,
    allowVersionUpgrade: config.security.maintenance.allowUpgrade,
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_15(scope: Construct) {
  // Using bitwise operations that result in non-zero (truthy)
  const securityLevel = 3;
  const upgradeMask = 1;
  
  // ok: typescript-cdk-redshift-cluster-maintenance-settings
  new redshift.CfnCluster(scope, 'MyRedshiftCluster15', {
    clusterType: 'multi-node',
    numberOfNodes: 2,
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    allowVersionUpgrade: Boolean(securityLevel & upgradeMask), // Evaluates to true
  });
}
// {/fact}