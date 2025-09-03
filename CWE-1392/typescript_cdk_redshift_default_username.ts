import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as redshift from 'aws-cdk-lib/aws-redshift';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';

// True Positive Examples (Vulnerable Code)

// {fact rule=default-credentials-usage@v1.0 defects=1}
function bad_case_1(scope: Construct) {
  // Using the default username "awsuser" explicitly
  // ruleid: typescript_cdk_redshift_default_username
  new redshift.CfnCluster(scope, 'RedshiftCluster1', {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
    masterUsername: 'awsuser',
    masterUserPassword: 'StrongPassword123!',
  });
}
// {/fact}

// {fact rule=default-credentials-usage@v1.0 defects=1}
function bad_case_2(scope: Construct) {
  // Using the default username "awsuser" with other configurations
  const params = {
    clusterType: 'multi-node',
    nodeType: 'dc2.large',
    numberOfNodes: 2,
    // ruleid: typescript_cdk_redshift_default_username
    masterUsername: 'awsuser',
    masterUserPassword: 'StrongPassword123!',
    encrypted: true,
  };
  
  new redshift.CfnCluster(scope, 'RedshiftCluster2', params);
}
// {/fact}

// {fact rule=default-credentials-usage@v1.0 defects=1}
function bad_case_3(scope: Construct) {
  // Using the default username "awsuser" in a variable
  const username = 'awsuser';
  
  // ruleid: typescript_cdk_redshift_default_username
  new redshift.CfnCluster(scope, 'RedshiftCluster3', {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
    masterUsername: username,
    masterUserPassword: 'StrongPassword123!',
  });
}
// {/fact}

// {fact rule=default-credentials-usage@v1.0 defects=1}
function bad_case_4(scope: Construct, env: string) {
  // Using the default username "awsuser" in a conditional
  const username = env === 'prod' ? 'admin' : 'awsuser';
  
  // ruleid: typescript_cdk_redshift_default_username
  new redshift.CfnCluster(scope, 'RedshiftCluster4', {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
    masterUsername: username,
    masterUserPassword: 'StrongPassword123!',
  });
}
// {/fact}

// {fact rule=default-credentials-usage@v1.0 defects=1}
function bad_case_5(scope: Construct) {
  // Using the default username "awsuser" with template literals
  const prefix = 'aws';
  const suffix = 'user';
  
  // ruleid: typescript_cdk_redshift_default_username
  new redshift.CfnCluster(scope, 'RedshiftCluster5', {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
    masterUsername: `${prefix}${suffix}`,
    masterUserPassword: 'StrongPassword123!',
  });
}
// {/fact}

// {fact rule=default-credentials-usage@v1.0 defects=1}
function bad_case_6(scope: Construct) {
  // Using the default username "awsuser" in an object
  const clusterProps = {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
    masterUsername: 'awsuser',
    masterUserPassword: 'StrongPassword123!',
  };
  
  // ruleid: typescript_cdk_redshift_default_username
  new redshift.CfnCluster(scope, 'RedshiftCluster6', clusterProps);
}
// {/fact}

// {fact rule=default-credentials-usage@v1.0 defects=1}
function bad_case_7(scope: Construct) {
  // Using the default username "awsuser" with string concatenation
  const username = 'aws' + 'user';
  
  // ruleid: typescript_cdk_redshift_default_username
  new redshift.CfnCluster(scope, 'RedshiftCluster7', {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
    masterUsername: username,
    masterUserPassword: 'StrongPassword123!',
  });
}
// {/fact}

// {fact rule=default-credentials-usage@v1.0 defects=1}
function bad_case_8(scope: Construct) {
  // Using the default username "awsuser" with a function that returns the default
  const getUsername = () => 'awsuser';
  
  // ruleid: typescript_cdk_redshift_default_username
  new redshift.CfnCluster(scope, 'RedshiftCluster8', {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
    masterUsername: getUsername(),
    masterUserPassword: 'StrongPassword123!',
  });
}
// {/fact}

// {fact rule=default-credentials-usage@v1.0 defects=1}
function bad_case_9(scope: Construct) {
  // Using the default username "awsuser" in a more complex object structure
  const config = {
    cluster: {
      type: 'single-node',
      credentials: {
        username: 'awsuser',
        password: 'StrongPassword123!'
      }
    }
  };
  
  // ruleid: typescript_cdk_redshift_default_username
  new redshift.CfnCluster(scope, 'RedshiftCluster9', {
    clusterType: config.cluster.type,
    nodeType: 'dc2.large',
    masterUsername: config.cluster.credentials.username,
    masterUserPassword: config.cluster.credentials.password,
  });
}
// {/fact}

// {fact rule=default-credentials-usage@v1.0 defects=1}
function bad_case_10(scope: Construct) {
  // Using the default username "awsuser" with a ternary that always evaluates to the default
  const isProduction = false;
  
  // ruleid: typescript_cdk_redshift_default_username
  new redshift.CfnCluster(scope, 'RedshiftCluster10', {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
    masterUsername: isProduction ? 'awsuser' : 'awsuser',
    masterUserPassword: 'StrongPassword123!',
  });
}
// {/fact}

// {fact rule=default-credentials-usage@v1.0 defects=1}
function bad_case_11(scope: Construct) {
  // Using the default username "awsuser" in a different case (should still be detected)
  // ruleid: typescript_cdk_redshift_default_username
  new redshift.CfnCluster(scope, 'RedshiftCluster11', {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
    masterUsername: 'AwSuSeR',
    masterUserPassword: 'StrongPassword123!',
  });
}
// {/fact}

// {fact rule=default-credentials-usage@v1.0 defects=1}
function bad_case_12(scope: Construct) {
  // Using the default username "awsuser" with whitespace (should still be detected)
  // ruleid: typescript_cdk_redshift_default_username
  new redshift.CfnCluster(scope, 'RedshiftCluster12', {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
    masterUsername: ' awsuser ',
    masterUserPassword: 'StrongPassword123!',
  });
}
// {/fact}

// {fact rule=default-credentials-usage@v1.0 defects=1}
function bad_case_13(scope: Construct) {
  // Using the default username "awsuser" in a different CDK construct pattern
  const props = {
    masterUsername: 'awsuser',
    masterUserPassword: 'StrongPassword123!',
  };
  
  // ruleid: typescript_cdk_redshift_default_username
  const cluster = new redshift.CfnCluster(scope, 'RedshiftCluster13', {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
    ...props
  });
}
// {/fact}

// {fact rule=default-credentials-usage@v1.0 defects=1}
function bad_case_14(scope: Construct) {
  // Using the default username "awsuser" with property assignment
  const cluster = new redshift.CfnCluster(scope, 'RedshiftCluster14', {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
  });
  
  // ruleid: typescript_cdk_redshift_default_username
  cluster.masterUsername = 'awsuser';
  cluster.masterUserPassword = 'StrongPassword123!';
}
// {/fact}

// {fact rule=default-credentials-usage@v1.0 defects=1}
function bad_case_15(scope: Construct) {
  // Using the default username "awsuser" with a more complex setup
  const config = new Map<string, string>();
  config.set('username', 'awsuser');
  config.set('password', 'StrongPassword123!');
  
  // ruleid: typescript_cdk_redshift_default_username
  new redshift.CfnCluster(scope, 'RedshiftCluster15', {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
    masterUsername: config.get('username'),
    masterUserPassword: config.get('password'),
  });
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=default-credentials-usage@v1.0 defects=0}
function good_case_1(scope: Construct) {
  // Using a custom username instead of the default
  // ok: typescript_cdk_redshift_default_username
  new redshift.CfnCluster(scope, 'RedshiftCluster1', {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
    masterUsername: 'custom_admin',
    masterUserPassword: 'StrongPassword123!',
  });
}
// {/fact}

// {fact rule=default-credentials-usage@v1.0 defects=0}
function good_case_2(scope: Construct) {
  // Using a custom username with other configurations
  const params = {
    clusterType: 'multi-node',
    nodeType: 'dc2.large',
    numberOfNodes: 2,
    // ok: typescript_cdk_redshift_default_username
    masterUsername: 'db_admin',
    masterUserPassword: 'StrongPassword123!',
    encrypted: true,
  };
  
  new redshift.CfnCluster(scope, 'RedshiftCluster2', params);
}
// {/fact}

// {fact rule=default-credentials-usage@v1.0 defects=0}
function good_case_3(scope: Construct) {
  // Using a custom username from environment variable
  const username = process.env.DB_USERNAME || 'custom_admin';
  
  // ok: typescript_cdk_redshift_default_username
  new redshift.CfnCluster(scope, 'RedshiftCluster3', {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
    masterUsername: username,
    masterUserPassword: process.env.DB_PASSWORD || 'StrongPassword123!',
  });
}
// {/fact}

// {fact rule=default-credentials-usage@v1.0 defects=0}
function good_case_4(scope: Construct) {
  // Using a username from AWS Secrets Manager
  const secret = new secretsmanager.Secret(scope, 'RedshiftCredentials', {
    generateSecretString: {
      secretStringTemplate: JSON.stringify({ username: 'admin_user' }),
      generateStringKey: 'password',
    },
  });
  
  const secretValue = secret.secretValueFromJson('username');
  
  // ok: typescript_cdk_redshift_default_username
  new redshift.CfnCluster(scope, 'RedshiftCluster4', {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
    masterUsername: secretValue.toString(),
    masterUserPassword: secret.secretValueFromJson('password').toString(),
  });
}
// {/fact}

// {fact rule=default-credentials-usage@v1.0 defects=0}
function good_case_5(scope: Construct) {
  // Using a custom username with template literals
  const prefix = 'admin';
  const suffix = '_user';
  
  // ok: typescript_cdk_redshift_default_username
  new redshift.CfnCluster(scope, 'RedshiftCluster5', {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
    masterUsername: `${prefix}${suffix}`,
    masterUserPassword: 'StrongPassword123!',
  });
}
// {/fact}

// {fact rule=default-credentials-usage@v1.0 defects=0}
function good_case_6(scope: Construct) {
  // Using a custom username in an object
  const clusterProps = {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
    masterUsername: 'redshift_admin',
    masterUserPassword: 'StrongPassword123!',
  };
  
  // ok: typescript_cdk_redshift_default_username
  new redshift.CfnCluster(scope, 'RedshiftCluster6', clusterProps);
}
// {/fact}

// {fact rule=default-credentials-usage@v1.0 defects=0}
function good_case_7(scope: Construct) {
  // Using a custom username with string concatenation
  const username = 'custom_' + 'admin';
  
  // ok: typescript_cdk_redshift_default_username
  new redshift.CfnCluster(scope, 'RedshiftCluster7', {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
    masterUsername: username,
    masterUserPassword: 'StrongPassword123!',
  });
}
// {/fact}

// {fact rule=default-credentials-usage@v1.0 defects=0}
function good_case_8(scope: Construct) {
  // Using a custom username with a function
  const getUsername = () => 'redshift_admin_' + Math.floor(Math.random() * 1000);
  
  // ok: typescript_cdk_redshift_default_username
  new redshift.CfnCluster(scope, 'RedshiftCluster8', {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
    masterUsername: getUsername(),
    masterUserPassword: 'StrongPassword123!',
  });
}
// {/fact}

// {fact rule=default-credentials-usage@v1.0 defects=0}
function good_case_9(scope: Construct) {
  // Using a custom username in a more complex object structure
  const config = {
    cluster: {
      type: 'single-node',
      credentials: {
        username: 'custom_redshift_user',
        password: 'StrongPassword123!'
      }
    }
  };
  
  // ok: typescript_cdk_redshift_default_username
  new redshift.CfnCluster(scope, 'RedshiftCluster9', {
    clusterType: config.cluster.type,
    nodeType: 'dc2.large',
    masterUsername: config.cluster.credentials.username,
    masterUserPassword: config.cluster.credentials.password,
  });
}
// {/fact}

// {fact rule=default-credentials-usage@v1.0 defects=0}
function good_case_10(scope: Construct) {
  // Using a custom username with a ternary
  const isProduction = true;
  
  // ok: typescript_cdk_redshift_default_username
  new redshift.CfnCluster(scope, 'RedshiftCluster10', {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
    masterUsername: isProduction ? 'prod_admin' : 'dev_admin',
    masterUserPassword: 'StrongPassword123!',
  });
}
// {/fact}

// {fact rule=default-credentials-usage@v1.0 defects=0}
function good_case_11(scope: Construct) {
  // Using a custom username with property assignment
  const cluster = new redshift.CfnCluster(scope, 'RedshiftCluster11', {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
  });
  
  // ok: typescript_cdk_redshift_default_username
  cluster.masterUsername = 'custom_redshift_user';
  cluster.masterUserPassword = 'StrongPassword123!';
}
// {/fact}

// {fact rule=default-credentials-usage@v1.0 defects=0}
function good_case_12(scope: Construct) {
  // Using a custom username with a more complex setup
  const config = new Map<string, string>();
  config.set('username', 'redshift_admin_user');
  config.set('password', 'StrongPassword123!');
  
  // ok: typescript_cdk_redshift_default_username
  new redshift.CfnCluster(scope, 'RedshiftCluster12', {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
    masterUsername: config.get('username'),
    masterUserPassword: config.get('password'),
  });
}
// {/fact}

// {fact rule=default-credentials-usage@v1.0 defects=0}
function good_case_13(scope: Construct) {
  // Using a custom username with a generated value
  const timestamp = new Date().getTime();
  const username = `admin_${timestamp}`;
  
  // ok: typescript_cdk_redshift_default_username
  new redshift.CfnCluster(scope, 'RedshiftCluster13', {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
    masterUsername: username,
    masterUserPassword: 'StrongPassword123!',
  });
}
// {/fact}

// {fact rule=default-credentials-usage@v1.0 defects=0}
function good_case_14(scope: Construct) {
  // Using a custom username with environment-specific configuration
  const env = process.env.ENVIRONMENT || 'dev';
  const username = `${env}_redshift_admin`;
  
  // ok: typescript_cdk_redshift_default_username
  new redshift.CfnCluster(scope, 'RedshiftCluster14', {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
    masterUsername: username,
    masterUserPassword: 'StrongPassword123!',
  });
}
// {/fact}

// {fact rule=default-credentials-usage@v1.0 defects=0}
function good_case_15(scope: Construct) {
  // Using a custom username with a different CDK construct pattern
  const props = {
    masterUsername: 'custom_redshift_user',
    masterUserPassword: 'StrongPassword123!',
  };
  
  // ok: typescript_cdk_redshift_default_username
  const cluster = new redshift.CfnCluster(scope, 'RedshiftCluster15', {
    clusterType: 'single-node',
    nodeType: 'dc2.large',
    ...props
  });
}
// {/fact}