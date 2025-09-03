import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as redshift from 'aws-cdk-lib/aws-redshift';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import { SecretValue } from 'aws-cdk-lib';

// True positives (vulnerable code)

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_1(scope: Construct) {
  // Creating a Redshift cluster without specifying encryption
  // ruleid: typescript_cdk_redshift_missing_encryption
  const cluster = new redshift.CfnCluster(scope, 'MyRedshiftCluster', {
    clusterType: 'multi-node',
    numberOfNodes: 2,
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    dbName: 'mydb',
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_2(scope: Construct) {
  // Creating a Redshift cluster with encryption explicitly set to false
  // ruleid: typescript_cdk_redshift_missing_encryption
  const cluster = new redshift.CfnCluster(scope, 'MyRedshiftCluster', {
    clusterType: 'multi-node',
    numberOfNodes: 2,
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    dbName: 'mydb',
    encrypted: false,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_3(scope: Construct, vpc: ec2.Vpc) {
  // Using higher-level construct without encryption
  // ruleid: typescript_cdk_redshift_missing_encryption
  const cluster = new redshift.Cluster(scope, 'MyRedshiftCluster', {
    vpc,
    masterUser: {
      username: 'admin',
      password: SecretValue.unsafePlainText('Password123'),
    },
    nodeType: redshift.NodeType.DC2_LARGE,
    numberOfNodes: 2,
    encrypted: false,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_4(scope: Construct) {
  // Using object variable for properties but missing encryption
  const clusterProps = {
    clusterType: 'multi-node',
    numberOfNodes: 2,
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    dbName: 'mydb',
  };
  
  // ruleid: typescript_cdk_redshift_missing_encryption
  const cluster = new redshift.CfnCluster(scope, 'MyRedshiftCluster', clusterProps);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_5(scope: Construct) {
  // Using object variable with encryption explicitly set to false
  const clusterProps = {
    clusterType: 'multi-node',
    numberOfNodes: 2,
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    dbName: 'mydb',
    encrypted: false,
  };
  
  // ruleid: typescript_cdk_redshift_missing_encryption
  const cluster = new redshift.CfnCluster(scope, 'MyRedshiftCluster', clusterProps);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_6(scope: Construct, vpc: ec2.Vpc) {
  // Using conditional logic but still not encrypting
  const isProduction = process.env.ENV === 'production';
  
  // ruleid: typescript_cdk_redshift_missing_encryption
  const cluster = new redshift.Cluster(scope, 'MyRedshiftCluster', {
    vpc,
    masterUser: {
      username: 'admin',
      password: SecretValue.unsafePlainText('Password123'),
    },
    nodeType: isProduction ? redshift.NodeType.DC2_LARGE : redshift.NodeType.DC2_XLARGE,
    numberOfNodes: isProduction ? 4 : 2,
    // Encryption is missing
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_7(scope: Construct) {
  // Using a function to create cluster configuration but missing encryption
  function getClusterConfig() {
    return {
      clusterType: 'multi-node',
      numberOfNodes: 2,
      nodeType: 'dc2.large',
      masterUsername: 'admin',
      masterUserPassword: 'Password123',
      dbName: 'mydb',
    };
  }
  
  // ruleid: typescript_cdk_redshift_missing_encryption
  const cluster = new redshift.CfnCluster(scope, 'MyRedshiftCluster', getClusterConfig());
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_8(scope: Construct, vpc: ec2.Vpc) {
  // Using a class to manage cluster creation but missing encryption
  class RedshiftClusterManager {
    createCluster(scope: Construct, vpc: ec2.Vpc) {
      // ruleid: typescript_cdk_redshift_missing_encryption
      return new redshift.Cluster(scope, 'MyRedshiftCluster', {
        vpc,
        masterUser: {
          username: 'admin',
          password: SecretValue.unsafePlainText('Password123'),
        },
        nodeType: redshift.NodeType.DC2_LARGE,
        numberOfNodes: 2,
      });
    }
  }
  
  const manager = new RedshiftClusterManager();
  const cluster = manager.createCluster(scope, vpc);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_9(scope: Construct) {
  // Using spread operator but missing encryption
  const baseProps = {
    clusterType: 'multi-node',
    numberOfNodes: 2,
    nodeType: 'dc2.large',
  };
  
  const credentials = {
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    dbName: 'mydb',
  };
  
  // ruleid: typescript_cdk_redshift_missing_encryption
  const cluster = new redshift.CfnCluster(scope, 'MyRedshiftCluster', {
    ...baseProps,
    ...credentials,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_10(scope: Construct, vpc: ec2.Vpc) {
  // Using higher-level construct with encryption undefined
  const encryptionConfig = undefined;
  
  // ruleid: typescript_cdk_redshift_missing_encryption
  const cluster = new redshift.Cluster(scope, 'MyRedshiftCluster', {
    vpc,
    masterUser: {
      username: 'admin',
      password: SecretValue.unsafePlainText('Password123'),
    },
    nodeType: redshift.NodeType.DC2_LARGE,
    numberOfNodes: 2,
    encrypted: encryptionConfig,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_11(scope: Construct) {
  // Using a factory pattern but missing encryption
  class RedshiftFactory {
    static createBasicCluster(scope: Construct) {
      // ruleid: typescript_cdk_redshift_missing_encryption
      return new redshift.CfnCluster(scope, 'MyRedshiftCluster', {
        clusterType: 'multi-node',
        numberOfNodes: 2,
        nodeType: 'dc2.large',
        masterUsername: 'admin',
        masterUserPassword: 'Password123',
        dbName: 'mydb',
      });
    }
  }
  
  const cluster = RedshiftFactory.createBasicCluster(scope);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_12(scope: Construct) {
  // Using environment variables for configuration but missing encryption
  const nodeType = process.env.NODE_TYPE || 'dc2.large';
  const nodeCount = process.env.NODE_COUNT ? parseInt(process.env.NODE_COUNT) : 2;
  
  // ruleid: typescript_cdk_redshift_missing_encryption
  const cluster = new redshift.CfnCluster(scope, 'MyRedshiftCluster', {
    clusterType: 'multi-node',
    numberOfNodes: nodeCount,
    nodeType: nodeType,
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    dbName: 'mydb',
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_13(scope: Construct, vpc: ec2.Vpc) {
  // Using a builder pattern but missing encryption
  class RedshiftClusterBuilder {
    private props: any = {};
    
    withNodeType(nodeType: string) {
      this.props.nodeType = nodeType;
      return this;
    }
    
    withNodes(count: number) {
      this.props.numberOfNodes = count;
      return this;
    }
    
    withCredentials(username: string, password: string) {
      this.props.masterUser = {
        username: username,
        password: SecretValue.unsafePlainText(password),
      };
      return this;
    }
    
    build(scope: Construct, vpc: ec2.Vpc) {
      // ruleid: typescript_cdk_redshift_missing_encryption
      return new redshift.Cluster(scope, 'MyRedshiftCluster', {
        vpc,
        ...this.props,
      });
    }
  }
  
  const cluster = new RedshiftClusterBuilder()
    .withNodeType(redshift.NodeType.DC2_LARGE)
    .withNodes(2)
    .withCredentials('admin', 'Password123')
    .build(scope, vpc);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_14(scope: Construct) {
  // Using a configuration object with nested properties but missing encryption
  const config = {
    cluster: {
      type: 'multi-node',
      nodes: 2,
      nodeType: 'dc2.large',
    },
    database: {
      name: 'mydb',
      credentials: {
        username: 'admin',
        password: 'Password123',
      },
    },
  };
  
  // ruleid: typescript_cdk_redshift_missing_encryption
  const cluster = new redshift.CfnCluster(scope, 'MyRedshiftCluster', {
    clusterType: config.cluster.type,
    numberOfNodes: config.cluster.nodes,
    nodeType: config.cluster.nodeType,
    masterUsername: config.database.credentials.username,
    masterUserPassword: config.database.credentials.password,
    dbName: config.database.name,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_15(scope: Construct) {
  // Using a mix of direct properties and variables but missing encryption
  const username = 'admin';
  const password = 'Password123';
  
  // ruleid: typescript_cdk_redshift_missing_encryption
  const cluster = new redshift.CfnCluster(scope, 'MyRedshiftCluster', {
    clusterType: 'multi-node',
    numberOfNodes: 2,
    nodeType: 'dc2.large',
    masterUsername: username,
    masterUserPassword: password,
    dbName: 'mydb',
  });
}
// {/fact}

// True negatives (secure code)

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_1(scope: Construct) {
  // Creating a Redshift cluster with encryption enabled
  // ok: typescript_cdk_redshift_missing_encryption
  const cluster = new redshift.CfnCluster(scope, 'MyRedshiftCluster', {
    clusterType: 'multi-node',
    numberOfNodes: 2,
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    dbName: 'mydb',
    encrypted: true,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_2(scope: Construct, vpc: ec2.Vpc) {
  // Using higher-level construct with encryption enabled
  // ok: typescript_cdk_redshift_missing_encryption
  const cluster = new redshift.Cluster(scope, 'MyRedshiftCluster', {
    vpc,
    masterUser: {
      username: 'admin',
      password: SecretValue.unsafePlainText('Password123'),
    },
    nodeType: redshift.NodeType.DC2_LARGE,
    numberOfNodes: 2,
    encrypted: true,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_3(scope: Construct) {
  // Using object variable for properties with encryption enabled
  const clusterProps = {
    clusterType: 'multi-node',
    numberOfNodes: 2,
    nodeType: 'dc2.large',
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    dbName: 'mydb',
    encrypted: true,
  };
  
  // ok: typescript_cdk_redshift_missing_encryption
  const cluster = new redshift.CfnCluster(scope, 'MyRedshiftCluster', clusterProps);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_4(scope: Construct, vpc: ec2.Vpc) {
  // Using conditional logic with encryption always enabled
  const isProduction = process.env.ENV === 'production';
  
  // ok: typescript_cdk_redshift_missing_encryption
  const cluster = new redshift.Cluster(scope, 'MyRedshiftCluster', {
    vpc,
    masterUser: {
      username: 'admin',
      password: SecretValue.unsafePlainText('Password123'),
    },
    nodeType: isProduction ? redshift.NodeType.DC2_LARGE : redshift.NodeType.DC2_XLARGE,
    numberOfNodes: isProduction ? 4 : 2,
    encrypted: true,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_5(scope: Construct) {
  // Using a function to create cluster configuration with encryption enabled
  function getClusterConfig() {
    return {
      clusterType: 'multi-node',
      numberOfNodes: 2,
      nodeType: 'dc2.large',
      masterUsername: 'admin',
      masterUserPassword: 'Password123',
      dbName: 'mydb',
      encrypted: true,
    };
  }
  
  // ok: typescript_cdk_redshift_missing_encryption
  const cluster = new redshift.CfnCluster(scope, 'MyRedshiftCluster', getClusterConfig());
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_6(scope: Construct, vpc: ec2.Vpc) {
  // Using a class to manage cluster creation with encryption enabled
  class RedshiftClusterManager {
    createCluster(scope: Construct, vpc: ec2.Vpc) {
      // ok: typescript_cdk_redshift_missing_encryption
      return new redshift.Cluster(scope, 'MyRedshiftCluster', {
        vpc,
        masterUser: {
          username: 'admin',
          password: SecretValue.unsafePlainText('Password123'),
        },
        nodeType: redshift.NodeType.DC2_LARGE,
        numberOfNodes: 2,
        encrypted: true,
      });
    }
  }
  
  const manager = new RedshiftClusterManager();
  const cluster = manager.createCluster(scope, vpc);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_7(scope: Construct) {
  // Using spread operator with encryption enabled
  const baseProps = {
    clusterType: 'multi-node',
    numberOfNodes: 2,
    nodeType: 'dc2.large',
  };
  
  const credentials = {
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    dbName: 'mydb',
  };
  
  const securityProps = {
    encrypted: true,
  };
  
  // ok: typescript_cdk_redshift_missing_encryption
  const cluster = new redshift.CfnCluster(scope, 'MyRedshiftCluster', {
    ...baseProps,
    ...credentials,
    ...securityProps,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_8(scope: Construct, vpc: ec2.Vpc) {
  // Using higher-level construct with encryption explicitly set to true
  const encryptionConfig = true;
  
  // ok: typescript_cdk_redshift_missing_encryption
  const cluster = new redshift.Cluster(scope, 'MyRedshiftCluster', {
    vpc,
    masterUser: {
      username: 'admin',
      password: SecretValue.unsafePlainText('Password123'),
    },
    nodeType: redshift.NodeType.DC2_LARGE,
    numberOfNodes: 2,
    encrypted: encryptionConfig,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_9(scope: Construct) {
  // Using a factory pattern with encryption enabled
  class RedshiftFactory {
    static createSecureCluster(scope: Construct) {
      // ok: typescript_cdk_redshift_missing_encryption
      return new redshift.CfnCluster(scope, 'MyRedshiftCluster', {
        clusterType: 'multi-node',
        numberOfNodes: 2,
        nodeType: 'dc2.large',
        masterUsername: 'admin',
        masterUserPassword: 'Password123',
        dbName: 'mydb',
        encrypted: true,
      });
    }
  }
  
  const cluster = RedshiftFactory.createSecureCluster(scope);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_10(scope: Construct) {
  // Using environment variables for configuration with encryption enabled
  const nodeType = process.env.NODE_TYPE || 'dc2.large';
  const nodeCount = process.env.NODE_COUNT ? parseInt(process.env.NODE_COUNT) : 2;
  
  // ok: typescript_cdk_redshift_missing_encryption
  const cluster = new redshift.CfnCluster(scope, 'MyRedshiftCluster', {
    clusterType: 'multi-node',
    numberOfNodes: nodeCount,
    nodeType: nodeType,
    masterUsername: 'admin',
    masterUserPassword: 'Password123',
    dbName: 'mydb',
    encrypted: true,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_11(scope: Construct, vpc: ec2.Vpc) {
  // Using a builder pattern with encryption enabled
  class RedshiftClusterBuilder {
    private props: any = {};
    
    withNodeType(nodeType: string) {
      this.props.nodeType = nodeType;
      return this;
    }
    
    withNodes(count: number) {
      this.props.numberOfNodes = count;
      return this;
    }
    
    withCredentials(username: string, password: string) {
      this.props.masterUser = {
        username: username,
        password: SecretValue.unsafePlainText(password),
      };
      return this;
    }
    
    withEncryption() {
      this.props.encrypted = true;
      return this;
    }
    
    build(scope: Construct, vpc: ec2.Vpc) {
      // ok: typescript_cdk_redshift_missing_encryption
      return new redshift.Cluster(scope, 'MyRedshiftCluster', {
        vpc,
        ...this.props,
      });
    }
  }
  
  const cluster = new RedshiftClusterBuilder()
    .withNodeType(redshift.NodeType.DC2_LARGE)
    .withNodes(2)
    .withCredentials('admin', 'Password123')
    .withEncryption()
    .build(scope, vpc);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_12(scope: Construct) {
  // Using a configuration object with nested properties and encryption enabled
  const config = {
    cluster: {
      type: 'multi-node',
      nodes: 2,
      nodeType: 'dc2.large',
    },
    database: {
      name: 'mydb',
      credentials: {
        username: 'admin',
        password: 'Password123',
      },
    },
    security: {
      encrypted: true,
    },
  };
  
  // ok: typescript_cdk_redshift_missing_encryption
  const cluster = new redshift.CfnCluster(scope, 'MyRedshiftCluster', {
    clusterType: config.cluster.type,
    numberOfNodes: config.cluster.nodes,
    nodeType: config.cluster.nodeType,
    masterUsername: config.database.credentials.username,
    masterUserPassword: config.database.credentials.password,
    dbName: config.database.name,
    encrypted: config.security.encrypted,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_13(scope: Construct) {
  // Using a mix of direct properties and variables with encryption enabled
  const username = 'admin';
  const password = 'Password123';
  const isEncrypted = true;
  
  // ok: typescript_cdk_redshift_missing_encryption
  const cluster = new redshift.CfnCluster(scope, 'MyRedshiftCluster', {
    clusterType: 'multi-node',
    numberOfNodes: 2,
    nodeType: 'dc2.large',
    masterUsername: username,
    masterUserPassword: password,
    dbName: 'mydb',
    encrypted: isEncrypted,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_14(scope: Construct, vpc: ec2.Vpc) {
  // Using encryption with KMS key
  const kmsKey = new cdk.aws_kms.Key(scope, 'RedshiftEncryptionKey', {
    enableKeyRotation: true,
  });
  
  // ok: typescript_cdk_redshift_missing_encryption
  const cluster = new redshift.Cluster(scope, 'MyRedshiftCluster', {
    vpc,
    masterUser: {
      username: 'admin',
      password: SecretValue.unsafePlainText('Password123'),
    },
    nodeType: redshift.NodeType.DC2_LARGE,
    numberOfNodes: 2,
    encrypted: true,
    encryptionKey: kmsKey,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_15(scope: Construct) {
  // Using a secret from Secrets Manager for credentials with encryption enabled
  const databaseCredentialsSecret = new secretsmanager.Secret(scope, 'RedshiftCredentials', {
    secretName: 'redshift/credentials',
    generateSecretString: {
      secretStringTemplate: JSON.stringify({ username: 'admin' }),
      generateStringKey: 'password',
      excludeCharacters: '/@"',
    },
  });
  
  const username = databaseCredentialsSecret.secretValueFromJson('username').toString();
  const password = databaseCredentialsSecret.secretValueFromJson('password').toString();
  
  // ok: typescript_cdk_redshift_missing_encryption
  const cluster = new redshift.CfnCluster(scope, 'MyRedshiftCluster', {
    clusterType: 'multi-node',
    numberOfNodes: 2,
    nodeType: 'dc2.large',
    masterUsername: username,
    masterUserPassword: password,
    dbName: 'mydb',
    encrypted: true,
  });
}
// {/fact}