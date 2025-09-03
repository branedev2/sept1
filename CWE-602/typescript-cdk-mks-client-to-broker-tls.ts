import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as msk from 'aws-cdk-lib/aws-msk';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as kms from 'aws-cdk-lib/aws-kms';

// True Positive Examples (Vulnerable Code)

// {fact rule=client-side-enforcement-of-server-side-security@v1.0 defects=1}
function bad_case_1(scope: Construct) {
  // MSK cluster without specifying clientBroker encryption
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript-cdk-mks-client-to-broker-tls
  new msk.CfnCluster(scope, 'MskCluster', {
    clusterName: 'my-kafka-cluster',
    kafkaVersion: '2.8.1',
    numberOfBrokerNodes: 3,
    brokerNodeGroupInfo: {
      instanceType: 'kafka.m5.large',
      clientSubnets: vpc.privateSubnets.map(subnet => subnet.subnetId),
      securityGroups: ['sg-12345'],
      storageInfo: {
        ebsStorageInfo: {
          volumeSize: 100,
        },
      },
    },
    // Missing clientBroker: 'TLS' in encryptionInfo
    encryptionInfo: {
      encryptionInTransit: {
        inCluster: true,
      },
    },
  });
}
// {/fact}

// {fact rule=client-side-enforcement-of-server-side-security@v1.0 defects=1}
function bad_case_2(scope: Construct) {
  // MSK cluster with explicitly setting clientBroker to PLAINTEXT
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript-cdk-mks-client-to-broker-tls
  new msk.CfnCluster(scope, 'MskCluster', {
    clusterName: 'insecure-kafka-cluster',
    kafkaVersion: '2.8.1',
    numberOfBrokerNodes: 3,
    brokerNodeGroupInfo: {
      instanceType: 'kafka.m5.large',
      clientSubnets: vpc.privateSubnets.map(subnet => subnet.subnetId),
      securityGroups: ['sg-12345'],
      storageInfo: {
        ebsStorageInfo: {
          volumeSize: 100,
        },
      },
    },
    encryptionInfo: {
      encryptionInTransit: {
        inCluster: true,
        clientBroker: 'PLAINTEXT', // Explicitly insecure
      },
    },
  });
}
// {/fact}

// {fact rule=client-side-enforcement-of-server-side-security@v1.0 defects=1}
function bad_case_3(scope: Construct) {
  // MSK cluster with clientBroker set to TLS_PLAINTEXT (allows both)
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript-cdk-mks-client-to-broker-tls
  new msk.CfnCluster(scope, 'MskCluster', {
    clusterName: 'mixed-security-kafka-cluster',
    kafkaVersion: '2.8.1',
    numberOfBrokerNodes: 3,
    brokerNodeGroupInfo: {
      instanceType: 'kafka.m5.large',
      clientSubnets: vpc.privateSubnets.map(subnet => subnet.subnetId),
      securityGroups: ['sg-12345'],
      storageInfo: {
        ebsStorageInfo: {
          volumeSize: 100,
        },
      },
    },
    encryptionInfo: {
      encryptionInTransit: {
        inCluster: true,
        clientBroker: 'TLS_PLAINTEXT', // Allows both secure and insecure
      },
    },
  });
}
// {/fact}

// {fact rule=client-side-enforcement-of-server-side-security@v1.0 defects=1}
function bad_case_4(scope: Construct) {
  // MSK cluster with no encryptionInfo at all
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript-cdk-mks-client-to-broker-tls
  new msk.CfnCluster(scope, 'MskCluster', {
    clusterName: 'no-encryption-kafka-cluster',
    kafkaVersion: '2.8.1',
    numberOfBrokerNodes: 3,
    brokerNodeGroupInfo: {
      instanceType: 'kafka.m5.large',
      clientSubnets: vpc.privateSubnets.map(subnet => subnet.subnetId),
      securityGroups: ['sg-12345'],
      storageInfo: {
        ebsStorageInfo: {
          volumeSize: 100,
        },
      },
    },
    // No encryptionInfo specified at all
  });
}
// {/fact}

// {fact rule=client-side-enforcement-of-server-side-security@v1.0 defects=1}
function bad_case_5(scope: Construct) {
  // MSK cluster with encryptionInTransit but no clientBroker setting
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript-cdk-mks-client-to-broker-tls
  new msk.CfnCluster(scope, 'MskCluster', {
    clusterName: 'incomplete-encryption-kafka-cluster',
    kafkaVersion: '2.8.1',
    numberOfBrokerNodes: 3,
    brokerNodeGroupInfo: {
      instanceType: 'kafka.m5.large',
      clientSubnets: vpc.privateSubnets.map(subnet => subnet.subnetId),
      securityGroups: ['sg-12345'],
      storageInfo: {
        ebsStorageInfo: {
          volumeSize: 100,
        },
      },
    },
    encryptionInfo: {
      encryptionInTransit: {
        inCluster: true,
        // Missing clientBroker setting
      },
    },
  });
}
// {/fact}

// {fact rule=client-side-enforcement-of-server-side-security@v1.0 defects=1}
function bad_case_6(scope: Construct) {
  // Using L2 construct with default settings (no encryption specified)
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript-cdk-mks-client-to-broker-tls
  new msk.Cluster(scope, 'MskCluster', {
    clusterName: 'l2-default-kafka-cluster',
    kafkaVersion: msk.KafkaVersion.V2_8_1,
    vpc,
    encryptionInTransit: {
      inCluster: true,
      // Missing clientBroker setting
    },
    instanceType: new ec2.InstanceType('kafka.m5.large'),
    removalPolicy: cdk.RemovalPolicy.DESTROY,
  });
}
// {/fact}

// {fact rule=client-side-enforcement-of-server-side-security@v1.0 defects=1}
function bad_case_7(scope: Construct) {
  // Using L2 construct with explicit PLAINTEXT setting
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript-cdk-mks-client-to-broker-tls
  new msk.Cluster(scope, 'MskCluster', {
    clusterName: 'l2-plaintext-kafka-cluster',
    kafkaVersion: msk.KafkaVersion.V2_8_1,
    vpc,
    encryptionInTransit: {
      inCluster: true,
      clientBroker: msk.ClientBrokerEncryption.PLAINTEXT,
    },
    instanceType: new ec2.InstanceType('kafka.m5.large'),
    removalPolicy: cdk.RemovalPolicy.DESTROY,
  });
}
// {/fact}

// {fact rule=client-side-enforcement-of-server-side-security@v1.0 defects=1}
function bad_case_8(scope: Construct) {
  // Using L2 construct with TLS_PLAINTEXT setting
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript-cdk-mks-client-to-broker-tls
  new msk.Cluster(scope, 'MskCluster', {
    clusterName: 'l2-mixed-kafka-cluster',
    kafkaVersion: msk.KafkaVersion.V2_8_1,
    vpc,
    encryptionInTransit: {
      inCluster: true,
      clientBroker: msk.ClientBrokerEncryption.TLS_PLAINTEXT,
    },
    instanceType: new ec2.InstanceType('kafka.m5.large'),
    removalPolicy: cdk.RemovalPolicy.DESTROY,
  });
}
// {/fact}

// {fact rule=client-side-enforcement-of-server-side-security@v1.0 defects=1}
function bad_case_9(scope: Construct) {
  // Using a variable that's set to PLAINTEXT
  const vpc = new ec2.Vpc(scope, 'VPC');
  const encryptionType = 'PLAINTEXT';
  
  // ruleid: typescript-cdk-mks-client-to-broker-tls
  new msk.CfnCluster(scope, 'MskCluster', {
    clusterName: 'variable-plaintext-kafka-cluster',
    kafkaVersion: '2.8.1',
    numberOfBrokerNodes: 3,
    brokerNodeGroupInfo: {
      instanceType: 'kafka.m5.large',
      clientSubnets: vpc.privateSubnets.map(subnet => subnet.subnetId),
      securityGroups: ['sg-12345'],
      storageInfo: {
        ebsStorageInfo: {
          volumeSize: 100,
        },
      },
    },
    encryptionInfo: {
      encryptionInTransit: {
        inCluster: true,
        clientBroker: encryptionType,
      },
    },
  });
}
// {/fact}

// {fact rule=client-side-enforcement-of-server-side-security@v1.0 defects=1}
function bad_case_10(scope: Construct) {
  // Using a variable that's set to TLS_PLAINTEXT
  const vpc = new ec2.Vpc(scope, 'VPC');
  const encryptionType = msk.ClientBrokerEncryption.TLS_PLAINTEXT;
  
  // ruleid: typescript-cdk-mks-client-to-broker-tls
  new msk.Cluster(scope, 'MskCluster', {
    clusterName: 'variable-mixed-kafka-cluster',
    kafkaVersion: msk.KafkaVersion.V2_8_1,
    vpc,
    encryptionInTransit: {
      inCluster: true,
      clientBroker: encryptionType,
    },
    instanceType: new ec2.InstanceType('kafka.m5.large'),
    removalPolicy: cdk.RemovalPolicy.DESTROY,
  });
}
// {/fact}

// {fact rule=client-side-enforcement-of-server-side-security@v1.0 defects=1}
function bad_case_11(scope: Construct) {
  // Using a conditional that can result in PLAINTEXT
  const vpc = new ec2.Vpc(scope, 'VPC');
  const useSecureConfig = false;
  const encryptionType = useSecureConfig ? 'TLS' : 'PLAINTEXT';
  
  // ruleid: typescript-cdk-mks-client-to-broker-tls
  new msk.CfnCluster(scope, 'MskCluster', {
    clusterName: 'conditional-kafka-cluster',
    kafkaVersion: '2.8.1',
    numberOfBrokerNodes: 3,
    brokerNodeGroupInfo: {
      instanceType: 'kafka.m5.large',
      clientSubnets: vpc.privateSubnets.map(subnet => subnet.subnetId),
      securityGroups: ['sg-12345'],
      storageInfo: {
        ebsStorageInfo: {
          volumeSize: 100,
        },
      },
    },
    encryptionInfo: {
      encryptionInTransit: {
        inCluster: true,
        clientBroker: encryptionType,
      },
    },
  });
}
// {/fact}

// {fact rule=client-side-enforcement-of-server-side-security@v1.0 defects=1}
function bad_case_12(scope: Construct) {
  // Using a function that returns PLAINTEXT
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  function getEncryptionType() {
    return 'PLAINTEXT';
  }
  
  // ruleid: typescript-cdk-mks-client-to-broker-tls
  new msk.CfnCluster(scope, 'MskCluster', {
    clusterName: 'function-plaintext-kafka-cluster',
    kafkaVersion: '2.8.1',
    numberOfBrokerNodes: 3,
    brokerNodeGroupInfo: {
      instanceType: 'kafka.m5.large',
      clientSubnets: vpc.privateSubnets.map(subnet => subnet.subnetId),
      securityGroups: ['sg-12345'],
      storageInfo: {
        ebsStorageInfo: {
          volumeSize: 100,
        },
      },
    },
    encryptionInfo: {
      encryptionInTransit: {
        inCluster: true,
        clientBroker: getEncryptionType(),
      },
    },
  });
}
// {/fact}

// {fact rule=client-side-enforcement-of-server-side-security@v1.0 defects=1}
function bad_case_13(scope: Construct) {
  // Using a config object
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  const clusterConfig = {
    encryptionInfo: {
      encryptionInTransit: {
        inCluster: true,
        clientBroker: 'TLS_PLAINTEXT',
      },
    },
  };
  
  // ruleid: typescript-cdk-mks-client-to-broker-tls
  new msk.CfnCluster(scope, 'MskCluster', {
    clusterName: 'config-object-kafka-cluster',
    kafkaVersion: '2.8.1',
    numberOfBrokerNodes: 3,
    brokerNodeGroupInfo: {
      instanceType: 'kafka.m5.large',
      clientSubnets: vpc.privateSubnets.map(subnet => subnet.subnetId),
      securityGroups: ['sg-12345'],
      storageInfo: {
        ebsStorageInfo: {
          volumeSize: 100,
        },
      },
    },
    ...clusterConfig,
  });
}
// {/fact}

// {fact rule=client-side-enforcement-of-server-side-security@v1.0 defects=1}
function bad_case_14(scope: Construct) {
  // Using empty encryptionInfo object
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript-cdk-mks-client-to-broker-tls
  new msk.CfnCluster(scope, 'MskCluster', {
    clusterName: 'empty-encryption-kafka-cluster',
    kafkaVersion: '2.8.1',
    numberOfBrokerNodes: 3,
    brokerNodeGroupInfo: {
      instanceType: 'kafka.m5.large',
      clientSubnets: vpc.privateSubnets.map(subnet => subnet.subnetId),
      securityGroups: ['sg-12345'],
      storageInfo: {
        ebsStorageInfo: {
          volumeSize: 100,
        },
      },
    },
    encryptionInfo: {}, // Empty encryption info
  });
}
// {/fact}

// {fact rule=client-side-enforcement-of-server-side-security@v1.0 defects=1}
function bad_case_15(scope: Construct) {
  // Using empty encryptionInTransit object
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript-cdk-mks-client-to-broker-tls
  new msk.CfnCluster(scope, 'MskCluster', {
    clusterName: 'empty-transit-kafka-cluster',
    kafkaVersion: '2.8.1',
    numberOfBrokerNodes: 3,
    brokerNodeGroupInfo: {
      instanceType: 'kafka.m5.large',
      clientSubnets: vpc.privateSubnets.map(subnet => subnet.subnetId),
      securityGroups: ['sg-12345'],
      storageInfo: {
        ebsStorageInfo: {
          volumeSize: 100,
        },
      },
    },
    encryptionInfo: {
      encryptionInTransit: {}, // Empty encryptionInTransit object
    },
  });
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=client-side-enforcement-of-server-side-security@v1.0 defects=0}
function good_case_1(scope: Construct) {
  // MSK cluster with clientBroker explicitly set to TLS
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript-cdk-mks-client-to-broker-tls
  new msk.CfnCluster(scope, 'MskCluster', {
    clusterName: 'secure-kafka-cluster',
    kafkaVersion: '2.8.1',
    numberOfBrokerNodes: 3,
    brokerNodeGroupInfo: {
      instanceType: 'kafka.m5.large',
      clientSubnets: vpc.privateSubnets.map(subnet => subnet.subnetId),
      securityGroups: ['sg-12345'],
      storageInfo: {
        ebsStorageInfo: {
          volumeSize: 100,
        },
      },
    },
    encryptionInfo: {
      encryptionInTransit: {
        inCluster: true,
        clientBroker: 'TLS', // Secure setting
      },
    },
  });
}
// {/fact}

// {fact rule=client-side-enforcement-of-server-side-security@v1.0 defects=0}
function good_case_2(scope: Construct) {
  // Using L2 construct with TLS setting
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript-cdk-mks-client-to-broker-tls
  new msk.Cluster(scope, 'MskCluster', {
    clusterName: 'l2-secure-kafka-cluster',
    kafkaVersion: msk.KafkaVersion.V2_8_1,
    vpc,
    encryptionInTransit: {
      inCluster: true,
      clientBroker: msk.ClientBrokerEncryption.TLS,
    },
    instanceType: new ec2.InstanceType('kafka.m5.large'),
    removalPolicy: cdk.RemovalPolicy.DESTROY,
  });
}
// {/fact}

// {fact rule=client-side-enforcement-of-server-side-security@v1.0 defects=0}
function good_case_3(scope: Construct) {
  // Using a variable that's set to TLS
  const vpc = new ec2.Vpc(scope, 'VPC');
  const encryptionType = 'TLS';
  
  // ok: typescript-cdk-mks-client-to-broker-tls
  new msk.CfnCluster(scope, 'MskCluster', {
    clusterName: 'variable-secure-kafka-cluster',
    kafkaVersion: '2.8.1',
    numberOfBrokerNodes: 3,
    brokerNodeGroupInfo: {
      instanceType: 'kafka.m5.large',
      clientSubnets: vpc.privateSubnets.map(subnet => subnet.subnetId),
      securityGroups: ['sg-12345'],
      storageInfo: {
        ebsStorageInfo: {
          volumeSize: 100,
        },
      },
    },
    encryptionInfo: {
      encryptionInTransit: {
        inCluster: true,
        clientBroker: encryptionType,
      },
    },
  });
}
// {/fact}

// {fact rule=client-side-enforcement-of-server-side-security@v1.0 defects=0}
function good_case_4(scope: Construct) {
  // Using a variable with L2 construct
  const vpc = new ec2.Vpc(scope, 'VPC');
  const encryptionType = msk.ClientBrokerEncryption.TLS;
  
  // ok: typescript-cdk-mks-client-to-broker-tls
  new msk.Cluster(scope, 'MskCluster', {
    clusterName: 'l2-variable-secure-kafka-cluster',
    kafkaVersion: msk.KafkaVersion.V2_8_1,
    vpc,
    encryptionInTransit: {
      inCluster: true,
      clientBroker: encryptionType,
    },
    instanceType: new ec2.InstanceType('kafka.m5.large'),
    removalPolicy: cdk.RemovalPolicy.DESTROY,
  });
}
// {/fact}

// {fact rule=client-side-enforcement-of-server-side-security@v1.0 defects=0}
function good_case_5(scope: Construct) {
  // Using a conditional that always results in TLS
  const vpc = new ec2.Vpc(scope, 'VPC');
  const useSecureConfig = true;
  const encryptionType = useSecureConfig ? 'TLS' : 'PLAINTEXT';
  
  // ok: typescript-cdk-mks-client-to-broker-tls
  new msk.CfnCluster(scope, 'MskCluster', {
    clusterName: 'conditional-secure-kafka-cluster',
    kafkaVersion: '2.8.1',
    numberOfBrokerNodes: 3,
    brokerNodeGroupInfo: {
      instanceType: 'kafka.m5.large',
      clientSubnets: vpc.privateSubnets.map(subnet => subnet.subnetId),
      securityGroups: ['sg-12345'],
      storageInfo: {
        ebsStorageInfo: {
          volumeSize: 100,
        },
      },
    },
    encryptionInfo: {
      encryptionInTransit: {
        inCluster: true,
        clientBroker: encryptionType,
      },
    },
  });
}
// {/fact}

// {fact rule=client-side-enforcement-of-server-side-security@v1.0 defects=0}
function good_case_6(scope: Construct) {
  // Using a function that returns TLS
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  function getEncryptionType() {
    return 'TLS';
  }
  
  // ok: typescript-cdk-mks-client-to-broker-tls
  new msk.CfnCluster(scope, 'MskCluster', {
    clusterName: 'function-secure-kafka-cluster',
    kafkaVersion: '2.8.1',
    numberOfBrokerNodes: 3,
    brokerNodeGroupInfo: {
      instanceType: 'kafka.m5.large',
      clientSubnets: vpc.privateSubnets.map(subnet => subnet.subnetId),
      securityGroups: ['sg-12345'],
      storageInfo: {
        ebsStorageInfo: {
          volumeSize: 100,
        },
      },
    },
    encryptionInfo: {
      encryptionInTransit: {
        inCluster: true,
        clientBroker: getEncryptionType(),
      },
    },
  });
}
// {/fact}

// {fact rule=client-side-enforcement-of-server-side-security@v1.0 defects=0}
function good_case_7(scope: Construct) {
  // Using a config object with TLS
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  const clusterConfig = {
    encryptionInfo: {
      encryptionInTransit: {
        inCluster: true,
        clientBroker: 'TLS',
      },
    },
  };
  
  // ok: typescript-cdk-mks-client-to-broker-tls
  new msk.CfnCluster(scope, 'MskCluster', {
    clusterName: 'config-object-secure-kafka-cluster',
    kafkaVersion: '2.8.1',
    numberOfBrokerNodes: 3,
    brokerNodeGroupInfo: {
      instanceType: 'kafka.m5.large',
      clientSubnets: vpc.privateSubnets.map(subnet => subnet.subnetId),
      securityGroups: ['sg-12345'],
      storageInfo: {
        ebsStorageInfo: {
          volumeSize: 100,
        },
      },
    },
    ...clusterConfig,
  });
}
// {/fact}

// {fact rule=client-side-enforcement-of-server-side-security@v1.0 defects=0}
function good_case_8(scope: Construct) {
  // Using a config object with L2 construct
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  const encryptionConfig = {
    encryptionInTransit: {
      inCluster: true,
      clientBroker: msk.ClientBrokerEncryption.TLS,
    },
  };
  
  // ok: typescript-cdk-mks-client-to-broker-tls
  new msk.Cluster(scope, 'MskCluster', {
    clusterName: 'l2-config-object-secure-kafka-cluster',
    kafkaVersion: msk.KafkaVersion.V2_8_1,
    vpc,
    ...encryptionConfig,
    instanceType: new ec2.InstanceType('kafka.m5.large'),
    removalPolicy: cdk.RemovalPolicy.DESTROY,
  });
}
// {/fact}

// {fact rule=client-side-enforcement-of-server-side-security@v1.0 defects=0}
function good_case_9(scope: Construct) {
  // Using environment variables for configuration
  const vpc = new ec2.Vpc(scope, 'VPC');
  const encryptionType = process.env.ENCRYPTION_TYPE || 'TLS'; // Default to TLS if not specified
  
  // ok: typescript-cdk-mks-client-to-broker-tls
  new msk.CfnCluster(scope, 'MskCluster', {
    clusterName: 'env-var-kafka-cluster',
    kafkaVersion: '2.8.1',
    numberOfBrokerNodes: 3,
    brokerNodeGroupInfo: {
      instanceType: 'kafka.m5.large',
      clientSubnets: vpc.privateSubnets.map(subnet => subnet.subnetId),
      securityGroups: ['sg-12345'],
      storageInfo: {
        ebsStorageInfo: {
          volumeSize: 100,
        },
      },
    },
    encryptionInfo: {
      encryptionInTransit: {
        inCluster: true,
        clientBroker: 'TLS', // Always use TLS regardless of environment variable
      },
    },
  });
}
// {/fact}

// {fact rule=client-side-enforcement-of-server-side-security@v1.0 defects=0}
function good_case_10(scope: Construct) {
  // Using a helper function to ensure TLS
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  function getSecureEncryptionConfig() {
    return {
      encryptionInTransit: {
        inCluster: true,
        clientBroker: msk.ClientBrokerEncryption.TLS,
      },
    };
  }
  
  // ok: typescript-cdk-mks-client-to-broker-tls
  new msk.Cluster(scope, 'MskCluster', {
    clusterName: 'helper-function-secure-kafka-cluster',
    kafkaVersion: msk.KafkaVersion.V2_8_1,
    vpc,
    ...getSecureEncryptionConfig(),
    instanceType: new ec2.InstanceType('kafka.m5.large'),
    removalPolicy: cdk.RemovalPolicy.DESTROY,
  });
}
// {/fact}

// {fact rule=client-side-enforcement-of-server-side-security@v1.0 defects=0}
function good_case_11(scope: Construct) {
  // Using a constant for TLS configuration
  const vpc = new ec2.Vpc(scope, 'VPC');
  const TLS_ENCRYPTION = 'TLS';
  
  // ok: typescript-cdk-mks-client-to-broker-tls
  new msk.CfnCluster(scope, 'MskCluster', {
    clusterName: 'constant-secure-kafka-cluster',
    kafkaVersion: '2.8.1',
    numberOfBrokerNodes: 3,
    brokerNodeGroupInfo: {
      instanceType: 'kafka.m5.large',
      clientSubnets: vpc.privateSubnets.map(subnet => subnet.subnetId),
      securityGroups: ['sg-12345'],
      storageInfo: {
        ebsStorageInfo: {
          volumeSize: 100,
        },
      },
    },
    encryptionInfo: {
      encryptionInTransit: {
        inCluster: true,
        clientBroker: TLS_ENCRYPTION,
      },
    },
  });
}
// {/fact}

// {fact rule=client-side-enforcement-of-server-side-security@v1.0 defects=0}
function good_case_12(scope: Construct) {
  // Using a factory pattern to create a secure cluster
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  class SecureMskClusterFactory {
    static createCluster(scope: Construct, id: string, clusterName: string) {
      return new msk.CfnCluster(scope, id, {
        clusterName,
        kafkaVersion: '2.8.1',
        numberOfBrokerNodes: 3,
        brokerNodeGroupInfo: {
          instanceType: 'kafka.m5.large',
          clientSubnets: vpc.privateSubnets.map(subnet => subnet.subnetId),
          securityGroups: ['sg-12345'],
          storageInfo: {
            ebsStorageInfo: {
              volumeSize: 100,
            },
          },
        },
        encryptionInfo: {
          encryptionInTransit: {
            inCluster: true,
            clientBroker: 'TLS',
          },
        },
      });
    }
  }
  
  // ok: typescript-cdk-mks-client-to-broker-tls
  SecureMskClusterFactory.createCluster(scope, 'MskCluster', 'factory-secure-kafka-cluster');
}
// {/fact}

// {fact rule=client-side-enforcement-of-server-side-security@v1.0 defects=0}
function good_case_13(scope: Construct) {
  // Using a builder pattern for secure cluster configuration
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  class MskClusterBuilder {
    private props: any = {};
    
    constructor(private scope: Construct, private id: string) {
      this.props = {
        kafkaVersion: '2.8.1',
        numberOfBrokerNodes: 3,
        brokerNodeGroupInfo: {
          instanceType: 'kafka.m5.large',
          clientSubnets: vpc.privateSubnets.map(subnet => subnet.subnetId),
          securityGroups: ['sg-12345'],
          storageInfo: {
            ebsStorageInfo: {
              volumeSize: 100,
            },
          },
        },
      };
    }
    
    withClusterName(name: string): MskClusterBuilder {
      this.props.clusterName = name;
      return this;
    }
    
    withSecureEncryption(): MskClusterBuilder {
      this.props.encryptionInfo = {
        encryptionInTransit: {
          inCluster: true,
          clientBroker: 'TLS',
        },
      };
      return this;
    }
    
    build(): msk.CfnCluster {
      return new msk.CfnCluster(this.scope, this.id, this.props);
    }
  }
  
  // ok: typescript-cdk-mks-client-to-broker-tls
  new MskClusterBuilder(scope, 'MskCluster')
    .withClusterName('builder-secure-kafka-cluster')
    .withSecureEncryption()
    .build();
}
// {/fact}

// {fact rule=client-side-enforcement-of-server-side-security@v1.0 defects=0}
function good_case_14(scope: Construct) {
  // Using a secure configuration with KMS encryption
  const vpc = new ec2.Vpc(scope, 'VPC');
  const encryptionKey = new kms.Key(scope, 'MskEncryptionKey');
  
  // ok: typescript-cdk-mks-client-to-broker-tls
  new msk.CfnCluster(scope, 'MskCluster', {
    clusterName: 'fully-secure-kafka-cluster',
    kafkaVersion: '2.8.1',
    numberOfBrokerNodes: 3,
    brokerNodeGroupInfo: {
      instanceType: 'kafka.m5.large',
      clientSubnets: vpc.privateSubnets.map(subnet => subnet.subnetId),
      securityGroups: ['sg-12345'],
      storageInfo: {
        ebsStorageInfo: {
          volumeSize: 100,
        },
      },
    },
    encryptionInfo: {
      encryptionAtRest: {
        dataVolumeKMSKeyId: encryptionKey.keyId,
      },
      encryptionInTransit: {
        inCluster: true,
        clientBroker: 'TLS',
      },
    },
  });
}
// {/fact}

// {fact rule=client-side-enforcement-of-server-side-security@v1.0 defects=0}
function good_case_15(scope: Construct) {
  // Using a secure configuration with L2 construct and KMS encryption
  const vpc = new ec2.Vpc(scope, 'VPC');
  const encryptionKey = new kms.Key(scope, 'MskEncryptionKey');
  
  // ok: typescript-cdk-mks-client-to-broker-tls
  new msk.Cluster(scope, 'MskCluster', {
    clusterName: 'l2-fully-secure-kafka-cluster',
    kafkaVersion: msk.KafkaVersion.V2_8_1,
    vpc,
    encryptionInTransit: {
      inCluster: true,
      clientBroker: msk.ClientBrokerEncryption.TLS,
    },
    encryptionAtRest: {
      kmsKey: encryptionKey,
    },
    instanceType: new ec2.InstanceType('kafka.m5.large'),
    removalPolicy: cdk.RemovalPolicy.DESTROY,
  });
}
// {/fact}