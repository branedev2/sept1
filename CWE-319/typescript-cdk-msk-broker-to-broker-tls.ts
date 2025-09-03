import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as msk from 'aws-cdk-lib/aws-msk';

// True Positives (Vulnerable Cases)

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_1() {
  const stack = new cdk.Stack();
  
  // Creating MSK cluster with inCluster explicitly set to false
  // ruleid: typescript-cdk-msk-broker-to-broker-tls
  new msk.CfnCluster(stack, 'MskCluster1', {
    clusterName: 'msk-cluster-1',
    kafkaVersion: '2.8.1',
    numberOfBrokerNodes: 3,
    brokerNodeGroupInfo: {
      instanceType: 'kafka.m5.large',
      clientSubnets: ['subnet-1', 'subnet-2', 'subnet-3'],
      securityGroups: ['sg-1'],
    },
    encryptionInfo: {
      encryptionInTransit: {
        clientBroker: 'TLS',
        inCluster: false,
      },
    },
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_2() {
  const stack = new cdk.Stack();
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // Creating MSK cluster without specifying inCluster (defaults to false)
  // ruleid: typescript-cdk-msk-broker-to-broker-tls
  new msk.CfnCluster(stack, 'MskCluster2', {
    clusterName: 'msk-cluster-2',
    kafkaVersion: '2.8.1',
    numberOfBrokerNodes: 3,
    brokerNodeGroupInfo: {
      instanceType: 'kafka.m5.large',
      clientSubnets: [
        vpc.privateSubnets[0].subnetId,
        vpc.privateSubnets[1].subnetId,
        vpc.privateSubnets[2].subnetId,
      ],
      securityGroups: [vpc.vpcDefaultSecurityGroup],
    },
    encryptionInfo: {
      encryptionInTransit: {
        clientBroker: 'TLS',
        // inCluster is missing, which defaults to false
      },
    },
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_3() {
  const stack = new cdk.Stack();
  
  // Creating MSK cluster with encryptionInTransit but without inCluster
  // ruleid: typescript-cdk-msk-broker-to-broker-tls
  new msk.CfnCluster(stack, 'MskCluster3', {
    clusterName: 'msk-cluster-3',
    kafkaVersion: '2.8.1',
    numberOfBrokerNodes: 3,
    brokerNodeGroupInfo: {
      instanceType: 'kafka.m5.large',
      clientSubnets: ['subnet-1', 'subnet-2', 'subnet-3'],
      securityGroups: ['sg-1'],
    },
    encryptionInfo: {
      encryptionInTransit: {
        clientBroker: 'TLS_PLAINTEXT',
      },
    },
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_4() {
  const stack = new cdk.Stack();
  
  // Using a variable that's set to false for inCluster
  const enableInClusterTLS = false;
  
  // ruleid: typescript-cdk-msk-broker-to-broker-tls
  new msk.CfnCluster(stack, 'MskCluster4', {
    clusterName: 'msk-cluster-4',
    kafkaVersion: '2.8.1',
    numberOfBrokerNodes: 3,
    brokerNodeGroupInfo: {
      instanceType: 'kafka.m5.large',
      clientSubnets: ['subnet-1', 'subnet-2', 'subnet-3'],
      securityGroups: ['sg-1'],
    },
    encryptionInfo: {
      encryptionInTransit: {
        clientBroker: 'TLS',
        inCluster: enableInClusterTLS,
      },
    },
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_5() {
  const stack = new cdk.Stack();
  
  // Creating MSK cluster with encryptionInfo but without encryptionInTransit
  // ruleid: typescript-cdk-msk-broker-to-broker-tls
  new msk.CfnCluster(stack, 'MskCluster5', {
    clusterName: 'msk-cluster-5',
    kafkaVersion: '2.8.1',
    numberOfBrokerNodes: 3,
    brokerNodeGroupInfo: {
      instanceType: 'kafka.m5.large',
      clientSubnets: ['subnet-1', 'subnet-2', 'subnet-3'],
      securityGroups: ['sg-1'],
    },
    encryptionInfo: {
      // encryptionInTransit is missing
    },
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_6() {
  const stack = new cdk.Stack();
  
  // Creating MSK cluster without encryptionInfo at all
  // ruleid: typescript-cdk-msk-broker-to-broker-tls
  new msk.CfnCluster(stack, 'MskCluster6', {
    clusterName: 'msk-cluster-6',
    kafkaVersion: '2.8.1',
    numberOfBrokerNodes: 3,
    brokerNodeGroupInfo: {
      instanceType: 'kafka.m5.large',
      clientSubnets: ['subnet-1', 'subnet-2', 'subnet-3'],
      securityGroups: ['sg-1'],
    },
    // encryptionInfo is missing
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_7() {
  const stack = new cdk.Stack();
  
  // Using a conditional that results in false for inCluster
  const isProduction = false;
  
  // ruleid: typescript-cdk-msk-broker-to-broker-tls
  new msk.CfnCluster(stack, 'MskCluster7', {
    clusterName: 'msk-cluster-7',
    kafkaVersion: '2.8.1',
    numberOfBrokerNodes: 3,
    brokerNodeGroupInfo: {
      instanceType: 'kafka.m5.large',
      clientSubnets: ['subnet-1', 'subnet-2', 'subnet-3'],
      securityGroups: ['sg-1'],
    },
    encryptionInfo: {
      encryptionInTransit: {
        clientBroker: 'TLS',
        inCluster: isProduction ? true : false,
      },
    },
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_8() {
  const stack = new cdk.Stack();
  
  // Creating MSK cluster with properties from an object that has inCluster set to false
  const clusterProps = {
    clusterName: 'msk-cluster-8',
    kafkaVersion: '2.8.1',
    numberOfBrokerNodes: 3,
    brokerNodeGroupInfo: {
      instanceType: 'kafka.m5.large',
      clientSubnets: ['subnet-1', 'subnet-2', 'subnet-3'],
      securityGroups: ['sg-1'],
    },
    encryptionInfo: {
      encryptionInTransit: {
        clientBroker: 'TLS',
        inCluster: false,
      },
    },
  };
  
  // ruleid: typescript-cdk-msk-broker-to-broker-tls
  new msk.CfnCluster(stack, 'MskCluster8', clusterProps);
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_9() {
  const stack = new cdk.Stack();
  
  // Creating MSK cluster with a function that returns false for inCluster
  const getInClusterSetting = () => false;
  
  // ruleid: typescript-cdk-msk-broker-to-broker-tls
  new msk.CfnCluster(stack, 'MskCluster9', {
    clusterName: 'msk-cluster-9',
    kafkaVersion: '2.8.1',
    numberOfBrokerNodes: 3,
    brokerNodeGroupInfo: {
      instanceType: 'kafka.m5.large',
      clientSubnets: ['subnet-1', 'subnet-2', 'subnet-3'],
      securityGroups: ['sg-1'],
    },
    encryptionInfo: {
      encryptionInTransit: {
        clientBroker: 'TLS',
        inCluster: getInClusterSetting(),
      },
    },
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_10() {
  class MskStack extends cdk.Stack {
    constructor(scope: Construct, id: string, props?: cdk.StackProps) {
      super(scope, id, props);
      
      // Creating MSK cluster in a class with inCluster set to false
      // ruleid: typescript-cdk-msk-broker-to-broker-tls
      new msk.CfnCluster(this, 'MskCluster10', {
        clusterName: 'msk-cluster-10',
        kafkaVersion: '2.8.1',
        numberOfBrokerNodes: 3,
        brokerNodeGroupInfo: {
          instanceType: 'kafka.m5.large',
          clientSubnets: ['subnet-1', 'subnet-2', 'subnet-3'],
          securityGroups: ['sg-1'],
        },
        encryptionInfo: {
          encryptionInTransit: {
            clientBroker: 'TLS',
            inCluster: false,
          },
        },
      });
    }
  }
  
  const app = new cdk.App();
  new MskStack(app, 'MskStack10');
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_11() {
  const stack = new cdk.Stack();
  
  // Creating MSK cluster with string 'false' for inCluster (type error but demonstrates intent)
  // ruleid: typescript-cdk-msk-broker-to-broker-tls
  new msk.CfnCluster(stack, 'MskCluster11', {
    clusterName: 'msk-cluster-11',
    kafkaVersion: '2.8.1',
    numberOfBrokerNodes: 3,
    brokerNodeGroupInfo: {
      instanceType: 'kafka.m5.large',
      clientSubnets: ['subnet-1', 'subnet-2', 'subnet-3'],
      securityGroups: ['sg-1'],
    },
    encryptionInfo: {
      encryptionInTransit: {
        clientBroker: 'TLS',
        inCluster: 'false' as unknown as boolean,
      },
    },
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_12() {
  const stack = new cdk.Stack();
  
  // Creating MSK cluster with environment variable that defaults to false
  const inClusterSetting = process.env.ENABLE_TLS === 'true' ? true : false;
  
  // ruleid: typescript-cdk-msk-broker-to-broker-tls
  new msk.CfnCluster(stack, 'MskCluster12', {
    clusterName: 'msk-cluster-12',
    kafkaVersion: '2.8.1',
    numberOfBrokerNodes: 3,
    brokerNodeGroupInfo: {
      instanceType: 'kafka.m5.large',
      clientSubnets: ['subnet-1', 'subnet-2', 'subnet-3'],
      securityGroups: ['sg-1'],
    },
    encryptionInfo: {
      encryptionInTransit: {
        clientBroker: 'TLS',
        inCluster: inClusterSetting,
      },
    },
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_13() {
  const stack = new cdk.Stack();
  
  // Creating MSK cluster with a complex expression that evaluates to false
  const devEnvironment = true;
  const prodSettings = { enableTLS: true };
  const devSettings = { enableTLS: false };
  
  // ruleid: typescript-cdk-msk-broker-to-broker-tls
  new msk.CfnCluster(stack, 'MskCluster13', {
    clusterName: 'msk-cluster-13',
    kafkaVersion: '2.8.1',
    numberOfBrokerNodes: 3,
    brokerNodeGroupInfo: {
      instanceType: 'kafka.m5.large',
      clientSubnets: ['subnet-1', 'subnet-2', 'subnet-3'],
      securityGroups: ['sg-1'],
    },
    encryptionInfo: {
      encryptionInTransit: {
        clientBroker: 'TLS',
        inCluster: devEnvironment ? devSettings.enableTLS : prodSettings.enableTLS,
      },
    },
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_14() {
  const stack = new cdk.Stack();
  
  // Creating MSK cluster with a null check that defaults to false
  const securityConfig = null;
  
  // ruleid: typescript-cdk-msk-broker-to-broker-tls
  new msk.CfnCluster(stack, 'MskCluster14', {
    clusterName: 'msk-cluster-14',
    kafkaVersion: '2.8.1',
    numberOfBrokerNodes: 3,
    brokerNodeGroupInfo: {
      instanceType: 'kafka.m5.large',
      clientSubnets: ['subnet-1', 'subnet-2', 'subnet-3'],
      securityGroups: ['sg-1'],
    },
    encryptionInfo: {
      encryptionInTransit: {
        clientBroker: 'TLS',
        inCluster: securityConfig?.enableTLS || false,
      },
    },
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_15() {
  const stack = new cdk.Stack();
  
  // Creating MSK cluster with inCluster set to undefined (which defaults to false)
  let inClusterSetting: boolean | undefined;
  
  // ruleid: typescript-cdk-msk-broker-to-broker-tls
  new msk.CfnCluster(stack, 'MskCluster15', {
    clusterName: 'msk-cluster-15',
    kafkaVersion: '2.8.1',
    numberOfBrokerNodes: 3,
    brokerNodeGroupInfo: {
      instanceType: 'kafka.m5.large',
      clientSubnets: ['subnet-1', 'subnet-2', 'subnet-3'],
      securityGroups: ['sg-1'],
    },
    encryptionInfo: {
      encryptionInTransit: {
        clientBroker: 'TLS',
        inCluster: inClusterSetting,
      },
    },
  });
}
// {/fact}

// True Negatives (Secure Cases)

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_1() {
  const stack = new cdk.Stack();
  
  // Creating MSK cluster with inCluster explicitly set to true
  // ok: typescript-cdk-msk-broker-to-broker-tls
  new msk.CfnCluster(stack, 'MskCluster1', {
    clusterName: 'msk-cluster-1',
    kafkaVersion: '2.8.1',
    numberOfBrokerNodes: 3,
    brokerNodeGroupInfo: {
      instanceType: 'kafka.m5.large',
      clientSubnets: ['subnet-1', 'subnet-2', 'subnet-3'],
      securityGroups: ['sg-1'],
    },
    encryptionInfo: {
      encryptionInTransit: {
        clientBroker: 'TLS',
        inCluster: true,
      },
    },
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_2() {
  const stack = new cdk.Stack();
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // Creating MSK cluster with variable set to true for inCluster
  const enableInClusterTLS = true;
  
  // ok: typescript-cdk-msk-broker-to-broker-tls
  new msk.CfnCluster(stack, 'MskCluster2', {
    clusterName: 'msk-cluster-2',
    kafkaVersion: '2.8.1',
    numberOfBrokerNodes: 3,
    brokerNodeGroupInfo: {
      instanceType: 'kafka.m5.large',
      clientSubnets: [
        vpc.privateSubnets[0].subnetId,
        vpc.privateSubnets[1].subnetId,
        vpc.privateSubnets[2].subnetId,
      ],
      securityGroups: [vpc.vpcDefaultSecurityGroup],
    },
    encryptionInfo: {
      encryptionInTransit: {
        clientBroker: 'TLS',
        inCluster: enableInClusterTLS,
      },
    },
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_3() {
  const stack = new cdk.Stack();
  
  // Using a conditional that always evaluates to true for inCluster
  const isProduction = true;
  
  // ok: typescript-cdk-msk-broker-to-broker-tls
  new msk.CfnCluster(stack, 'MskCluster3', {
    clusterName: 'msk-cluster-3',
    kafkaVersion: '2.8.1',
    numberOfBrokerNodes: 3,
    brokerNodeGroupInfo: {
      instanceType: 'kafka.m5.large',
      clientSubnets: ['subnet-1', 'subnet-2', 'subnet-3'],
      securityGroups: ['sg-1'],
    },
    encryptionInfo: {
      encryptionInTransit: {
        clientBroker: 'TLS',
        inCluster: isProduction ? true : false,
      },
    },
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_4() {
  const stack = new cdk.Stack();
  
  // Creating MSK cluster with properties from an object that has inCluster set to true
  const clusterProps = {
    clusterName: 'msk-cluster-4',
    kafkaVersion: '2.8.1',
    numberOfBrokerNodes: 3,
    brokerNodeGroupInfo: {
      instanceType: 'kafka.m5.large',
      clientSubnets: ['subnet-1', 'subnet-2', 'subnet-3'],
      securityGroups: ['sg-1'],
    },
    encryptionInfo: {
      encryptionInTransit: {
        clientBroker: 'TLS',
        inCluster: true,
      },
    },
  };
  
  // ok: typescript-cdk-msk-broker-to-broker-tls
  new msk.CfnCluster(stack, 'MskCluster4', clusterProps);
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_5() {
  const stack = new cdk.Stack();
  
  // Creating MSK cluster with a function that returns true for inCluster
  const getInClusterSetting = () => true;
  
  // ok: typescript-cdk-msk-broker-to-broker-tls
  new msk.CfnCluster(stack, 'MskCluster5', {
    clusterName: 'msk-cluster-5',
    kafkaVersion: '2.8.1',
    numberOfBrokerNodes: 3,
    brokerNodeGroupInfo: {
      instanceType: 'kafka.m5.large',
      clientSubnets: ['subnet-1', 'subnet-2', 'subnet-3'],
      securityGroups: ['sg-1'],
    },
    encryptionInfo: {
      encryptionInTransit: {
        clientBroker: 'TLS',
        inCluster: getInClusterSetting(),
      },
    },
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_6() {
  class MskStack extends cdk.Stack {
    constructor(scope: Construct, id: string, props?: cdk.StackProps) {
      super(scope, id, props);
      
      // Creating MSK cluster in a class with inCluster set to true
      // ok: typescript-cdk-msk-broker-to-broker-tls
      new msk.CfnCluster(this, 'MskCluster6', {
        clusterName: 'msk-cluster-6',
        kafkaVersion: '2.8.1',
        numberOfBrokerNodes: 3,
        brokerNodeGroupInfo: {
          instanceType: 'kafka.m5.large',
          clientSubnets: ['subnet-1', 'subnet-2', 'subnet-3'],
          securityGroups: ['sg-1'],
        },
        encryptionInfo: {
          encryptionInTransit: {
            clientBroker: 'TLS',
            inCluster: true,
          },
        },
      });
    }
  }
  
  const app = new cdk.App();
  new MskStack(app, 'MskStack6');
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_7() {
  const stack = new cdk.Stack();
  
  // Creating MSK cluster with string 'true' for inCluster (type error but demonstrates intent)
  // ok: typescript-cdk-msk-broker-to-broker-tls
  new msk.CfnCluster(stack, 'MskCluster7', {
    clusterName: 'msk-cluster-7',
    kafkaVersion: '2.8.1',
    numberOfBrokerNodes: 3,
    brokerNodeGroupInfo: {
      instanceType: 'kafka.m5.large',
      clientSubnets: ['subnet-1', 'subnet-2', 'subnet-3'],
      securityGroups: ['sg-1'],
    },
    encryptionInfo: {
      encryptionInTransit: {
        clientBroker: 'TLS',
        inCluster: 'true' as unknown as boolean,
      },
    },
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_8() {
  const stack = new cdk.Stack();
  
  // Creating MSK cluster with environment variable that defaults to true
  process.env.ENABLE_TLS = 'true';
  const inClusterSetting = process.env.ENABLE_TLS === 'true' ? true : false;
  
  // ok: typescript-cdk-msk-broker-to-broker-tls
  new msk.CfnCluster(stack, 'MskCluster8', {
    clusterName: 'msk-cluster-8',
    kafkaVersion: '2.8.1',
    numberOfBrokerNodes: 3,
    brokerNodeGroupInfo: {
      instanceType: 'kafka.m5.large',
      clientSubnets: ['subnet-1', 'subnet-2', 'subnet-3'],
      securityGroups: ['sg-1'],
    },
    encryptionInfo: {
      encryptionInTransit: {
        clientBroker: 'TLS',
        inCluster: inClusterSetting,
      },
    },
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_9() {
  const stack = new cdk.Stack();
  
  // Creating MSK cluster with a complex expression that evaluates to true
  const devEnvironment = false;
  const prodSettings = { enableTLS: true };
  const devSettings = { enableTLS: false };
  
  // ok: typescript-cdk-msk-broker-to-broker-tls
  new msk.CfnCluster(stack, 'MskCluster9', {
    clusterName: 'msk-cluster-9',
    kafkaVersion: '2.8.1',
    numberOfBrokerNodes: 3,
    brokerNodeGroupInfo: {
      instanceType: 'kafka.m5.large',
      clientSubnets: ['subnet-1', 'subnet-2', 'subnet-3'],
      securityGroups: ['sg-1'],
    },
    encryptionInfo: {
      encryptionInTransit: {
        clientBroker: 'TLS',
        inCluster: devEnvironment ? devSettings.enableTLS : prodSettings.enableTLS,
      },
    },
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_10() {
  const stack = new cdk.Stack();
  
  // Creating MSK cluster with a null check that defaults to true
  const securityConfig = null;
  
  // ok: typescript-cdk-msk-broker-to-broker-tls
  new msk.CfnCluster(stack, 'MskCluster10', {
    clusterName: 'msk-cluster-10',
    kafkaVersion: '2.8.1',
    numberOfBrokerNodes: 3,
    brokerNodeGroupInfo: {
      instanceType: 'kafka.m5.large',
      clientSubnets: ['subnet-1', 'subnet-2', 'subnet-3'],
      securityGroups: ['sg-1'],
    },
    encryptionInfo: {
      encryptionInTransit: {
        clientBroker: 'TLS',
        inCluster: securityConfig?.enableTLS ?? true,
      },
    },
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_11() {
  const stack = new cdk.Stack();
  
  // Using the L2 construct which sets inCluster to true by default
  // ok: typescript-cdk-msk-broker-to-broker-tls
  new msk.Cluster(stack, 'MskCluster11', {
    clusterName: 'msk-cluster-11',
    kafkaVersion: msk.KafkaVersion.V2_8_1,
    vpc: new ec2.Vpc(stack, 'VPC'),
    encryptionInTransit: {
      clientBroker: msk.ClientBrokerEncryption.TLS,
    },
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_12() {
  const stack = new cdk.Stack();
  
  // Using a security best practices function that enforces TLS
  const getSecureEncryptionConfig = () => {
    return {
      encryptionInTransit: {
        clientBroker: 'TLS',
        inCluster: true,
      },
    };
  };
  
  // ok: typescript-cdk-msk-broker-to-broker-tls
  new msk.CfnCluster(stack, 'MskCluster12', {
    clusterName: 'msk-cluster-12',
    kafkaVersion: '2.8.1',
    numberOfBrokerNodes: 3,
    brokerNodeGroupInfo: {
      instanceType: 'kafka.m5.large',
      clientSubnets: ['subnet-1', 'subnet-2', 'subnet-3'],
      securityGroups: ['sg-1'],
    },
    encryptionInfo: getSecureEncryptionConfig(),
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_13() {
  const stack = new cdk.Stack();
  
  // Using a factory function to create the cluster with secure settings
  const createSecureMskCluster = (stack: cdk.Stack, id: string, name: string) => {
    // ok: typescript-cdk-msk-broker-to-broker-tls
    return new msk.CfnCluster(stack, id, {
      clusterName: name,
      kafkaVersion: '2.8.1',
      numberOfBrokerNodes: 3,
      brokerNodeGroupInfo: {
        instanceType: 'kafka.m5.large',
        clientSubnets: ['subnet-1', 'subnet-2', 'subnet-3'],
        securityGroups: ['sg-1'],
      },
      encryptionInfo: {
        encryptionInTransit: {
          clientBroker: 'TLS',
          inCluster: true,
        },
      },
    });
  };
  
  createSecureMskCluster(stack, 'MskCluster13', 'msk-cluster-13');
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_14() {
  const stack = new cdk.Stack();
  
  // Using a logical OR that ensures inCluster is true
  const userProvidedSetting = undefined;
  
  // ok: typescript-cdk-msk-broker-to-broker-tls
  new msk.CfnCluster(stack, 'MskCluster14', {
    clusterName: 'msk-cluster-14',
    kafkaVersion: '2.8.1',
    numberOfBrokerNodes: 3,
    brokerNodeGroupInfo: {
      instanceType: 'kafka.m5.large',
      clientSubnets: ['subnet-1', 'subnet-2', 'subnet-3'],
      securityGroups: ['sg-1'],
    },
    encryptionInfo: {
      encryptionInTransit: {
        clientBroker: 'TLS',
        inCluster: userProvidedSetting || true,
      },
    },
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_15() {
  const stack = new cdk.Stack();
  
  // Using a security compliance check before creating the cluster
  const clusterProps = {
    clusterName: 'msk-cluster-15',
    kafkaVersion: '2.8.1',
    numberOfBrokerNodes: 3,
    brokerNodeGroupInfo: {
      instanceType: 'kafka.m5.large',
      clientSubnets: ['subnet-1', 'subnet-2', 'subnet-3'],
      securityGroups: ['sg-1'],
    },
    encryptionInfo: {
      encryptionInTransit: {
        clientBroker: 'TLS',
        inCluster: false,
      },
    },
  };
  
  // Security compliance check
  const enforceSecureSettings = (props: any) => {
    const secureProps = { ...props };
    if (!secureProps.encryptionInfo) {
      secureProps.encryptionInfo = {};
    }
    if (!secureProps.encryptionInfo.encryptionInTransit) {
      secureProps.encryptionInfo.encryptionInTransit = {};
    }
    secureProps.encryptionInfo.encryptionInTransit.inCluster = true;
    return secureProps;
  };
  
  const secureClusterProps = enforceSecureSettings(clusterProps);
  
  // ok: typescript-cdk-msk-broker-to-broker-tls
  new msk.CfnCluster(stack, 'MskCluster15', secureClusterProps);
}
// {/fact}