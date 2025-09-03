import { Stack, StackProps, App } from 'aws-cdk-lib';
import * as msk from 'aws-cdk-lib/aws-msk';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as firehose from 'aws-cdk-lib/aws-kinesisfirehose';
import { Construct } from 'constructs';

// True Positive Cases (Vulnerable Code)

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_1(scope: Construct) {
  // MSK cluster with no broker logging configuration at all
  // ruleid: typescript-cdk-msk-broker-logging
  new msk.CfnCluster(scope, 'MskClusterNoLogging', {
    clusterName: 'kafka-cluster-no-logging',
    kafkaVersion: '2.8.1',
    numberOfBrokerNodes: 3,
    brokerNodeGroupInfo: {
      instanceType: 'kafka.m5.large',
      clientSubnets: ['subnet-1', 'subnet-2', 'subnet-3'],
      securityGroups: ['sg-12345'],
      storageInfo: {
        ebsStorageInfo: {
          volumeSize: 100
        }
      }
    }
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_2(scope: Construct) {
  // MSK cluster with empty brokerLogs property
  // ruleid: typescript-cdk-msk-broker-logging
  new msk.CfnCluster(scope, 'MskClusterEmptyLogs', {
    clusterName: 'kafka-cluster-empty-logs',
    kafkaVersion: '2.8.1',
    numberOfBrokerNodes: 3,
    brokerNodeGroupInfo: {
      instanceType: 'kafka.m5.large',
      clientSubnets: ['subnet-1', 'subnet-2', 'subnet-3'],
      securityGroups: ['sg-12345'],
      storageInfo: {
        ebsStorageInfo: {
          volumeSize: 100
        }
      }
    },
    loggingInfo: {
      brokerLogs: {}
    }
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_3(scope: Construct) {
  // MSK cluster with CloudWatch logs but disabled
  // ruleid: typescript-cdk-msk-broker-logging
  new msk.CfnCluster(scope, 'MskClusterDisabledCloudWatchLogs', {
    clusterName: 'kafka-cluster-disabled-cloudwatch',
    kafkaVersion: '2.8.1',
    numberOfBrokerNodes: 3,
    brokerNodeGroupInfo: {
      instanceType: 'kafka.m5.large',
      clientSubnets: ['subnet-1', 'subnet-2', 'subnet-3'],
      securityGroups: ['sg-12345'],
      storageInfo: {
        ebsStorageInfo: {
          volumeSize: 100
        }
      }
    },
    loggingInfo: {
      brokerLogs: {
        cloudWatchLogs: {
          enabled: false,
          logGroup: 'kafka-logs'
        }
      }
    }
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_4(scope: Construct) {
  // MSK cluster with S3 logs but disabled
  // ruleid: typescript-cdk-msk-broker-logging
  new msk.CfnCluster(scope, 'MskClusterDisabledS3Logs', {
    clusterName: 'kafka-cluster-disabled-s3',
    kafkaVersion: '2.8.1',
    numberOfBrokerNodes: 3,
    brokerNodeGroupInfo: {
      instanceType: 'kafka.m5.large',
      clientSubnets: ['subnet-1', 'subnet-2', 'subnet-3'],
      securityGroups: ['sg-12345'],
      storageInfo: {
        ebsStorageInfo: {
          volumeSize: 100
        }
      }
    },
    loggingInfo: {
      brokerLogs: {
        s3: {
          enabled: false,
          bucket: 'my-kafka-logs-bucket',
          prefix: 'logs/'
        }
      }
    }
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_5(scope: Construct) {
  // MSK cluster with Firehose logs but disabled
  // ruleid: typescript-cdk-msk-broker-logging
  new msk.CfnCluster(scope, 'MskClusterDisabledFirehoseLogs', {
    clusterName: 'kafka-cluster-disabled-firehose',
    kafkaVersion: '2.8.1',
    numberOfBrokerNodes: 3,
    brokerNodeGroupInfo: {
      instanceType: 'kafka.m5.large',
      clientSubnets: ['subnet-1', 'subnet-2', 'subnet-3'],
      securityGroups: ['sg-12345'],
      storageInfo: {
        ebsStorageInfo: {
          volumeSize: 100
        }
      }
    },
    loggingInfo: {
      brokerLogs: {
        firehose: {
          enabled: false,
          deliveryStream: 'kafka-logs-stream'
        }
      }
    }
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_6(scope: Construct) {
  // MSK cluster with all log types but all disabled
  // ruleid: typescript-cdk-msk-broker-logging
  new msk.CfnCluster(scope, 'MskClusterAllLogsDisabled', {
    clusterName: 'kafka-cluster-all-logs-disabled',
    kafkaVersion: '2.8.1',
    numberOfBrokerNodes: 3,
    brokerNodeGroupInfo: {
      instanceType: 'kafka.m5.large',
      clientSubnets: ['subnet-1', 'subnet-2', 'subnet-3'],
      securityGroups: ['sg-12345'],
      storageInfo: {
        ebsStorageInfo: {
          volumeSize: 100
        }
      }
    },
    loggingInfo: {
      brokerLogs: {
        cloudWatchLogs: {
          enabled: false,
          logGroup: 'kafka-logs'
        },
        s3: {
          enabled: false,
          bucket: 'my-kafka-logs-bucket',
          prefix: 'logs/'
        },
        firehose: {
          enabled: false,
          deliveryStream: 'kafka-logs-stream'
        }
      }
    }
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_7(scope: Construct) {
  // MSK cluster using L2 construct without logging
  const cluster = new msk.Cluster(scope, 'MskClusterL2NoLogging', {
    clusterName: 'kafka-cluster-l2-no-logging',
    kafkaVersion: msk.KafkaVersion.V2_8_1,
    vpc: {
      vpcId: 'vpc-12345',
      availabilityZones: ['us-east-1a', 'us-east-1b', 'us-east-1c'],
      privateSubnetIds: ['subnet-1', 'subnet-2', 'subnet-3']
    },
    instanceType: 'kafka.m5.large',
    encryptionInTransit: {
      clientBroker: msk.ClientBrokerEncryption.TLS
    }
  });
  
  // ruleid: typescript-cdk-msk-broker-logging
  const cfnCluster = cluster.node.defaultChild as msk.CfnCluster;
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_8(scope: Construct) {
  // MSK cluster with variable configuration but no logging
  const clusterName = 'kafka-cluster-variable-config';
  const kafkaVersion = '2.8.1';
  const nodeCount = 3;
  const instanceType = 'kafka.m5.large';
  
  // ruleid: typescript-cdk-msk-broker-logging
  new msk.CfnCluster(scope, 'MskClusterVariableConfig', {
    clusterName: clusterName,
    kafkaVersion: kafkaVersion,
    numberOfBrokerNodes: nodeCount,
    brokerNodeGroupInfo: {
      instanceType: instanceType,
      clientSubnets: ['subnet-1', 'subnet-2', 'subnet-3'],
      securityGroups: ['sg-12345'],
      storageInfo: {
        ebsStorageInfo: {
          volumeSize: 100
        }
      }
    }
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_9(scope: Construct) {
  // MSK cluster with logging info but no broker logs
  // ruleid: typescript-cdk-msk-broker-logging
  new msk.CfnCluster(scope, 'MskClusterNoSpecificLogs', {
    clusterName: 'kafka-cluster-no-specific-logs',
    kafkaVersion: '2.8.1',
    numberOfBrokerNodes: 3,
    brokerNodeGroupInfo: {
      instanceType: 'kafka.m5.large',
      clientSubnets: ['subnet-1', 'subnet-2', 'subnet-3'],
      securityGroups: ['sg-12345'],
      storageInfo: {
        ebsStorageInfo: {
          volumeSize: 100
        }
      }
    },
    loggingInfo: {} // Empty logging info
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_10(scope: Construct) {
  // MSK cluster with CloudWatch logs but missing enabled property
  // ruleid: typescript-cdk-msk-broker-logging
  new msk.CfnCluster(scope, 'MskClusterMissingEnabledProperty', {
    clusterName: 'kafka-cluster-missing-enabled',
    kafkaVersion: '2.8.1',
    numberOfBrokerNodes: 3,
    brokerNodeGroupInfo: {
      instanceType: 'kafka.m5.large',
      clientSubnets: ['subnet-1', 'subnet-2', 'subnet-3'],
      securityGroups: ['sg-12345'],
      storageInfo: {
        ebsStorageInfo: {
          volumeSize: 100
        }
      }
    },
    loggingInfo: {
      brokerLogs: {
        cloudWatchLogs: {
          logGroup: 'kafka-logs'
        }
      }
    }
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_11(scope: Construct) {
  // MSK cluster with props object but no logging
  const props = {
    clusterName: 'kafka-cluster-props-object',
    kafkaVersion: '2.8.1',
    numberOfBrokerNodes: 3,
    brokerNodeGroupInfo: {
      instanceType: 'kafka.m5.large',
      clientSubnets: ['subnet-1', 'subnet-2', 'subnet-3'],
      securityGroups: ['sg-12345'],
      storageInfo: {
        ebsStorageInfo: {
          volumeSize: 100
        }
      }
    }
  };
  
  // ruleid: typescript-cdk-msk-broker-logging
  new msk.CfnCluster(scope, 'MskClusterPropsObject', props);
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_12(scope: Construct) {
  // MSK cluster with CloudWatch logs enabled but S3 and Firehose disabled
  // ruleid: typescript-cdk-msk-broker-logging
  new msk.CfnCluster(scope, 'MskClusterMixedLoggingStates', {
    clusterName: 'kafka-cluster-mixed-logging',
    kafkaVersion: '2.8.1',
    numberOfBrokerNodes: 3,
    brokerNodeGroupInfo: {
      instanceType: 'kafka.m5.large',
      clientSubnets: ['subnet-1', 'subnet-2', 'subnet-3'],
      securityGroups: ['sg-12345'],
      storageInfo: {
        ebsStorageInfo: {
          volumeSize: 100
        }
      }
    },
    loggingInfo: {
      brokerLogs: {
        cloudWatchLogs: {
          enabled: false,
          logGroup: 'kafka-logs'
        },
        s3: {
          enabled: false,
          bucket: 'my-kafka-logs-bucket'
        },
        firehose: {
          enabled: false,
          deliveryStream: 'kafka-logs-stream'
        }
      }
    }
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_13(scope: Construct) {
  // MSK cluster with dynamic configuration but no logging
  const getClusterConfig = () => {
    return {
      clusterName: 'kafka-cluster-dynamic-config',
      kafkaVersion: '2.8.1',
      numberOfBrokerNodes: 3,
      brokerNodeGroupInfo: {
        instanceType: 'kafka.m5.large',
        clientSubnets: ['subnet-1', 'subnet-2', 'subnet-3'],
        securityGroups: ['sg-12345'],
        storageInfo: {
          ebsStorageInfo: {
            volumeSize: 100
          }
        }
      }
    };
  };
  
  // ruleid: typescript-cdk-msk-broker-logging
  new msk.CfnCluster(scope, 'MskClusterDynamicConfig', getClusterConfig());
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_14(scope: Construct) {
  // MSK cluster with conditional configuration but no logging in either case
  const isProd = process.env.ENV === 'production';
  const clusterConfig = isProd ? 
    {
      clusterName: 'kafka-cluster-prod',
      kafkaVersion: '2.8.1',
      numberOfBrokerNodes: 6,
      brokerNodeGroupInfo: {
        instanceType: 'kafka.m5.2xlarge',
        clientSubnets: ['subnet-1', 'subnet-2', 'subnet-3'],
        securityGroups: ['sg-12345'],
        storageInfo: {
          ebsStorageInfo: {
            volumeSize: 500
          }
        }
      }
    } : 
    {
      clusterName: 'kafka-cluster-dev',
      kafkaVersion: '2.8.1',
      numberOfBrokerNodes: 3,
      brokerNodeGroupInfo: {
        instanceType: 'kafka.t3.small',
        clientSubnets: ['subnet-1', 'subnet-2', 'subnet-3'],
        securityGroups: ['sg-12345'],
        storageInfo: {
          ebsStorageInfo: {
            volumeSize: 100
          }
        }
      }
    };
  
  // ruleid: typescript-cdk-msk-broker-logging
  new msk.CfnCluster(scope, 'MskClusterConditionalConfig', clusterConfig);
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_15(scope: Construct) {
  // MSK cluster with logging info defined separately but all disabled
  const loggingInfo = {
    brokerLogs: {
      cloudWatchLogs: {
        enabled: false,
        logGroup: 'kafka-logs'
      },
      s3: {
        enabled: false,
        bucket: 'my-kafka-logs-bucket'
      },
      firehose: {
        enabled: false,
        deliveryStream: 'kafka-logs-stream'
      }
    }
  };
  
  // ruleid: typescript-cdk-msk-broker-logging
  new msk.CfnCluster(scope, 'MskClusterSeparateLoggingConfig', {
    clusterName: 'kafka-cluster-separate-logging',
    kafkaVersion: '2.8.1',
    numberOfBrokerNodes: 3,
    brokerNodeGroupInfo: {
      instanceType: 'kafka.m5.large',
      clientSubnets: ['subnet-1', 'subnet-2', 'subnet-3'],
      securityGroups: ['sg-12345'],
      storageInfo: {
        ebsStorageInfo: {
          volumeSize: 100
        }
      }
    },
    loggingInfo: loggingInfo
  });
}
// {/fact}

// True Negative Cases (Secure Code)

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_1(scope: Construct) {
  // MSK cluster with CloudWatch logs enabled
  // ok: typescript-cdk-msk-broker-logging
  new msk.CfnCluster(scope, 'MskClusterCloudWatchLogsEnabled', {
    clusterName: 'kafka-cluster-cloudwatch-enabled',
    kafkaVersion: '2.8.1',
    numberOfBrokerNodes: 3,
    brokerNodeGroupInfo: {
      instanceType: 'kafka.m5.large',
      clientSubnets: ['subnet-1', 'subnet-2', 'subnet-3'],
      securityGroups: ['sg-12345'],
      storageInfo: {
        ebsStorageInfo: {
          volumeSize: 100
        }
      }
    },
    loggingInfo: {
      brokerLogs: {
        cloudWatchLogs: {
          enabled: true,
          logGroup: 'kafka-logs'
        }
      }
    }
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_2(scope: Construct) {
  // MSK cluster with S3 logs enabled
  // ok: typescript-cdk-msk-broker-logging
  new msk.CfnCluster(scope, 'MskClusterS3LogsEnabled', {
    clusterName: 'kafka-cluster-s3-enabled',
    kafkaVersion: '2.8.1',
    numberOfBrokerNodes: 3,
    brokerNodeGroupInfo: {
      instanceType: 'kafka.m5.large',
      clientSubnets: ['subnet-1', 'subnet-2', 'subnet-3'],
      securityGroups: ['sg-12345'],
      storageInfo: {
        ebsStorageInfo: {
          volumeSize: 100
        }
      }
    },
    loggingInfo: {
      brokerLogs: {
        s3: {
          enabled: true,
          bucket: 'my-kafka-logs-bucket',
          prefix: 'logs/'
        }
      }
    }
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_3(scope: Construct) {
  // MSK cluster with Firehose logs enabled
  // ok: typescript-cdk-msk-broker-logging
  new msk.CfnCluster(scope, 'MskClusterFirehoseLogsEnabled', {
    clusterName: 'kafka-cluster-firehose-enabled',
    kafkaVersion: '2.8.1',
    numberOfBrokerNodes: 3,
    brokerNodeGroupInfo: {
      instanceType: 'kafka.m5.large',
      clientSubnets: ['subnet-1', 'subnet-2', 'subnet-3'],
      securityGroups: ['sg-12345'],
      storageInfo: {
        ebsStorageInfo: {
          volumeSize: 100
        }
      }
    },
    loggingInfo: {
      brokerLogs: {
        firehose: {
          enabled: true,
          deliveryStream: 'kafka-logs-stream'
        }
      }
    }
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_4(scope: Construct) {
  // MSK cluster with all log types enabled
  // ok: typescript-cdk-msk-broker-logging
  new msk.CfnCluster(scope, 'MskClusterAllLogsEnabled', {
    clusterName: 'kafka-cluster-all-logs-enabled',
    kafkaVersion: '2.8.1',
    numberOfBrokerNodes: 3,
    brokerNodeGroupInfo: {
      instanceType: 'kafka.m5.large',
      clientSubnets: ['subnet-1', 'subnet-2', 'subnet-3'],
      securityGroups: ['sg-12345'],
      storageInfo: {
        ebsStorageInfo: {
          volumeSize: 100
        }
      }
    },
    loggingInfo: {
      brokerLogs: {
        cloudWatchLogs: {
          enabled: true,
          logGroup: 'kafka-logs'
        },
        s3: {
          enabled: true,
          bucket: 'my-kafka-logs-bucket',
          prefix: 'logs/'
        },
        firehose: {
          enabled: true,
          deliveryStream: 'kafka-logs-stream'
        }
      }
    }
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_5(scope: Construct) {
  // MSK cluster with some log types enabled and some disabled
  // ok: typescript-cdk-msk-broker-logging
  new msk.CfnCluster(scope, 'MskClusterMixedLogsEnabled', {
    clusterName: 'kafka-cluster-mixed-logs',
    kafkaVersion: '2.8.1',
    numberOfBrokerNodes: 3,
    brokerNodeGroupInfo: {
      instanceType: 'kafka.m5.large',
      clientSubnets: ['subnet-1', 'subnet-2', 'subnet-3'],
      securityGroups: ['sg-12345'],
      storageInfo: {
        ebsStorageInfo: {
          volumeSize: 100
        }
      }
    },
    loggingInfo: {
      brokerLogs: {
        cloudWatchLogs: {
          enabled: true,
          logGroup: 'kafka-logs'
        },
        s3: {
          enabled: false,
          bucket: 'my-kafka-logs-bucket'
        },
        firehose: {
          enabled: false,
          deliveryStream: 'kafka-logs-stream'
        }
      }
    }
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_6(scope: Construct) {
  // MSK cluster using L2 construct with logging enabled
  const logGroup = new logs.LogGroup(scope, 'KafkaLogs');
  const bucket = new s3.Bucket(scope, 'KafkaLogsBucket');
  
  const cluster = new msk.Cluster(scope, 'MskClusterL2WithLogging', {
    clusterName: 'kafka-cluster-l2-with-logging',
    kafkaVersion: msk.KafkaVersion.V2_8_1,
    vpc: {
      vpcId: 'vpc-12345',
      availabilityZones: ['us-east-1a', 'us-east-1b', 'us-east-1c'],
      privateSubnetIds: ['subnet-1', 'subnet-2', 'subnet-3']
    },
    instanceType: 'kafka.m5.large',
    encryptionInTransit: {
      clientBroker: msk.ClientBrokerEncryption.TLS
    },
    logging: {
      cloudwatchLogGroup: logGroup,
      s3: {
        bucket: bucket,
        prefix: 'logs/'
      }
    }
  });
  
  // ok: typescript-cdk-msk-broker-logging
  const cfnCluster = cluster.node.defaultChild as msk.CfnCluster;
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_7(scope: Construct) {
  // MSK cluster with variable configuration and logging enabled
  const clusterName = 'kafka-cluster-variable-config-with-logging';
  const kafkaVersion = '2.8.1';
  const nodeCount = 3;
  const instanceType = 'kafka.m5.large';
  const logGroup = 'kafka-logs';
  
  // ok: typescript-cdk-msk-broker-logging
  new msk.CfnCluster(scope, 'MskClusterVariableConfigWithLogging', {
    clusterName: clusterName,
    kafkaVersion: kafkaVersion,
    numberOfBrokerNodes: nodeCount,
    brokerNodeGroupInfo: {
      instanceType: instanceType,
      clientSubnets: ['subnet-1', 'subnet-2', 'subnet-3'],
      securityGroups: ['sg-12345'],
      storageInfo: {
        ebsStorageInfo: {
          volumeSize: 100
        }
      }
    },
    loggingInfo: {
      brokerLogs: {
        cloudWatchLogs: {
          enabled: true,
          logGroup: logGroup
        }
      }
    }
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_8(scope: Construct) {
  // MSK cluster with props object and logging enabled
  const props = {
    clusterName: 'kafka-cluster-props-object-with-logging',
    kafkaVersion: '2.8.1',
    numberOfBrokerNodes: 3,
    brokerNodeGroupInfo: {
      instanceType: 'kafka.m5.large',
      clientSubnets: ['subnet-1', 'subnet-2', 'subnet-3'],
      securityGroups: ['sg-12345'],
      storageInfo: {
        ebsStorageInfo: {
          volumeSize: 100
        }
      }
    },
    loggingInfo: {
      brokerLogs: {
        s3: {
          enabled: true,
          bucket: 'my-kafka-logs-bucket',
          prefix: 'logs/'
        }
      }
    }
  };
  
  // ok: typescript-cdk-msk-broker-logging
  new msk.CfnCluster(scope, 'MskClusterPropsObjectWithLogging', props);
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_9(scope: Construct) {
  // MSK cluster with dynamic configuration and logging enabled
  const getClusterConfig = () => {
    return {
      clusterName: 'kafka-cluster-dynamic-config-with-logging',
      kafkaVersion: '2.8.1',
      numberOfBrokerNodes: 3,
      brokerNodeGroupInfo: {
        instanceType: 'kafka.m5.large',
        clientSubnets: ['subnet-1', 'subnet-2', 'subnet-3'],
        securityGroups: ['sg-12345'],
        storageInfo: {
          ebsStorageInfo: {
            volumeSize: 100
          }
        }
      },
      loggingInfo: {
        brokerLogs: {
          cloudWatchLogs: {
            enabled: true,
            logGroup: 'kafka-logs'
          }
        }
      }
    };
  };
  
  // ok: typescript-cdk-msk-broker-logging
  new msk.CfnCluster(scope, 'MskClusterDynamicConfigWithLogging', getClusterConfig());
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_10(scope: Construct) {
  // MSK cluster with conditional configuration and logging enabled in both cases
  const isProd = process.env.ENV === 'production';
  const clusterConfig = isProd ? 
    {
      clusterName: 'kafka-cluster-prod-with-logging',
      kafkaVersion: '2.8.1',
      numberOfBrokerNodes: 6,
      brokerNodeGroupInfo: {
        instanceType: 'kafka.m5.2xlarge',
        clientSubnets: ['subnet-1', 'subnet-2', 'subnet-3'],
        securityGroups: ['sg-12345'],
        storageInfo: {
          ebsStorageInfo: {
            volumeSize: 500
          }
        }
      },
      loggingInfo: {
        brokerLogs: {
          cloudWatchLogs: {
            enabled: true,
            logGroup: 'kafka-logs-prod'
          },
          s3: {
            enabled: true,
            bucket: 'my-kafka-logs-bucket-prod',
            prefix: 'logs/'
          }
        }
      }
    } : 
    {
      clusterName: 'kafka-cluster-dev-with-logging',
      kafkaVersion: '2.8.1',
      numberOfBrokerNodes: 3,
      brokerNodeGroupInfo: {
        instanceType: 'kafka.t3.small',
        clientSubnets: ['subnet-1', 'subnet-2', 'subnet-3'],
        securityGroups: ['sg-12345'],
        storageInfo: {
          ebsStorageInfo: {
            volumeSize: 100
          }
        }
      },
      loggingInfo: {
        brokerLogs: {
          cloudWatchLogs: {
            enabled: true,
            logGroup: 'kafka-logs-dev'
          }
        }
      }
    };
  
  // ok: typescript-cdk-msk-broker-logging
  new msk.CfnCluster(scope, 'MskClusterConditionalConfigWithLogging', clusterConfig);
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_11(scope: Construct) {
  // MSK cluster with logging info defined separately and enabled
  const loggingInfo = {
    brokerLogs: {
      cloudWatchLogs: {
        enabled: true,
        logGroup: 'kafka-logs'
      }
    }
  };
  
  // ok: typescript-cdk-msk-broker-logging
  new msk.CfnCluster(scope, 'MskClusterSeparateLoggingConfigEnabled', {
    clusterName: 'kafka-cluster-separate-logging-enabled',
    kafkaVersion: '2.8.1',
    numberOfBrokerNodes: 3,
    brokerNodeGroupInfo: {
      instanceType: 'kafka.m5.large',
      clientSubnets: ['subnet-1', 'subnet-2', 'subnet-3'],
      securityGroups: ['sg-12345'],
      storageInfo: {
        ebsStorageInfo: {
          volumeSize: 100
        }
      }
    },
    loggingInfo: loggingInfo
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_12(scope: Construct) {
  // MSK cluster with CloudWatch logs enabled using a reference
  const logEnabled = true;
  const logGroup = 'kafka-logs-reference';
  
  // ok: typescript-cdk-msk-broker-logging
  new msk.CfnCluster(scope, 'MskClusterLogEnabledReference', {
    clusterName: 'kafka-cluster-log-enabled-reference',
    kafkaVersion: '2.8.1',
    numberOfBrokerNodes: 3,
    brokerNodeGroupInfo: {
      instanceType: 'kafka.m5.large',
      clientSubnets: ['subnet-1', 'subnet-2', 'subnet-3'],
      securityGroups: ['sg-12345'],
      storageInfo: {
        ebsStorageInfo: {
          volumeSize: 100
        }
      }
    },
    loggingInfo: {
      brokerLogs: {
        cloudWatchLogs: {
          enabled: logEnabled,
          logGroup: logGroup
        }
      }
    }
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_13(scope: Construct) {
  // MSK cluster with multiple log destinations and at least one enabled
  // ok: typescript-cdk-msk-broker-logging
  new msk.CfnCluster(scope, 'MskClusterMultipleDestinations', {
    clusterName: 'kafka-cluster-multiple-destinations',
    kafkaVersion: '2.8.1',
    numberOfBrokerNodes: 3,
    brokerNodeGroupInfo: {
      instanceType: 'kafka.m5.large',
      clientSubnets: ['subnet-1', 'subnet-2', 'subnet-3'],
      securityGroups: ['sg-12345'],
      storageInfo: {
        ebsStorageInfo: {
          volumeSize: 100
        }
      }
    },
    loggingInfo: {
      brokerLogs: {
        cloudWatchLogs: {
          enabled: false,
          logGroup: 'kafka-logs'
        },
        s3: {
          enabled: true,
          bucket: 'my-kafka-logs-bucket',
          prefix: 'logs/'
        },
        firehose: {
          enabled: false,
          deliveryStream: 'kafka-logs-stream'
        }
      }
    }
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_14(scope: Construct) {
  // MSK cluster with logging configuration built up programmatically
  const enableCloudWatchLogs = true;
  const enableS3Logs = false;
  const enableFirehoseLogs = false;
  
  const brokerLogs: any = {};
  
  if (enableCloudWatchLogs) {
    brokerLogs.cloudWatchLogs = {
      enabled: true,
      logGroup: 'kafka-logs'
    };
  }
  
  if (enableS3Logs) {
    brokerLogs.s3 = {
      enabled: true,
      bucket: 'my-kafka-logs-bucket',
      prefix: 'logs/'
    };
  }
  
  if (enableFirehoseLogs) {
    brokerLogs.firehose = {
      enabled: true,
      deliveryStream: 'kafka-logs-stream'
    };
  }
  
  // ok: typescript-cdk-msk-broker-logging
  new msk.CfnCluster(scope, 'MskClusterProgrammaticLogging', {
    clusterName: 'kafka-cluster-programmatic-logging',
    kafkaVersion: '2.8.1',
    numberOfBrokerNodes: 3,
    brokerNodeGroupInfo: {
      instanceType: 'kafka.m5.large',
      clientSubnets: ['subnet-1', 'subnet-2', 'subnet-3'],
      securityGroups: ['sg-12345'],
      storageInfo: {
        ebsStorageInfo: {
          volumeSize: 100
        }
      }
    },
    loggingInfo: {
      brokerLogs: brokerLogs
    }
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_15(scope: Construct) {
  // MSK cluster with logging configuration from environment variables
  const logEnabled = process.env.ENABLE_KAFKA_LOGS === 'true';
  const logGroup = process.env.KAFKA_LOG_GROUP || 'default-kafka-logs';
  
  // ok: typescript-cdk-msk-broker-logging
  new msk.CfnCluster(scope, 'MskClusterEnvVarLogging', {
    clusterName: 'kafka-cluster-env-var-logging',
    kafkaVersion: '2.8.1',
    numberOfBrokerNodes: 3,
    brokerNodeGroupInfo: {
      instanceType: 'kafka.m5.large',
      clientSubnets: ['subnet-1', 'subnet-2', 'subnet-3'],
      securityGroups: ['sg-12345'],
      storageInfo: {
        ebsStorageInfo: {
          volumeSize: 100
        }
      }
    },
    loggingInfo: {
      brokerLogs: {
        cloudWatchLogs: {
          enabled: true, // Always enable logs regardless of environment variable
          logGroup: logGroup
        }
      }
    }
  });
}
// {/fact}

// Main stack
class MskLoggingStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);
    
    // Examples of both vulnerable and secure MSK clusters
    bad_case_1(this);
    good_case_1(this);
  }
}

const app = new App();
new MskLoggingStack(app, 'MskLoggingStack');