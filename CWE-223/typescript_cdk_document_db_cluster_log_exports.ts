import { Stack, App } from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as docdb from 'aws-cdk-lib/aws-docdb';
import * as ec2 from 'aws-cdk-lib/aws-ec2';

// True Positive Examples (Vulnerable Code)

// {fact rule=security-information-omission@v1.0 defects=1}
function bad_case_1() {
  const app = new App();
  const stack = new Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ruleid: typescript_cdk_document_db_cluster_log_exports
  new docdb.DatabaseCluster(stack, 'DocDBCluster1', {
    masterUser: {
      username: 'admin',
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    vpc,
    vpcSubnets: {
      subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
    },
    // Missing log exports configuration
  });
}
// {/fact}

// {fact rule=security-information-omission@v1.0 defects=1}
function bad_case_2() {
  const app = new App();
  const stack = new Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ruleid: typescript_cdk_document_db_cluster_log_exports
  new docdb.DatabaseCluster(stack, 'DocDBCluster2', {
    masterUser: {
      username: 'admin',
      secretName: '/docdb/admin',
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    vpc,
    // Missing log exports configuration
    removalPolicy: RemovalPolicy.DESTROY,
  });
}
// {/fact}

// {fact rule=security-information-omission@v1.0 defects=1}
function bad_case_3() {
  const app = new App();
  const stack = new Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ruleid: typescript_cdk_document_db_cluster_log_exports
  new docdb.DatabaseCluster(stack, 'DocDBCluster3', {
    masterUser: {
      username: 'admin',
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    vpc,
    // Incomplete log exports - missing required types
    cloudwatchLogsExports: ['profiler'],
  });
}
// {/fact}

// {fact rule=security-information-omission@v1.0 defects=1}
function bad_case_4() {
  const app = new App();
  const stack = new Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ruleid: typescript_cdk_document_db_cluster_log_exports
  new docdb.DatabaseCluster(stack, 'DocDBCluster4', {
    masterUser: {
      username: 'admin',
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    vpc,
    // Missing 'authenticate' log export
    cloudwatchLogsExports: ['createIndex', 'dropCollection'],
  });
}
// {/fact}

// {fact rule=security-information-omission@v1.0 defects=1}
function bad_case_5() {
  const app = new App();
  const stack = new Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ruleid: typescript_cdk_document_db_cluster_log_exports
  new docdb.DatabaseCluster(stack, 'DocDBCluster5', {
    masterUser: {
      username: 'admin',
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    vpc,
    // Missing 'createIndex' log export
    cloudwatchLogsExports: ['authenticate', 'dropCollection'],
  });
}
// {/fact}

// {fact rule=security-information-omission@v1.0 defects=1}
function bad_case_6() {
  const app = new App();
  const stack = new Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ruleid: typescript_cdk_document_db_cluster_log_exports
  new docdb.DatabaseCluster(stack, 'DocDBCluster6', {
    masterUser: {
      username: 'admin',
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    vpc,
    // Missing 'dropCollection' log export
    cloudwatchLogsExports: ['authenticate', 'createIndex'],
  });
}
// {/fact}

// {fact rule=security-information-omission@v1.0 defects=1}
function bad_case_7() {
  const app = new App();
  const stack = new Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ruleid: typescript_cdk_document_db_cluster_log_exports
  const cluster = new docdb.DatabaseCluster(stack, 'DocDBCluster7', {
    masterUser: {
      username: 'admin',
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    vpc,
    // Empty log exports array
    cloudwatchLogsExports: [],
  });
}
// {/fact}

// {fact rule=security-information-omission@v1.0 defects=1}
function bad_case_8() {
  const app = new App();
  const stack = new Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ruleid: typescript_cdk_document_db_cluster_log_exports
  const cluster = new docdb.DatabaseCluster(stack, 'DocDBCluster8', {
    masterUser: {
      username: 'admin',
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    vpc,
    // Only one of the required log exports
    cloudwatchLogsExports: ['authenticate'],
  });
}
// {/fact}

// {fact rule=security-information-omission@v1.0 defects=1}
function bad_case_9() {
  const app = new App();
  const stack = new Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const params = {
    masterUser: {
      username: 'admin',
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    vpc,
    // No log exports in the parameters
  };
  
  // ruleid: typescript_cdk_document_db_cluster_log_exports
  new docdb.DatabaseCluster(stack, 'DocDBCluster9', params);
}
// {/fact}

// {fact rule=security-information-omission@v1.0 defects=1}
function bad_case_10() {
  const app = new App();
  const stack = new Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ruleid: typescript_cdk_document_db_cluster_log_exports
  const cluster = new docdb.DatabaseCluster(stack, 'DocDBCluster10', {
    masterUser: {
      username: 'admin',
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    vpc,
    // Different log exports, but missing the required ones
    cloudwatchLogsExports: ['audit', 'profiler'],
  });
}
// {/fact}

// {fact rule=security-information-omission@v1.0 defects=1}
function bad_case_11() {
  class DocDBStack extends Stack {
    constructor(scope: Construct, id: string, props?: StackProps) {
      super(scope, id, props);
      
      const vpc = new ec2.Vpc(this, 'VPC');
      
      // ruleid: typescript_cdk_document_db_cluster_log_exports
      new docdb.DatabaseCluster(this, 'DocDBCluster11', {
        masterUser: {
          username: 'admin',
        },
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
        vpc,
        // No log exports configuration in a class-based stack
      });
    }
  }
  
  const app = new App();
  new DocDBStack(app, 'DocDBStack11');
}
// {/fact}

// {fact rule=security-information-omission@v1.0 defects=1}
function bad_case_12() {
  const app = new App();
  const stack = new Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const logExports = ['profiler']; // Incomplete log exports
  
  // ruleid: typescript_cdk_document_db_cluster_log_exports
  new docdb.DatabaseCluster(stack, 'DocDBCluster12', {
    masterUser: {
      username: 'admin',
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    vpc,
    cloudwatchLogsExports: logExports,
  });
}
// {/fact}

// {fact rule=security-information-omission@v1.0 defects=1}
function bad_case_13() {
  const app = new App();
  const stack = new Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  function getLogExports() {
    // Returns incomplete log exports
    return ['authenticate', 'createIndex']; // Missing 'dropCollection'
  }
  
  // ruleid: typescript_cdk_document_db_cluster_log_exports
  new docdb.DatabaseCluster(stack, 'DocDBCluster13', {
    masterUser: {
      username: 'admin',
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    vpc,
    cloudwatchLogsExports: getLogExports(),
  });
}
// {/fact}

// {fact rule=security-information-omission@v1.0 defects=1}
function bad_case_14() {
  const app = new App();
  const stack = new Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ruleid: typescript_cdk_document_db_cluster_log_exports
  const cluster = new docdb.DatabaseCluster(stack, 'DocDBCluster14', {
    masterUser: {
      username: 'admin',
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    vpc,
    // Misspelled log export types
    cloudwatchLogsExports: ['authentcate', 'createIndx', 'dropColection'],
  });
}
// {/fact}

// {fact rule=security-information-omission@v1.0 defects=1}
function bad_case_15() {
  const app = new App();
  const stack = new Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const clusterProps = {
    masterUser: {
      username: 'admin',
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    vpc,
  };
  
  // ruleid: typescript_cdk_document_db_cluster_log_exports
  const cluster = new docdb.DatabaseCluster(stack, 'DocDBCluster15', {
    ...clusterProps,
    // No log exports added when spreading props
  });
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=security-information-omission@v1.0 defects=0}
function good_case_1() {
  const app = new App();
  const stack = new Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ok: typescript_cdk_document_db_cluster_log_exports
  new docdb.DatabaseCluster(stack, 'DocDBCluster1', {
    masterUser: {
      username: 'admin',
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    vpc,
    vpcSubnets: {
      subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
    },
    cloudwatchLogsExports: ['authenticate', 'createIndex', 'dropCollection'],
  });
}
// {/fact}

// {fact rule=security-information-omission@v1.0 defects=0}
function good_case_2() {
  const app = new App();
  const stack = new Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ok: typescript_cdk_document_db_cluster_log_exports
  new docdb.DatabaseCluster(stack, 'DocDBCluster2', {
    masterUser: {
      username: 'admin',
      secretName: '/docdb/admin',
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    vpc,
    cloudwatchLogsExports: ['authenticate', 'createIndex', 'dropCollection', 'profiler'],
  });
}
// {/fact}

// {fact rule=security-information-omission@v1.0 defects=0}
function good_case_3() {
  const app = new App();
  const stack = new Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const requiredLogExports = ['authenticate', 'createIndex', 'dropCollection'];
  
  // ok: typescript_cdk_document_db_cluster_log_exports
  new docdb.DatabaseCluster(stack, 'DocDBCluster3', {
    masterUser: {
      username: 'admin',
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    vpc,
    cloudwatchLogsExports: requiredLogExports,
  });
}
// {/fact}

// {fact rule=security-information-omission@v1.0 defects=0}
function good_case_4() {
  const app = new App();
  const stack = new Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  function getLogExports() {
    return ['authenticate', 'createIndex', 'dropCollection', 'profiler', 'audit'];
  }
  
  // ok: typescript_cdk_document_db_cluster_log_exports
  new docdb.DatabaseCluster(stack, 'DocDBCluster4', {
    masterUser: {
      username: 'admin',
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    vpc,
    cloudwatchLogsExports: getLogExports(),
  });
}
// {/fact}

// {fact rule=security-information-omission@v1.0 defects=0}
function good_case_5() {
  class DocDBStack extends Stack {
    constructor(scope: Construct, id: string, props?: StackProps) {
      super(scope, id, props);
      
      const vpc = new ec2.Vpc(this, 'VPC');
      
      // ok: typescript_cdk_document_db_cluster_log_exports
      new docdb.DatabaseCluster(this, 'DocDBCluster5', {
        masterUser: {
          username: 'admin',
        },
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
        vpc,
        cloudwatchLogsExports: ['authenticate', 'createIndex', 'dropCollection'],
      });
    }
  }
  
  const app = new App();
  new DocDBStack(app, 'DocDBStack5');
}
// {/fact}

// {fact rule=security-information-omission@v1.0 defects=0}
function good_case_6() {
  const app = new App();
  const stack = new Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const clusterProps = {
    masterUser: {
      username: 'admin',
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    vpc,
  };
  
  // ok: typescript_cdk_document_db_cluster_log_exports
  const cluster = new docdb.DatabaseCluster(stack, 'DocDBCluster6', {
    ...clusterProps,
    cloudwatchLogsExports: ['authenticate', 'createIndex', 'dropCollection'],
  });
}
// {/fact}

// {fact rule=security-information-omission@v1.0 defects=0}
function good_case_7() {
  const app = new App();
  const stack = new Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const requiredLogExports = ['authenticate', 'createIndex', 'dropCollection'];
  const additionalLogExports = ['profiler', 'audit'];
  const allLogExports = [...requiredLogExports, ...additionalLogExports];
  
  // ok: typescript_cdk_document_db_cluster_log_exports
  new docdb.DatabaseCluster(stack, 'DocDBCluster7', {
    masterUser: {
      username: 'admin',
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    vpc,
    cloudwatchLogsExports: allLogExports,
  });
}
// {/fact}

// {fact rule=security-information-omission@v1.0 defects=0}
function good_case_8() {
  const app = new App();
  const stack = new Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ok: typescript_cdk_document_db_cluster_log_exports
  const cluster = new docdb.DatabaseCluster(stack, 'DocDBCluster8', {
    masterUser: {
      username: 'admin',
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    vpc,
    cloudwatchLogsExports: ['authenticate', 'createIndex', 'dropCollection'],
    storageEncrypted: true, // Additional security measure
  });
}
// {/fact}

// {fact rule=security-information-omission@v1.0 defects=0}
function good_case_9() {
  const app = new App();
  const stack = new Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const params = {
    masterUser: {
      username: 'admin',
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    vpc,
    cloudwatchLogsExports: ['authenticate', 'createIndex', 'dropCollection'],
  };
  
  // ok: typescript_cdk_document_db_cluster_log_exports
  new docdb.DatabaseCluster(stack, 'DocDBCluster9', params);
}
// {/fact}

// {fact rule=security-information-omission@v1.0 defects=0}
function good_case_10() {
  const app = new App();
  const stack = new Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const logExports = [];
  logExports.push('authenticate');
  logExports.push('createIndex');
  logExports.push('dropCollection');
  
  // ok: typescript_cdk_document_db_cluster_log_exports
  new docdb.DatabaseCluster(stack, 'DocDBCluster10', {
    masterUser: {
      username: 'admin',
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    vpc,
    cloudwatchLogsExports: logExports,
  });
}
// {/fact}

// {fact rule=security-information-omission@v1.0 defects=0}
function good_case_11() {
  const app = new App();
  const stack = new Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // Define the required log exports
  const authenticate = 'authenticate';
  const createIndex = 'createIndex';
  const dropCollection = 'dropCollection';
  
  // ok: typescript_cdk_document_db_cluster_log_exports
  new docdb.DatabaseCluster(stack, 'DocDBCluster11', {
    masterUser: {
      username: 'admin',
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    vpc,
    cloudwatchLogsExports: [authenticate, createIndex, dropCollection],
  });
}
// {/fact}

// {fact rule=security-information-omission@v1.0 defects=0}
function good_case_12() {
  const app = new App();
  const stack = new Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const getRequiredLogExports = () => {
    const logs = [];
    logs.push('authenticate');
    logs.push('createIndex');
    logs.push('dropCollection');
    return logs;
  };
  
  // ok: typescript_cdk_document_db_cluster_log_exports
  new docdb.DatabaseCluster(stack, 'DocDBCluster12', {
    masterUser: {
      username: 'admin',
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    vpc,
    cloudwatchLogsExports: getRequiredLogExports(),
  });
}
// {/fact}

// {fact rule=security-information-omission@v1.0 defects=0}
function good_case_13() {
  const app = new App();
  const stack = new Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ok: typescript_cdk_document_db_cluster_log_exports
  const cluster = new docdb.DatabaseCluster(stack, 'DocDBCluster13', {
    masterUser: {
      username: 'admin',
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    vpc,
    cloudwatchLogsExports: ['authenticate', 'createIndex', 'dropCollection'],
    backupRetention: Duration.days(14), // Additional security measure
    deletionProtection: true, // Additional security measure
  });
}
// {/fact}

// {fact rule=security-information-omission@v1.0 defects=0}
function good_case_14() {
  const app = new App();
  const stack = new Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ok: typescript_cdk_document_db_cluster_log_exports
  const cluster = new docdb.DatabaseClusterFromSnapshot(stack, 'DocDBCluster14', {
    snapshotIdentifier: 'snapshot-id',
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    vpc,
    cloudwatchLogsExports: ['authenticate', 'createIndex', 'dropCollection'],
  });
}
// {/fact}

// {fact rule=security-information-omission@v1.0 defects=0}
function good_case_15() {
  const app = new App();
  const stack = new Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const securityConfig = {
    storageEncrypted: true,
    deletionProtection: true,
    cloudwatchLogsExports: ['authenticate', 'createIndex', 'dropCollection'],
  };
  
  // ok: typescript_cdk_document_db_cluster_log_exports
  new docdb.DatabaseCluster(stack, 'DocDBCluster15', {
    masterUser: {
      username: 'admin',
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    vpc,
    ...securityConfig,
  });
}
// {/fact}