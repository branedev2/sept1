import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as docdb from 'aws-cdk-lib/aws-docdb';
import * as ec2 from 'aws-cdk-lib/aws-ec2';

// True Positives (Vulnerable cases) - Using default port (27017) or not specifying port

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_1() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ruleid: typescript_cdk_document_db_cluster_non_default_port
  const cluster = new docdb.DatabaseCluster(stack, 'Database', {
    masterUser: {
      username: 'myuser',
      password: cdk.SecretValue.unsafePlainText('mypassword'),
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    vpcSubnets: {
      subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
    },
    vpc,
    // No port specified, will use default 27017
  });
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_2() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ruleid: typescript_cdk_document_db_cluster_non_default_port
  const cluster = new docdb.DatabaseCluster(stack, 'Database', {
    masterUser: {
      username: 'admin',
      password: cdk.SecretValue.secretsManager('db/password'),
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    vpcSubnets: {
      subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
    },
    vpc,
    port: 27017, // Explicitly using default MongoDB port
  });
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_3() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const defaultPort = 27017;
  
  // ruleid: typescript_cdk_document_db_cluster_non_default_port
  const cluster = new docdb.DatabaseCluster(stack, 'Database', {
    masterUser: {
      username: 'dbadmin',
      password: cdk.SecretValue.unsafePlainText('Password123!'),
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    vpcSubnets: {
      subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
    },
    vpc,
    port: defaultPort, // Using default port via variable
  });
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_4() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const portConfig = {
    mongodb: 27017
  };
  
  // ruleid: typescript_cdk_document_db_cluster_non_default_port
  const cluster = new docdb.DatabaseCluster(stack, 'Database', {
    masterUser: {
      username: 'root',
      password: cdk.SecretValue.secretsManager('db/creds'),
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.XLARGE),
    vpcSubnets: {
      subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
    },
    vpc,
    port: portConfig.mongodb, // Using default port from config object
  });
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_5() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  function getDefaultPort() {
    return 27017;
  }
  
  // ruleid: typescript_cdk_document_db_cluster_non_default_port
  const cluster = new docdb.DatabaseCluster(stack, 'Database', {
    masterUser: {
      username: 'admin',
      password: cdk.SecretValue.unsafePlainText('StrongP@ss!'),
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.LARGE),
    vpcSubnets: {
      subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
    },
    vpc,
    port: getDefaultPort(), // Using default port from function
  });
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_6() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const PORT = 27017;
  
  // ruleid: typescript_cdk_document_db_cluster_non_default_port
  new docdb.DatabaseCluster(stack, 'Database', {
    masterUser: {
      username: 'dbuser',
      password: cdk.SecretValue.secretsManager('db/password/key'),
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    vpcSubnets: {
      subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
    },
    vpc,
    port: PORT, // Using default port via constant
  });
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_7() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const ports = [27017, 27018, 27019];
  
  // ruleid: typescript_cdk_document_db_cluster_non_default_port
  const cluster = new docdb.DatabaseCluster(stack, 'Database', {
    masterUser: {
      username: 'mongouser',
      password: cdk.SecretValue.unsafePlainText('SecurePassword123!'),
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    vpcSubnets: {
      subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
    },
    vpc,
    port: ports[0], // Using default port from array
  });
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_8() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const config = {
    database: {
      port: 27017
    }
  };
  
  // ruleid: typescript_cdk_document_db_cluster_non_default_port
  const cluster = new docdb.DatabaseCluster(stack, 'Database', {
    masterUser: {
      username: 'admin',
      password: cdk.SecretValue.secretsManager('secrets/db'),
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.XLARGE),
    vpcSubnets: {
      subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
    },
    vpc,
    port: config.database.port, // Using default port from nested config
  });
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_9() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  let port = 0;
  if (process.env.NODE_ENV === 'production') {
    port = 27017;
  } else {
    port = 27018;
  }
  
  // ruleid: typescript_cdk_document_db_cluster_non_default_port
  const cluster = new docdb.DatabaseCluster(stack, 'Database', {
    masterUser: {
      username: 'dbuser',
      password: cdk.SecretValue.unsafePlainText('Password123!'),
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.LARGE),
    vpcSubnets: {
      subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
    },
    vpc,
    port: port, // Could be default port based on condition
  });
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_10() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const defaultMongoPort = 27017;
  
  // ruleid: typescript_cdk_document_db_cluster_non_default_port
  const cluster = new docdb.DatabaseCluster(stack, 'Database', {
    masterUser: {
      username: 'mongouser',
      password: cdk.SecretValue.secretsManager('db/credentials'),
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    vpcSubnets: {
      subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
    },
    vpc,
    port: defaultMongoPort, // Using default port with descriptive variable name
  });
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_11() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const portMap = new Map<string, number>([
    ['mongodb', 27017],
    ['mysql', 3306],
    ['postgres', 5432]
  ]);
  
  // ruleid: typescript_cdk_document_db_cluster_non_default_port
  const cluster = new docdb.DatabaseCluster(stack, 'Database', {
    masterUser: {
      username: 'admin',
      password: cdk.SecretValue.unsafePlainText('StrongP@ssw0rd!'),
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    vpcSubnets: {
      subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
    },
    vpc,
    port: portMap.get('mongodb'), // Using default port from Map
  });
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_12() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const a = 27000;
  const b = 17;
  
  // ruleid: typescript_cdk_document_db_cluster_non_default_port
  const cluster = new docdb.DatabaseCluster(stack, 'Database', {
    masterUser: {
      username: 'dbadmin',
      password: cdk.SecretValue.secretsManager('secrets/db/password'),
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.XLARGE),
    vpcSubnets: {
      subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
    },
    vpc,
    port: a + b, // Using default port through calculation (27000 + 17 = 27017)
  });
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_13() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ruleid: typescript_cdk_document_db_cluster_non_default_port
  const cluster = new docdb.DatabaseCluster(stack, 'Database', {
    masterUser: {
      username: 'mongouser',
      password: cdk.SecretValue.unsafePlainText('P@ssw0rd123!'),
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    vpcSubnets: {
      subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
    },
    vpc,
    port: parseInt('27017'), // Using default port as parsed string
  });
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_14() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const envPort = process.env.DB_PORT || '27017';
  
  // ruleid: typescript_cdk_document_db_cluster_non_default_port
  const cluster = new docdb.DatabaseCluster(stack, 'Database', {
    masterUser: {
      username: 'admin',
      password: cdk.SecretValue.secretsManager('db/master/password'),
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    vpcSubnets: {
      subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
    },
    vpc,
    port: parseInt(envPort), // Using default port from env or fallback
  });
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_15() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  class PortProvider {
    static getMongoPort() {
      return 27017;
    }
  }
  
  // ruleid: typescript_cdk_document_db_cluster_non_default_port
  const cluster = new docdb.DatabaseCluster(stack, 'Database', {
    masterUser: {
      username: 'dbuser',
      password: cdk.SecretValue.unsafePlainText('SecretP@ss123!'),
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.LARGE),
    vpcSubnets: {
      subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
    },
    vpc,
    port: PortProvider.getMongoPort(), // Using default port from class method
  });
}
// {/fact}

// True Negatives (Secure cases) - Using non-default ports

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_1() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ok: typescript_cdk_document_db_cluster_non_default_port
  const cluster = new docdb.DatabaseCluster(stack, 'Database', {
    masterUser: {
      username: 'myuser',
      password: cdk.SecretValue.secretsManager('db/password'),
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    vpcSubnets: {
      subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
    },
    vpc,
    port: 27018, // Using non-default port
  });
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_2() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const customPort = 27019;
  
  // ok: typescript_cdk_document_db_cluster_non_default_port
  const cluster = new docdb.DatabaseCluster(stack, 'Database', {
    masterUser: {
      username: 'admin',
      password: cdk.SecretValue.unsafePlainText('StrongP@ss!'),
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    vpcSubnets: {
      subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
    },
    vpc,
    port: customPort, // Using non-default port via variable
  });
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_3() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  function getSecurePort() {
    return 28017;
  }
  
  // ok: typescript_cdk_document_db_cluster_non_default_port
  const cluster = new docdb.DatabaseCluster(stack, 'Database', {
    masterUser: {
      username: 'dbadmin',
      password: cdk.SecretValue.secretsManager('db/credentials'),
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    vpcSubnets: {
      subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
    },
    vpc,
    port: getSecurePort(), // Using non-default port from function
  });
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_4() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const portConfig = {
    mongodb: 27117
  };
  
  // ok: typescript_cdk_document_db_cluster_non_default_port
  const cluster = new docdb.DatabaseCluster(stack, 'Database', {
    masterUser: {
      username: 'root',
      password: cdk.SecretValue.unsafePlainText('SecureP@ssw0rd!'),
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.XLARGE),
    vpcSubnets: {
      subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
    },
    vpc,
    port: portConfig.mongodb, // Using non-default port from config object
  });
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_5() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const SECURE_PORT = 27020;
  
  // ok: typescript_cdk_document_db_cluster_non_default_port
  new docdb.DatabaseCluster(stack, 'Database', {
    masterUser: {
      username: 'dbuser',
      password: cdk.SecretValue.secretsManager('db/password/key'),
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.LARGE),
    vpcSubnets: {
      subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
    },
    vpc,
    port: SECURE_PORT, // Using non-default port via constant
  });
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_6() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const ports = [27018, 27019, 27020];
  
  // ok: typescript_cdk_document_db_cluster_non_default_port
  const cluster = new docdb.DatabaseCluster(stack, 'Database', {
    masterUser: {
      username: 'mongouser',
      password: cdk.SecretValue.unsafePlainText('StrongP@ssw0rd!'),
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    vpcSubnets: {
      subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
    },
    vpc,
    port: ports[0], // Using non-default port from array
  });
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_7() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const config = {
    database: {
      port: 27117
    }
  };
  
  // ok: typescript_cdk_document_db_cluster_non_default_port
  const cluster = new docdb.DatabaseCluster(stack, 'Database', {
    masterUser: {
      username: 'admin',
      password: cdk.SecretValue.secretsManager('secrets/db'),
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.XLARGE),
    vpcSubnets: {
      subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
    },
    vpc,
    port: config.database.port, // Using non-default port from nested config
  });
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_8() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  let port = 0;
  if (process.env.NODE_ENV === 'production') {
    port = 27018;
  } else {
    port = 27019;
  }
  
  // ok: typescript_cdk_document_db_cluster_non_default_port
  const cluster = new docdb.DatabaseCluster(stack, 'Database', {
    masterUser: {
      username: 'dbuser',
      password: cdk.SecretValue.unsafePlainText('Password123!'),
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.LARGE),
    vpcSubnets: {
      subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
    },
    vpc,
    port: port, // Using non-default port based on condition
  });
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_9() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const customMongoPort = 27117;
  
  // ok: typescript_cdk_document_db_cluster_non_default_port
  const cluster = new docdb.DatabaseCluster(stack, 'Database', {
    masterUser: {
      username: 'mongouser',
      password: cdk.SecretValue.secretsManager('db/credentials'),
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    vpcSubnets: {
      subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
    },
    vpc,
    port: customMongoPort, // Using non-default port with descriptive variable name
  });
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_10() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const portMap = new Map<string, number>([
    ['mongodb_custom', 27018],
    ['mysql', 3306],
    ['postgres', 5432]
  ]);
  
  // ok: typescript_cdk_document_db_cluster_non_default_port
  const cluster = new docdb.DatabaseCluster(stack, 'Database', {
    masterUser: {
      username: 'admin',
      password: cdk.SecretValue.unsafePlainText('StrongP@ssw0rd!'),
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    vpcSubnets: {
      subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
    },
    vpc,
    port: portMap.get('mongodb_custom'), // Using non-default port from Map
  });
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_11() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const a = 27000;
  const b = 117;
  
  // ok: typescript_cdk_document_db_cluster_non_default_port
  const cluster = new docdb.DatabaseCluster(stack, 'Database', {
    masterUser: {
      username: 'dbadmin',
      password: cdk.SecretValue.secretsManager('secrets/db/password'),
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.XLARGE),
    vpcSubnets: {
      subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
    },
    vpc,
    port: a + b, // Using non-default port through calculation (27000 + 117 = 27117)
  });
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_12() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ok: typescript_cdk_document_db_cluster_non_default_port
  const cluster = new docdb.DatabaseCluster(stack, 'Database', {
    masterUser: {
      username: 'mongouser',
      password: cdk.SecretValue.unsafePlainText('P@ssw0rd123!'),
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    vpcSubnets: {
      subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
    },
    vpc,
    port: parseInt('27018'), // Using non-default port as parsed string
  });
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_13() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const envPort = process.env.DB_PORT || '27018';
  
  // ok: typescript_cdk_document_db_cluster_non_default_port
  const cluster = new docdb.DatabaseCluster(stack, 'Database', {
    masterUser: {
      username: 'admin',
      password: cdk.SecretValue.secretsManager('db/master/password'),
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    vpcSubnets: {
      subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
    },
    vpc,
    port: parseInt(envPort), // Using non-default port from env or fallback
  });
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_14() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  class PortProvider {
    static getSecureMongoPort() {
      return 27018;
    }
  }
  
  // ok: typescript_cdk_document_db_cluster_non_default_port
  const cluster = new docdb.DatabaseCluster(stack, 'Database', {
    masterUser: {
      username: 'dbuser',
      password: cdk.SecretValue.unsafePlainText('SecretP@ss123!'),
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.LARGE),
    vpcSubnets: {
      subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
    },
    vpc,
    port: PortProvider.getSecureMongoPort(), // Using non-default port from class method
  });
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_15() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ok: typescript_cdk_document_db_cluster_non_default_port
  const cluster = new docdb.DatabaseCluster(stack, 'Database', {
    masterUser: {
      username: 'admin',
      password: cdk.SecretValue.secretsManager('db/password'),
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    vpcSubnets: {
      subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
    },
    vpc,
    port: 28017, // Using a completely different non-default port
  });
}
// {/fact}