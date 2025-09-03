import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as rds from 'aws-cdk-lib/aws-rds';
import * as ec2 from 'aws-cdk-lib/aws-ec2';

// True Positive Cases (Vulnerable - Missing or disabled backtrack)

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_1() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  // ruleid: typescript-cdk-aurora-my-sql-backtrack
  new rds.DatabaseCluster(stack, 'Database', {
    engine: rds.DatabaseClusterEngine.auroraMysql({ version: rds.AuroraMysqlEngineVersion.VER_3_01_0 }),
    credentials: rds.Credentials.fromGeneratedSecret('clusteradmin'),
    instanceProps: {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    },
    // Missing backtrackWindow property
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_2() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  // ruleid: typescript-cdk-aurora-my-sql-backtrack
  new rds.DatabaseCluster(stack, 'Database', {
    engine: rds.DatabaseClusterEngine.auroraMysql({ version: rds.AuroraMysqlEngineVersion.VER_2_10_2 }),
    credentials: rds.Credentials.fromGeneratedSecret('clusteradmin'),
    instanceProps: {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    },
    backtrackWindow: cdk.Duration.seconds(0), // Backtrack disabled with 0 seconds
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_3() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const clusterParams = {
    engine: rds.DatabaseClusterEngine.auroraMysql({ version: rds.AuroraMysqlEngineVersion.VER_3_02_0 }),
    credentials: rds.Credentials.fromGeneratedSecret('clusteradmin'),
    instanceProps: {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.R6G, ec2.InstanceSize.XLARGE),
    },
    // No backtrack configuration
  };
  
  // ruleid: typescript-cdk-aurora-my-sql-backtrack
  new rds.DatabaseCluster(stack, 'Database', clusterParams);
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_4() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  // ruleid: typescript-cdk-aurora-my-sql-backtrack
  const cluster = new rds.DatabaseCluster(stack, 'Database', {
    engine: rds.DatabaseClusterEngine.auroraMysql({ version: rds.AuroraMysqlEngineVersion.VER_2_07_1 }),
    credentials: rds.Credentials.fromGeneratedSecret('clusteradmin'),
    instanceProps: {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.LARGE),
    },
    backtrackWindow: cdk.Duration.hours(0), // Zero hours means disabled
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_5() {
  class DatabaseStack extends cdk.Stack {
    constructor(scope: Construct, id: string, props?: cdk.StackProps) {
      super(scope, id, props);
      
      const vpc = new ec2.Vpc(this, 'MyVpc');
      
      // ruleid: typescript-cdk-aurora-my-sql-backtrack
      new rds.DatabaseCluster(this, 'Database', {
        engine: rds.DatabaseClusterEngine.auroraMysql({ version: rds.AuroraMysqlEngineVersion.VER_3_02_0 }),
        credentials: rds.Credentials.fromGeneratedSecret('clusteradmin'),
        instanceProps: {
          vpc,
          instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
        },
        // Backtrack not configured
      });
    }
  }
  
  const app = new cdk.App();
  new DatabaseStack(app, 'DatabaseStack');
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_6() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const backtrackDuration = 0; // Zero duration
  
  // ruleid: typescript-cdk-aurora-my-sql-backtrack
  new rds.DatabaseCluster(stack, 'Database', {
    engine: rds.DatabaseClusterEngine.auroraMysql({ version: rds.AuroraMysqlEngineVersion.VER_2_10_0 }),
    credentials: rds.Credentials.fromGeneratedSecret('clusteradmin'),
    instanceProps: {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    },
    backtrackWindow: cdk.Duration.hours(backtrackDuration),
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_7() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  // ruleid: typescript-cdk-aurora-my-sql-backtrack
  const cluster = new rds.DatabaseCluster(stack, 'Database', {
    engine: rds.DatabaseClusterEngine.auroraMysql({ version: rds.AuroraMysqlEngineVersion.VER_2_09_1 }),
    credentials: rds.Credentials.fromGeneratedSecret('clusteradmin'),
    instanceProps: {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    },
    backtrackWindow: cdk.Duration.minutes(0), // Zero minutes
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_8() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const config = {
    engine: rds.DatabaseClusterEngine.auroraMysql({ version: rds.AuroraMysqlEngineVersion.VER_3_01_0 }),
    credentials: rds.Credentials.fromGeneratedSecret('clusteradmin'),
    instanceProps: {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    },
    // No backtrack configuration
  };
  
  // ruleid: typescript-cdk-aurora-my-sql-backtrack
  new rds.DatabaseCluster(stack, 'Database', config);
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_9() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const isProduction = false;
  const backtrackWindow = isProduction ? cdk.Duration.hours(24) : cdk.Duration.seconds(0);
  
  // ruleid: typescript-cdk-aurora-my-sql-backtrack
  new rds.DatabaseCluster(stack, 'Database', {
    engine: rds.DatabaseClusterEngine.auroraMysql({ version: rds.AuroraMysqlEngineVersion.VER_2_10_2 }),
    credentials: rds.Credentials.fromGeneratedSecret('clusteradmin'),
    instanceProps: {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    },
    backtrackWindow: backtrackWindow, // Will be 0 for non-production
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_10() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  // ruleid: typescript-cdk-aurora-my-sql-backtrack
  new rds.DatabaseCluster(stack, 'Database', {
    engine: rds.DatabaseClusterEngine.auroraMysql({ version: rds.AuroraMysqlEngineVersion.VER_3_02_0 }),
    credentials: rds.Credentials.fromGeneratedSecret('clusteradmin'),
    instanceProps: {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    },
    backtrackWindow: cdk.Duration.millis(0), // Zero milliseconds
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_11() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const engineVersion = rds.AuroraMysqlEngineVersion.VER_2_10_2;
  const engine = rds.DatabaseClusterEngine.auroraMysql({ version: engineVersion });
  
  // ruleid: typescript-cdk-aurora-my-sql-backtrack
  new rds.DatabaseCluster(stack, 'Database', {
    engine: engine,
    credentials: rds.Credentials.fromGeneratedSecret('clusteradmin'),
    instanceProps: {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    },
    // No backtrack configuration
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_12() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  function createCluster(id: string) {
    // ruleid: typescript-cdk-aurora-my-sql-backtrack
    return new rds.DatabaseCluster(stack, id, {
      engine: rds.DatabaseClusterEngine.auroraMysql({ version: rds.AuroraMysqlEngineVersion.VER_3_01_0 }),
      credentials: rds.Credentials.fromGeneratedSecret('clusteradmin'),
      instanceProps: {
        vpc,
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
      },
      // Missing backtrack configuration
    });
  }
  
  createCluster('Database');
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_13() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const backtrackValue = 0;
  
  // ruleid: typescript-cdk-aurora-my-sql-backtrack
  new rds.DatabaseCluster(stack, 'Database', {
    engine: rds.DatabaseClusterEngine.auroraMysql({ version: rds.AuroraMysqlEngineVersion.VER_2_10_2 }),
    credentials: rds.Credentials.fromGeneratedSecret('clusteradmin'),
    instanceProps: {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    },
    backtrackWindow: cdk.Duration.days(backtrackValue), // Zero days
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_14() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  // ruleid: typescript-cdk-aurora-my-sql-backtrack
  const cluster = new rds.DatabaseCluster(stack, 'Database', {
    engine: rds.DatabaseClusterEngine.auroraMysql({ version: rds.AuroraMysqlEngineVersion.VER_3_02_0 }),
    credentials: rds.Credentials.fromGeneratedSecret('clusteradmin'),
    instanceProps: {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    },
    // No backtrack configuration
  });
  
  // Adding other configurations but still missing backtrack
  cluster.addRotationSingleUser();
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_15() {
  class DatabaseConstruct extends Construct {
    constructor(scope: Construct, id: string) {
      super(scope, id);
      
      const vpc = new ec2.Vpc(this, 'MyVpc');
      
      // ruleid: typescript-cdk-aurora-my-sql-backtrack
      new rds.DatabaseCluster(this, 'Database', {
        engine: rds.DatabaseClusterEngine.auroraMysql({ version: rds.AuroraMysqlEngineVersion.VER_2_10_2 }),
        credentials: rds.Credentials.fromGeneratedSecret('clusteradmin'),
        instanceProps: {
          vpc,
          instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
        },
        backtrackWindow: cdk.Duration.seconds(0), // Zero seconds
      });
    }
  }
  
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  new DatabaseConstruct(stack, 'MyDatabase');
}
// {/fact}

// True Negative Cases (Secure - Backtrack enabled)

// {fact rule=object-presence@v1.0 defects=0}
function good_case_1() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  // ok: typescript-cdk-aurora-my-sql-backtrack
  new rds.DatabaseCluster(stack, 'Database', {
    engine: rds.DatabaseClusterEngine.auroraMysql({ version: rds.AuroraMysqlEngineVersion.VER_3_01_0 }),
    credentials: rds.Credentials.fromGeneratedSecret('clusteradmin'),
    instanceProps: {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    },
    backtrackWindow: cdk.Duration.hours(24), // 24 hours backtrack window
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_2() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  // ok: typescript-cdk-aurora-my-sql-backtrack
  new rds.DatabaseCluster(stack, 'Database', {
    engine: rds.DatabaseClusterEngine.auroraMysql({ version: rds.AuroraMysqlEngineVersion.VER_2_10_2 }),
    credentials: rds.Credentials.fromGeneratedSecret('clusteradmin'),
    instanceProps: {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    },
    backtrackWindow: cdk.Duration.seconds(3600), // 1 hour in seconds
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_3() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const clusterParams = {
    engine: rds.DatabaseClusterEngine.auroraMysql({ version: rds.AuroraMysqlEngineVersion.VER_3_02_0 }),
    credentials: rds.Credentials.fromGeneratedSecret('clusteradmin'),
    instanceProps: {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.R6G, ec2.InstanceSize.XLARGE),
    },
    backtrackWindow: cdk.Duration.days(1), // 1 day backtrack window
  };
  
  // ok: typescript-cdk-aurora-my-sql-backtrack
  new rds.DatabaseCluster(stack, 'Database', clusterParams);
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_4() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  // ok: typescript-cdk-aurora-my-sql-backtrack
  const cluster = new rds.DatabaseCluster(stack, 'Database', {
    engine: rds.DatabaseClusterEngine.auroraMysql({ version: rds.AuroraMysqlEngineVersion.VER_2_07_1 }),
    credentials: rds.Credentials.fromGeneratedSecret('clusteradmin'),
    instanceProps: {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.LARGE),
    },
    backtrackWindow: cdk.Duration.hours(72), // 72 hours (3 days)
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_5() {
  class DatabaseStack extends cdk.Stack {
    constructor(scope: Construct, id: string, props?: cdk.StackProps) {
      super(scope, id, props);
      
      const vpc = new ec2.Vpc(this, 'MyVpc');
      
      // ok: typescript-cdk-aurora-my-sql-backtrack
      new rds.DatabaseCluster(this, 'Database', {
        engine: rds.DatabaseClusterEngine.auroraMysql({ version: rds.AuroraMysqlEngineVersion.VER_3_02_0 }),
        credentials: rds.Credentials.fromGeneratedSecret('clusteradmin'),
        instanceProps: {
          vpc,
          instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
        },
        backtrackWindow: cdk.Duration.minutes(60), // 60 minutes
      });
    }
  }
  
  const app = new cdk.App();
  new DatabaseStack(app, 'DatabaseStack');
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_6() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const backtrackDuration = 48; // 48 hours
  
  // ok: typescript-cdk-aurora-my-sql-backtrack
  new rds.DatabaseCluster(stack, 'Database', {
    engine: rds.DatabaseClusterEngine.auroraMysql({ version: rds.AuroraMysqlEngineVersion.VER_2_10_0 }),
    credentials: rds.Credentials.fromGeneratedSecret('clusteradmin'),
    instanceProps: {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    },
    backtrackWindow: cdk.Duration.hours(backtrackDuration),
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_7() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  // ok: typescript-cdk-aurora-my-sql-backtrack
  const cluster = new rds.DatabaseCluster(stack, 'Database', {
    engine: rds.DatabaseClusterEngine.auroraMysql({ version: rds.AuroraMysqlEngineVersion.VER_2_09_1 }),
    credentials: rds.Credentials.fromGeneratedSecret('clusteradmin'),
    instanceProps: {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    },
    backtrackWindow: cdk.Duration.minutes(120), // 2 hours in minutes
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_8() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const config = {
    engine: rds.DatabaseClusterEngine.auroraMysql({ version: rds.AuroraMysqlEngineVersion.VER_3_01_0 }),
    credentials: rds.Credentials.fromGeneratedSecret('clusteradmin'),
    instanceProps: {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    },
    backtrackWindow: cdk.Duration.seconds(86400), // 24 hours in seconds
  };
  
  // ok: typescript-cdk-aurora-my-sql-backtrack
  new rds.DatabaseCluster(stack, 'Database', config);
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_9() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const isProduction = true;
  const backtrackWindow = isProduction ? cdk.Duration.hours(24) : cdk.Duration.hours(1);
  
  // ok: typescript-cdk-aurora-my-sql-backtrack
  new rds.DatabaseCluster(stack, 'Database', {
    engine: rds.DatabaseClusterEngine.auroraMysql({ version: rds.AuroraMysqlEngineVersion.VER_2_10_2 }),
    credentials: rds.Credentials.fromGeneratedSecret('clusteradmin'),
    instanceProps: {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    },
    backtrackWindow: backtrackWindow, // Will be 24 hours for production
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_10() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  // ok: typescript-cdk-aurora-my-sql-backtrack
  new rds.DatabaseCluster(stack, 'Database', {
    engine: rds.DatabaseClusterEngine.auroraMysql({ version: rds.AuroraMysqlEngineVersion.VER_3_02_0 }),
    credentials: rds.Credentials.fromGeneratedSecret('clusteradmin'),
    instanceProps: {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    },
    backtrackWindow: cdk.Duration.millis(3600000), // 1 hour in milliseconds
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_11() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const engineVersion = rds.AuroraMysqlEngineVersion.VER_2_10_2;
  const engine = rds.DatabaseClusterEngine.auroraMysql({ version: engineVersion });
  
  // ok: typescript-cdk-aurora-my-sql-backtrack
  new rds.DatabaseCluster(stack, 'Database', {
    engine: engine,
    credentials: rds.Credentials.fromGeneratedSecret('clusteradmin'),
    instanceProps: {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    },
    backtrackWindow: cdk.Duration.hours(12), // 12 hours
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_12() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  function createCluster(id: string) {
    // ok: typescript-cdk-aurora-my-sql-backtrack
    return new rds.DatabaseCluster(stack, id, {
      engine: rds.DatabaseClusterEngine.auroraMysql({ version: rds.AuroraMysqlEngineVersion.VER_3_01_0 }),
      credentials: rds.Credentials.fromGeneratedSecret('clusteradmin'),
      instanceProps: {
        vpc,
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
      },
      backtrackWindow: cdk.Duration.days(2), // 2 days
    });
  }
  
  createCluster('Database');
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_13() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const backtrackValue = 3; // 3 days
  
  // ok: typescript-cdk-aurora-my-sql-backtrack
  new rds.DatabaseCluster(stack, 'Database', {
    engine: rds.DatabaseClusterEngine.auroraMysql({ version: rds.AuroraMysqlEngineVersion.VER_2_10_2 }),
    credentials: rds.Credentials.fromGeneratedSecret('clusteradmin'),
    instanceProps: {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    },
    backtrackWindow: cdk.Duration.days(backtrackValue),
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_14() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  // ok: typescript-cdk-aurora-my-sql-backtrack
  const cluster = new rds.DatabaseCluster(stack, 'Database', {
    engine: rds.DatabaseClusterEngine.auroraMysql({ version: rds.AuroraMysqlEngineVersion.VER_3_02_0 }),
    credentials: rds.Credentials.fromGeneratedSecret('clusteradmin'),
    instanceProps: {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    },
    backtrackWindow: cdk.Duration.hours(36), // 36 hours
  });
  
  // Adding other configurations with backtrack enabled
  cluster.addRotationSingleUser();
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_15() {
  class DatabaseConstruct extends Construct {
    constructor(scope: Construct, id: string) {
      super(scope, id);
      
      const vpc = new ec2.Vpc(this, 'MyVpc');
      
      // ok: typescript-cdk-aurora-my-sql-backtrack
      new rds.DatabaseCluster(this, 'Database', {
        engine: rds.DatabaseClusterEngine.auroraMysql({ version: rds.AuroraMysqlEngineVersion.VER_2_10_2 }),
        credentials: rds.Credentials.fromGeneratedSecret('clusteradmin'),
        instanceProps: {
          vpc,
          instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
        },
        backtrackWindow: cdk.Duration.minutes(720), // 12 hours in minutes
      });
    }
  }
  
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  new DatabaseConstruct(stack, 'MyDatabase');
}
// {/fact}