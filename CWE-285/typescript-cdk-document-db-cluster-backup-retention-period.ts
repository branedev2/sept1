import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as docdb from 'aws-cdk-lib/aws-docdb';
import * as ec2 from 'aws-cdk-lib/aws-ec2';

// True Positives (Vulnerable Code)

// {fact rule=improper-authentication@v1.0 defects=1}
function bad_case_1() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ruleid: typescript-cdk-document-db-cluster-backup-retention-period
  new docdb.DatabaseCluster(stack, 'DocDBCluster', {
    masterUser: {
      username: 'admin',
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
    vpc,
    // No backup retention period specified (defaults to 1 day)
  });
}
// {/fact}

// {fact rule=improper-authentication@v1.0 defects=1}
function bad_case_2() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ruleid: typescript-cdk-document-db-cluster-backup-retention-period
  new docdb.DatabaseCluster(stack, 'DocDBCluster', {
    masterUser: {
      username: 'admin',
      secretName: '/docdb/admin',
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    vpc,
    backup: { retention: cdk.Duration.days(1) } // Too short retention period
  });
}
// {/fact}

// {fact rule=improper-authentication@v1.0 defects=1}
function bad_case_3() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ruleid: typescript-cdk-document-db-cluster-backup-retention-period
  const cluster = new docdb.DatabaseCluster(stack, 'DocDBCluster', {
    masterUser: {
      username: 'admin',
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    vpc,
    backup: { retention: cdk.Duration.days(3) } // Less than recommended 7 days
  });
}
// {/fact}

// {fact rule=improper-authentication@v1.0 defects=1}
function bad_case_4() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const retentionPeriod = cdk.Duration.days(5); // Still less than recommended
  
  // ruleid: typescript-cdk-document-db-cluster-backup-retention-period
  new docdb.DatabaseCluster(stack, 'DocDBCluster', {
    masterUser: {
      username: 'admin',
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.XLARGE),
    vpc,
    backup: { retention: retentionPeriod }
  });
}
// {/fact}

// {fact rule=improper-authentication@v1.0 defects=1}
function bad_case_5() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ruleid: typescript-cdk-document-db-cluster-backup-retention-period
  new docdb.DatabaseCluster(stack, 'DocDBCluster', {
    masterUser: {
      username: 'admin',
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    vpc,
    backup: { retention: cdk.Duration.hours(36) } // Less than 7 days (only 36 hours)
  });
}
// {/fact}

// {fact rule=improper-authentication@v1.0 defects=1}
function bad_case_6() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const options = {
    masterUser: {
      username: 'admin',
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    vpc,
    backup: { retention: cdk.Duration.days(6) } // Less than recommended 7 days
  };
  
  // ruleid: typescript-cdk-document-db-cluster-backup-retention-period
  new docdb.DatabaseCluster(stack, 'DocDBCluster', options);
}
// {/fact}

// {fact rule=improper-authentication@v1.0 defects=1}
function bad_case_7() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ruleid: typescript-cdk-document-db-cluster-backup-retention-period
  const cluster = new docdb.DatabaseCluster(stack, 'DocDBCluster', {
    masterUser: {
      username: 'admin',
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    vpc,
    backup: { 
      retention: cdk.Duration.days(2), // Too short
      preferredWindow: '01:00-02:00'
    }
  });
}
// {/fact}

// {fact rule=improper-authentication@v1.0 defects=1}
function bad_case_8() {
  class DatabaseStack extends cdk.Stack {
    constructor(scope: Construct, id: string, props?: cdk.StackProps) {
      super(scope, id, props);
      
      const vpc = new ec2.Vpc(this, 'VPC');
      
      // ruleid: typescript-cdk-document-db-cluster-backup-retention-period
      new docdb.DatabaseCluster(this, 'DocDBCluster', {
        masterUser: {
          username: 'admin',
        },
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
        vpc,
        backup: { retention: cdk.Duration.days(4) } // Less than recommended 7 days
      });
    }
  }
  
  const app = new cdk.App();
  new DatabaseStack(app, 'DatabaseStack');
}
// {/fact}

// {fact rule=improper-authentication@v1.0 defects=1}
function bad_case_9() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const days = 0; // No retention
  
  // ruleid: typescript-cdk-document-db-cluster-backup-retention-period
  new docdb.DatabaseCluster(stack, 'DocDBCluster', {
    masterUser: {
      username: 'admin',
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    vpc,
    backup: { retention: cdk.Duration.days(days) }
  });
}
// {/fact}

// {fact rule=improper-authentication@v1.0 defects=1}
function bad_case_10() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ruleid: typescript-cdk-document-db-cluster-backup-retention-period
  const cluster = new docdb.DatabaseCluster(stack, 'DocDBCluster', {
    masterUser: {
      username: 'admin',
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    vpc,
    backup: { 
      retention: cdk.Duration.minutes(4320) // 3 days in minutes, less than recommended
    }
  });
}
// {/fact}

// {fact rule=improper-authentication@v1.0 defects=1}
function bad_case_11() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ruleid: typescript-cdk-document-db-cluster-backup-retention-period
  const cluster = new docdb.DatabaseCluster(stack, 'DocDBCluster', {
    masterUser: {
      username: 'admin',
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    vpc,
    removalPolicy: cdk.RemovalPolicy.DESTROY,
    backup: { retention: cdk.Duration.days(1) } // Too short with DESTROY policy
  });
}
// {/fact}

// {fact rule=improper-authentication@v1.0 defects=1}
function bad_case_12() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const createCluster = () => {
    // ruleid: typescript-cdk-document-db-cluster-backup-retention-period
    return new docdb.DatabaseCluster(stack, 'DocDBCluster', {
      masterUser: {
        username: 'admin',
      },
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
      vpc,
      backup: { retention: cdk.Duration.days(2) } // Too short
    });
  };
  
  const cluster = createCluster();
}
// {/fact}

// {fact rule=improper-authentication@v1.0 defects=1}
function bad_case_13() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ruleid: typescript-cdk-document-db-cluster-backup-retention-period
  const cluster = new docdb.DatabaseCluster(stack, 'DocDBCluster', {
    masterUser: {
      username: 'admin',
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    vpc,
    backup: { 
      retention: cdk.Duration.seconds(259200) // 3 days in seconds, less than recommended
    }
  });
}
// {/fact}

// {fact rule=improper-authentication@v1.0 defects=1}
function bad_case_14() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const backupConfig = {
    retention: cdk.Duration.days(5) // Less than recommended
  };
  
  // ruleid: typescript-cdk-document-db-cluster-backup-retention-period
  new docdb.DatabaseCluster(stack, 'DocDBCluster', {
    masterUser: {
      username: 'admin',
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    vpc,
    backup: backupConfig
  });
}
// {/fact}

// {fact rule=improper-authentication@v1.0 defects=1}
function bad_case_15() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const retentionDays = process.env.RETENTION_DAYS ? parseInt(process.env.RETENTION_DAYS) : 3; // Default is too short
  
  // ruleid: typescript-cdk-document-db-cluster-backup-retention-period
  new docdb.DatabaseCluster(stack, 'DocDBCluster', {
    masterUser: {
      username: 'admin',
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    vpc,
    backup: { retention: cdk.Duration.days(retentionDays) }
  });
}
// {/fact}

// True Negatives (Secure Code)

// {fact rule=improper-authentication@v1.0 defects=0}
function good_case_1() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ok: typescript-cdk-document-db-cluster-backup-retention-period
  new docdb.DatabaseCluster(stack, 'DocDBCluster', {
    masterUser: {
      username: 'admin',
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    vpc,
    backup: { retention: cdk.Duration.days(7) } // Minimum recommended retention period
  });
}
// {/fact}

// {fact rule=improper-authentication@v1.0 defects=0}
function good_case_2() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ok: typescript-cdk-document-db-cluster-backup-retention-period
  new docdb.DatabaseCluster(stack, 'DocDBCluster', {
    masterUser: {
      username: 'admin',
      secretName: '/docdb/admin',
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    vpc,
    backup: { retention: cdk.Duration.days(14) } // More than minimum recommended
  });
}
// {/fact}

// {fact rule=improper-authentication@v1.0 defects=0}
function good_case_3() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ok: typescript-cdk-document-db-cluster-backup-retention-period
  const cluster = new docdb.DatabaseCluster(stack, 'DocDBCluster', {
    masterUser: {
      username: 'admin',
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    vpc,
    backup: { retention: cdk.Duration.days(30) } // 30 days retention
  });
}
// {/fact}

// {fact rule=improper-authentication@v1.0 defects=0}
function good_case_4() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const retentionPeriod = cdk.Duration.days(10); // More than recommended minimum
  
  // ok: typescript-cdk-document-db-cluster-backup-retention-period
  new docdb.DatabaseCluster(stack, 'DocDBCluster', {
    masterUser: {
      username: 'admin',
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.XLARGE),
    vpc,
    backup: { retention: retentionPeriod }
  });
}
// {/fact}

// {fact rule=improper-authentication@v1.0 defects=0}
function good_case_5() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ok: typescript-cdk-document-db-cluster-backup-retention-period
  new docdb.DatabaseCluster(stack, 'DocDBCluster', {
    masterUser: {
      username: 'admin',
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    vpc,
    backup: { retention: cdk.Duration.days(7 * 5) } // 35 days (5 weeks)
  });
}
// {/fact}

// {fact rule=improper-authentication@v1.0 defects=0}
function good_case_6() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const options = {
    masterUser: {
      username: 'admin',
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    vpc,
    backup: { retention: cdk.Duration.days(7) } // Minimum recommended
  };
  
  // ok: typescript-cdk-document-db-cluster-backup-retention-period
  new docdb.DatabaseCluster(stack, 'DocDBCluster', options);
}
// {/fact}

// {fact rule=improper-authentication@v1.0 defects=0}
function good_case_7() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ok: typescript-cdk-document-db-cluster-backup-retention-period
  const cluster = new docdb.DatabaseCluster(stack, 'DocDBCluster', {
    masterUser: {
      username: 'admin',
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    vpc,
    backup: { 
      retention: cdk.Duration.days(14), // Good retention period
      preferredWindow: '01:00-02:00'
    }
  });
}
// {/fact}

// {fact rule=improper-authentication@v1.0 defects=0}
function good_case_8() {
  class DatabaseStack extends cdk.Stack {
    constructor(scope: Construct, id: string, props?: cdk.StackProps) {
      super(scope, id, props);
      
      const vpc = new ec2.Vpc(this, 'VPC');
      
      // ok: typescript-cdk-document-db-cluster-backup-retention-period
      new docdb.DatabaseCluster(this, 'DocDBCluster', {
        masterUser: {
          username: 'admin',
        },
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
        vpc,
        backup: { retention: cdk.Duration.days(90) } // 90 days retention
      });
    }
  }
  
  const app = new cdk.App();
  new DatabaseStack(app, 'DatabaseStack');
}
// {/fact}

// {fact rule=improper-authentication@v1.0 defects=0}
function good_case_9() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const days = 35; // More than minimum recommended
  
  // ok: typescript-cdk-document-db-cluster-backup-retention-period
  new docdb.DatabaseCluster(stack, 'DocDBCluster', {
    masterUser: {
      username: 'admin',
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    vpc,
    backup: { retention: cdk.Duration.days(days) }
  });
}
// {/fact}

// {fact rule=improper-authentication@v1.0 defects=0}
function good_case_10() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ok: typescript-cdk-document-db-cluster-backup-retention-period
  const cluster = new docdb.DatabaseCluster(stack, 'DocDBCluster', {
    masterUser: {
      username: 'admin',
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    vpc,
    backup: { 
      retention: cdk.Duration.hours(24 * 7) // 7 days in hours, meets minimum
    }
  });
}
// {/fact}

// {fact rule=improper-authentication@v1.0 defects=0}
function good_case_11() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ok: typescript-cdk-document-db-cluster-backup-retention-period
  const cluster = new docdb.DatabaseCluster(stack, 'DocDBCluster', {
    masterUser: {
      username: 'admin',
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    vpc,
    removalPolicy: cdk.RemovalPolicy.SNAPSHOT,
    backup: { retention: cdk.Duration.days(7) } // Minimum with SNAPSHOT policy
  });
}
// {/fact}

// {fact rule=improper-authentication@v1.0 defects=0}
function good_case_12() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const createCluster = () => {
    // ok: typescript-cdk-document-db-cluster-backup-retention-period
    return new docdb.DatabaseCluster(stack, 'DocDBCluster', {
      masterUser: {
        username: 'admin',
      },
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
      vpc,
      backup: { retention: cdk.Duration.days(21) } // 3 weeks, more than minimum
    });
  };
  
  const cluster = createCluster();
}
// {/fact}

// {fact rule=improper-authentication@v1.0 defects=0}
function good_case_13() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ok: typescript-cdk-document-db-cluster-backup-retention-period
  const cluster = new docdb.DatabaseCluster(stack, 'DocDBCluster', {
    masterUser: {
      username: 'admin',
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    vpc,
    backup: { 
      retention: cdk.Duration.seconds(604800) // 7 days in seconds, meets minimum
    }
  });
}
// {/fact}

// {fact rule=improper-authentication@v1.0 defects=0}
function good_case_14() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const backupConfig = {
    retention: cdk.Duration.days(15) // More than minimum recommended
  };
  
  // ok: typescript-cdk-document-db-cluster-backup-retention-period
  new docdb.DatabaseCluster(stack, 'DocDBCluster', {
    masterUser: {
      username: 'admin',
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    vpc,
    backup: backupConfig
  });
}
// {/fact}

// {fact rule=improper-authentication@v1.0 defects=0}
function good_case_15() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'DocDBStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const retentionDays = process.env.RETENTION_DAYS ? parseInt(process.env.RETENTION_DAYS) : 7; // Default is minimum recommended
  
  // ok: typescript-cdk-document-db-cluster-backup-retention-period
  new docdb.DatabaseCluster(stack, 'DocDBCluster', {
    masterUser: {
      username: 'admin',
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    vpc,
    backup: { retention: cdk.Duration.days(Math.max(retentionDays, 7)) } // Ensures minimum of 7 days
  });
}
// {/fact}