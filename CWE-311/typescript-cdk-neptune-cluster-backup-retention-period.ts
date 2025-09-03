import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as neptune from 'aws-cdk-lib/aws-neptune';

// TRUE POSITIVES (Vulnerable Code)

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_1() {
  const stack = new cdk.Stack();
  
  // ruleid: typescript-cdk-neptune-cluster-backup-retention-period
  new neptune.DatabaseCluster(stack, 'NeptuneCluster1', {
    vpc: new cdk.aws_ec2.Vpc(stack, 'Vpc'),
    instanceType: neptune.InstanceType.R5_LARGE,
    // Missing backupRetentionPeriod completely
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_2() {
  const stack = new cdk.Stack();
  
  // ruleid: typescript-cdk-neptune-cluster-backup-retention-period
  const cluster = new neptune.DatabaseCluster(stack, 'NeptuneCluster2', {
    vpc: new cdk.aws_ec2.Vpc(stack, 'Vpc'),
    instanceType: neptune.InstanceType.R5_LARGE,
    backupRetentionPeriod: cdk.Duration.days(0), // Zero days is insufficient
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_3() {
  const stack = new cdk.Stack();
  
  // ruleid: typescript-cdk-neptune-cluster-backup-retention-period
  const cluster = new neptune.DatabaseCluster(stack, 'NeptuneCluster3', {
    vpc: new cdk.aws_ec2.Vpc(stack, 'Vpc'),
    instanceType: neptune.InstanceType.R5_LARGE,
    backupRetentionPeriod: cdk.Duration.days(1), // One day is insufficient
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_4() {
  const stack = new cdk.Stack();
  const vpc = new cdk.aws_ec2.Vpc(stack, 'Vpc');
  
  // ruleid: typescript-cdk-neptune-cluster-backup-retention-period
  const cluster = new neptune.DatabaseCluster(stack, 'NeptuneCluster4', {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
    backupRetentionPeriod: cdk.Duration.hours(36), // 36 hours (1.5 days) is insufficient
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_5() {
  const stack = new cdk.Stack();
  
  // ruleid: typescript-cdk-neptune-cluster-backup-retention-period
  const cluster = new neptune.DatabaseCluster(stack, 'NeptuneCluster5', {
    vpc: new cdk.aws_ec2.Vpc(stack, 'Vpc'),
    instanceType: neptune.InstanceType.R5_LARGE,
    backupRetentionPeriod: cdk.Duration.days(3), // 3 days is insufficient
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_6() {
  const stack = new cdk.Stack();
  const retentionPeriod = cdk.Duration.days(5); // 5 days is insufficient
  
  // ruleid: typescript-cdk-neptune-cluster-backup-retention-period
  const cluster = new neptune.DatabaseCluster(stack, 'NeptuneCluster6', {
    vpc: new cdk.aws_ec2.Vpc(stack, 'Vpc'),
    instanceType: neptune.InstanceType.R5_LARGE,
    backupRetentionPeriod: retentionPeriod,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_7() {
  const stack = new cdk.Stack();
  
  const props = {
    vpc: new cdk.aws_ec2.Vpc(stack, 'Vpc'),
    instanceType: neptune.InstanceType.R5_LARGE,
    backupRetentionPeriod: cdk.Duration.days(6), // 6 days is insufficient
  };
  
  // ruleid: typescript-cdk-neptune-cluster-backup-retention-period
  const cluster = new neptune.DatabaseCluster(stack, 'NeptuneCluster7', props);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_8() {
  const stack = new cdk.Stack();
  
  class CustomNeptuneStack extends cdk.Stack {
    constructor(scope: Construct, id: string) {
      super(scope, id);
      
      // ruleid: typescript-cdk-neptune-cluster-backup-retention-period
      new neptune.DatabaseCluster(this, 'NeptuneCluster8', {
        vpc: new cdk.aws_ec2.Vpc(this, 'Vpc'),
        instanceType: neptune.InstanceType.R5_LARGE,
        backupRetentionPeriod: cdk.Duration.days(2), // 2 days is insufficient
      });
    }
  }
  
  new CustomNeptuneStack(stack, 'CustomNeptuneStack');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_9() {
  const stack = new cdk.Stack();
  
  function createNeptuneCluster(scope: Construct) {
    // ruleid: typescript-cdk-neptune-cluster-backup-retention-period
    return new neptune.DatabaseCluster(scope, 'NeptuneCluster9', {
      vpc: new cdk.aws_ec2.Vpc(scope, 'Vpc'),
      instanceType: neptune.InstanceType.R5_LARGE,
      backupRetentionPeriod: cdk.Duration.hours(120), // 120 hours (5 days) is insufficient
    });
  }
  
  createNeptuneCluster(stack);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_10() {
  const stack = new cdk.Stack();
  const vpc = new cdk.aws_ec2.Vpc(stack, 'Vpc');
  
  // ruleid: typescript-cdk-neptune-cluster-backup-retention-period
  const cluster = new neptune.DatabaseCluster(stack, 'NeptuneCluster10', {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
    backupRetentionPeriod: cdk.Duration.days(4), // 4 days is insufficient
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_11() {
  const stack = new cdk.Stack();
  
  const clusterParams = {
    vpc: new cdk.aws_ec2.Vpc(stack, 'Vpc'),
    instanceType: neptune.InstanceType.R5_LARGE,
  };
  
  // ruleid: typescript-cdk-neptune-cluster-backup-retention-period
  const cluster = new neptune.DatabaseCluster(stack, 'NeptuneCluster11', clusterParams);
  // No backupRetentionPeriod specified at all
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_12() {
  const stack = new cdk.Stack();
  
  // ruleid: typescript-cdk-neptune-cluster-backup-retention-period
  const cluster = new neptune.DatabaseCluster(stack, 'NeptuneCluster12', {
    vpc: new cdk.aws_ec2.Vpc(stack, 'Vpc'),
    instanceType: neptune.InstanceType.R5_LARGE,
    backupRetentionPeriod: cdk.Duration.minutes(8640), // 8640 minutes (6 days) is insufficient
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_13() {
  const stack = new cdk.Stack();
  const days = 3; // Insufficient days
  
  // ruleid: typescript-cdk-neptune-cluster-backup-retention-period
  const cluster = new neptune.DatabaseCluster(stack, 'NeptuneCluster13', {
    vpc: new cdk.aws_ec2.Vpc(stack, 'Vpc'),
    instanceType: neptune.InstanceType.R5_LARGE,
    backupRetentionPeriod: cdk.Duration.days(days),
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_14() {
  const stack = new cdk.Stack();
  
  const options = {
    backupRetentionPeriod: cdk.Duration.days(5), // 5 days is insufficient
  };
  
  // ruleid: typescript-cdk-neptune-cluster-backup-retention-period
  const cluster = new neptune.DatabaseCluster(stack, 'NeptuneCluster14', {
    vpc: new cdk.aws_ec2.Vpc(stack, 'Vpc'),
    instanceType: neptune.InstanceType.R5_LARGE,
    ...options,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_15() {
  const stack = new cdk.Stack();
  
  // ruleid: typescript-cdk-neptune-cluster-backup-retention-period
  const cluster = new neptune.DatabaseCluster(stack, 'NeptuneCluster15', {
    vpc: new cdk.aws_ec2.Vpc(stack, 'Vpc'),
    instanceType: neptune.InstanceType.R5_LARGE,
    backupRetentionPeriod: cdk.Duration.seconds(518400), // 518400 seconds (6 days) is insufficient
  });
}
// {/fact}

// TRUE NEGATIVES (Secure Code)

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_1() {
  const stack = new cdk.Stack();
  
  // ok: typescript-cdk-neptune-cluster-backup-retention-period
  const cluster = new neptune.DatabaseCluster(stack, 'NeptuneCluster1', {
    vpc: new cdk.aws_ec2.Vpc(stack, 'Vpc'),
    instanceType: neptune.InstanceType.R5_LARGE,
    backupRetentionPeriod: cdk.Duration.days(7), // 7 days is sufficient
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_2() {
  const stack = new cdk.Stack();
  
  // ok: typescript-cdk-neptune-cluster-backup-retention-period
  const cluster = new neptune.DatabaseCluster(stack, 'NeptuneCluster2', {
    vpc: new cdk.aws_ec2.Vpc(stack, 'Vpc'),
    instanceType: neptune.InstanceType.R5_LARGE,
    backupRetentionPeriod: cdk.Duration.days(14), // 14 days is sufficient
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_3() {
  const stack = new cdk.Stack();
  const vpc = new cdk.aws_ec2.Vpc(stack, 'Vpc');
  
  // ok: typescript-cdk-neptune-cluster-backup-retention-period
  const cluster = new neptune.DatabaseCluster(stack, 'NeptuneCluster3', {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
    backupRetentionPeriod: cdk.Duration.days(30), // 30 days is sufficient
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_4() {
  const stack = new cdk.Stack();
  const retentionPeriod = cdk.Duration.days(10); // 10 days is sufficient
  
  // ok: typescript-cdk-neptune-cluster-backup-retention-period
  const cluster = new neptune.DatabaseCluster(stack, 'NeptuneCluster4', {
    vpc: new cdk.aws_ec2.Vpc(stack, 'Vpc'),
    instanceType: neptune.InstanceType.R5_LARGE,
    backupRetentionPeriod: retentionPeriod,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_5() {
  const stack = new cdk.Stack();
  
  const props = {
    vpc: new cdk.aws_ec2.Vpc(stack, 'Vpc'),
    instanceType: neptune.InstanceType.R5_LARGE,
    backupRetentionPeriod: cdk.Duration.days(21), // 21 days is sufficient
  };
  
  // ok: typescript-cdk-neptune-cluster-backup-retention-period
  const cluster = new neptune.DatabaseCluster(stack, 'NeptuneCluster5', props);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_6() {
  const stack = new cdk.Stack();
  
  class CustomNeptuneStack extends cdk.Stack {
    constructor(scope: Construct, id: string) {
      super(scope, id);
      
      // ok: typescript-cdk-neptune-cluster-backup-retention-period
      new neptune.DatabaseCluster(this, 'NeptuneCluster6', {
        vpc: new cdk.aws_ec2.Vpc(this, 'Vpc'),
        instanceType: neptune.InstanceType.R5_LARGE,
        backupRetentionPeriod: cdk.Duration.days(35), // 35 days is sufficient
      });
    }
  }
  
  new CustomNeptuneStack(stack, 'CustomNeptuneStack');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_7() {
  const stack = new cdk.Stack();
  
  function createNeptuneCluster(scope: Construct) {
    // ok: typescript-cdk-neptune-cluster-backup-retention-period
    return new neptune.DatabaseCluster(scope, 'NeptuneCluster7', {
      vpc: new cdk.aws_ec2.Vpc(scope, 'Vpc'),
      instanceType: neptune.InstanceType.R5_LARGE,
      backupRetentionPeriod: cdk.Duration.hours(168), // 168 hours (7 days) is sufficient
    });
  }
  
  createNeptuneCluster(stack);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_8() {
  const stack = new cdk.Stack();
  const vpc = new cdk.aws_ec2.Vpc(stack, 'Vpc');
  
  // ok: typescript-cdk-neptune-cluster-backup-retention-period
  const cluster = new neptune.DatabaseCluster(stack, 'NeptuneCluster8', {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
    backupRetentionPeriod: cdk.Duration.days(8), // 8 days is sufficient
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_9() {
  const stack = new cdk.Stack();
  const days = 15; // 15 days is sufficient
  
  // ok: typescript-cdk-neptune-cluster-backup-retention-period
  const cluster = new neptune.DatabaseCluster(stack, 'NeptuneCluster9', {
    vpc: new cdk.aws_ec2.Vpc(stack, 'Vpc'),
    instanceType: neptune.InstanceType.R5_LARGE,
    backupRetentionPeriod: cdk.Duration.days(days),
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_10() {
  const stack = new cdk.Stack();
  
  const options = {
    backupRetentionPeriod: cdk.Duration.days(28), // 28 days is sufficient
  };
  
  // ok: typescript-cdk-neptune-cluster-backup-retention-period
  const cluster = new neptune.DatabaseCluster(stack, 'NeptuneCluster10', {
    vpc: new cdk.aws_ec2.Vpc(stack, 'Vpc'),
    instanceType: neptune.InstanceType.R5_LARGE,
    ...options,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_11() {
  const stack = new cdk.Stack();
  
  // ok: typescript-cdk-neptune-cluster-backup-retention-period
  const cluster = new neptune.DatabaseCluster(stack, 'NeptuneCluster11', {
    vpc: new cdk.aws_ec2.Vpc(stack, 'Vpc'),
    instanceType: neptune.InstanceType.R5_LARGE,
    backupRetentionPeriod: cdk.Duration.minutes(10080), // 10080 minutes (7 days) is sufficient
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_12() {
  const stack = new cdk.Stack();
  
  // ok: typescript-cdk-neptune-cluster-backup-retention-period
  const cluster = new neptune.DatabaseCluster(stack, 'NeptuneCluster12', {
    vpc: new cdk.aws_ec2.Vpc(stack, 'Vpc'),
    instanceType: neptune.InstanceType.R5_LARGE,
    backupRetentionPeriod: cdk.Duration.seconds(604800), // 604800 seconds (7 days) is sufficient
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_13() {
  const stack = new cdk.Stack();
  
  const getRetentionPeriod = () => {
    return cdk.Duration.days(14); // 14 days is sufficient
  };
  
  // ok: typescript-cdk-neptune-cluster-backup-retention-period
  const cluster = new neptune.DatabaseCluster(stack, 'NeptuneCluster13', {
    vpc: new cdk.aws_ec2.Vpc(stack, 'Vpc'),
    instanceType: neptune.InstanceType.R5_LARGE,
    backupRetentionPeriod: getRetentionPeriod(),
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_14() {
  const stack = new cdk.Stack();
  
  // ok: typescript-cdk-neptune-cluster-backup-retention-period
  const cluster = new neptune.DatabaseCluster(stack, 'NeptuneCluster14', {
    vpc: new cdk.aws_ec2.Vpc(stack, 'Vpc'),
    instanceType: neptune.InstanceType.R5_LARGE,
    backupRetentionPeriod: cdk.Duration.days(7 * 5), // 35 days is sufficient
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_15() {
  const stack = new cdk.Stack();
  
  const minRetentionDays = 7;
  const additionalDays = 3;
  
  // ok: typescript-cdk-neptune-cluster-backup-retention-period
  const cluster = new neptune.DatabaseCluster(stack, 'NeptuneCluster15', {
    vpc: new cdk.aws_ec2.Vpc(stack, 'Vpc'),
    instanceType: neptune.InstanceType.R5_LARGE,
    backupRetentionPeriod: cdk.Duration.days(minRetentionDays + additionalDays), // 10 days is sufficient
  });
}
// {/fact}