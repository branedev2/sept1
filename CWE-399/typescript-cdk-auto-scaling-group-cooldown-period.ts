import { Stack, StackProps } from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as autoscaling from 'aws-cdk-lib/aws-autoscaling';
import * as ec2 from 'aws-cdk-lib/aws-ec2';

// TRUE POSITIVES (vulnerable cases)

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_1() {
  const stack = new Stack();
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ruleid: typescript-cdk-auto-scaling-group-cooldown-period
  new autoscaling.AutoScalingGroup(stack, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T2, ec2.InstanceSize.MICRO),
    machineImage: new ec2.AmazonLinuxImage(),
    minCapacity: 1,
    maxCapacity: 10,
    // Missing cooldown period
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_2() {
  const stack = new Stack();
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ruleid: typescript-cdk-auto-scaling-group-cooldown-period
  const asg = new autoscaling.AutoScalingGroup(stack, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.SMALL),
    machineImage: new ec2.AmazonLinuxImage(),
    minCapacity: 2,
    maxCapacity: 5,
    // No cooldown period defined
  });
  
  asg.scaleOnCpuUtilization('CpuScaling', {
    targetUtilizationPercent: 50,
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_3() {
  class MyStack extends Stack {
    constructor(scope: Construct, id: string, props?: StackProps) {
      super(scope, id, props);
      
      const vpc = new ec2.Vpc(this, 'VPC');
      
      // ruleid: typescript-cdk-auto-scaling-group-cooldown-period
      const asg = new autoscaling.AutoScalingGroup(this, 'ASG', {
        vpc,
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.M5, ec2.InstanceSize.LARGE),
        machineImage: new ec2.AmazonLinuxImage(),
        minCapacity: 3,
        maxCapacity: 15,
        // Cooldown period not specified
      });
    }
  }
  
  const app = new Stack();
  new MyStack(app, 'MyStack');
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_4() {
  const stack = new Stack();
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const createAsg = () => {
    // ruleid: typescript-cdk-auto-scaling-group-cooldown-period
    return new autoscaling.AutoScalingGroup(stack, 'ASG', {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.C5, ec2.InstanceSize.XLARGE),
      machineImage: new ec2.AmazonLinuxImage(),
      minCapacity: 1,
      maxCapacity: 5,
      // Missing cooldown configuration
    });
  };
  
  const asg = createAsg();
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_5() {
  const stack = new Stack();
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const asgProps = {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    machineImage: new ec2.AmazonLinuxImage(),
    minCapacity: 2,
    maxCapacity: 8,
    // No cooldown period
  };
  
  // ruleid: typescript-cdk-auto-scaling-group-cooldown-period
  new autoscaling.AutoScalingGroup(stack, 'ASG', asgProps);
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_6() {
  const stack = new Stack();
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ruleid: typescript-cdk-auto-scaling-group-cooldown-period
  const asg = new autoscaling.AutoScalingGroup(stack, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T2, ec2.InstanceSize.MICRO),
    machineImage: new ec2.AmazonLinuxImage(),
    minCapacity: 1,
    maxCapacity: 10,
    // Explicitly setting cooldown to 0, which is effectively no cooldown
    cooldown: 0,
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_7() {
  const stack = new Stack();
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const config = {
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.M5, ec2.InstanceSize.LARGE),
    machineImage: new ec2.AmazonLinuxImage(),
    minCapacity: 2,
    maxCapacity: 10,
  };
  
  // ruleid: typescript-cdk-auto-scaling-group-cooldown-period
  new autoscaling.AutoScalingGroup(stack, 'ASG', {
    vpc,
    ...config,
    // No cooldown period in either object
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_8() {
  const stack = new Stack();
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ruleid: typescript-cdk-auto-scaling-group-cooldown-period
  const asg = new autoscaling.AutoScalingGroup(stack, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    machineImage: new ec2.AmazonLinuxImage(),
    minCapacity: 2,
    maxCapacity: 6,
    // Missing cooldown period
  });
  
  // Adding scaling policies but still no cooldown
  asg.scaleOnCpuUtilization('CpuScaling', {
    targetUtilizationPercent: 70,
  });
  
  asg.scaleOnMetric('CustomMetricScaling', {
    metric: new ec2.Metric({
      namespace: 'AWS/EC2',
      metricName: 'NetworkIn',
      statistic: 'Average',
    }),
    scalingSteps: [
      { upper: 10, change: -1 },
      { lower: 50, change: +1 },
      { lower: 70, change: +2 },
    ],
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_9() {
  class InfraStack extends Stack {
    constructor(scope: Construct, id: string, props?: StackProps) {
      super(scope, id, props);
      
      const vpc = new ec2.Vpc(this, 'VPC');
      
      for (let i = 1; i <= 3; i++) {
        // ruleid: typescript-cdk-auto-scaling-group-cooldown-period
        new autoscaling.AutoScalingGroup(this, `ASG-${i}`, {
          vpc,
          instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.SMALL),
          machineImage: new ec2.AmazonLinuxImage(),
          minCapacity: 1,
          maxCapacity: 5,
          // No cooldown period in any of the ASGs
        });
      }
    }
  }
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_10() {
  const stack = new Stack();
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const createAsgWithOptions = (id: string, options: any) => {
    // ruleid: typescript-cdk-auto-scaling-group-cooldown-period
    return new autoscaling.AutoScalingGroup(stack, id, {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.T2, ec2.InstanceSize.MICRO),
      machineImage: new ec2.AmazonLinuxImage(),
      minCapacity: 1,
      maxCapacity: 5,
      ...options,
      // No cooldown period
    });
  };
  
  createAsgWithOptions('ASG1', { desiredCapacity: 2 });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_11() {
  const stack = new Stack();
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  let cooldownValue: number | undefined;
  // cooldownValue remains undefined
  
  // ruleid: typescript-cdk-auto-scaling-group-cooldown-period
  new autoscaling.AutoScalingGroup(stack, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T2, ec2.InstanceSize.MICRO),
    machineImage: new ec2.AmazonLinuxImage(),
    minCapacity: 1,
    maxCapacity: 5,
    cooldown: cooldownValue, // This is undefined, so effectively no cooldown
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_12() {
  const stack = new Stack();
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const environmentConfig = {
    dev: {},
    prod: { cooldown: 300 },
  };
  
  const env = 'dev'; // Using dev environment which has no cooldown
  
  // ruleid: typescript-cdk-auto-scaling-group-cooldown-period
  new autoscaling.AutoScalingGroup(stack, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T2, ec2.InstanceSize.MICRO),
    machineImage: new ec2.AmazonLinuxImage(),
    minCapacity: 1,
    maxCapacity: 5,
    ...environmentConfig[env], // No cooldown for dev environment
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_13() {
  const stack = new Stack();
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ruleid: typescript-cdk-auto-scaling-group-cooldown-period
  const asg = new autoscaling.AutoScalingGroup(stack, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T2, ec2.InstanceSize.MICRO),
    machineImage: new ec2.AmazonLinuxImage(),
    minCapacity: 1,
    maxCapacity: 5,
    // Using negative cooldown, which is invalid and will be ignored
    cooldown: -60,
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_14() {
  const stack = new Stack();
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const asgProps: autoscaling.AutoScalingGroupProps = {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T2, ec2.InstanceSize.MICRO),
    machineImage: new ec2.AmazonLinuxImage(),
    minCapacity: 1,
    maxCapacity: 5,
    // No cooldown property
  };
  
  // ruleid: typescript-cdk-auto-scaling-group-cooldown-period
  new autoscaling.AutoScalingGroup(stack, 'ASG', asgProps);
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_15() {
  const stack = new Stack();
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const options = {
    minCapacity: 1,
    maxCapacity: 5,
  };
  
  // ruleid: typescript-cdk-auto-scaling-group-cooldown-period
  new autoscaling.AutoScalingGroup(stack, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T2, ec2.InstanceSize.MICRO),
    machineImage: new ec2.AmazonLinuxImage(),
    ...options,
    // No cooldown period
  });
}
// {/fact}

// TRUE NEGATIVES (safe cases)

// {fact rule=object-presence@v1.0 defects=0}
function good_case_1() {
  const stack = new Stack();
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ok: typescript-cdk-auto-scaling-group-cooldown-period
  new autoscaling.AutoScalingGroup(stack, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T2, ec2.InstanceSize.MICRO),
    machineImage: new ec2.AmazonLinuxImage(),
    minCapacity: 1,
    maxCapacity: 10,
    cooldown: 300, // 5 minutes cooldown period
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_2() {
  const stack = new Stack();
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ok: typescript-cdk-auto-scaling-group-cooldown-period
  const asg = new autoscaling.AutoScalingGroup(stack, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.SMALL),
    machineImage: new ec2.AmazonLinuxImage(),
    minCapacity: 2,
    maxCapacity: 5,
    cooldown: 180, // 3 minutes cooldown
  });
  
  asg.scaleOnCpuUtilization('CpuScaling', {
    targetUtilizationPercent: 50,
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_3() {
  class MyStack extends Stack {
    constructor(scope: Construct, id: string, props?: StackProps) {
      super(scope, id, props);
      
      const vpc = new ec2.Vpc(this, 'VPC');
      
      // ok: typescript-cdk-auto-scaling-group-cooldown-period
      const asg = new autoscaling.AutoScalingGroup(this, 'ASG', {
        vpc,
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.M5, ec2.InstanceSize.LARGE),
        machineImage: new ec2.AmazonLinuxImage(),
        minCapacity: 3,
        maxCapacity: 15,
        cooldown: 600, // 10 minutes cooldown
      });
    }
  }
  
  const app = new Stack();
  new MyStack(app, 'MyStack');
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_4() {
  const stack = new Stack();
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const createAsg = () => {
    // ok: typescript-cdk-auto-scaling-group-cooldown-period
    return new autoscaling.AutoScalingGroup(stack, 'ASG', {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.C5, ec2.InstanceSize.XLARGE),
      machineImage: new ec2.AmazonLinuxImage(),
      minCapacity: 1,
      maxCapacity: 5,
      cooldown: 240, // 4 minutes cooldown
    });
  };
  
  const asg = createAsg();
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_5() {
  const stack = new Stack();
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const asgProps = {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    machineImage: new ec2.AmazonLinuxImage(),
    minCapacity: 2,
    maxCapacity: 8,
    cooldown: 120, // 2 minutes cooldown
  };
  
  // ok: typescript-cdk-auto-scaling-group-cooldown-period
  new autoscaling.AutoScalingGroup(stack, 'ASG', asgProps);
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_6() {
  const stack = new Stack();
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const cooldownPeriod = 300; // 5 minutes
  
  // ok: typescript-cdk-auto-scaling-group-cooldown-period
  const asg = new autoscaling.AutoScalingGroup(stack, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T2, ec2.InstanceSize.MICRO),
    machineImage: new ec2.AmazonLinuxImage(),
    minCapacity: 1,
    maxCapacity: 10,
    cooldown: cooldownPeriod,
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_7() {
  const stack = new Stack();
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const config = {
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.M5, ec2.InstanceSize.LARGE),
    machineImage: new ec2.AmazonLinuxImage(),
    minCapacity: 2,
    maxCapacity: 10,
    cooldown: 360, // 6 minutes cooldown
  };
  
  // ok: typescript-cdk-auto-scaling-group-cooldown-period
  new autoscaling.AutoScalingGroup(stack, 'ASG', {
    vpc,
    ...config,
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_8() {
  const stack = new Stack();
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ok: typescript-cdk-auto-scaling-group-cooldown-period
  const asg = new autoscaling.AutoScalingGroup(stack, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    machineImage: new ec2.AmazonLinuxImage(),
    minCapacity: 2,
    maxCapacity: 6,
    cooldown: 300, // 5 minutes cooldown
  });
  
  asg.scaleOnCpuUtilization('CpuScaling', {
    targetUtilizationPercent: 70,
  });
  
  asg.scaleOnMetric('CustomMetricScaling', {
    metric: new ec2.Metric({
      namespace: 'AWS/EC2',
      metricName: 'NetworkIn',
      statistic: 'Average',
    }),
    scalingSteps: [
      { upper: 10, change: -1 },
      { lower: 50, change: +1 },
      { lower: 70, change: +2 },
    ],
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_9() {
  class InfraStack extends Stack {
    constructor(scope: Construct, id: string, props?: StackProps) {
      super(scope, id, props);
      
      const vpc = new ec2.Vpc(this, 'VPC');
      
      for (let i = 1; i <= 3; i++) {
        // ok: typescript-cdk-auto-scaling-group-cooldown-period
        new autoscaling.AutoScalingGroup(this, `ASG-${i}`, {
          vpc,
          instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.SMALL),
          machineImage: new ec2.AmazonLinuxImage(),
          minCapacity: 1,
          maxCapacity: 5,
          cooldown: 180 + (i * 60), // Different cooldown for each ASG
        });
      }
    }
  }
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_10() {
  const stack = new Stack();
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const createAsgWithOptions = (id: string, options: any) => {
    // ok: typescript-cdk-auto-scaling-group-cooldown-period
    return new autoscaling.AutoScalingGroup(stack, id, {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.T2, ec2.InstanceSize.MICRO),
      machineImage: new ec2.AmazonLinuxImage(),
      minCapacity: 1,
      maxCapacity: 5,
      cooldown: 300, // 5 minutes cooldown
      ...options,
    });
  };
  
  createAsgWithOptions('ASG1', { desiredCapacity: 2 });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_11() {
  const stack = new Stack();
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const environmentConfig = {
    dev: { cooldown: 180 },
    prod: { cooldown: 300 },
  };
  
  const env = 'dev';
  
  // ok: typescript-cdk-auto-scaling-group-cooldown-period
  new autoscaling.AutoScalingGroup(stack, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T2, ec2.InstanceSize.MICRO),
    machineImage: new ec2.AmazonLinuxImage(),
    minCapacity: 1,
    maxCapacity: 5,
    ...environmentConfig[env], // Includes cooldown for dev environment
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_12() {
  const stack = new Stack();
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const getCooldownForEnvironment = (env: string): number => {
    const cooldowns = {
      dev: 180,
      test: 240,
      prod: 300,
    };
    return cooldowns[env] || 300; // Default to 5 minutes
  };
  
  // ok: typescript-cdk-auto-scaling-group-cooldown-period
  new autoscaling.AutoScalingGroup(stack, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T2, ec2.InstanceSize.MICRO),
    machineImage: new ec2.AmazonLinuxImage(),
    minCapacity: 1,
    maxCapacity: 5,
    cooldown: getCooldownForEnvironment('prod'),
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_13() {
  const stack = new Stack();
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const asgProps: autoscaling.AutoScalingGroupProps = {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T2, ec2.InstanceSize.MICRO),
    machineImage: new ec2.AmazonLinuxImage(),
    minCapacity: 1,
    maxCapacity: 5,
    cooldown: 300, // 5 minutes cooldown
  };
  
  // ok: typescript-cdk-auto-scaling-group-cooldown-period
  new autoscaling.AutoScalingGroup(stack, 'ASG', asgProps);
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_14() {
  const stack = new Stack();
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const options = {
    minCapacity: 1,
    maxCapacity: 5,
  };
  
  // ok: typescript-cdk-auto-scaling-group-cooldown-period
  new autoscaling.AutoScalingGroup(stack, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T2, ec2.InstanceSize.MICRO),
    machineImage: new ec2.AmazonLinuxImage(),
    ...options,
    cooldown: 300, // 5 minutes cooldown
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_15() {
  const stack = new Stack();
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // Dynamically calculate cooldown based on environment
  const isProduction = process.env.NODE_ENV === 'production';
  const cooldownPeriod = isProduction ? 300 : 180; // 5 minutes for prod, 3 minutes for others
  
  // ok: typescript-cdk-auto-scaling-group-cooldown-period
  new autoscaling.AutoScalingGroup(stack, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T2, ec2.InstanceSize.MICRO),
    machineImage: new ec2.AmazonLinuxImage(),
    minCapacity: 1,
    maxCapacity: 5,
    cooldown: cooldownPeriod,
  });
}
// {/fact}