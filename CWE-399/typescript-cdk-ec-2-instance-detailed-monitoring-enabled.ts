import { Stack, App } from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as autoscaling from 'aws-cdk-lib/aws-autoscaling';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import { Monitoring } from 'aws-cdk-lib/aws-autoscaling';

// True Positive Examples (Vulnerable Code)

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_1() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  // ruleid: typescript-cdk-ec-2-instance-detailed-monitoring-enabled
  new autoscaling.AutoScalingGroup(stack, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T2, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    // No instanceMonitoring specified, defaults to basic monitoring
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_2() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  // ruleid: typescript-cdk-ec-2-instance-detailed-monitoring-enabled
  new autoscaling.AutoScalingGroup(stack, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T2, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    instanceMonitoring: Monitoring.BASIC, // Explicitly setting basic monitoring
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_3() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const launchTemplate = new ec2.LaunchTemplate(stack, 'LaunchTemplate', {
    // ruleid: typescript-cdk-ec-2-instance-detailed-monitoring-enabled
    monitoring: false, // Explicitly disabling monitoring
  });
  
  new autoscaling.AutoScalingGroup(stack, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T2, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    launchTemplate: launchTemplate,
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_4() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  // ruleid: typescript-cdk-ec-2-instance-detailed-monitoring-enabled
  new ec2.Instance(stack, 'Instance', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T2, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    // No detailedMonitoring specified, defaults to false
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_5() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  // ruleid: typescript-cdk-ec-2-instance-detailed-monitoring-enabled
  new ec2.Instance(stack, 'Instance', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T2, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    detailedMonitoring: false, // Explicitly disabling detailed monitoring
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_6() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const launchTemplateData = {
    // ruleid: typescript-cdk-ec-2-instance-detailed-monitoring-enabled
    monitoring: { enabled: false }, // Explicitly disabling monitoring in template data
  };
  
  const launchTemplate = new ec2.CfnLaunchTemplate(stack, 'LaunchTemplate', {
    launchTemplateData: launchTemplateData,
  });
  
  new autoscaling.CfnAutoScalingGroup(stack, 'ASG', {
    maxSize: '1',
    minSize: '1',
    launchTemplate: {
      version: launchTemplate.attrLatestVersionNumber,
      launchTemplateId: launchTemplate.ref,
    },
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_7() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  // ruleid: typescript-cdk-ec-2-instance-detailed-monitoring-enabled
  const asg = new autoscaling.AutoScalingGroup(stack, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T2, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
  });
  
  // No instanceMonitoring set after creation either
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_8() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const instanceProps = {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T2, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
  };
  
  // ruleid: typescript-cdk-ec-2-instance-detailed-monitoring-enabled
  new ec2.Instance(stack, 'Instance', instanceProps);
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_9() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const monitoringEnabled = false;
  
  // ruleid: typescript-cdk-ec-2-instance-detailed-monitoring-enabled
  new ec2.Instance(stack, 'Instance', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T2, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    detailedMonitoring: monitoringEnabled,
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_10() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const getMonitoringConfig = () => {
    return Monitoring.BASIC;
  };
  
  // ruleid: typescript-cdk-ec-2-instance-detailed-monitoring-enabled
  new autoscaling.AutoScalingGroup(stack, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T2, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    instanceMonitoring: getMonitoringConfig(),
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_11() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const launchTemplateProps = {
    monitoring: false,
  };
  
  // ruleid: typescript-cdk-ec-2-instance-detailed-monitoring-enabled
  const launchTemplate = new ec2.LaunchTemplate(stack, 'LaunchTemplate', launchTemplateProps);
  
  new autoscaling.AutoScalingGroup(stack, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T2, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    launchTemplate: launchTemplate,
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_12() {
  class MyConstruct extends Construct {
    constructor(scope: Construct, id: string) {
      super(scope, id);
      const vpc = new ec2.Vpc(this, 'MyVpc');
      
      // ruleid: typescript-cdk-ec-2-instance-detailed-monitoring-enabled
      new autoscaling.AutoScalingGroup(this, 'ASG', {
        vpc,
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.T2, ec2.InstanceSize.MICRO),
        machineImage: ec2.MachineImage.latestAmazonLinux(),
        instanceMonitoring: Monitoring.BASIC,
      });
    }
  }
  
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  new MyConstruct(stack, 'MyConstruct');
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_13() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const configureASG = (stack: Stack, vpc: ec2.Vpc) => {
    // ruleid: typescript-cdk-ec-2-instance-detailed-monitoring-enabled
    return new autoscaling.AutoScalingGroup(stack, 'ASG', {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.T2, ec2.InstanceSize.MICRO),
      machineImage: ec2.MachineImage.latestAmazonLinux(),
      // No monitoring config
    });
  };
  
  configureASG(stack, vpc);
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_14() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  // ruleid: typescript-cdk-ec-2-instance-detailed-monitoring-enabled
  const cfnInstance = new ec2.CfnInstance(stack, 'Instance', {
    instanceType: 't2.micro',
    imageId: 'ami-12345678',
    monitoring: false,
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_15() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const asgProps = {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T2, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
  };
  
  // ruleid: typescript-cdk-ec-2-instance-detailed-monitoring-enabled
  new autoscaling.AutoScalingGroup(stack, 'ASG', asgProps);
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=object-presence@v1.0 defects=0}
function good_case_1() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  // ok: typescript-cdk-ec-2-instance-detailed-monitoring-enabled
  new autoscaling.AutoScalingGroup(stack, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T2, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    instanceMonitoring: Monitoring.DETAILED, // Properly enabling detailed monitoring
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_2() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const launchTemplate = new ec2.LaunchTemplate(stack, 'LaunchTemplate', {
    // ok: typescript-cdk-ec-2-instance-detailed-monitoring-enabled
    monitoring: true, // Properly enabling monitoring
  });
  
  new autoscaling.AutoScalingGroup(stack, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T2, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    launchTemplate: launchTemplate,
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_3() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  // ok: typescript-cdk-ec-2-instance-detailed-monitoring-enabled
  new ec2.Instance(stack, 'Instance', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T2, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    detailedMonitoring: true, // Properly enabling detailed monitoring
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_4() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const launchTemplateData = {
    // ok: typescript-cdk-ec-2-instance-detailed-monitoring-enabled
    monitoring: { enabled: true }, // Properly enabling monitoring in template data
  };
  
  const launchTemplate = new ec2.CfnLaunchTemplate(stack, 'LaunchTemplate', {
    launchTemplateData: launchTemplateData,
  });
  
  new autoscaling.CfnAutoScalingGroup(stack, 'ASG', {
    maxSize: '1',
    minSize: '1',
    launchTemplate: {
      version: launchTemplate.attrLatestVersionNumber,
      launchTemplateId: launchTemplate.ref,
    },
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_5() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const asg = new autoscaling.AutoScalingGroup(stack, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T2, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    // ok: typescript-cdk-ec-2-instance-detailed-monitoring-enabled
    instanceMonitoring: Monitoring.DETAILED,
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_6() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const instanceProps = {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T2, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    // ok: typescript-cdk-ec-2-instance-detailed-monitoring-enabled
    detailedMonitoring: true,
  };
  
  new ec2.Instance(stack, 'Instance', instanceProps);
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_7() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const monitoringEnabled = true;
  
  // ok: typescript-cdk-ec-2-instance-detailed-monitoring-enabled
  new ec2.Instance(stack, 'Instance', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T2, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    detailedMonitoring: monitoringEnabled,
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_8() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const getMonitoringConfig = () => {
    return Monitoring.DETAILED;
  };
  
  // ok: typescript-cdk-ec-2-instance-detailed-monitoring-enabled
  new autoscaling.AutoScalingGroup(stack, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T2, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    instanceMonitoring: getMonitoringConfig(),
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_9() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const launchTemplateProps = {
    // ok: typescript-cdk-ec-2-instance-detailed-monitoring-enabled
    monitoring: true,
  };
  
  const launchTemplate = new ec2.LaunchTemplate(stack, 'LaunchTemplate', launchTemplateProps);
  
  new autoscaling.AutoScalingGroup(stack, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T2, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    launchTemplate: launchTemplate,
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_10() {
  class MyConstruct extends Construct {
    constructor(scope: Construct, id: string) {
      super(scope, id);
      const vpc = new ec2.Vpc(this, 'MyVpc');
      
      // ok: typescript-cdk-ec-2-instance-detailed-monitoring-enabled
      new autoscaling.AutoScalingGroup(this, 'ASG', {
        vpc,
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.T2, ec2.InstanceSize.MICRO),
        machineImage: ec2.MachineImage.latestAmazonLinux(),
        instanceMonitoring: Monitoring.DETAILED,
      });
    }
  }
  
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  new MyConstruct(stack, 'MyConstruct');
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_11() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const configureASG = (stack: Stack, vpc: ec2.Vpc) => {
    // ok: typescript-cdk-ec-2-instance-detailed-monitoring-enabled
    return new autoscaling.AutoScalingGroup(stack, 'ASG', {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.T2, ec2.InstanceSize.MICRO),
      machineImage: ec2.MachineImage.latestAmazonLinux(),
      instanceMonitoring: Monitoring.DETAILED,
    });
  };
  
  configureASG(stack, vpc);
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_12() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  // ok: typescript-cdk-ec-2-instance-detailed-monitoring-enabled
  const cfnInstance = new ec2.CfnInstance(stack, 'Instance', {
    instanceType: 't2.micro',
    imageId: 'ami-12345678',
    monitoring: true,
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_13() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const asgProps = {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T2, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    // ok: typescript-cdk-ec-2-instance-detailed-monitoring-enabled
    instanceMonitoring: Monitoring.DETAILED,
  };
  
  new autoscaling.AutoScalingGroup(stack, 'ASG', asgProps);
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_14() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  // Using environment variable to determine monitoring level
  const isProduction = process.env.ENVIRONMENT === 'production';
  
  // ok: typescript-cdk-ec-2-instance-detailed-monitoring-enabled
  new autoscaling.AutoScalingGroup(stack, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T2, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    instanceMonitoring: isProduction ? Monitoring.DETAILED : Monitoring.DETAILED, // Always using DETAILED regardless of environment
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_15() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  // Using a function to configure monitoring based on instance type
  const getMonitoringForInstance = (instanceType: ec2.InstanceType) => {
    // Always return DETAILED monitoring regardless of instance type
    return Monitoring.DETAILED;
  };
  
  const instanceType = ec2.InstanceType.of(ec2.InstanceClass.T2, ec2.InstanceSize.MICRO);
  
  // ok: typescript-cdk-ec-2-instance-detailed-monitoring-enabled
  new autoscaling.AutoScalingGroup(stack, 'ASG', {
    vpc,
    instanceType: instanceType,
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    instanceMonitoring: getMonitoringForInstance(instanceType),
  });
}
// {/fact}