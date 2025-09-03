import * as cdk from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as autoscaling from 'aws-cdk-lib/aws-autoscaling';
import * as iam from 'aws-cdk-lib/aws-iam';
import { Construct } from 'constructs';
import * as mfn from 'aws-cdk-lib/aws-managedfleet'; // Hypothetical import for MFN

// True Positives (vulnerable/insecure code that MUST be detected)

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_1(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript_cdk_asg_without_patching
  new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux2(),
    minCapacity: 1,
    maxCapacity: 3,
  });
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_2(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript_cdk_asg_without_patching
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.M5, ec2.InstanceSize.LARGE),
    machineImage: ec2.MachineImage.latestAmazonLinux2(),
    minCapacity: 2,
    maxCapacity: 10,
    desiredCapacity: 2,
  });
  
  // Adding other configurations but not MFN
  asg.scaleOnCpuUtilization('CpuScaling', {
    targetUtilizationPercent: 50,
  });
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_3(scope: Construct, app: cdk.App) {
  const stack = new cdk.Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ruleid: typescript_cdk_asg_without_patching
  const asg = new autoscaling.AutoScalingGroup(stack, 'WebServerASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T2, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux2(),
    minCapacity: 1,
    maxCapacity: 5,
  });
  
  // Adding user data but not MFN
  asg.addUserData(
    'yum update -y',
    'yum install -y httpd',
    'systemctl start httpd',
    'systemctl enable httpd'
  );
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_4(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // Creating a custom role but not using MFN
  const role = new iam.Role(scope, 'ASGRole', {
    assumedBy: new iam.ServicePrincipal('ec2.amazonaws.com'),
  });
  
  role.addManagedPolicy(iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonSSMManagedInstanceCore'));
  
  // ruleid: typescript_cdk_asg_without_patching
  new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.C5, ec2.InstanceSize.LARGE),
    machineImage: ec2.MachineImage.latestAmazonLinux2(),
    role: role,
    minCapacity: 1,
    maxCapacity: 3,
  });
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_5(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript_cdk_asg_without_patching
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.XLARGE),
    machineImage: ec2.MachineImage.latestWindowsImage({
      version: ec2.WindowsVersion.WINDOWS_SERVER_2019_ENGLISH_FULL_BASE,
    }),
    minCapacity: 1,
    maxCapacity: 5,
  });
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_6(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript_cdk_asg_without_patching
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.genericLinux({
      'us-east-1': 'ami-0123456789abcdef0',
      'us-west-2': 'ami-0123456789abcdef1',
    }),
    minCapacity: 1,
    maxCapacity: 3,
  });
  
  // Adding health check but not MFN
  asg.scaleOnSchedule('PeakTimeScaling', {
    schedule: autoscaling.Schedule.cron({ hour: '8', minute: '0' }),
    desiredCapacity: 3,
  });
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_7(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // Creating a launch template but not using MFN
  const launchTemplate = new ec2.LaunchTemplate(scope, 'LaunchTemplate', {
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux2(),
  });
  
  // ruleid: typescript_cdk_asg_without_patching
  new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    launchTemplate: launchTemplate,
    minCapacity: 1,
    maxCapacity: 3,
  });
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_8(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript_cdk_asg_without_patching
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux2(),
    minCapacity: 1,
    maxCapacity: 3,
    updatePolicy: autoscaling.UpdatePolicy.rollingUpdate(),
  });
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_9(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript_cdk_asg_without_patching
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux2(),
    minCapacity: 1,
    maxCapacity: 3,
    spotPrice: '0.01',
  });
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_10(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript_cdk_asg_without_patching
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux2(),
    minCapacity: 1,
    maxCapacity: 3,
    keyName: 'my-key-pair',
  });
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_11(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript_cdk_asg_without_patching
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux2(),
    minCapacity: 1,
    maxCapacity: 3,
    blockDevices: [
      {
        deviceName: '/dev/xvda',
        volume: autoscaling.BlockDeviceVolume.ebs(50),
      },
    ],
  });
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_12(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript_cdk_asg_without_patching
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux2(),
    minCapacity: 1,
    maxCapacity: 3,
    signals: autoscaling.Signals.waitForMinCapacity({
      timeout: cdk.Duration.minutes(10),
    }),
  });
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_13(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript_cdk_asg_without_patching
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux2(),
    minCapacity: 1,
    maxCapacity: 3,
    healthCheck: autoscaling.HealthCheck.elb({
      grace: cdk.Duration.minutes(5),
    }),
  });
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_14(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript_cdk_asg_without_patching
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux2(),
    minCapacity: 1,
    maxCapacity: 3,
    cooldown: cdk.Duration.minutes(5),
  });
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_15(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // Creating a security group but not using MFN
  const securityGroup = new ec2.SecurityGroup(scope, 'SecurityGroup', {
    vpc,
    description: 'Allow SSH access',
    allowAllOutbound: true,
  });
  securityGroup.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(22), 'Allow SSH access');
  
  // ruleid: typescript_cdk_asg_without_patching
  new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux2(),
    minCapacity: 1,
    maxCapacity: 3,
    securityGroup: securityGroup,
  });
}
// {/fact}

// True Negatives (safe/secure code that MUST NOT be detected)

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_1(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript_cdk_asg_without_patching
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux2(),
    minCapacity: 1,
    maxCapacity: 3,
  });
  
  // Using MFN for patching
  const fleet = new mfn.ManagedFleet(scope, 'ManagedFleet', {
    autoScalingGroup: asg,
    patchBaseline: mfn.PatchBaseline.AMAZON_LINUX_2,
    updateSchedule: mfn.UpdateSchedule.cron({
      hour: '3',
      minute: '0',
      weekDay: 'SUN',
    }),
  });
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_2(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript_cdk_asg_without_patching
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.M5, ec2.InstanceSize.LARGE),
    machineImage: ec2.MachineImage.latestAmazonLinux2(),
    minCapacity: 2,
    maxCapacity: 10,
    desiredCapacity: 2,
  });
  
  // Using MFN with custom configuration
  new mfn.ManagedFleet(scope, 'ManagedFleet', {
    autoScalingGroup: asg,
    patchBaseline: mfn.PatchBaseline.AMAZON_LINUX_2,
    updateSchedule: mfn.UpdateSchedule.cron({
      hour: '4',
      minute: '30',
      weekDay: 'TUE',
    }),
    approvalModel: mfn.ApprovalModel.AUTOMATIC,
  });
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_3(scope: Construct, app: cdk.App) {
  const stack = new cdk.Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ok: typescript_cdk_asg_without_patching
  const asg = new autoscaling.AutoScalingGroup(stack, 'WebServerASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T2, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux2(),
    minCapacity: 1,
    maxCapacity: 5,
  });
  
  // Adding user data and MFN
  asg.addUserData(
    'yum update -y',
    'yum install -y httpd',
    'systemctl start httpd',
    'systemctl enable httpd'
  );
  
  new mfn.ManagedFleet(stack, 'ManagedFleet', {
    autoScalingGroup: asg,
    patchBaseline: mfn.PatchBaseline.AMAZON_LINUX_2,
  });
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_4(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // Creating a custom role and using MFN
  const role = new iam.Role(scope, 'ASGRole', {
    assumedBy: new iam.ServicePrincipal('ec2.amazonaws.com'),
  });
  
  role.addManagedPolicy(iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonSSMManagedInstanceCore'));
  
  // ok: typescript_cdk_asg_without_patching
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.C5, ec2.InstanceSize.LARGE),
    machineImage: ec2.MachineImage.latestAmazonLinux2(),
    role: role,
    minCapacity: 1,
    maxCapacity: 3,
  });
  
  new mfn.ManagedFleet(scope, 'ManagedFleet', {
    autoScalingGroup: asg,
    patchBaseline: mfn.PatchBaseline.AMAZON_LINUX_2,
  });
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_5(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript_cdk_asg_without_patching
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.XLARGE),
    machineImage: ec2.MachineImage.latestWindowsImage({
      version: ec2.WindowsVersion.WINDOWS_SERVER_2019_ENGLISH_FULL_BASE,
    }),
    minCapacity: 1,
    maxCapacity: 5,
  });
  
  new mfn.ManagedFleet(scope, 'ManagedFleet', {
    autoScalingGroup: asg,
    patchBaseline: mfn.PatchBaseline.WINDOWS_SERVER_2019,
    updateSchedule: mfn.UpdateSchedule.cron({
      hour: '2',
      minute: '0',
      weekDay: 'SAT',
    }),
  });
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_6(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript_cdk_asg_without_patching
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.genericLinux({
      'us-east-1': 'ami-0123456789abcdef0',
      'us-west-2': 'ami-0123456789abcdef1',
    }),
    minCapacity: 1,
    maxCapacity: 3,
  });
  
  // Adding health check and MFN
  asg.scaleOnSchedule('PeakTimeScaling', {
    schedule: autoscaling.Schedule.cron({ hour: '8', minute: '0' }),
    desiredCapacity: 3,
  });
  
  new mfn.ManagedFleet(scope, 'ManagedFleet', {
    autoScalingGroup: asg,
    patchBaseline: mfn.PatchBaseline.CUSTOM,
    customPatchBaseline: 'pb-0123456789abcdef0',
  });
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_7(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // Creating a launch template and using MFN
  const launchTemplate = new ec2.LaunchTemplate(scope, 'LaunchTemplate', {
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux2(),
  });
  
  // ok: typescript_cdk_asg_without_patching
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    launchTemplate: launchTemplate,
    minCapacity: 1,
    maxCapacity: 3,
  });
  
  new mfn.ManagedFleet(scope, 'ManagedFleet', {
    autoScalingGroup: asg,
    patchBaseline: mfn.PatchBaseline.AMAZON_LINUX_2,
  });
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_8(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript_cdk_asg_without_patching
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux2(),
    minCapacity: 1,
    maxCapacity: 3,
    updatePolicy: autoscaling.UpdatePolicy.rollingUpdate(),
  });
  
  new mfn.ManagedFleet(scope, 'ManagedFleet', {
    autoScalingGroup: asg,
    patchBaseline: mfn.PatchBaseline.AMAZON_LINUX_2,
    approvalModel: mfn.ApprovalModel.MANUAL,
  });
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_9(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript_cdk_asg_without_patching
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux2(),
    minCapacity: 1,
    maxCapacity: 3,
    spotPrice: '0.01',
  });
  
  // Using MFN with spot instances
  new mfn.ManagedFleet(scope, 'ManagedFleet', {
    autoScalingGroup: asg,
    patchBaseline: mfn.PatchBaseline.AMAZON_LINUX_2,
    updateSchedule: mfn.UpdateSchedule.cron({
      hour: '1',
      minute: '0',
      weekDay: 'MON',
    }),
  });
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_10(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript_cdk_asg_without_patching
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux2(),
    minCapacity: 1,
    maxCapacity: 3,
    keyName: 'my-key-pair',
  });
  
  // Using MFN with key pair
  new mfn.ManagedFleet(scope, 'ManagedFleet', {
    autoScalingGroup: asg,
    patchBaseline: mfn.PatchBaseline.AMAZON_LINUX_2,
  });
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_11(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript_cdk_asg_without_patching
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux2(),
    minCapacity: 1,
    maxCapacity: 3,
    blockDevices: [
      {
        deviceName: '/dev/xvda',
        volume: autoscaling.BlockDeviceVolume.ebs(50),
      },
    ],
  });
  
  // Using MFN with block devices
  new mfn.ManagedFleet(scope, 'ManagedFleet', {
    autoScalingGroup: asg,
    patchBaseline: mfn.PatchBaseline.AMAZON_LINUX_2,
  });
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_12(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript_cdk_asg_without_patching
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux2(),
    minCapacity: 1,
    maxCapacity: 3,
    signals: autoscaling.Signals.waitForMinCapacity({
      timeout: cdk.Duration.minutes(10),
    }),
  });
  
  // Using MFN with signals
  new mfn.ManagedFleet(scope, 'ManagedFleet', {
    autoScalingGroup: asg,
    patchBaseline: mfn.PatchBaseline.AMAZON_LINUX_2,
  });
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_13(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript_cdk_asg_without_patching
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux2(),
    minCapacity: 1,
    maxCapacity: 3,
    healthCheck: autoscaling.HealthCheck.elb({
      grace: cdk.Duration.minutes(5),
    }),
  });
  
  // Using MFN with health check
  new mfn.ManagedFleet(scope, 'ManagedFleet', {
    autoScalingGroup: asg,
    patchBaseline: mfn.PatchBaseline.AMAZON_LINUX_2,
  });
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_14(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript_cdk_asg_without_patching
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux2(),
    minCapacity: 1,
    maxCapacity: 3,
    cooldown: cdk.Duration.minutes(5),
  });
  
  // Using MFN with cooldown
  new mfn.ManagedFleet(scope, 'ManagedFleet', {
    autoScalingGroup: asg,
    patchBaseline: mfn.PatchBaseline.AMAZON_LINUX_2,
  });
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_15(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // Creating a security group and using MFN
  const securityGroup = new ec2.SecurityGroup(scope, 'SecurityGroup', {
    vpc,
    description: 'Allow SSH access',
    allowAllOutbound: true,
  });
  securityGroup.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(22), 'Allow SSH access');
  
  // ok: typescript_cdk_asg_without_patching
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux2(),
    minCapacity: 1,
    maxCapacity: 3,
    securityGroup: securityGroup,
  });
  
  new mfn.ManagedFleet(scope, 'ManagedFleet', {
    autoScalingGroup: asg,
    patchBaseline: mfn.PatchBaseline.AMAZON_LINUX_2,
  });
}
// {/fact}