import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as autoscaling from 'aws-cdk-lib/aws-autoscaling';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as elbv2 from 'aws-cdk-lib/aws-elasticloadbalancingv2';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';

// True Positive Examples (Vulnerable Code)

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_1(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  const alb = new elbv2.ApplicationLoadBalancer(scope, 'ALB', { vpc });
  const listener = alb.addListener('Listener', { port: 80 });
  const targetGroup = listener.addTargets('Fleet', { port: 80 });
  
  // ruleid: typescript-cdk-auto-scaling-group-health-check
  new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    minCapacity: 2,
    maxCapacity: 10,
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_2(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  const alb = new elbv2.ApplicationLoadBalancer(scope, 'ALB', { vpc });
  
  // ruleid: typescript-cdk-auto-scaling-group-health-check
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    healthCheck: autoscaling.HealthCheck.ec2(), // Only EC2 health check, no ELB
  });
  
  const listener = alb.addListener('Listener', { port: 80 });
  const targetGroup = listener.addTargets('Fleet', {
    port: 80,
    targets: [asg]
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_3(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  const nlb = new elbv2.NetworkLoadBalancer(scope, 'NLB', { vpc });
  
  // ruleid: typescript-cdk-auto-scaling-group-health-check
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    // No health check specified, defaults to EC2
  });
  
  const listener = nlb.addListener('Listener', { port: 80 });
  const targetGroup = listener.addTargets('Fleet', {
    port: 80,
    targets: [asg]
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_4(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript-cdk-auto-scaling-group-health-check
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    healthCheck: autoscaling.HealthCheck.ec2(),
    cooldown: cdk.Duration.seconds(300),
  });
  
  // Create ALB after ASG
  const alb = new elbv2.ApplicationLoadBalancer(scope, 'ALB', { vpc });
  const listener = alb.addListener('Listener', { port: 80 });
  listener.addTargets('Fleet', {
    port: 80,
    targets: [asg]
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_5(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  const alb = new elbv2.ApplicationLoadBalancer(scope, 'ALB', { vpc });
  
  // ruleid: typescript-cdk-auto-scaling-group-health-check
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    // Missing healthCheck property
    desiredCapacity: 3,
  });
  
  const listener = alb.addListener('Listener', { port: 80 });
  listener.addTargets('Fleet', {
    port: 80,
    targets: [asg]
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_6(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  const alb = new elbv2.ApplicationLoadBalancer(scope, 'ALB', { vpc });
  
  // ruleid: typescript-cdk-auto-scaling-group-health-check
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    healthCheck: {
      type: autoscaling.HealthCheckType.EC2,
      gracePeriod: cdk.Duration.minutes(5),
    },
  });
  
  asg.attachToApplicationTargetGroup(
    listener.addTargets('Fleet', { port: 80 })
  );
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_7(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript-cdk-auto-scaling-group-health-check
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    healthCheck: autoscaling.HealthCheck.ec2(),
  });
  
  // Creating ALB and attaching ASG later
  const alb = new elbv2.ApplicationLoadBalancer(scope, 'ALB', { vpc });
  const listener = alb.addListener('Listener', { port: 80 });
  const targetGroup = listener.addTargets('Fleet', { port: 80 });
  
  asg.attachToApplicationTargetGroup(targetGroup);
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_8(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  const alb = new elbv2.ApplicationLoadBalancer(scope, 'ALB', { vpc });
  
  // ruleid: typescript-cdk-auto-scaling-group-health-check
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    // Using explicit EC2 health check type
    healthCheck: {
      type: autoscaling.HealthCheckType.EC2,
    },
  });
  
  const listener = alb.addListener('Listener', { port: 80 });
  listener.addTargets('WebTargets', {
    port: 80,
    targets: [asg],
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_9(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  const alb = new elbv2.ApplicationLoadBalancer(scope, 'ALB', { vpc });
  
  // ruleid: typescript-cdk-auto-scaling-group-health-check
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
  });
  
  // Setting up scaling policies but no ELB health check
  asg.scaleOnCpuUtilization('CpuScaling', {
    targetUtilizationPercent: 50,
  });
  
  const listener = alb.addListener('Listener', { port: 80 });
  listener.addTargets('Fleet', {
    port: 80,
    targets: [asg],
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_10(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  const alb = new elbv2.ApplicationLoadBalancer(scope, 'ALB', { vpc });
  
  // ruleid: typescript-cdk-auto-scaling-group-health-check
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    // Setting up custom health check but not ELB
    healthCheck: {
      type: autoscaling.HealthCheckType.EC2,
      gracePeriod: cdk.Duration.seconds(300),
    },
  });
  
  // Setting up ALB with ASG
  const listener = alb.addListener('Listener', { port: 80 });
  const targetGroup = listener.addTargets('Fleet', {
    port: 80,
    targets: [asg],
    healthCheck: {
      path: '/health',
      interval: cdk.Duration.seconds(30),
    },
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_11(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  const alb = new elbv2.ApplicationLoadBalancer(scope, 'ALB', { vpc });
  
  // ruleid: typescript-cdk-auto-scaling-group-health-check
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
  });
  
  // Setting up metrics but no ELB health check
  new cloudwatch.Metric({
    namespace: 'AWS/AutoScaling',
    metricName: 'GroupInServiceInstances',
    dimensionsMap: {
      AutoScalingGroupName: asg.autoScalingGroupName,
    },
    statistic: 'Average',
    period: cdk.Duration.minutes(5),
  });
  
  const listener = alb.addListener('Listener', { port: 80 });
  listener.addTargets('Fleet', {
    port: 80,
    targets: [asg],
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_12(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript-cdk-auto-scaling-group-health-check
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    // Using EC2 health check explicitly
    healthCheck: autoscaling.HealthCheck.ec2(),
  });
  
  // Create ALB and attach ASG
  const alb = new elbv2.ApplicationLoadBalancer(scope, 'ALB', { vpc });
  const listener = alb.addListener('Listener', { port: 80 });
  
  // Even with health check in target group, ASG still needs ELB health check
  const targetGroup = listener.addTargets('Fleet', {
    port: 80,
    targets: [asg],
    healthCheck: {
      path: '/health',
      interval: cdk.Duration.seconds(60),
      timeout: cdk.Duration.seconds(5),
    },
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_13(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  const alb = new elbv2.ApplicationLoadBalancer(scope, 'ALB', { vpc });
  
  // ruleid: typescript-cdk-auto-scaling-group-health-check
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    // No health check specified, defaults to EC2
    minCapacity: 1,
    maxCapacity: 5,
    desiredCapacity: 2,
  });
  
  // Using a more complex setup with multiple listeners
  const httpListener = alb.addListener('HttpListener', { port: 80 });
  const httpsListener = alb.addListener('HttpsListener', { port: 443 });
  
  httpListener.addTargets('HttpTargets', {
    port: 80,
    targets: [asg],
  });
  
  httpsListener.addTargets('HttpsTargets', {
    port: 443,
    targets: [asg],
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_14(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript-cdk-auto-scaling-group-health-check
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    // Using EC2 health check with custom grace period
    healthCheck: {
      type: autoscaling.HealthCheckType.EC2,
      gracePeriod: cdk.Duration.minutes(10),
    },
  });
  
  // Create NLB and attach ASG
  const nlb = new elbv2.NetworkLoadBalancer(scope, 'NLB', { vpc });
  const listener = nlb.addListener('Listener', { port: 80 });
  
  listener.addTargets('Fleet', {
    port: 80,
    targets: [asg],
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_15(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  const alb = new elbv2.ApplicationLoadBalancer(scope, 'ALB', { vpc });
  
  // ruleid: typescript-cdk-auto-scaling-group-health-check
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    // Explicitly setting EC2 health check type
    healthCheck: {
      type: autoscaling.HealthCheckType.EC2,
      gracePeriod: cdk.Duration.minutes(5),
    },
    updatePolicy: autoscaling.UpdatePolicy.rollingUpdate(),
  });
  
  const listener = alb.addListener('Listener', { port: 80 });
  listener.addTargets('Fleet', {
    port: 80,
    targets: [asg],
  });
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=object-presence@v1.0 defects=0}
function good_case_1(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  const alb = new elbv2.ApplicationLoadBalancer(scope, 'ALB', { vpc });
  
  // ok: typescript-cdk-auto-scaling-group-health-check
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    healthCheck: autoscaling.HealthCheck.elb(), // Using ELB health check
  });
  
  const listener = alb.addListener('Listener', { port: 80 });
  listener.addTargets('Fleet', {
    port: 80,
    targets: [asg],
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_2(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  const alb = new elbv2.ApplicationLoadBalancer(scope, 'ALB', { vpc });
  
  // ok: typescript-cdk-auto-scaling-group-health-check
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    healthCheck: {
      type: autoscaling.HealthCheckType.ELB,
      gracePeriod: cdk.Duration.minutes(5),
    },
  });
  
  const listener = alb.addListener('Listener', { port: 80 });
  listener.addTargets('Fleet', {
    port: 80,
    targets: [asg],
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_3(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  const nlb = new elbv2.NetworkLoadBalancer(scope, 'NLB', { vpc });
  
  // ok: typescript-cdk-auto-scaling-group-health-check
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    healthCheck: autoscaling.HealthCheck.elb(),
  });
  
  const listener = nlb.addListener('Listener', { port: 80 });
  listener.addTargets('Fleet', {
    port: 80,
    targets: [asg],
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_4(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  const alb = new elbv2.ApplicationLoadBalancer(scope, 'ALB', { vpc });
  
  // ok: typescript-cdk-auto-scaling-group-health-check
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    healthCheck: {
      type: autoscaling.HealthCheckType.ELB,
      gracePeriod: cdk.Duration.seconds(300),
    },
    cooldown: cdk.Duration.seconds(300),
  });
  
  const listener = alb.addListener('Listener', { port: 80 });
  listener.addTargets('Fleet', {
    port: 80,
    targets: [asg],
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_5(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  const alb = new elbv2.ApplicationLoadBalancer(scope, 'ALB', { vpc });
  
  // ok: typescript-cdk-auto-scaling-group-health-check
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    healthCheck: autoscaling.HealthCheck.elb(),
    desiredCapacity: 3,
  });
  
  asg.scaleOnCpuUtilization('CpuScaling', {
    targetUtilizationPercent: 50,
  });
  
  const listener = alb.addListener('Listener', { port: 80 });
  listener.addTargets('Fleet', {
    port: 80,
    targets: [asg],
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_6(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  const alb = new elbv2.ApplicationLoadBalancer(scope, 'ALB', { vpc });
  
  // ok: typescript-cdk-auto-scaling-group-health-check
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    healthCheck: autoscaling.HealthCheck.elb(),
  });
  
  const listener = alb.addListener('Listener', { port: 80 });
  const targetGroup = listener.addTargets('Fleet', {
    port: 80,
    targets: [asg],
    healthCheck: {
      path: '/health',
      interval: cdk.Duration.seconds(30),
      timeout: cdk.Duration.seconds(5),
    },
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_7(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript-cdk-auto-scaling-group-health-check
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    healthCheck: autoscaling.HealthCheck.elb(),
  });
  
  // Create ALB after ASG
  const alb = new elbv2.ApplicationLoadBalancer(scope, 'ALB', { vpc });
  const listener = alb.addListener('Listener', { port: 80 });
  listener.addTargets('Fleet', {
    port: 80,
    targets: [asg],
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_8(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  const alb = new elbv2.ApplicationLoadBalancer(scope, 'ALB', { vpc });
  
  // ok: typescript-cdk-auto-scaling-group-health-check
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    healthCheck: {
      type: autoscaling.HealthCheckType.ELB,
      gracePeriod: cdk.Duration.minutes(2),
    },
    minCapacity: 2,
    maxCapacity: 10,
  });
  
  const listener = alb.addListener('Listener', { port: 80 });
  listener.addTargets('WebTargets', {
    port: 80,
    targets: [asg],
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_9(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript-cdk-auto-scaling-group-health-check
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    healthCheck: autoscaling.HealthCheck.elb(),
  });
  
  // Create NLB and attach ASG
  const nlb = new elbv2.NetworkLoadBalancer(scope, 'NLB', { vpc });
  const listener = nlb.addListener('Listener', { port: 80 });
  
  listener.addTargets('Fleet', {
    port: 80,
    targets: [asg],
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_10(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  const alb = new elbv2.ApplicationLoadBalancer(scope, 'ALB', { vpc });
  
  // ok: typescript-cdk-auto-scaling-group-health-check
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    healthCheck: autoscaling.HealthCheck.elb(),
    updatePolicy: autoscaling.UpdatePolicy.rollingUpdate(),
  });
  
  // Using a more complex setup with multiple listeners
  const httpListener = alb.addListener('HttpListener', { port: 80 });
  const httpsListener = alb.addListener('HttpsListener', { port: 443 });
  
  httpListener.addTargets('HttpTargets', {
    port: 80,
    targets: [asg],
  });
  
  httpsListener.addTargets('HttpsTargets', {
    port: 443,
    targets: [asg],
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_11(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  const alb = new elbv2.ApplicationLoadBalancer(scope, 'ALB', { vpc });
  
  // ok: typescript-cdk-auto-scaling-group-health-check
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    healthCheck: {
      type: autoscaling.HealthCheckType.ELB,
      gracePeriod: cdk.Duration.minutes(5),
    },
  });
  
  // Setting up metrics with ELB health check
  new cloudwatch.Metric({
    namespace: 'AWS/AutoScaling',
    metricName: 'GroupInServiceInstances',
    dimensionsMap: {
      AutoScalingGroupName: asg.autoScalingGroupName,
    },
    statistic: 'Average',
    period: cdk.Duration.minutes(5),
  });
  
  const listener = alb.addListener('Listener', { port: 80 });
  listener.addTargets('Fleet', {
    port: 80,
    targets: [asg],
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_12(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  const alb = new elbv2.ApplicationLoadBalancer(scope, 'ALB', { vpc });
  
  // ok: typescript-cdk-auto-scaling-group-health-check
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    healthCheck: autoscaling.HealthCheck.elb(),
  });
  
  // Create target group first
  const targetGroup = new elbv2.ApplicationTargetGroup(scope, 'TargetGroup', {
    vpc,
    port: 80,
    targets: [asg],
    healthCheck: {
      path: '/health',
      interval: cdk.Duration.seconds(30),
    },
  });
  
  // Then add to listener
  const listener = alb.addListener('Listener', { port: 80 });
  listener.addTargetGroups('Fleet', {
    targetGroups: [targetGroup],
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_13(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  const alb = new elbv2.ApplicationLoadBalancer(scope, 'ALB', { vpc });
  
  // ok: typescript-cdk-auto-scaling-group-health-check
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    healthCheck: {
      type: autoscaling.HealthCheckType.ELB,
      gracePeriod: cdk.Duration.minutes(3),
    },
    minCapacity: 1,
    maxCapacity: 5,
    desiredCapacity: 2,
  });
  
  // Using a more complex setup with path-based routing
  const listener = alb.addListener('Listener', { port: 80 });
  
  // Add default target
  listener.addTargets('Default', {
    port: 80,
    targets: [asg],
    priority: 10,
    conditions: [
      elbv2.ListenerCondition.pathPatterns(['/api/*']),
    ],
  });
  
  // Add another path-based target
  listener.addTargets('Static', {
    port: 80,
    targets: [asg],
    priority: 20,
    conditions: [
      elbv2.ListenerCondition.pathPatterns(['/static/*']),
    ],
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_14(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript-cdk-auto-scaling-group-health-check
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    healthCheck: autoscaling.HealthCheck.elb(),
  });
  
  // Create ALB with HTTPS listener
  const alb = new elbv2.ApplicationLoadBalancer(scope, 'ALB', { vpc });
  const listener = alb.addListener('HttpsListener', { 
    port: 443,
    certificates: [/* certificate details would go here */],
  });
  
  listener.addTargets('Fleet', {
    port: 80,
    targets: [asg],
    healthCheck: {
      path: '/health',
      interval: cdk.Duration.seconds(60),
      timeout: cdk.Duration.seconds(5),
      healthyThresholdCount: 2,
      unhealthyThresholdCount: 3,
    },
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_15(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  const alb = new elbv2.ApplicationLoadBalancer(scope, 'ALB', { vpc });
  
  // ok: typescript-cdk-auto-scaling-group-health-check
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    healthCheck: {
      type: autoscaling.HealthCheckType.ELB,
      gracePeriod: cdk.Duration.minutes(5),
    },
    minCapacity: 2,
    maxCapacity: 10,
    desiredCapacity: 4,
  });
  
  // Setting up scaling policies with ELB health check
  asg.scaleOnCpuUtilization('CpuScaling', {
    targetUtilizationPercent: 50,
  });
  
  asg.scaleOnSchedule('ScaleUpInMorning', {
    schedule: autoscaling.Schedule.cron({ hour: '8', minute: '0' }),
    desiredCapacity: 5,
  });
  
  asg.scaleOnSchedule('ScaleDownAtNight', {
    schedule: autoscaling.Schedule.cron({ hour: '20', minute: '0' }),
    desiredCapacity: 2,
  });
  
  const listener = alb.addListener('Listener', { port: 80 });
  listener.addTargets('Fleet', {
    port: 80,
    targets: [asg],
  });
}
// {/fact}