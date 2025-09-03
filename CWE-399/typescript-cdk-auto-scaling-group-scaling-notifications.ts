import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as autoscaling from 'aws-cdk-lib/aws-autoscaling';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as subscriptions from 'aws-cdk-lib/aws-sns-subscriptions';
import * as ec2 from 'aws-cdk-lib/aws-ec2';

// True Positives (Vulnerable Code)

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_1(scope: Construct) {
  // Creating an Auto Scaling Group without any notifications
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript-cdk-auto-scaling-group-scaling-notifications
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T2, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    minCapacity: 1,
    maxCapacity: 3,
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_2(scope: Construct) {
  // Creating an Auto Scaling Group with only partial notifications (missing termination events)
  const vpc = new ec2.Vpc(scope, 'VPC');
  const topic = new sns.Topic(scope, 'Topic');
  
  // ruleid: typescript-cdk-auto-scaling-group-scaling-notifications
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T2, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    minCapacity: 1,
    maxCapacity: 3,
  });
  
  // Only notifying for instance launch events, missing other required notifications
  asg.notifyOnInstanceLaunch(topic);
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_3(scope: Construct) {
  // Creating an Auto Scaling Group with only launch error notifications
  const vpc = new ec2.Vpc(scope, 'VPC');
  const topic = new sns.Topic(scope, 'Topic');
  
  // ruleid: typescript-cdk-auto-scaling-group-scaling-notifications
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.SMALL),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    minCapacity: 2,
    maxCapacity: 5,
  });
  
  // Only notifying for launch error events
  asg.notifyOnLaunchError(topic);
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_4(scope: Construct) {
  // Creating multiple Auto Scaling Groups without notifications
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript-cdk-auto-scaling-group-scaling-notifications
  const asg1 = new autoscaling.AutoScalingGroup(scope, 'ASG1', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T2, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    minCapacity: 1,
    maxCapacity: 3,
  });
  
  // ruleid: typescript-cdk-auto-scaling-group-scaling-notifications
  const asg2 = new autoscaling.AutoScalingGroup(scope, 'ASG2', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T2, ec2.InstanceSize.SMALL),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    minCapacity: 2,
    maxCapacity: 4,
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_5(scope: Construct) {
  // Creating an Auto Scaling Group with only termination notifications
  const vpc = new ec2.Vpc(scope, 'VPC');
  const topic = new sns.Topic(scope, 'Topic');
  
  // ruleid: typescript-cdk-auto-scaling-group-scaling-notifications
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.M5, ec2.InstanceSize.LARGE),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    minCapacity: 2,
    maxCapacity: 10,
  });
  
  // Only notifying for termination events
  asg.notifyOnInstanceTerminate(topic);
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_6(scope: Construct) {
  // Creating an Auto Scaling Group with only termination error notifications
  const vpc = new ec2.Vpc(scope, 'VPC');
  const topic = new sns.Topic(scope, 'Topic');
  
  // ruleid: typescript-cdk-auto-scaling-group-scaling-notifications
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.C5, ec2.InstanceSize.XLARGE),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    minCapacity: 3,
    maxCapacity: 8,
  });
  
  // Only notifying for termination error events
  asg.notifyOnTerminationError(topic);
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_7(scope: Construct) {
  // Creating an Auto Scaling Group with launch and launch error but missing termination notifications
  const vpc = new ec2.Vpc(scope, 'VPC');
  const topic = new sns.Topic(scope, 'Topic');
  
  // ruleid: typescript-cdk-auto-scaling-group-scaling-notifications
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    minCapacity: 1,
    maxCapacity: 5,
  });
  
  // Missing termination and termination error notifications
  asg.notifyOnInstanceLaunch(topic);
  asg.notifyOnLaunchError(topic);
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_8(scope: Construct) {
  // Creating an Auto Scaling Group with termination and termination error but missing launch notifications
  const vpc = new ec2.Vpc(scope, 'VPC');
  const topic = new sns.Topic(scope, 'Topic');
  
  // ruleid: typescript-cdk-auto-scaling-group-scaling-notifications
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.I3, ec2.InstanceSize.XLARGE),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    minCapacity: 2,
    maxCapacity: 6,
  });
  
  // Missing launch and launch error notifications
  asg.notifyOnInstanceTerminate(topic);
  asg.notifyOnTerminationError(topic);
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_9(scope: Construct) {
  // Creating an Auto Scaling Group with launch and termination but missing error notifications
  const vpc = new ec2.Vpc(scope, 'VPC');
  const topic = new sns.Topic(scope, 'Topic');
  
  // ruleid: typescript-cdk-auto-scaling-group-scaling-notifications
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.G4, ec2.InstanceSize.XLARGE),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    minCapacity: 1,
    maxCapacity: 4,
  });
  
  // Missing launch error and termination error notifications
  asg.notifyOnInstanceLaunch(topic);
  asg.notifyOnInstanceTerminate(topic);
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_10(scope: Construct) {
  // Creating an Auto Scaling Group with error notifications but missing success notifications
  const vpc = new ec2.Vpc(scope, 'VPC');
  const topic = new sns.Topic(scope, 'Topic');
  
  // ruleid: typescript-cdk-auto-scaling-group-scaling-notifications
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.M5, ec2.InstanceSize.XLARGE),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    minCapacity: 2,
    maxCapacity: 8,
  });
  
  // Missing instance launch and termination notifications
  asg.notifyOnLaunchError(topic);
  asg.notifyOnTerminationError(topic);
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_11(scope: Construct) {
  // Creating an Auto Scaling Group with notifications set up for a different resource
  const vpc = new ec2.Vpc(scope, 'VPC');
  const topic = new sns.Topic(scope, 'Topic');
  
  // ruleid: typescript-cdk-auto-scaling-group-scaling-notifications
  const asg1 = new autoscaling.AutoScalingGroup(scope, 'ASG1', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    minCapacity: 1,
    maxCapacity: 5,
  });
  
  const asg2 = new autoscaling.AutoScalingGroup(scope, 'ASG2', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    minCapacity: 1,
    maxCapacity: 5,
  });
  
  // Only setting up notifications for asg2, leaving asg1 without notifications
  asg2.notifyOnInstanceLaunch(topic);
  asg2.notifyOnLaunchError(topic);
  asg2.notifyOnInstanceTerminate(topic);
  asg2.notifyOnTerminationError(topic);
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_12(scope: Construct) {
  // Creating an Auto Scaling Group with a topic but not configuring notifications
  const vpc = new ec2.Vpc(scope, 'VPC');
  const topic = new sns.Topic(scope, 'Topic');
  
  // ruleid: typescript-cdk-auto-scaling-group-scaling-notifications
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.C5, ec2.InstanceSize.LARGE),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    minCapacity: 2,
    maxCapacity: 6,
  });
  
  // Creating a topic but not using it for ASG notifications
  topic.addSubscription(new subscriptions.EmailSubscription('admin@example.com'));
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_13(scope: Construct) {
  // Creating an Auto Scaling Group with conditional notifications that might not be applied
  const vpc = new ec2.Vpc(scope, 'VPC');
  const topic = new sns.Topic(scope, 'Topic');
  const enableNotifications = false;
  
  // ruleid: typescript-cdk-auto-scaling-group-scaling-notifications
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.LARGE),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    minCapacity: 1,
    maxCapacity: 4,
  });
  
  // Notifications are conditionally applied and might not be set
  if (enableNotifications) {
    asg.notifyOnInstanceLaunch(topic);
    asg.notifyOnLaunchError(topic);
    asg.notifyOnInstanceTerminate(topic);
    asg.notifyOnTerminationError(topic);
  }
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_14(scope: Construct) {
  // Creating an Auto Scaling Group with notifications that will be added later (but not in this code)
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript-cdk-auto-scaling-group-scaling-notifications
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.M5, ec2.InstanceSize.MEDIUM),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    minCapacity: 2,
    maxCapacity: 5,
  });
  
  // Comment indicating future implementation, but no actual notifications set
  // TODO: Add notifications for scaling events
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_15(scope: Construct) {
  // Creating an Auto Scaling Group with a topic that's not properly configured
  const vpc = new ec2.Vpc(scope, 'VPC');
  let topic: sns.Topic | undefined;
  
  // ruleid: typescript-cdk-auto-scaling-group-scaling-notifications
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.XLARGE),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    minCapacity: 3,
    maxCapacity: 10,
  });
  
  // Topic might be undefined, so notifications might not be properly set up
  if (Math.random() > 0.5) {
    topic = new sns.Topic(scope, 'Topic');
    // Even if topic is created, notifications are not set up for the ASG
  }
}
// {/fact}

// True Negatives (Secure Code)

// {fact rule=object-presence@v1.0 defects=0}
function good_case_1(scope: Construct) {
  // Creating an Auto Scaling Group with all required notifications
  const vpc = new ec2.Vpc(scope, 'VPC');
  const topic = new sns.Topic(scope, 'Topic');
  
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T2, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    minCapacity: 1,
    maxCapacity: 3,
  });
  
  // ok: typescript-cdk-auto-scaling-group-scaling-notifications
  asg.notifyOnInstanceLaunch(topic);
  asg.notifyOnLaunchError(topic);
  asg.notifyOnInstanceTerminate(topic);
  asg.notifyOnTerminationError(topic);
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_2(scope: Construct) {
  // Creating an Auto Scaling Group with all notifications using a different topic for each
  const vpc = new ec2.Vpc(scope, 'VPC');
  const launchTopic = new sns.Topic(scope, 'LaunchTopic');
  const launchErrorTopic = new sns.Topic(scope, 'LaunchErrorTopic');
  const terminateTopic = new sns.Topic(scope, 'TerminateTopic');
  const terminateErrorTopic = new sns.Topic(scope, 'TerminateErrorTopic');
  
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.SMALL),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    minCapacity: 2,
    maxCapacity: 5,
  });
  
  // ok: typescript-cdk-auto-scaling-group-scaling-notifications
  asg.notifyOnInstanceLaunch(launchTopic);
  asg.notifyOnLaunchError(launchErrorTopic);
  asg.notifyOnInstanceTerminate(terminateTopic);
  asg.notifyOnTerminationError(terminateErrorTopic);
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_3(scope: Construct) {
  // Creating multiple Auto Scaling Groups with all required notifications
  const vpc = new ec2.Vpc(scope, 'VPC');
  const topic = new sns.Topic(scope, 'Topic');
  
  const asg1 = new autoscaling.AutoScalingGroup(scope, 'ASG1', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T2, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    minCapacity: 1,
    maxCapacity: 3,
  });
  
  const asg2 = new autoscaling.AutoScalingGroup(scope, 'ASG2', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T2, ec2.InstanceSize.SMALL),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    minCapacity: 2,
    maxCapacity: 4,
  });
  
  // ok: typescript-cdk-auto-scaling-group-scaling-notifications
  asg1.notifyOnInstanceLaunch(topic);
  asg1.notifyOnLaunchError(topic);
  asg1.notifyOnInstanceTerminate(topic);
  asg1.notifyOnTerminationError(topic);
  
  // ok: typescript-cdk-auto-scaling-group-scaling-notifications
  asg2.notifyOnInstanceLaunch(topic);
  asg2.notifyOnLaunchError(topic);
  asg2.notifyOnInstanceTerminate(topic);
  asg2.notifyOnTerminationError(topic);
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_4(scope: Construct) {
  // Creating an Auto Scaling Group with notifications and email subscription
  const vpc = new ec2.Vpc(scope, 'VPC');
  const topic = new sns.Topic(scope, 'Topic');
  
  // Add email subscription to the topic
  topic.addSubscription(new subscriptions.EmailSubscription('admin@example.com'));
  
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.M5, ec2.InstanceSize.LARGE),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    minCapacity: 2,
    maxCapacity: 10,
  });
  
  // ok: typescript-cdk-auto-scaling-group-scaling-notifications
  asg.notifyOnInstanceLaunch(topic);
  asg.notifyOnLaunchError(topic);
  asg.notifyOnInstanceTerminate(topic);
  asg.notifyOnTerminationError(topic);
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_5(scope: Construct) {
  // Creating an Auto Scaling Group with notifications conditionally but ensuring all are set
  const vpc = new ec2.Vpc(scope, 'VPC');
  const topic = new sns.Topic(scope, 'Topic');
  const useDetailedMonitoring = true;
  
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.C5, ec2.InstanceSize.XLARGE),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    minCapacity: 3,
    maxCapacity: 8,
  });
  
  // ok: typescript-cdk-auto-scaling-group-scaling-notifications
  if (useDetailedMonitoring) {
    // Add detailed monitoring with all notifications
    asg.notifyOnInstanceLaunch(topic);
    asg.notifyOnLaunchError(topic);
    asg.notifyOnInstanceTerminate(topic);
    asg.notifyOnTerminationError(topic);
  } else {
    // Still add all required notifications even without detailed monitoring
    asg.notifyOnInstanceLaunch(topic);
    asg.notifyOnLaunchError(topic);
    asg.notifyOnInstanceTerminate(topic);
    asg.notifyOnTerminationError(topic);
  }
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_6(scope: Construct) {
  // Creating an Auto Scaling Group with notifications using a helper function
  const vpc = new ec2.Vpc(scope, 'VPC');
  const topic = new sns.Topic(scope, 'Topic');
  
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    minCapacity: 1,
    maxCapacity: 5,
  });
  
  // Helper function to add all required notifications
  function addAllNotifications(autoScalingGroup: autoscaling.AutoScalingGroup, notificationTopic: sns.Topic) {
    autoScalingGroup.notifyOnInstanceLaunch(notificationTopic);
    autoScalingGroup.notifyOnLaunchError(notificationTopic);
    autoScalingGroup.notifyOnInstanceTerminate(notificationTopic);
    autoScalingGroup.notifyOnTerminationError(notificationTopic);
  }
  
  // ok: typescript-cdk-auto-scaling-group-scaling-notifications
  addAllNotifications(asg, topic);
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_7(scope: Construct) {
  // Creating an Auto Scaling Group with notifications using a loop for multiple topics
  const vpc = new ec2.Vpc(scope, 'VPC');
  const topics = [
    new sns.Topic(scope, 'Topic1'),
    new sns.Topic(scope, 'Topic2'),
    new sns.Topic(scope, 'Topic3')
  ];
  
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.I3, ec2.InstanceSize.XLARGE),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    minCapacity: 2,
    maxCapacity: 6,
  });
  
  // ok: typescript-cdk-auto-scaling-group-scaling-notifications
  // Add notifications to all topics
  for (const topic of topics) {
    asg.notifyOnInstanceLaunch(topic);
    asg.notifyOnLaunchError(topic);
    asg.notifyOnInstanceTerminate(topic);
    asg.notifyOnTerminationError(topic);
  }
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_8(scope: Construct) {
  // Creating an Auto Scaling Group with notifications and custom instance configuration
  const vpc = new ec2.Vpc(scope, 'VPC');
  const topic = new sns.Topic(scope, 'Topic');
  
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.G4, ec2.InstanceSize.XLARGE),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    minCapacity: 1,
    maxCapacity: 4,
    desiredCapacity: 2,
    cooldown: cdk.Duration.minutes(5),
    healthCheck: autoscaling.HealthCheck.ec2(),
  });
  
  // ok: typescript-cdk-auto-scaling-group-scaling-notifications
  asg.notifyOnInstanceLaunch(topic);
  asg.notifyOnLaunchError(topic);
  asg.notifyOnInstanceTerminate(topic);
  asg.notifyOnTerminationError(topic);
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_9(scope: Construct) {
  // Creating an Auto Scaling Group with notifications and scaling policies
  const vpc = new ec2.Vpc(scope, 'VPC');
  const topic = new sns.Topic(scope, 'Topic');
  
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.M5, ec2.InstanceSize.XLARGE),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    minCapacity: 2,
    maxCapacity: 8,
  });
  
  // Add scaling policies
  asg.scaleOnCpuUtilization('CpuScaling', {
    targetUtilizationPercent: 70,
  });
  
  // ok: typescript-cdk-auto-scaling-group-scaling-notifications
  asg.notifyOnInstanceLaunch(topic);
  asg.notifyOnLaunchError(topic);
  asg.notifyOnInstanceTerminate(topic);
  asg.notifyOnTerminationError(topic);
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_10(scope: Construct) {
  // Creating an Auto Scaling Group with notifications and using a factory pattern
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  function createAutoScalingGroup(id: string): autoscaling.AutoScalingGroup {
    const asg = new autoscaling.AutoScalingGroup(scope, id, {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
      machineImage: ec2.MachineImage.latestAmazonLinux(),
      minCapacity: 1,
      maxCapacity: 5,
    });
    
    const topic = new sns.Topic(scope, `${id}Topic`);
    
    // Add all required notifications
    asg.notifyOnInstanceLaunch(topic);
    asg.notifyOnLaunchError(topic);
    asg.notifyOnInstanceTerminate(topic);
    asg.notifyOnTerminationError(topic);
    
    return asg;
  }
  
  // ok: typescript-cdk-auto-scaling-group-scaling-notifications
  const asg = createAutoScalingGroup('ASG');
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_11(scope: Construct) {
  // Creating an Auto Scaling Group with notifications and using a custom topic name
  const vpc = new ec2.Vpc(scope, 'VPC');
  const topicName = 'ASGNotifications';
  const topic = new sns.Topic(scope, 'Topic', {
    topicName: topicName,
  });
  
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.C5, ec2.InstanceSize.LARGE),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    minCapacity: 2,
    maxCapacity: 6,
  });
  
  // ok: typescript-cdk-auto-scaling-group-scaling-notifications
  asg.notifyOnInstanceLaunch(topic);
  asg.notifyOnLaunchError(topic);
  asg.notifyOnInstanceTerminate(topic);
  asg.notifyOnTerminationError(topic);
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_12(scope: Construct) {
  // Creating an Auto Scaling Group with notifications and multiple subscriptions
  const vpc = new ec2.Vpc(scope, 'VPC');
  const topic = new sns.Topic(scope, 'Topic');
  
  // Add multiple subscriptions to the topic
  topic.addSubscription(new subscriptions.EmailSubscription('admin@example.com'));
  topic.addSubscription(new subscriptions.EmailSubscription('alerts@example.com'));
  topic.addSubscription(new subscriptions.SmsSubscription('+1234567890'));
  
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.LARGE),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    minCapacity: 1,
    maxCapacity: 4,
  });
  
  // ok: typescript-cdk-auto-scaling-group-scaling-notifications
  asg.notifyOnInstanceLaunch(topic);
  asg.notifyOnLaunchError(topic);
  asg.notifyOnInstanceTerminate(topic);
  asg.notifyOnTerminationError(topic);
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_13(scope: Construct) {
  // Creating an Auto Scaling Group with notifications and using environment variables for configuration
  const vpc = new ec2.Vpc(scope, 'VPC');
  const topic = new sns.Topic(scope, 'Topic');
  
  // Using environment variables for configuration
  const minCapacity = process.env.MIN_CAPACITY ? parseInt(process.env.MIN_CAPACITY) : 1;
  const maxCapacity = process.env.MAX_CAPACITY ? parseInt(process.env.MAX_CAPACITY) : 5;
  
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.M5, ec2.InstanceSize.MEDIUM),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    minCapacity: minCapacity,
    maxCapacity: maxCapacity,
  });
  
  // ok: typescript-cdk-auto-scaling-group-scaling-notifications
  asg.notifyOnInstanceLaunch(topic);
  asg.notifyOnLaunchError(topic);
  asg.notifyOnInstanceTerminate(topic);
  asg.notifyOnTerminationError(topic);
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_14(scope: Construct) {
  // Creating an Auto Scaling Group with notifications and using a cross-stack reference
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // Simulate a cross-stack reference for the topic
  const topicArn = new cdk.CfnParameter(scope as any, 'TopicArn', {
    type: 'String',
    description: 'ARN of the SNS topic for notifications',
  }).valueAsString;
  
  const topic = sns.Topic.fromTopicArn(scope, 'ImportedTopic', topicArn);
  
  const asg = new autoscaling.AutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.XLARGE),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    minCapacity: 3,
    maxCapacity: 10,
  });
  
  // ok: typescript-cdk-auto-scaling-group-scaling-notifications
  asg.notifyOnInstanceLaunch(topic);
  asg.notifyOnLaunchError(topic);
  asg.notifyOnInstanceTerminate(topic);
  asg.notifyOnTerminationError(topic);
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_15(scope: Construct) {
  // Creating an Auto Scaling Group with notifications using a higher-level construct
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  class SecureAutoScalingGroup extends autoscaling.AutoScalingGroup {
    constructor(scope: Construct, id: string, props: autoscaling.AutoScalingGroupProps) {
      super(scope, id, props);
      
      // Automatically add notifications to all ASGs created with this construct
      const topic = new sns.Topic(scope, `${id}Topic`);
      this.notifyOnInstanceLaunch(topic);
      this.notifyOnLaunchError(topic);
      this.notifyOnInstanceTerminate(topic);
      this.notifyOnTerminationError(topic);
    }
  }
  
  // ok: typescript-cdk-auto-scaling-group-scaling-notifications
  const asg = new SecureAutoScalingGroup(scope, 'ASG', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T2, ec2.InstanceSize.LARGE),
    machineImage: ec2.MachineImage.latestAmazonLinux(),
    minCapacity: 2,
    maxCapacity: 6,
  });
}
// {/fact}