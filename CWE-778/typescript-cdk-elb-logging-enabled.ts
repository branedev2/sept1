import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as elb from 'aws-cdk-lib/aws-elasticloadbalancing';
import * as elbv2 from 'aws-cdk-lib/aws-elasticloadbalancingv2';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as ec2 from 'aws-cdk-lib/aws-ec2';

// True Positive Examples (Vulnerable Code)

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_1(scope: Construct) {
  // Classic Load Balancer without access logging enabled
  // ruleid: typescript-cdk-elb-logging-enabled
  const loadBalancer = new elb.LoadBalancer(scope, 'LoadBalancer', {
    vpc: new ec2.Vpc(scope, 'VPC'),
    internetFacing: true,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_2(scope: Construct) {
  // Application Load Balancer without access logging configured
  // ruleid: typescript-cdk-elb-logging-enabled
  const alb = new elbv2.ApplicationLoadBalancer(scope, 'ALB', {
    vpc: new ec2.Vpc(scope, 'VPC'),
    internetFacing: true,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_3(scope: Construct) {
  // Network Load Balancer without access logging configured
  // ruleid: typescript-cdk-elb-logging-enabled
  const nlb = new elbv2.NetworkLoadBalancer(scope, 'NLB', {
    vpc: new ec2.Vpc(scope, 'VPC'),
    internetFacing: true,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_4(scope: Construct) {
  // Classic Load Balancer with access logging explicitly disabled
  // ruleid: typescript-cdk-elb-logging-enabled
  const loadBalancer = new elb.CfnLoadBalancer(scope, 'LoadBalancer', {
    listeners: [
      {
        loadBalancerPort: '80',
        instancePort: '80',
        protocol: 'HTTP',
      },
    ],
    accessLoggingPolicy: {
      enabled: false,
      s3BucketName: 'my-bucket',
      emitInterval: 60,
      s3BucketPrefix: 'logs',
    },
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_5(scope: Construct) {
  // Application Load Balancer with incomplete logging configuration
  const vpc = new ec2.Vpc(scope, 'VPC');
  // ruleid: typescript-cdk-elb-logging-enabled
  const alb = new elbv2.ApplicationLoadBalancer(scope, 'ALB', {
    vpc,
    internetFacing: true,
  });
  
  // No logging configuration provided
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_6(scope: Construct) {
  // Network Load Balancer in a stack without logging
  const vpc = new ec2.Vpc(scope, 'VPC');
  // ruleid: typescript-cdk-elb-logging-enabled
  const nlb = new elbv2.NetworkLoadBalancer(scope, 'NLB', {
    vpc,
    internetFacing: false,
  });
  
  // Adding listeners but no logging
  nlb.addListener('Listener', {
    port: 80,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_7(scope: Construct, stack: cdk.Stack) {
  // Classic Load Balancer with access logging policy but enabled is missing
  // ruleid: typescript-cdk-elb-logging-enabled
  const loadBalancer = new elb.CfnLoadBalancer(scope, 'LoadBalancer', {
    listeners: [
      {
        loadBalancerPort: '443',
        instancePort: '443',
        protocol: 'HTTPS',
      },
    ],
    accessLoggingPolicy: {
      s3BucketName: 'my-logging-bucket',
      emitInterval: 60,
      s3BucketPrefix: 'elb-logs',
    },
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_8(scope: Construct) {
  // Application Load Balancer with logging bucket but not configured
  const vpc = new ec2.Vpc(scope, 'VPC');
  const logBucket = new s3.Bucket(scope, 'LogBucket');
  
  // ruleid: typescript-cdk-elb-logging-enabled
  const alb = new elbv2.ApplicationLoadBalancer(scope, 'ALB', {
    vpc,
    internetFacing: true,
  });
  
  // Bucket exists but not used for logging
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_9(scope: Construct) {
  // Network Load Balancer with commented out logging configuration
  const vpc = new ec2.Vpc(scope, 'VPC');
  const logBucket = new s3.Bucket(scope, 'LogBucket');
  
  // ruleid: typescript-cdk-elb-logging-enabled
  const nlb = new elbv2.NetworkLoadBalancer(scope, 'NLB', {
    vpc,
    internetFacing: true,
  });
  
  // Logging configuration is commented out
  // nlb.logAccessLogs(logBucket, 'nlb-logs');
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_10(scope: Construct) {
  // Classic Load Balancer with null access logging policy
  // ruleid: typescript-cdk-elb-logging-enabled
  const loadBalancer = new elb.CfnLoadBalancer(scope, 'LoadBalancer', {
    listeners: [
      {
        loadBalancerPort: '80',
        instancePort: '80',
        protocol: 'HTTP',
      },
    ],
    accessLoggingPolicy: null,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_11(scope: Construct) {
  // Application Load Balancer with conditional logging that's not applied
  const vpc = new ec2.Vpc(scope, 'VPC');
  const logBucket = new s3.Bucket(scope, 'LogBucket');
  
  // ruleid: typescript-cdk-elb-logging-enabled
  const alb = new elbv2.ApplicationLoadBalancer(scope, 'ALB', {
    vpc,
    internetFacing: true,
  });
  
  const enableLogging = false;
  if (enableLogging) {
    alb.logAccessLogs(logBucket, 'alb-logs');
  }
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_12(scope: Construct) {
  // Network Load Balancer in a production environment without logging
  const vpc = new ec2.Vpc(scope, 'ProductionVPC');
  
  // ruleid: typescript-cdk-elb-logging-enabled
  const nlb = new elbv2.NetworkLoadBalancer(scope, 'ProductionNLB', {
    vpc,
    internetFacing: true,
    loadBalancerName: 'production-nlb',
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_13(scope: Construct) {
  // Classic Load Balancer with empty access logging policy
  // ruleid: typescript-cdk-elb-logging-enabled
  const loadBalancer = new elb.CfnLoadBalancer(scope, 'LoadBalancer', {
    listeners: [
      {
        loadBalancerPort: '80',
        instancePort: '80',
        protocol: 'HTTP',
      },
    ],
    accessLoggingPolicy: {},
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_14(scope: Construct) {
  // Application Load Balancer with logging configured but then removed
  const vpc = new ec2.Vpc(scope, 'VPC');
  const logBucket = new s3.Bucket(scope, 'LogBucket');
  
  // ruleid: typescript-cdk-elb-logging-enabled
  const alb = new elbv2.ApplicationLoadBalancer(scope, 'ALB', {
    vpc,
    internetFacing: true,
  });
  
  // Configure logging
  alb.logAccessLogs(logBucket, 'alb-logs');
  
  // But then remove it (this is just to illustrate a bad pattern)
  const cfnAlb = alb.node.defaultChild as elbv2.CfnLoadBalancer;
  cfnAlb.loadBalancerAttributes = cfnAlb.loadBalancerAttributes?.filter(
    attr => !attr.key?.startsWith('access_logs')
  );
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_15(scope: Construct) {
  // Network Load Balancer with logging bucket that doesn't have the right permissions
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // Creating a bucket without proper permissions for ELB logging
  const logBucket = new s3.Bucket(scope, 'LogBucket', {
    blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
    encryption: s3.BucketEncryption.S3_MANAGED,
  });
  
  // ruleid: typescript-cdk-elb-logging-enabled
  const nlb = new elbv2.NetworkLoadBalancer(scope, 'NLB', {
    vpc,
    internetFacing: true,
  });
  
  // No logging configured
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_1(scope: Construct) {
  // Classic Load Balancer with access logging enabled
  const logBucket = new s3.Bucket(scope, 'LogBucket');
  
  // ok: typescript-cdk-elb-logging-enabled
  const loadBalancer = new elb.CfnLoadBalancer(scope, 'LoadBalancer', {
    listeners: [
      {
        loadBalancerPort: '80',
        instancePort: '80',
        protocol: 'HTTP',
      },
    ],
    accessLoggingPolicy: {
      enabled: true,
      s3BucketName: logBucket.bucketName,
      emitInterval: 60,
      s3BucketPrefix: 'elb-logs',
    },
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_2(scope: Construct) {
  // Application Load Balancer with S3 access logging configured
  const vpc = new ec2.Vpc(scope, 'VPC');
  const logBucket = new s3.Bucket(scope, 'LogBucket');
  
  const alb = new elbv2.ApplicationLoadBalancer(scope, 'ALB', {
    vpc,
    internetFacing: true,
  });
  
  // ok: typescript-cdk-elb-logging-enabled
  alb.logAccessLogs(logBucket, 'alb-logs');
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_3(scope: Construct) {
  // Network Load Balancer with S3 access logging configured
  const vpc = new ec2.Vpc(scope, 'VPC');
  const logBucket = new s3.Bucket(scope, 'LogBucket');
  
  const nlb = new elbv2.NetworkLoadBalancer(scope, 'NLB', {
    vpc,
    internetFacing: true,
  });
  
  // ok: typescript-cdk-elb-logging-enabled
  nlb.logAccessLogs(logBucket, 'nlb-logs');
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_4(scope: Construct) {
  // Classic Load Balancer with access logging enabled and all parameters
  const logBucket = new s3.Bucket(scope, 'LogBucket');
  
  // ok: typescript-cdk-elb-logging-enabled
  const loadBalancer = new elb.LoadBalancer(scope, 'LoadBalancer', {
    vpc: new ec2.Vpc(scope, 'VPC'),
    internetFacing: true,
    accessLoggingPolicy: {
      enabled: true,
      s3BucketName: logBucket.bucketName,
      emitInterval: 5,
      s3BucketPrefix: 'classic-elb-logs',
    },
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_5(scope: Construct) {
  // Application Load Balancer with CloudWatch logging configured
  const vpc = new ec2.Vpc(scope, 'VPC');
  const logGroup = new logs.LogGroup(scope, 'ALBLogGroup');
  
  const alb = new elbv2.ApplicationLoadBalancer(scope, 'ALB', {
    vpc,
    internetFacing: true,
  });
  
  // ok: typescript-cdk-elb-logging-enabled
  alb.logAccessLogs(undefined, 'alb-logs', logGroup);
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_6(scope: Construct) {
  // Network Load Balancer with logging enabled through attributes
  const vpc = new ec2.Vpc(scope, 'VPC');
  const logBucket = new s3.Bucket(scope, 'LogBucket');
  
  const nlb = new elbv2.NetworkLoadBalancer(scope, 'NLB', {
    vpc,
    internetFacing: true,
  });
  
  // ok: typescript-cdk-elb-logging-enabled
  nlb.logAccessLogs(logBucket);
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_7(scope: Construct) {
  // Classic Load Balancer with access logging enabled conditionally
  const logBucket = new s3.Bucket(scope, 'LogBucket');
  const enableLogging = true;
  
  // ok: typescript-cdk-elb-logging-enabled
  const loadBalancer = new elb.CfnLoadBalancer(scope, 'LoadBalancer', {
    listeners: [
      {
        loadBalancerPort: '80',
        instancePort: '80',
        protocol: 'HTTP',
      },
    ],
    accessLoggingPolicy: enableLogging ? {
      enabled: true,
      s3BucketName: logBucket.bucketName,
      emitInterval: 60,
      s3BucketPrefix: 'elb-logs',
    } : undefined,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_8(scope: Construct) {
  // Application Load Balancer with logging configured in a separate step
  const vpc = new ec2.Vpc(scope, 'VPC');
  const logBucket = new s3.Bucket(scope, 'LogBucket');
  
  const alb = new elbv2.ApplicationLoadBalancer(scope, 'ALB', {
    vpc,
    internetFacing: true,
  });
  
  // ok: typescript-cdk-elb-logging-enabled
  alb.logAccessLogs(logBucket, 'access-logs');
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_9(scope: Construct) {
  // Network Load Balancer with logging configured with prefix
  const vpc = new ec2.Vpc(scope, 'VPC');
  const logBucket = new s3.Bucket(scope, 'LogBucket');
  
  const nlb = new elbv2.NetworkLoadBalancer(scope, 'NLB', {
    vpc,
    internetFacing: true,
  });
  
  // ok: typescript-cdk-elb-logging-enabled
  nlb.logAccessLogs(logBucket, 'network-lb-logs');
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_10(scope: Construct) {
  // Classic Load Balancer with access logging enabled with environment-specific settings
  const env = 'prod';
  const logBucket = new s3.Bucket(scope, 'LogBucket');
  
  // ok: typescript-cdk-elb-logging-enabled
  const loadBalancer = new elb.CfnLoadBalancer(scope, 'LoadBalancer', {
    listeners: [
      {
        loadBalancerPort: '443',
        instancePort: '443',
        protocol: 'HTTPS',
      },
    ],
    accessLoggingPolicy: {
      enabled: true,
      s3BucketName: logBucket.bucketName,
      emitInterval: env === 'prod' ? 5 : 60,
      s3BucketPrefix: `${env}-elb-logs`,
    },
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_11(scope: Construct) {
  // Application Load Balancer with logging enabled through CDK L2 construct
  const vpc = new ec2.Vpc(scope, 'VPC');
  const logBucket = new s3.Bucket(scope, 'LogBucket');
  
  const alb = new elbv2.ApplicationLoadBalancer(scope, 'ALB', {
    vpc,
    internetFacing: true,
  });
  
  // ok: typescript-cdk-elb-logging-enabled
  alb.logAccessLogs(logBucket);
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_12(scope: Construct) {
  // Network Load Balancer with logging configured with both bucket and prefix
  const vpc = new ec2.Vpc(scope, 'VPC');
  const logBucket = new s3.Bucket(scope, 'LogBucket', {
    removalPolicy: cdk.RemovalPolicy.RETAIN,
  });
  
  const nlb = new elbv2.NetworkLoadBalancer(scope, 'NLB', {
    vpc,
    internetFacing: false,
  });
  
  // ok: typescript-cdk-elb-logging-enabled
  nlb.logAccessLogs(logBucket, 'internal-nlb-logs');
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_13(scope: Construct) {
  // Classic Load Balancer with access logging enabled with dynamic bucket name
  const stackName = 'my-stack';
  const logBucket = new s3.Bucket(scope, 'LogBucket');
  
  // ok: typescript-cdk-elb-logging-enabled
  const loadBalancer = new elb.CfnLoadBalancer(scope, 'LoadBalancer', {
    listeners: [
      {
        loadBalancerPort: '80',
        instancePort: '80',
        protocol: 'HTTP',
      },
    ],
    accessLoggingPolicy: {
      enabled: true,
      s3BucketName: logBucket.bucketName,
      emitInterval: 60,
      s3BucketPrefix: `${stackName}/elb-logs`,
    },
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_14(scope: Construct) {
  // Application Load Balancer with logging configured through CloudFormation attributes
  const vpc = new ec2.Vpc(scope, 'VPC');
  const logBucket = new s3.Bucket(scope, 'LogBucket');
  
  const alb = new elbv2.ApplicationLoadBalancer(scope, 'ALB', {
    vpc,
    internetFacing: true,
  });
  
  const cfnAlb = alb.node.defaultChild as elbv2.CfnLoadBalancer;
  
  // ok: typescript-cdk-elb-logging-enabled
  cfnAlb.loadBalancerAttributes = [
    {
      key: 'access_logs.s3.enabled',
      value: 'true',
    },
    {
      key: 'access_logs.s3.bucket',
      value: logBucket.bucketName,
    },
    {
      key: 'access_logs.s3.prefix',
      value: 'alb-logs',
    },
  ];
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_15(scope: Construct) {
  // Network Load Balancer with logging configured in a secure way
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // Create a bucket with proper permissions for ELB logging
  const logBucket = new s3.Bucket(scope, 'LogBucket', {
    blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
    encryption: s3.BucketEncryption.S3_MANAGED,
    lifecycleRules: [
      {
        expiration: cdk.Duration.days(90),
        transitions: [
          {
            storageClass: s3.StorageClass.INFREQUENT_ACCESS,
            transitionAfter: cdk.Duration.days(30),
          },
        ],
      },
    ],
  });
  
  const nlb = new elbv2.NetworkLoadBalancer(scope, 'NLB', {
    vpc,
    internetFacing: true,
  });
  
  // ok: typescript-cdk-elb-logging-enabled
  nlb.logAccessLogs(logBucket, 'secure-nlb-logs');
}
// {/fact}