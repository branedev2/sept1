import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as ec2 from 'aws-cdk-lib/aws-ec2';

class EC2TerminationProtectionStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);
  }

  // True Positive Examples (Vulnerable)

  bad_case_1() {
    // EC2 instance with termination protection explicitly disabled
    // ruleid: typescript-cdk-ec2-instance-termination-protection
    new ec2.CfnInstance(this, 'BadInstance1', {
      imageId: 'ami-12345678',
      instanceType: 't2.micro',
      disableApiTermination: false,
    });
  }

  bad_case_2() {
    // Production instance without termination protection
    const vpc = new ec2.Vpc(this, 'ProductionVPC');
    // ruleid: typescript-cdk-ec2-instance-termination-protection
    new ec2.Instance(this, 'ProductionServer', {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.M5, ec2.InstanceSize.LARGE),
      machineImage: ec2.MachineImage.latestAmazonLinux2(),
      disableApiTermination: false,
    });
  }

  bad_case_3() {
    // Database server without termination protection
    const vpc = new ec2.Vpc(this, 'DatabaseVPC');
    // ruleid: typescript-cdk-ec2-instance-termination-protection
    const dbServer = new ec2.Instance(this, 'DatabaseServer', {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.XLARGE),
      machineImage: ec2.MachineImage.latestAmazonLinux2(),
    });
    
    // Setting termination protection to false after creation
    dbServer.node.addPropertyOverride('DisableApiTermination', false);
  }

  bad_case_4() {
    // Critical application server with termination protection disabled
    const vpc = new ec2.Vpc(this, 'AppVPC');
    
    // ruleid: typescript-cdk-ec2-instance-termination-protection
    const props: ec2.InstanceProps = {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.C5, ec2.InstanceSize.LARGE),
      machineImage: ec2.MachineImage.latestAmazonLinux2(),
      disableApiTermination: false,
    };
    
    new ec2.Instance(this, 'CriticalAppServer', props);
  }

  bad_case_5() {
    // Web server in production without termination protection
    const vpc = new ec2.Vpc(this, 'WebVPC');
    
    // ruleid: typescript-cdk-ec2-instance-termination-protection
    new ec2.CfnInstance(this, 'WebServer', {
      imageId: 'ami-87654321',
      instanceType: 't3.large',
      subnetId: vpc.privateSubnets[0].subnetId,
      tags: [
        {
          key: 'Environment',
          value: 'Production'
        }
      ],
      disableApiTermination: false,
    });
  }

  bad_case_6() {
    // Payment processing server without termination protection
    const vpc = new ec2.Vpc(this, 'PaymentVPC');
    
    // ruleid: typescript-cdk-ec2-instance-termination-protection
    const instance = new ec2.Instance(this, 'PaymentServer', {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.M5, ec2.InstanceSize.XLARGE),
      machineImage: ec2.MachineImage.latestAmazonLinux2(),
    });
    
    // Explicitly setting termination protection to false
    const cfnInstance = instance.node.defaultChild as ec2.CfnInstance;
    cfnInstance.disableApiTermination = false;
  }

  bad_case_7() {
    // Cluster of instances without termination protection
    const vpc = new ec2.Vpc(this, 'ClusterVPC');
    
    for (let i = 0; i < 5; i++) {
      // ruleid: typescript-cdk-ec2-instance-termination-protection
      new ec2.Instance(this, `ClusterNode${i}`, {
        vpc,
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.C5, ec2.InstanceSize.LARGE),
        machineImage: ec2.MachineImage.latestAmazonLinux2(),
        disableApiTermination: false,
      });
    }
  }

  bad_case_8() {
    // Authentication server without termination protection
    const vpc = new ec2.Vpc(this, 'AuthVPC');
    
    const securityGroup = new ec2.SecurityGroup(this, 'AuthSG', { vpc });
    securityGroup.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(443));
    
    // ruleid: typescript-cdk-ec2-instance-termination-protection
    new ec2.Instance(this, 'AuthServer', {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
      machineImage: ec2.MachineImage.latestAmazonLinux2(),
      securityGroup,
      disableApiTermination: false,
    });
  }

  bad_case_9() {
    // Backup server without termination protection
    const vpc = new ec2.Vpc(this, 'BackupVPC');
    
    // ruleid: typescript-cdk-ec2-instance-termination-protection
    new ec2.CfnInstance(this, 'BackupServer', {
      imageId: 'ami-12345678',
      instanceType: 'r5.2xlarge',
      blockDeviceMappings: [
        {
          deviceName: '/dev/sda1',
          ebs: {
            volumeSize: 500,
            volumeType: 'gp3',
          },
        },
      ],
      disableApiTermination: false,
    });
  }

  bad_case_10() {
    // Load balancer instance without termination protection
    const vpc = new ec2.Vpc(this, 'LbVPC');
    
    // ruleid: typescript-cdk-ec2-instance-termination-protection
    const loadBalancer = new ec2.Instance(this, 'LoadBalancer', {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.M5, ec2.InstanceSize.XLARGE),
      machineImage: ec2.MachineImage.latestAmazonLinux2(),
    });
    
    const cfnLB = loadBalancer.node.defaultChild as ec2.CfnInstance;
    cfnLB.disableApiTermination = false;
  }

  bad_case_11() {
    // Cache server without termination protection
    const vpc = new ec2.Vpc(this, 'CacheVPC');
    
    // ruleid: typescript-cdk-ec2-instance-termination-protection
    new ec2.Instance(this, 'CacheServer', {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
      machineImage: ec2.MachineImage.latestAmazonLinux2(),
      disableApiTermination: false,
      userData: ec2.UserData.forLinux(),
    });
  }

  bad_case_12() {
    // API gateway server without termination protection
    const vpc = new ec2.Vpc(this, 'ApiVPC');
    
    // ruleid: typescript-cdk-ec2-instance-termination-protection
    new ec2.CfnInstance(this, 'ApiGatewayServer', {
      imageId: 'ami-12345678',
      instanceType: 'c5.large',
      networkInterfaces: [
        {
          deviceIndex: '0',
          associatePublicIpAddress: true,
          deleteOnTermination: true,
        },
      ],
      disableApiTermination: false,
    });
  }

  bad_case_13() {
    // Monitoring server without termination protection
    const vpc = new ec2.Vpc(this, 'MonitoringVPC');
    
    // ruleid: typescript-cdk-ec2-instance-termination-protection
    const monitoringServer = new ec2.Instance(this, 'MonitoringServer', {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.LARGE),
      machineImage: ec2.MachineImage.latestAmazonLinux2(),
    });
    
    // Setting termination protection to false
    const cfnInstance = monitoringServer.node.defaultChild as ec2.CfnInstance;
    cfnInstance.addPropertyOverride('DisableApiTermination', false);
  }

  bad_case_14() {
    // Analytics server without termination protection
    const vpc = new ec2.Vpc(this, 'AnalyticsVPC');
    
    const userData = ec2.UserData.forLinux();
    userData.addCommands('yum update -y', 'yum install -y docker');
    
    // ruleid: typescript-cdk-ec2-instance-termination-protection
    new ec2.Instance(this, 'AnalyticsServer', {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.C5, ec2.InstanceSize.XLARGE),
      machineImage: ec2.MachineImage.latestAmazonLinux2(),
      userData,
      disableApiTermination: false,
    });
  }

  bad_case_15() {
    // Logging server without termination protection
    const vpc = new ec2.Vpc(this, 'LoggingVPC');
    
    // ruleid: typescript-cdk-ec2-instance-termination-protection
    const loggingServer = new ec2.Instance(this, 'LoggingServer', {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.M5, ec2.InstanceSize.LARGE),
      machineImage: ec2.MachineImage.latestAmazonLinux2(),
    });
    
    const cfnInstance = loggingServer.node.defaultChild as ec2.CfnInstance;
    cfnInstance.disableApiTermination = false;
  }

  // True Negative Examples (Secure)

  good_case_1() {
    // EC2 instance with termination protection enabled
    // ok: typescript-cdk-ec2-instance-termination-protection
    new ec2.CfnInstance(this, 'GoodInstance1', {
      imageId: 'ami-12345678',
      instanceType: 't2.micro',
      disableApiTermination: true,
    });
  }

  good_case_2() {
    // Production instance with termination protection
    const vpc = new ec2.Vpc(this, 'SecureProductionVPC');
    // ok: typescript-cdk-ec2-instance-termination-protection
    new ec2.Instance(this, 'SecureProductionServer', {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.M5, ec2.InstanceSize.LARGE),
      machineImage: ec2.MachineImage.latestAmazonLinux2(),
      disableApiTermination: true,
    });
  }

  good_case_3() {
    // Database server with termination protection
    const vpc = new ec2.Vpc(this, 'SecureDatabaseVPC');
    // ok: typescript-cdk-ec2-instance-termination-protection
    const dbServer = new ec2.Instance(this, 'SecureDatabaseServer', {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.XLARGE),
      machineImage: ec2.MachineImage.latestAmazonLinux2(),
    });
    
    // Setting termination protection to true after creation
    dbServer.node.addPropertyOverride('DisableApiTermination', true);
  }

  good_case_4() {
    // Critical application server with termination protection enabled
    const vpc = new ec2.Vpc(this, 'SecureAppVPC');
    
    // ok: typescript-cdk-ec2-instance-termination-protection
    const props: ec2.InstanceProps = {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.C5, ec2.InstanceSize.LARGE),
      machineImage: ec2.MachineImage.latestAmazonLinux2(),
      disableApiTermination: true,
    };
    
    new ec2.Instance(this, 'SecureCriticalAppServer', props);
  }

  good_case_5() {
    // Web server in production with termination protection
    const vpc = new ec2.Vpc(this, 'SecureWebVPC');
    
    // ok: typescript-cdk-ec2-instance-termination-protection
    new ec2.CfnInstance(this, 'SecureWebServer', {
      imageId: 'ami-87654321',
      instanceType: 't3.large',
      subnetId: vpc.privateSubnets[0].subnetId,
      tags: [
        {
          key: 'Environment',
          value: 'Production'
        }
      ],
      disableApiTermination: true,
    });
  }

  good_case_6() {
    // Payment processing server with termination protection
    const vpc = new ec2.Vpc(this, 'SecurePaymentVPC');
    
    // ok: typescript-cdk-ec2-instance-termination-protection
    const instance = new ec2.Instance(this, 'SecurePaymentServer', {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.M5, ec2.InstanceSize.XLARGE),
      machineImage: ec2.MachineImage.latestAmazonLinux2(),
    });
    
    // Explicitly setting termination protection to true
    const cfnInstance = instance.node.defaultChild as ec2.CfnInstance;
    cfnInstance.disableApiTermination = true;
  }

  good_case_7() {
    // Cluster of instances with termination protection
    const vpc = new ec2.Vpc(this, 'SecureClusterVPC');
    
    for (let i = 0; i < 5; i++) {
      // ok: typescript-cdk-ec2-instance-termination-protection
      new ec2.Instance(this, `SecureClusterNode${i}`, {
        vpc,
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.C5, ec2.InstanceSize.LARGE),
        machineImage: ec2.MachineImage.latestAmazonLinux2(),
        disableApiTermination: true,
      });
    }
  }

  good_case_8() {
    // Authentication server with termination protection
    const vpc = new ec2.Vpc(this, 'SecureAuthVPC');
    
    const securityGroup = new ec2.SecurityGroup(this, 'SecureAuthSG', { vpc });
    securityGroup.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(443));
    
    // ok: typescript-cdk-ec2-instance-termination-protection
    new ec2.Instance(this, 'SecureAuthServer', {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
      machineImage: ec2.MachineImage.latestAmazonLinux2(),
      securityGroup,
      disableApiTermination: true,
    });
  }

  good_case_9() {
    // Backup server with termination protection
    const vpc = new ec2.Vpc(this, 'SecureBackupVPC');
    
    // ok: typescript-cdk-ec2-instance-termination-protection
    new ec2.CfnInstance(this, 'SecureBackupServer', {
      imageId: 'ami-12345678',
      instanceType: 'r5.2xlarge',
      blockDeviceMappings: [
        {
          deviceName: '/dev/sda1',
          ebs: {
            volumeSize: 500,
            volumeType: 'gp3',
          },
        },
      ],
      disableApiTermination: true,
    });
  }

  good_case_10() {
    // Load balancer instance with termination protection
    const vpc = new ec2.Vpc(this, 'SecureLbVPC');
    
    // ok: typescript-cdk-ec2-instance-termination-protection
    const loadBalancer = new ec2.Instance(this, 'SecureLoadBalancer', {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.M5, ec2.InstanceSize.XLARGE),
      machineImage: ec2.MachineImage.latestAmazonLinux2(),
    });
    
    const cfnLB = loadBalancer.node.defaultChild as ec2.CfnInstance;
    cfnLB.disableApiTermination = true;
  }

  good_case_11() {
    // Cache server with termination protection
    const vpc = new ec2.Vpc(this, 'SecureCacheVPC');
    
    // ok: typescript-cdk-ec2-instance-termination-protection
    new ec2.Instance(this, 'SecureCacheServer', {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
      machineImage: ec2.MachineImage.latestAmazonLinux2(),
      disableApiTermination: true,
      userData: ec2.UserData.forLinux(),
    });
  }

  good_case_12() {
    // API gateway server with termination protection
    const vpc = new ec2.Vpc(this, 'SecureApiVPC');
    
    // ok: typescript-cdk-ec2-instance-termination-protection
    new ec2.CfnInstance(this, 'SecureApiGatewayServer', {
      imageId: 'ami-12345678',
      instanceType: 'c5.large',
      networkInterfaces: [
        {
          deviceIndex: '0',
          associatePublicIpAddress: true,
          deleteOnTermination: true,
        },
      ],
      disableApiTermination: true,
    });
  }

  good_case_13() {
    // Monitoring server with termination protection
    const vpc = new ec2.Vpc(this, 'SecureMonitoringVPC');
    
    // ok: typescript-cdk-ec2-instance-termination-protection
    const monitoringServer = new ec2.Instance(this, 'SecureMonitoringServer', {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.LARGE),
      machineImage: ec2.MachineImage.latestAmazonLinux2(),
    });
    
    // Setting termination protection to true
    const cfnInstance = monitoringServer.node.defaultChild as ec2.CfnInstance;
    cfnInstance.addPropertyOverride('DisableApiTermination', true);
  }

  good_case_14() {
    // Analytics server with termination protection
    const vpc = new ec2.Vpc(this, 'SecureAnalyticsVPC');
    
    const userData = ec2.UserData.forLinux();
    userData.addCommands('yum update -y', 'yum install -y docker');
    
    // ok: typescript-cdk-ec2-instance-termination-protection
    new ec2.Instance(this, 'SecureAnalyticsServer', {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.C5, ec2.InstanceSize.XLARGE),
      machineImage: ec2.MachineImage.latestAmazonLinux2(),
      userData,
      disableApiTermination: true,
    });
  }

  good_case_15() {
    // Logging server with termination protection
    const vpc = new ec2.Vpc(this, 'SecureLoggingVPC');
    
    // ok: typescript-cdk-ec2-instance-termination-protection
    const loggingServer = new ec2.Instance(this, 'SecureLoggingServer', {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.M5, ec2.InstanceSize.LARGE),
      machineImage: ec2.MachineImage.latestAmazonLinux2(),
    });
    
    const cfnInstance = loggingServer.node.defaultChild as ec2.CfnInstance;
    cfnInstance.disableApiTermination = true;
  }
}

const app = new cdk.App();
new EC2TerminationProtectionStack(app, 'EC2TerminationProtectionStack');