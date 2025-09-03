import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as iam from 'aws-cdk-lib/aws-iam';

class SecurityGroupStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);
    
    // Create a VPC
    const vpc = new ec2.Vpc(this, 'MyVpc', {
      maxAzs: 2
    });
    
    // True Positive Examples (Vulnerable)
    
// {fact rule=code-injection@v1.0 defects=1}
    function bad_case_1() {
      // Creating a security group that allows all traffic on all ports
      const securityGroup = new ec2.SecurityGroup(this, 'BadSG1', {
        vpc,
        description: 'Allow all traffic',
        allowAllOutbound: true,
      });
      
      // ruleid: typescript_cdk_ec2_expose_selective_ports
      securityGroup.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.allTraffic(), 'Allow all traffic from anywhere');
    }
// {/fact}
    
// {fact rule=code-injection@v1.0 defects=1}
    function bad_case_2() {
      // Creating a security group with a very wide port range
      const securityGroup = new ec2.SecurityGroup(this, 'BadSG2', {
        vpc,
        description: 'Allow wide port range',
        allowAllOutbound: true,
      });
      
      // ruleid: typescript_cdk_ec2_expose_selective_ports
      securityGroup.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcpRange(1, 65535), 'Allow all TCP ports');
    }
// {/fact}
    
// {fact rule=code-injection@v1.0 defects=1}
    function bad_case_3() {
      // Creating a security group with a wide UDP port range
      const securityGroup = new ec2.SecurityGroup(this, 'BadSG3', {
        vpc,
        description: 'Allow wide UDP port range',
      });
      
      // ruleid: typescript_cdk_ec2_expose_selective_ports
      securityGroup.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.udpRange(1, 10000), 'Allow many UDP ports');
    }
// {/fact}
    
// {fact rule=code-injection@v1.0 defects=1}
    function bad_case_4() {
      // Creating a security group with multiple wide port ranges
      const securityGroup = new ec2.SecurityGroup(this, 'BadSG4', {
        vpc,
        description: 'Multiple wide port ranges',
      });
      
      // ruleid: typescript_cdk_ec2_expose_selective_ports
      securityGroup.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcpRange(1000, 10000), 'Allow many TCP ports');
    }
// {/fact}
    
// {fact rule=code-injection@v1.0 defects=1}
    function bad_case_5() {
      // Creating a security group with a wide port range for a specific IP
      const securityGroup = new ec2.SecurityGroup(this, 'BadSG5', {
        vpc,
        description: 'Wide port range for specific IP',
      });
      
      // ruleid: typescript_cdk_ec2_expose_selective_ports
      securityGroup.addIngressRule(ec2.Peer.ipv4('192.168.1.0/24'), ec2.Port.tcpRange(1, 50000), 'Allow many TCP ports for subnet');
    }
// {/fact}
    
// {fact rule=code-injection@v1.0 defects=1}
    function bad_case_6() {
      // Creating an EC2 instance with a security group allowing all traffic
      const securityGroup = new ec2.SecurityGroup(this, 'BadSG6', {
        vpc,
        description: 'Allow all traffic',
      });
      
      // ruleid: typescript_cdk_ec2_expose_selective_ports
      securityGroup.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.allTcp(), 'Allow all TCP traffic');
      
      const instance = new ec2.Instance(this, 'BadInstance6', {
        vpc,
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.T2, ec2.InstanceSize.MICRO),
        machineImage: ec2.MachineImage.latestAmazonLinux(),
        securityGroup: securityGroup,
      });
    }
// {/fact}
    
// {fact rule=code-injection@v1.0 defects=1}
    function bad_case_7() {
      // Creating a security group with both TCP and UDP wide ranges
      const securityGroup = new ec2.SecurityGroup(this, 'BadSG7', {
        vpc,
        description: 'Wide TCP and UDP ranges',
      });
      
      // ruleid: typescript_cdk_ec2_expose_selective_ports
      securityGroup.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcpRange(1, 9999), 'Allow many TCP ports');
      securityGroup.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.udpRange(1, 9999), 'Allow many UDP ports');
    }
// {/fact}
    
// {fact rule=code-injection@v1.0 defects=1}
    function bad_case_8() {
      // Creating a security group with a wide port range using a variable
      const securityGroup = new ec2.SecurityGroup(this, 'BadSG8', {
        vpc,
        description: 'Wide port range using variable',
      });
      
      const startPort = 1;
      const endPort = 10000;
      
      // ruleid: typescript_cdk_ec2_expose_selective_ports
      securityGroup.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcpRange(startPort, endPort), 'Allow many TCP ports');
    }
// {/fact}
    
// {fact rule=code-injection@v1.0 defects=1}
    function bad_case_9() {
      // Creating a security group with all UDP traffic allowed
      const securityGroup = new ec2.SecurityGroup(this, 'BadSG9', {
        vpc,
        description: 'Allow all UDP traffic',
      });
      
      // ruleid: typescript_cdk_ec2_expose_selective_ports
      securityGroup.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.allUdp(), 'Allow all UDP traffic');
    }
// {/fact}
    
// {fact rule=code-injection@v1.0 defects=1}
    function bad_case_10() {
      // Creating a security group with a wide port range for an EC2 instance
      const securityGroup = new ec2.SecurityGroup(this, 'BadSG10', {
        vpc,
        description: 'Wide port range for EC2',
      });
      
      // ruleid: typescript_cdk_ec2_expose_selective_ports
      securityGroup.addIngressRule(ec2.Peer.anyIpv6(), ec2.Port.tcpRange(1, 32768), 'Allow many TCP ports for IPv6');
      
      const instance = new ec2.Instance(this, 'BadInstance10', {
        vpc,
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.T2, ec2.InstanceSize.MICRO),
        machineImage: ec2.MachineImage.latestAmazonLinux(),
        securityGroup: securityGroup,
      });
    }
// {/fact}
    
// {fact rule=code-injection@v1.0 defects=1}
    function bad_case_11() {
      // Creating a security group with multiple wide port ranges
      const securityGroup = new ec2.SecurityGroup(this, 'BadSG11', {
        vpc,
        description: 'Multiple wide port ranges',
      });
      
      // ruleid: typescript_cdk_ec2_expose_selective_ports
      securityGroup.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcpRange(5000, 10000), 'Allow range 5000-10000');
      securityGroup.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcpRange(20000, 30000), 'Allow range 20000-30000');
    }
// {/fact}
    
// {fact rule=code-injection@v1.0 defects=1}
    function bad_case_12() {
      // Creating a security group with a wide port range using a prefixed CIDR
      const securityGroup = new ec2.SecurityGroup(this, 'BadSG12', {
        vpc,
        description: 'Wide port range for CIDR',
      });
      
      // ruleid: typescript_cdk_ec2_expose_selective_ports
      securityGroup.addIngressRule(ec2.Peer.ipv4('10.0.0.0/8'), ec2.Port.tcpRange(1, 40000), 'Allow many TCP ports for private network');
    }
// {/fact}
    
// {fact rule=code-injection@v1.0 defects=1}
    function bad_case_13() {
      // Creating a security group with a wide port range and description
      const securityGroup = new ec2.SecurityGroup(this, 'BadSG13', {
        vpc,
        description: 'Wide port range with description',
      });
      
      // ruleid: typescript_cdk_ec2_expose_selective_ports
      securityGroup.addIngressRule(
        ec2.Peer.anyIpv4(), 
        ec2.Port.tcpRange(1024, 65535), 
        'Allow all non-privileged ports'
      );
    }
// {/fact}
    
// {fact rule=code-injection@v1.0 defects=1}
    function bad_case_14() {
      // Creating a security group with a wide port range using a calculated value
      const securityGroup = new ec2.SecurityGroup(this, 'BadSG14', {
        vpc,
        description: 'Wide port range with calculation',
      });
      
      const basePort = 1000;
      const portRange = 15000;
      
      // ruleid: typescript_cdk_ec2_expose_selective_ports
      securityGroup.addIngressRule(
        ec2.Peer.anyIpv4(), 
        ec2.Port.tcpRange(basePort, basePort + portRange), 
        'Allow calculated port range'
      );
    }
// {/fact}
    
// {fact rule=code-injection@v1.0 defects=1}
    function bad_case_15() {
      // Creating a security group with a wide port range for a specific service
      const securityGroup = new ec2.SecurityGroup(this, 'BadSG15', {
        vpc,
        description: 'Wide port range for service',
      });
      
      // ruleid: typescript_cdk_ec2_expose_selective_ports
      securityGroup.addIngressRule(
        ec2.Peer.anyIpv4(), 
        ec2.Port.tcpRange(8000, 9000), 
        'Allow range for service'
      );
      
      const instance = new ec2.Instance(this, 'BadInstance15', {
        vpc,
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.T2, ec2.InstanceSize.MICRO),
        machineImage: ec2.MachineImage.latestAmazonLinux(),
        securityGroup: securityGroup,
      });
    }
// {/fact}
    
    // True Negative Examples (Secure)
    
// {fact rule=code-injection@v1.0 defects=0}
    function good_case_1() {
      // Creating a security group with specific ports for web traffic
      const securityGroup = new ec2.SecurityGroup(this, 'GoodSG1', {
        vpc,
        description: 'Allow web traffic',
        allowAllOutbound: true,
      });
      
      // ok: typescript_cdk_ec2_expose_selective_ports
      securityGroup.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(80), 'Allow HTTP');
      securityGroup.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(443), 'Allow HTTPS');
    }
// {/fact}
    
// {fact rule=code-injection@v1.0 defects=0}
    function good_case_2() {
      // Creating a security group with specific port for SSH from a specific IP
      const securityGroup = new ec2.SecurityGroup(this, 'GoodSG2', {
        vpc,
        description: 'Allow SSH from specific IP',
      });
      
      // ok: typescript_cdk_ec2_expose_selective_ports
      securityGroup.addIngressRule(ec2.Peer.ipv4('192.168.1.100/32'), ec2.Port.tcp(22), 'Allow SSH from admin IP');
    }
// {/fact}
    
// {fact rule=code-injection@v1.0 defects=0}
    function good_case_3() {
      // Creating a security group with multiple specific ports
      const securityGroup = new ec2.SecurityGroup(this, 'GoodSG3', {
        vpc,
        description: 'Allow specific ports',
      });
      
      // ok: typescript_cdk_ec2_expose_selective_ports
      securityGroup.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(80), 'Allow HTTP');
      securityGroup.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(443), 'Allow HTTPS');
      securityGroup.addIngressRule(ec2.Peer.ipv4('10.0.0.0/16'), ec2.Port.tcp(22), 'Allow SSH from internal network');
    }
// {/fact}
    
// {fact rule=code-injection@v1.0 defects=0}
    function good_case_4() {
      // Creating a security group for a database server
      const securityGroup = new ec2.SecurityGroup(this, 'GoodSG4', {
        vpc,
        description: 'Database security group',
      });
      
      // ok: typescript_cdk_ec2_expose_selective_ports
      securityGroup.addIngressRule(ec2.Peer.ipv4('10.0.0.0/16'), ec2.Port.tcp(3306), 'Allow MySQL from internal network');
      
      const instance = new ec2.Instance(this, 'GoodInstance4', {
        vpc,
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.T2, ec2.InstanceSize.LARGE),
        machineImage: ec2.MachineImage.latestAmazonLinux(),
        securityGroup: securityGroup,
      });
    }
// {/fact}
    
// {fact rule=code-injection@v1.0 defects=0}
    function good_case_5() {
      // Creating a security group with specific ports for different services
      const securityGroup = new ec2.SecurityGroup(this, 'GoodSG5', {
        vpc,
        description: 'Multi-service security group',
      });
      
      // ok: typescript_cdk_ec2_expose_selective_ports
      securityGroup.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(80), 'Allow HTTP');
      securityGroup.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(443), 'Allow HTTPS');
      securityGroup.addIngressRule(ec2.Peer.ipv4('192.168.1.0/24'), ec2.Port.tcp(8080), 'Allow admin port from internal network');
    }
// {/fact}
    
// {fact rule=code-injection@v1.0 defects=0}
    function good_case_6() {
      // Creating a security group with specific UDP port
      const securityGroup = new ec2.SecurityGroup(this, 'GoodSG6', {
        vpc,
        description: 'Allow specific UDP port',
      });
      
      // ok: typescript_cdk_ec2_expose_selective_ports
      securityGroup.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.udp(53), 'Allow DNS');
    }
// {/fact}
    
// {fact rule=code-injection@v1.0 defects=0}
    function good_case_7() {
      // Creating a security group with specific ports for a web application
      const securityGroup = new ec2.SecurityGroup(this, 'GoodSG7', {
        vpc,
        description: 'Web application security group',
      });
      
      // ok: typescript_cdk_ec2_expose_selective_ports
      securityGroup.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(80), 'Allow HTTP');
      securityGroup.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(443), 'Allow HTTPS');
      securityGroup.addIngressRule(ec2.Peer.ipv4('10.0.0.0/8'), ec2.Port.tcp(8443), 'Allow admin HTTPS from corporate network');
      
      const instance = new ec2.Instance(this, 'GoodInstance7', {
        vpc,
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.T2, ec2.InstanceSize.MEDIUM),
        machineImage: ec2.MachineImage.latestAmazonLinux(),
        securityGroup: securityGroup,
      });
    }
// {/fact}
    
// {fact rule=code-injection@v1.0 defects=0}
    function good_case_8() {
      // Creating a security group with specific ports using variables
      const securityGroup = new ec2.SecurityGroup(this, 'GoodSG8', {
        vpc,
        description: 'Variable ports security group',
      });
      
      const httpPort = 80;
      const httpsPort = 443;
      
      // ok: typescript_cdk_ec2_expose_selective_ports
      securityGroup.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(httpPort), 'Allow HTTP');
      securityGroup.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(httpsPort), 'Allow HTTPS');
    }
// {/fact}
    
// {fact rule=code-injection@v1.0 defects=0}
    function good_case_9() {
      // Creating a security group with specific ports for a mail server
      const securityGroup = new ec2.SecurityGroup(this, 'GoodSG9', {
        vpc,
        description: 'Mail server security group',
      });
      
      // ok: typescript_cdk_ec2_expose_selective_ports
      securityGroup.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(25), 'Allow SMTP');
      securityGroup.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(143), 'Allow IMAP');
      securityGroup.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(587), 'Allow SMTP submission');
      securityGroup.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(993), 'Allow IMAPS');
    }
// {/fact}
    
// {fact rule=code-injection@v1.0 defects=0}
    function good_case_10() {
      // Creating a security group with specific ports for a custom application
      const securityGroup = new ec2.SecurityGroup(this, 'GoodSG10', {
        vpc,
        description: 'Custom application security group',
      });
      
      // ok: typescript_cdk_ec2_expose_selective_ports
      securityGroup.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(8080), 'Allow application port');
      securityGroup.addIngressRule(ec2.Peer.ipv4('10.0.0.0/16'), ec2.Port.tcp(8443), 'Allow secure application port from internal network');
    }
// {/fact}
    
// {fact rule=code-injection@v1.0 defects=0}
    function good_case_11() {
      // Creating a security group with specific ports for a game server
      const securityGroup = new ec2.SecurityGroup(this, 'GoodSG11', {
        vpc,
        description: 'Game server security group',
      });
      
      // ok: typescript_cdk_ec2_expose_selective_ports
      securityGroup.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(27015), 'Allow game server port');
      securityGroup.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.udp(27015), 'Allow game server UDP port');
      securityGroup.addIngressRule(ec2.Peer.ipv4('192.168.1.0/24'), ec2.Port.tcp(22), 'Allow SSH from admin network');
    }
// {/fact}
    
// {fact rule=code-injection@v1.0 defects=0}
    function good_case_12() {
      // Creating a security group with specific ports for a web server with admin access
      const securityGroup = new ec2.SecurityGroup(this, 'GoodSG12', {
        vpc,
        description: 'Web server with admin access',
      });
      
      // ok: typescript_cdk_ec2_expose_selective_ports
      securityGroup.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(80), 'Allow HTTP');
      securityGroup.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(443), 'Allow HTTPS');
      securityGroup.addIngressRule(ec2.Peer.ipv4('10.0.0.0/8'), ec2.Port.tcp(22), 'Allow SSH from corporate network');
      securityGroup.addIngressRule(ec2.Peer.ipv4('10.0.0.0/8'), ec2.Port.tcp(3389), 'Allow RDP from corporate network');
    }
// {/fact}
    
// {fact rule=code-injection@v1.0 defects=0}
    function good_case_13() {
      // Creating a security group with specific ports for a database cluster
      const securityGroup = new ec2.SecurityGroup(this, 'GoodSG13', {
        vpc,
        description: 'Database cluster security group',
      });
      
      // ok: typescript_cdk_ec2_expose_selective_ports
      securityGroup.addIngressRule(ec2.Peer.ipv4('10.0.0.0/16'), ec2.Port.tcp(3306), 'Allow MySQL from application subnet');
      securityGroup.addIngressRule(ec2.Peer.ipv4('10.1.0.0/16'), ec2.Port.tcp(3306), 'Allow MySQL from another application subnet');
    }
// {/fact}
    
// {fact rule=code-injection@v1.0 defects=0}
    function good_case_14() {
      // Creating a security group with specific ports for a cache server
      const securityGroup = new ec2.SecurityGroup(this, 'GoodSG14', {
        vpc,
        description: 'Cache server security group',
      });
      
      // ok: typescript_cdk_ec2_expose_selective_ports
      securityGroup.addIngressRule(ec2.Peer.ipv4('10.0.0.0/16'), ec2.Port.tcp(6379), 'Allow Redis from application subnet');
      securityGroup.addIngressRule(ec2.Peer.ipv4('10.0.0.0/16'), ec2.Port.tcp(11211), 'Allow Memcached from application subnet');
    }
// {/fact}
    
// {fact rule=code-injection@v1.0 defects=0}
    function good_case_15() {
      // Creating a security group with specific ports for a microservice
      const securityGroup = new ec2.SecurityGroup(this, 'GoodSG15', {
        vpc,
        description: 'Microservice security group',
      });
      
      // ok: typescript_cdk_ec2_expose_selective_ports
      securityGroup.addIngressRule(ec2.Peer.securityGroupId('sg-12345678'), ec2.Port.tcp(9000), 'Allow traffic from API gateway');
      securityGroup.addIngressRule(ec2.Peer.ipv4('10.0.0.0/16'), ec2.Port.tcp(8080), 'Allow traffic from internal services');
      
      const instance = new ec2.Instance(this, 'GoodInstance15', {
        vpc,
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.SMALL),
        machineImage: ec2.MachineImage.latestAmazonLinux(),
        securityGroup: securityGroup,
      });
    }
// {/fact}
    
    // Execute all the functions to create the resources
    bad_case_1();
    bad_case_2();
    bad_case_3();
    bad_case_4();
    bad_case_5();
    bad_case_6();
    bad_case_7();
    bad_case_8();
    bad_case_9();
    bad_case_10();
    bad_case_11();
    bad_case_12();
    bad_case_13();
    bad_case_14();
    bad_case_15();
    
    good_case_1();
    good_case_2();
    good_case_3();
    good_case_4();
    good_case_5();
    good_case_6();
    good_case_7();
    good_case_8();
    good_case_9();
    good_case_10();
    good_case_11();
    good_case_12();
    good_case_13();
    good_case_14();
    good_case_15();
  }
}

const app = new cdk.App();
new SecurityGroupStack(app, 'SecurityGroupStack');