import * as cdk from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as rds from 'aws-cdk-lib/aws-rds';
import { Construct } from 'constructs';

// True positives (vulnerable cases)

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_1() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  // ruleid: typescript_cdk_allows_rds_db_security_group_for_inbound_access
  const dbsg = new ec2.SecurityGroup(stack, 'DatabaseSecurityGroup', {
    vpc,
    description: 'Allow database access',
  });
  
  dbsg.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(3306), 'Allow MySQL access from anywhere');
  
  new rds.DatabaseInstance(stack, 'Database', {
    engine: rds.DatabaseInstanceEngine.mysql({ version: rds.MysqlEngineVersion.VER_8_0_28 }),
    vpc,
    securityGroups: [dbsg],
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_2() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const dbsg = new ec2.SecurityGroup(stack, 'DatabaseSecurityGroup', {
    vpc,
    description: 'Allow database access',
  });
  
  // ruleid: typescript_cdk_allows_rds_db_security_group_for_inbound_access
  dbsg.addIngressRule(ec2.Peer.ipv4('0.0.0.0/0'), ec2.Port.tcp(5432), 'Allow PostgreSQL access from anywhere');
  
  new rds.DatabaseInstance(stack, 'Database', {
    engine: rds.DatabaseInstanceEngine.postgres({ version: rds.PostgresEngineVersion.VER_13_4 }),
    vpc,
    securityGroups: [dbsg],
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_3() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const dbsg = new ec2.SecurityGroup(stack, 'DatabaseSecurityGroup', {
    vpc,
    description: 'Allow database access',
  });
  
  // ruleid: typescript_cdk_allows_rds_db_security_group_for_inbound_access
  dbsg.addIngressRule(ec2.Peer.ipv4('0.0.0.0/0'), ec2.Port.tcp(1433), 'Allow SQL Server access');
  
  const cluster = new rds.DatabaseCluster(stack, 'Database', {
    engine: rds.DatabaseClusterEngine.auroraPostgres({ version: rds.AuroraPostgresEngineVersion.VER_13_4 }),
    instanceProps: {
      vpc,
      securityGroups: [dbsg],
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    },
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_4() {
  class DatabaseStack extends cdk.Stack {
    constructor(scope: Construct, id: string, props?: cdk.StackProps) {
      super(scope, id, props);
      
      const vpc = new ec2.Vpc(this, 'MyVpc');
      
      const dbsg = new ec2.SecurityGroup(this, 'DatabaseSecurityGroup', {
        vpc,
        description: 'Allow database access',
      });
      
      // ruleid: typescript_cdk_allows_rds_db_security_group_for_inbound_access
      dbsg.addIngressRule(ec2.Peer.ipv4('0.0.0.0/0'), ec2.Port.tcp(3306), 'Allow MySQL access');
      
      new rds.DatabaseInstance(this, 'Database', {
        engine: rds.DatabaseInstanceEngine.mysql({ version: rds.MysqlEngineVersion.VER_8_0_28 }),
        vpc,
        securityGroups: [dbsg],
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
      });
    }
  }
  
  const app = new cdk.App();
  new DatabaseStack(app, 'DatabaseStack');
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_5() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const dbsg = new ec2.SecurityGroup(stack, 'DatabaseSecurityGroup', {
    vpc,
    description: 'Allow database access',
    allowAllOutbound: true,
  });
  
  const cidr = '0.0.0.0/0';
  // ruleid: typescript_cdk_allows_rds_db_security_group_for_inbound_access
  dbsg.addIngressRule(ec2.Peer.ipv4(cidr), ec2.Port.tcp(3306), 'Allow MySQL access');
  
  new rds.DatabaseInstance(stack, 'Database', {
    engine: rds.DatabaseInstanceEngine.mysql({ version: rds.MysqlEngineVersion.VER_8_0_28 }),
    vpc,
    securityGroups: [dbsg],
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_6() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const dbsg = new ec2.SecurityGroup(stack, 'DatabaseSecurityGroup', {
    vpc,
    description: 'Allow database access',
  });
  
  const ports = [3306, 5432, 1433];
  
  for (const port of ports) {
    // ruleid: typescript_cdk_allows_rds_db_security_group_for_inbound_access
    dbsg.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(port), `Allow port ${port} access`);
  }
  
  new rds.DatabaseInstance(stack, 'Database', {
    engine: rds.DatabaseInstanceEngine.mysql({ version: rds.MysqlEngineVersion.VER_8_0_28 }),
    vpc,
    securityGroups: [dbsg],
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_7() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const dbsg = new ec2.SecurityGroup(stack, 'DatabaseSecurityGroup', {
    vpc,
    description: 'Allow database access',
  });
  
  const portRange = ec2.Port.tcpRange(3300, 3310);
  // ruleid: typescript_cdk_allows_rds_db_security_group_for_inbound_access
  dbsg.addIngressRule(ec2.Peer.ipv4('0.0.0.0/0'), portRange, 'Allow MySQL port range access');
  
  new rds.DatabaseInstance(stack, 'Database', {
    engine: rds.DatabaseInstanceEngine.mysql({ version: rds.MysqlEngineVersion.VER_8_0_28 }),
    vpc,
    securityGroups: [dbsg],
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_8() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const dbsg = new ec2.SecurityGroup(stack, 'DatabaseSecurityGroup', {
    vpc,
    description: 'Allow database access',
  });
  
  // ruleid: typescript_cdk_allows_rds_db_security_group_for_inbound_access
  dbsg.connections.allowFrom(ec2.Peer.anyIpv4(), ec2.Port.tcp(3306), 'Allow MySQL access');
  
  new rds.DatabaseInstance(stack, 'Database', {
    engine: rds.DatabaseInstanceEngine.mysql({ version: rds.MysqlEngineVersion.VER_8_0_28 }),
    vpc,
    securityGroups: [dbsg],
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_9() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const dbsg = new ec2.SecurityGroup(stack, 'DatabaseSecurityGroup', {
    vpc,
    description: 'Allow database access',
  });
  
  const anyIp = '0.0.0.0/0';
  const port = 3306;
  
  // ruleid: typescript_cdk_allows_rds_db_security_group_for_inbound_access
  dbsg.addIngressRule(ec2.Peer.ipv4(anyIp), ec2.Port.tcp(port), 'Allow MySQL access');
  
  new rds.DatabaseInstance(stack, 'Database', {
    engine: rds.DatabaseInstanceEngine.mysql({ version: rds.MysqlEngineVersion.VER_8_0_28 }),
    vpc,
    securityGroups: [dbsg],
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_10() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const dbsg = new ec2.SecurityGroup(stack, 'DatabaseSecurityGroup', {
    vpc,
    description: 'Allow database access',
  });
  
  // ruleid: typescript_cdk_allows_rds_db_security_group_for_inbound_access
  dbsg.connections.allowFromAnyIpv4(ec2.Port.tcp(3306), 'Allow MySQL access');
  
  new rds.DatabaseInstance(stack, 'Database', {
    engine: rds.DatabaseInstanceEngine.mysql({ version: rds.MysqlEngineVersion.VER_8_0_28 }),
    vpc,
    securityGroups: [dbsg],
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_11() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  // Creating security group with initial ingress rule
  // ruleid: typescript_cdk_allows_rds_db_security_group_for_inbound_access
  const dbsg = new ec2.SecurityGroup(stack, 'DatabaseSecurityGroup', {
    vpc,
    description: 'Allow database access',
    securityGroupName: 'database-sg',
    allowAllOutbound: true,
    disableInlineRules: false,
  });
  
  dbsg.addIngressRule(ec2.Peer.ipv4('0.0.0.0/0'), ec2.Port.tcp(3306), 'Allow MySQL access');
  
  new rds.DatabaseInstance(stack, 'Database', {
    engine: rds.DatabaseInstanceEngine.mysql({ version: rds.MysqlEngineVersion.VER_8_0_28 }),
    vpc,
    securityGroups: [dbsg],
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_12() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const dbsg = new ec2.SecurityGroup(stack, 'DatabaseSecurityGroup', {
    vpc,
    description: 'Allow database access',
  });
  
  // Multiple ingress rules, one of which is insecure
  dbsg.addIngressRule(ec2.Peer.ipv4('192.168.1.0/24'), ec2.Port.tcp(3306), 'Allow internal MySQL access');
  // ruleid: typescript_cdk_allows_rds_db_security_group_for_inbound_access
  dbsg.addIngressRule(ec2.Peer.ipv4('0.0.0.0/0'), ec2.Port.tcp(3306), 'Allow public MySQL access');
  
  new rds.DatabaseInstance(stack, 'Database', {
    engine: rds.DatabaseInstanceEngine.mysql({ version: rds.MysqlEngineVersion.VER_8_0_28 }),
    vpc,
    securityGroups: [dbsg],
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_13() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const dbsg = new ec2.SecurityGroup(stack, 'DatabaseSecurityGroup', {
    vpc,
    description: 'Allow database access',
  });
  
  const allowedPorts = [22, 3306, 5432];
  allowedPorts.forEach(port => {
    if (port === 3306) {
      // ruleid: typescript_cdk_allows_rds_db_security_group_for_inbound_access
      dbsg.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(port), `Allow port ${port} access`);
    } else {
      dbsg.addIngressRule(ec2.Peer.ipv4('192.168.1.0/24'), ec2.Port.tcp(port), `Allow port ${port} access`);
    }
  });
  
  new rds.DatabaseInstance(stack, 'Database', {
    engine: rds.DatabaseInstanceEngine.mysql({ version: rds.MysqlEngineVersion.VER_8_0_28 }),
    vpc,
    securityGroups: [dbsg],
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_14() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const dbsg = new ec2.SecurityGroup(stack, 'DatabaseSecurityGroup', {
    vpc,
    description: 'Allow database access',
  });
  
  // Using a variable to define the CIDR
  const publicCidr = '0.0.0.0/0';
  const dbPort = 3306;
  
  // ruleid: typescript_cdk_allows_rds_db_security_group_for_inbound_access
  dbsg.addIngressRule(
    ec2.Peer.ipv4(publicCidr),
    ec2.Port.tcp(dbPort),
    'Allow MySQL access'
  );
  
  new rds.DatabaseInstance(stack, 'Database', {
    engine: rds.DatabaseInstanceEngine.mysql({ version: rds.MysqlEngineVersion.VER_8_0_28 }),
    vpc,
    securityGroups: [dbsg],
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_15() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const dbsg = new ec2.SecurityGroup(stack, 'DatabaseSecurityGroup', {
    vpc,
    description: 'Allow database access',
  });
  
  // Using a function to add ingress rules
  function addDatabaseAccess(sg: ec2.SecurityGroup, port: number) {
    // ruleid: typescript_cdk_allows_rds_db_security_group_for_inbound_access
    sg.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(port), `Allow port ${port} access`);
  }
  
  addDatabaseAccess(dbsg, 3306);
  
  new rds.DatabaseInstance(stack, 'Database', {
    engine: rds.DatabaseInstanceEngine.mysql({ version: rds.MysqlEngineVersion.VER_8_0_28 }),
    vpc,
    securityGroups: [dbsg],
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
  });
}
// {/fact}

// True negatives (secure cases)

// {fact rule=code-injection@v1.0 defects=0}
function good_case_1() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const dbsg = new ec2.SecurityGroup(stack, 'DatabaseSecurityGroup', {
    vpc,
    description: 'Allow database access',
  });
  
  // ok: typescript_cdk_allows_rds_db_security_group_for_inbound_access
  dbsg.addIngressRule(ec2.Peer.ipv4('10.0.0.0/16'), ec2.Port.tcp(3306), 'Allow MySQL access from VPC only');
  
  new rds.DatabaseInstance(stack, 'Database', {
    engine: rds.DatabaseInstanceEngine.mysql({ version: rds.MysqlEngineVersion.VER_8_0_28 }),
    vpc,
    securityGroups: [dbsg],
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_2() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const websg = new ec2.SecurityGroup(stack, 'WebSecurityGroup', {
    vpc,
    description: 'Security group for web servers',
  });
  
  const dbsg = new ec2.SecurityGroup(stack, 'DatabaseSecurityGroup', {
    vpc,
    description: 'Allow database access',
  });
  
  // ok: typescript_cdk_allows_rds_db_security_group_for_inbound_access
  dbsg.connections.allowFrom(websg, ec2.Port.tcp(3306), 'Allow MySQL access from web tier');
  
  new rds.DatabaseInstance(stack, 'Database', {
    engine: rds.DatabaseInstanceEngine.mysql({ version: rds.MysqlEngineVersion.VER_8_0_28 }),
    vpc,
    securityGroups: [dbsg],
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_3() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const dbsg = new ec2.SecurityGroup(stack, 'DatabaseSecurityGroup', {
    vpc,
    description: 'Allow database access',
  });
  
  // ok: typescript_cdk_allows_rds_db_security_group_for_inbound_access
  dbsg.addIngressRule(ec2.Peer.ipv4('192.168.1.0/24'), ec2.Port.tcp(3306), 'Allow MySQL access from corporate network');
  dbsg.addIngressRule(ec2.Peer.ipv4('172.16.0.0/16'), ec2.Port.tcp(3306), 'Allow MySQL access from VPN network');
  
  new rds.DatabaseInstance(stack, 'Database', {
    engine: rds.DatabaseInstanceEngine.mysql({ version: rds.MysqlEngineVersion.VER_8_0_28 }),
    vpc,
    securityGroups: [dbsg],
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_4() {
  class DatabaseStack extends cdk.Stack {
    constructor(scope: Construct, id: string, props?: cdk.StackProps) {
      super(scope, id, props);
      
      const vpc = new ec2.Vpc(this, 'MyVpc');
      
      const appsg = new ec2.SecurityGroup(this, 'AppSecurityGroup', {
        vpc,
        description: 'Security group for application servers',
      });
      
      const dbsg = new ec2.SecurityGroup(this, 'DatabaseSecurityGroup', {
        vpc,
        description: 'Allow database access',
      });
      
      // ok: typescript_cdk_allows_rds_db_security_group_for_inbound_access
      dbsg.connections.allowFrom(appsg, ec2.Port.tcp(3306), 'Allow MySQL access from app tier');
      
      new rds.DatabaseInstance(this, 'Database', {
        engine: rds.DatabaseInstanceEngine.mysql({ version: rds.MysqlEngineVersion.VER_8_0_28 }),
        vpc,
        securityGroups: [dbsg],
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
      });
    }
  }
  
  const app = new cdk.App();
  new DatabaseStack(app, 'DatabaseStack');
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_5() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const dbsg = new ec2.SecurityGroup(stack, 'DatabaseSecurityGroup', {
    vpc,
    description: 'Allow database access',
    allowAllOutbound: true,
  });
  
  const cidr = '10.0.0.0/8';
  // ok: typescript_cdk_allows_rds_db_security_group_for_inbound_access
  dbsg.addIngressRule(ec2.Peer.ipv4(cidr), ec2.Port.tcp(3306), 'Allow MySQL access from private network');
  
  new rds.DatabaseInstance(stack, 'Database', {
    engine: rds.DatabaseInstanceEngine.mysql({ version: rds.MysqlEngineVersion.VER_8_0_28 }),
    vpc,
    securityGroups: [dbsg],
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_6() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const dbsg = new ec2.SecurityGroup(stack, 'DatabaseSecurityGroup', {
    vpc,
    description: 'Allow database access',
  });
  
  const ports = [3306, 5432, 1433];
  
  for (const port of ports) {
    // ok: typescript_cdk_allows_rds_db_security_group_for_inbound_access
    dbsg.addIngressRule(ec2.Peer.ipv4('10.0.0.0/16'), ec2.Port.tcp(port), `Allow port ${port} access from VPC`);
  }
  
  new rds.DatabaseInstance(stack, 'Database', {
    engine: rds.DatabaseInstanceEngine.mysql({ version: rds.MysqlEngineVersion.VER_8_0_28 }),
    vpc,
    securityGroups: [dbsg],
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_7() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const dbsg = new ec2.SecurityGroup(stack, 'DatabaseSecurityGroup', {
    vpc,
    description: 'Allow database access',
  });
  
  // Using security group as source instead of CIDR
  const appsg = new ec2.SecurityGroup(stack, 'AppSecurityGroup', {
    vpc,
    description: 'Security group for application servers',
  });
  
  // ok: typescript_cdk_allows_rds_db_security_group_for_inbound_access
  dbsg.connections.allowFrom(appsg, ec2.Port.tcp(3306), 'Allow MySQL access from app servers');
  
  new rds.DatabaseInstance(stack, 'Database', {
    engine: rds.DatabaseInstanceEngine.mysql({ version: rds.MysqlEngineVersion.VER_8_0_28 }),
    vpc,
    securityGroups: [dbsg],
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_8() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  // Creating a database without explicitly defining security group rules
  // ok: typescript_cdk_allows_rds_db_security_group_for_inbound_access
  new rds.DatabaseInstance(stack, 'Database', {
    engine: rds.DatabaseInstanceEngine.mysql({ version: rds.MysqlEngineVersion.VER_8_0_28 }),
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_9() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const dbsg = new ec2.SecurityGroup(stack, 'DatabaseSecurityGroup', {
    vpc,
    description: 'Allow database access',
  });
  
  // ok: typescript_cdk_allows_rds_db_security_group_for_inbound_access
  dbsg.addIngressRule(ec2.Peer.securityGroupId('sg-12345678'), ec2.Port.tcp(3306), 'Allow MySQL access from specific security group');
  
  new rds.DatabaseInstance(stack, 'Database', {
    engine: rds.DatabaseInstanceEngine.mysql({ version: rds.MysqlEngineVersion.VER_8_0_28 }),
    vpc,
    securityGroups: [dbsg],
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_10() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const dbsg = new ec2.SecurityGroup(stack, 'DatabaseSecurityGroup', {
    vpc,
    description: 'Allow database access',
  });
  
  // ok: typescript_cdk_allows_rds_db_security_group_for_inbound_access
  dbsg.connections.allowFrom(ec2.Peer.ipv4('192.168.1.0/24'), ec2.Port.tcp(3306), 'Allow MySQL access from specific network');
  
  new rds.DatabaseInstance(stack, 'Database', {
    engine: rds.DatabaseInstanceEngine.mysql({ version: rds.MysqlEngineVersion.VER_8_0_28 }),
    vpc,
    securityGroups: [dbsg],
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_11() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  // Creating security group with initial ingress rule
  // ok: typescript_cdk_allows_rds_db_security_group_for_inbound_access
  const dbsg = new ec2.SecurityGroup(stack, 'DatabaseSecurityGroup', {
    vpc,
    description: 'Allow database access',
    securityGroupName: 'database-sg',
    allowAllOutbound: true,
    disableInlineRules: false,
  });
  
  // Adding ingress rules from specific subnets
  vpc.privateSubnets.forEach((subnet, index) => {
    dbsg.addIngressRule(
      ec2.Peer.ipv4(subnet.ipv4CidrBlock),
      ec2.Port.tcp(3306),
      `Allow MySQL access from private subnet ${index}`
    );
  });
  
  new rds.DatabaseInstance(stack, 'Database', {
    engine: rds.DatabaseInstanceEngine.mysql({ version: rds.MysqlEngineVersion.VER_8_0_28 }),
    vpc,
    securityGroups: [dbsg],
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_12() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const dbsg = new ec2.SecurityGroup(stack, 'DatabaseSecurityGroup', {
    vpc,
    description: 'Allow database access',
  });
  
  // Multiple ingress rules, all secure
  // ok: typescript_cdk_allows_rds_db_security_group_for_inbound_access
  dbsg.addIngressRule(ec2.Peer.ipv4('192.168.1.0/24'), ec2.Port.tcp(3306), 'Allow internal MySQL access');
  dbsg.addIngressRule(ec2.Peer.ipv4('10.0.0.0/8'), ec2.Port.tcp(3306), 'Allow VPC MySQL access');
  
  new rds.DatabaseInstance(stack, 'Database', {
    engine: rds.DatabaseInstanceEngine.mysql({ version: rds.MysqlEngineVersion.VER_8_0_28 }),
    vpc,
    securityGroups: [dbsg],
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_13() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const dbsg = new ec2.SecurityGroup(stack, 'DatabaseSecurityGroup', {
    vpc,
    description: 'Allow database access',
  });
  
  // Using a function to add secure ingress rules
  // ok: typescript_cdk_allows_rds_db_security_group_for_inbound_access
  function addSecureDatabaseAccess(sg: ec2.SecurityGroup, port: number) {
    sg.addIngressRule(ec2.Peer.ipv4('10.0.0.0/8'), ec2.Port.tcp(port), `Allow port ${port} access from private network`);
  }
  
  addSecureDatabaseAccess(dbsg, 3306);
  
  new rds.DatabaseInstance(stack, 'Database', {
    engine: rds.DatabaseInstanceEngine.mysql({ version: rds.MysqlEngineVersion.VER_8_0_28 }),
    vpc,
    securityGroups: [dbsg],
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_14() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  // Using a VPC endpoint to access the database
  // ok: typescript_cdk_allows_rds_db_security_group_for_inbound_access
  const dbsg = new ec2.SecurityGroup(stack, 'DatabaseSecurityGroup', {
    vpc,
    description: 'Allow database access',
  });
  
  // Create a VPC endpoint for RDS
  const rdsEndpoint = new ec2.InterfaceVpcEndpoint(stack, 'RdsEndpoint', {
    vpc,
    service: new ec2.InterfaceVpcEndpointService('com.amazonaws.region.rds', 443),
    securityGroups: [dbsg],
    privateDnsEnabled: true,
  });
  
  // Allow access only from the VPC endpoint
  dbsg.addIngressRule(
    ec2.Peer.securityGroupId(rdsEndpoint.securityGroupId),
    ec2.Port.tcp(3306),
    'Allow MySQL access via VPC endpoint'
  );
  
  new rds.DatabaseInstance(stack, 'Database', {
    engine: rds.DatabaseInstanceEngine.mysql({ version: rds.MysqlEngineVersion.VER_8_0_28 }),
    vpc,
    securityGroups: [dbsg],
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_15() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  // Using a bastion host to access the database
  const bastionSg = new ec2.SecurityGroup(stack, 'BastionSecurityGroup', {
    vpc,
    description: 'Security group for bastion host',
  });
  
  const dbsg = new ec2.SecurityGroup(stack, 'DatabaseSecurityGroup', {
    vpc,
    description: 'Allow database access',
  });
  
  // ok: typescript_cdk_allows_rds_db_security_group_for_inbound_access
  dbsg.addIngressRule(bastionSg, ec2.Port.tcp(3306), 'Allow MySQL access from bastion host');
  
  // Create a bastion host
  const bastion = new ec2.Instance(stack, 'BastionHost', {
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    machineImage: ec2.MachineImage.latestAmazonLinux2(),
    securityGroup: bastionSg,
    vpcSubnets: { subnetType: ec2.SubnetType.PUBLIC },
  });
  
  new rds.DatabaseInstance(stack, 'Database', {
    engine: rds.DatabaseInstanceEngine.mysql({ version: rds.MysqlEngineVersion.VER_8_0_28 }),
    vpc,
    securityGroups: [dbsg],
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
  });
}
// {/fact}