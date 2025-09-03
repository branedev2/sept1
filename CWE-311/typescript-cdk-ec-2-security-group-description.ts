import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as ec2 from 'aws-cdk-lib/aws-ec2';

// True Positives (vulnerable code that MUST be detected)

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_1(scope: Construct, id: string) {
  const vpc = new ec2.Vpc(scope, 'MyVpc', {
    maxAzs: 2
  });
  
  // ruleid: typescript-cdk-ec-2-security-group-description
  const securityGroup = new ec2.SecurityGroup(scope, 'MySG', {
    vpc,
    allowAllOutbound: true,
  });
  
  securityGroup.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(22), 'SSH access');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_2(scope: Construct, id: string) {
  const vpc = new ec2.Vpc(scope, 'MyVpc', {
    maxAzs: 3
  });
  
  // ruleid: typescript-cdk-ec-2-security-group-description
  const webServerSG = new ec2.SecurityGroup(scope, 'WebServerSG', {
    vpc,
  });
  
  webServerSG.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(80), 'HTTP');
  webServerSG.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(443), 'HTTPS');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_3(scope: Construct, id: string) {
  const stack = new cdk.Stack(scope, id);
  const vpc = ec2.Vpc.fromLookup(stack, 'VPC', {
    isDefault: true
  });
  
  // ruleid: typescript-cdk-ec-2-security-group-description
  const dbSG = new ec2.SecurityGroup(stack, 'DatabaseSG', {
    vpc,
    allowAllOutbound: false,
  });
  
  dbSG.addIngressRule(ec2.Peer.ipv4('10.0.0.0/16'), ec2.Port.tcp(3306));
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_4(scope: Construct, id: string) {
  const stack = new cdk.Stack(scope, id);
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  // ruleid: typescript-cdk-ec-2-security-group-description
  return new ec2.SecurityGroup(stack, 'ElasticSearchSG', {
    vpc,
    securityGroupName: 'elasticsearch-sg',
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_5(scope: Construct, id: string) {
  const stack = new cdk.Stack(scope, id);
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  // ruleid: typescript-cdk-ec-2-security-group-description
  const sg = new ec2.SecurityGroup(stack, 'AppSG', {
    vpc,
    disableInlineRules: true,
  });
  
  return sg;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_6(scope: Construct, id: string) {
  const stack = new cdk.Stack(scope, id);
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  for (let i = 0; i < 3; i++) {
    // ruleid: typescript-cdk-ec-2-security-group-description
    const sg = new ec2.SecurityGroup(stack, `ServiceSG-${i}`, {
      vpc,
      allowAllOutbound: true,
    });
    
    sg.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(8080));
  }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_7(scope: Construct, id: string) {
  const stack = new cdk.Stack(scope, id);
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const createSG = (name: string) => {
    // ruleid: typescript-cdk-ec-2-security-group-description
    return new ec2.SecurityGroup(stack, name, {
      vpc,
      securityGroupName: name,
    });
  };
  
  const sg1 = createSG('CacheSG');
  const sg2 = createSG('QueueSG');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_8(scope: Construct, id: string) {
  const stack = new cdk.Stack(scope, id);
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const params = {
    vpc,
    allowAllOutbound: true,
  };
  
  // ruleid: typescript-cdk-ec-2-security-group-description
  const sg = new ec2.SecurityGroup(stack, 'ConfigFromParams', params);
  
  sg.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(22));
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_9(scope: Construct, id: string) {
  const stack = new cdk.Stack(scope, id);
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  if (process.env.ENVIRONMENT === 'production') {
    // ruleid: typescript-cdk-ec-2-security-group-description
    return new ec2.SecurityGroup(stack, 'ProdSG', {
      vpc,
      allowAllOutbound: false,
    });
  } else {
    // ruleid: typescript-cdk-ec-2-security-group-description
    return new ec2.SecurityGroup(stack, 'DevSG', {
      vpc,
      allowAllOutbound: true,
    });
  }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_10(scope: Construct, id: string) {
  const stack = new cdk.Stack(scope, id);
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  try {
    // ruleid: typescript-cdk-ec-2-security-group-description
    const sg = new ec2.SecurityGroup(stack, 'TrySG', {
      vpc,
    });
    return sg;
  } catch (error) {
    console.error('Failed to create security group', error);
    throw error;
  }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_11(scope: Construct, id: string) {
  class CustomStack extends cdk.Stack {
    constructor(scope: Construct, id: string, props?: cdk.StackProps) {
      super(scope, id, props);
      
      const vpc = new ec2.Vpc(this, 'MyVpc');
      
      // ruleid: typescript-cdk-ec-2-security-group-description
      this.securityGroup = new ec2.SecurityGroup(this, 'ClassSG', {
        vpc,
        allowAllOutbound: true,
      });
    }
    
    securityGroup: ec2.SecurityGroup;
  }
  
  return new CustomStack(scope, id);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_12(scope: Construct, id: string) {
  const stack = new cdk.Stack(scope, id);
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const sgProps = {};
  Object.assign(sgProps, {
    vpc,
    allowAllOutbound: true,
  });
  
  // ruleid: typescript-cdk-ec-2-security-group-description
  return new ec2.SecurityGroup(stack, 'AssignedSG', sgProps as ec2.SecurityGroupProps);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_13(scope: Construct, id: string) {
  const stack = new cdk.Stack(scope, id);
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  // Empty string description is effectively no description
  // ruleid: typescript-cdk-ec-2-security-group-description
  const sg = new ec2.SecurityGroup(stack, 'EmptyDescSG', {
    vpc,
    description: '',
    allowAllOutbound: true,
  });
  
  return sg;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_14(scope: Construct, id: string) {
  const stack = new cdk.Stack(scope, id);
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  // Whitespace-only description is effectively no description
  // ruleid: typescript-cdk-ec-2-security-group-description
  const sg = new ec2.SecurityGroup(stack, 'WhitespaceDescSG', {
    vpc,
    description: '   ',
    allowAllOutbound: true,
  });
  
  return sg;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_15(scope: Construct, id: string) {
  const stack = new cdk.Stack(scope, id);
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const description = process.env.SG_DESCRIPTION;
  // If description is undefined, this will be missing a description
  // ruleid: typescript-cdk-ec-2-security-group-description
  const sg = new ec2.SecurityGroup(stack, 'EnvVarDescSG', {
    vpc,
    description,
    allowAllOutbound: true,
  });
  
  return sg;
}
// {/fact}

// True Negatives (secure code that MUST NOT be detected)

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_1(scope: Construct, id: string) {
  const vpc = new ec2.Vpc(scope, 'MyVpc', {
    maxAzs: 2
  });
  
  // ok: typescript-cdk-ec-2-security-group-description
  const securityGroup = new ec2.SecurityGroup(scope, 'MySG', {
    vpc,
    description: 'Security group for SSH access to EC2 instances',
    allowAllOutbound: true,
  });
  
  securityGroup.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(22), 'SSH access');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_2(scope: Construct, id: string) {
  const vpc = new ec2.Vpc(scope, 'MyVpc', {
    maxAzs: 3
  });
  
  // ok: typescript-cdk-ec-2-security-group-description
  const webServerSG = new ec2.SecurityGroup(scope, 'WebServerSG', {
    vpc,
    description: 'Security group for web servers allowing HTTP and HTTPS traffic',
  });
  
  webServerSG.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(80), 'HTTP');
  webServerSG.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(443), 'HTTPS');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_3(scope: Construct, id: string) {
  const stack = new cdk.Stack(scope, id);
  const vpc = ec2.Vpc.fromLookup(stack, 'VPC', {
    isDefault: true
  });
  
  // ok: typescript-cdk-ec-2-security-group-description
  const dbSG = new ec2.SecurityGroup(stack, 'DatabaseSG', {
    vpc,
    description: 'Security group for database instances with restricted access',
    allowAllOutbound: false,
  });
  
  dbSG.addIngressRule(ec2.Peer.ipv4('10.0.0.0/16'), ec2.Port.tcp(3306), 'MySQL access from internal network');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_4(scope: Construct, id: string) {
  const stack = new cdk.Stack(scope, id);
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  // ok: typescript-cdk-ec-2-security-group-description
  return new ec2.SecurityGroup(stack, 'ElasticSearchSG', {
    vpc,
    description: 'Security group for ElasticSearch cluster',
    securityGroupName: 'elasticsearch-sg',
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_5(scope: Construct, id: string) {
  const stack = new cdk.Stack(scope, id);
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  // ok: typescript-cdk-ec-2-security-group-description
  const sg = new ec2.SecurityGroup(stack, 'AppSG', {
    vpc,
    description: 'Application security group with inline rules disabled',
    disableInlineRules: true,
  });
  
  return sg;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_6(scope: Construct, id: string) {
  const stack = new cdk.Stack(scope, id);
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  for (let i = 0; i < 3; i++) {
    // ok: typescript-cdk-ec-2-security-group-description
    const sg = new ec2.SecurityGroup(stack, `ServiceSG-${i}`, {
      vpc,
      description: `Security group for service instance ${i}`,
      allowAllOutbound: true,
    });
    
    sg.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(8080), `Service ${i} HTTP access`);
  }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_7(scope: Construct, id: string) {
  const stack = new cdk.Stack(scope, id);
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const createSG = (name: string, desc: string) => {
    // ok: typescript-cdk-ec-2-security-group-description
    return new ec2.SecurityGroup(stack, name, {
      vpc,
      description: desc,
      securityGroupName: name,
    });
  };
  
  const sg1 = createSG('CacheSG', 'Security group for Redis cache instances');
  const sg2 = createSG('QueueSG', 'Security group for SQS queue access');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_8(scope: Construct, id: string) {
  const stack = new cdk.Stack(scope, id);
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const params = {
    vpc,
    description: 'Security group created from parameter object',
    allowAllOutbound: true,
  };
  
  // ok: typescript-cdk-ec-2-security-group-description
  const sg = new ec2.SecurityGroup(stack, 'ConfigFromParams', params);
  
  sg.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(22), 'SSH access');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_9(scope: Construct, id: string) {
  const stack = new cdk.Stack(scope, id);
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  if (process.env.ENVIRONMENT === 'production') {
    // ok: typescript-cdk-ec-2-security-group-description
    return new ec2.SecurityGroup(stack, 'ProdSG', {
      vpc,
      description: 'Production environment security group with restricted outbound access',
      allowAllOutbound: false,
    });
  } else {
    // ok: typescript-cdk-ec-2-security-group-description
    return new ec2.SecurityGroup(stack, 'DevSG', {
      vpc,
      description: 'Development environment security group',
      allowAllOutbound: true,
    });
  }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_10(scope: Construct, id: string) {
  const stack = new cdk.Stack(scope, id);
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  try {
    // ok: typescript-cdk-ec-2-security-group-description
    const sg = new ec2.SecurityGroup(stack, 'TrySG', {
      vpc,
      description: 'Security group created in try-catch block',
    });
    return sg;
  } catch (error) {
    console.error('Failed to create security group', error);
    throw error;
  }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_11(scope: Construct, id: string) {
  class CustomStack extends cdk.Stack {
    constructor(scope: Construct, id: string, props?: cdk.StackProps) {
      super(scope, id, props);
      
      const vpc = new ec2.Vpc(this, 'MyVpc');
      
      // ok: typescript-cdk-ec-2-security-group-description
      this.securityGroup = new ec2.SecurityGroup(this, 'ClassSG', {
        vpc,
        description: 'Security group defined in a custom stack class',
        allowAllOutbound: true,
      });
    }
    
    securityGroup: ec2.SecurityGroup;
  }
  
  return new CustomStack(scope, id);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_12(scope: Construct, id: string) {
  const stack = new cdk.Stack(scope, id);
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const sgProps = {
    description: 'Security group with properties assigned dynamically'
  };
  Object.assign(sgProps, {
    vpc,
    allowAllOutbound: true,
  });
  
  // ok: typescript-cdk-ec-2-security-group-description
  return new ec2.SecurityGroup(stack, 'AssignedSG', sgProps as ec2.SecurityGroupProps);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_13(scope: Construct, id: string) {
  const stack = new cdk.Stack(scope, id);
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const getDescription = () => {
    return 'Security group with description from a function';
  };
  
  // ok: typescript-cdk-ec-2-security-group-description
  const sg = new ec2.SecurityGroup(stack, 'FunctionDescSG', {
    vpc,
    description: getDescription(),
    allowAllOutbound: true,
  });
  
  return sg;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_14(scope: Construct, id: string) {
  const stack = new cdk.Stack(scope, id);
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const env = process.env.ENVIRONMENT || 'dev';
  
  // ok: typescript-cdk-ec-2-security-group-description
  const sg = new ec2.SecurityGroup(stack, 'EnvBasedSG', {
    vpc,
    description: `Security group for ${env} environment`,
    allowAllOutbound: true,
  });
  
  return sg;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_15(scope: Construct, id: string) {
  const stack = new cdk.Stack(scope, id);
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const description = process.env.SG_DESCRIPTION || 'Default security group description';
  
  // ok: typescript-cdk-ec-2-security-group-description
  const sg = new ec2.SecurityGroup(stack, 'EnvVarDescSG', {
    vpc,
    description,
    allowAllOutbound: true,
  });
  
  return sg;
}
// {/fact}