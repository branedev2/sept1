import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as redshift from 'aws-cdk-lib/aws-redshift';
import * as ec2 from 'aws-cdk-lib/aws-ec2';

// True Positive Examples (Vulnerable Code)

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_1(scope: Construct) {
  // Creating a Redshift cluster without specifying a VPC
  // ruleid: typescript-cdk-redshift-cluster-in-vpc
  const cluster = new redshift.Cluster(scope, 'MyRedshiftCluster', {
    masterUsername: 'admin',
    masterPassword: cdk.SecretValue.unsafePlainText('Password123'),
    nodeType: redshift.NodeType.RA3_4XLARGE,
    clusterType: redshift.ClusterType.MULTI_NODE,
    numberOfNodes: 2,
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_2(scope: Construct) {
  // Creating a Redshift cluster with explicit vpc: undefined
  // ruleid: typescript-cdk-redshift-cluster-in-vpc
  const cluster = new redshift.Cluster(scope, 'RedshiftClusterNoVpc', {
    masterUsername: 'admin',
    masterPassword: cdk.SecretValue.secretsManager('redshift/password'),
    nodeType: redshift.NodeType.RA3_XLPLUS,
    vpc: undefined,
    clusterType: redshift.ClusterType.SINGLE_NODE,
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_3(scope: Construct) {
  // Creating a serverless Redshift cluster without VPC
  // ruleid: typescript-cdk-redshift-cluster-in-vpc
  const serverlessCluster = new redshift.CfnEndpointAccess(scope, 'ServerlessRedshift', {
    endpointName: 'my-serverless-endpoint',
    clusterIdentifier: 'my-redshift-cluster',
    resourceOwner: 'arn:aws:iam::123456789012:role/RedshiftRole',
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_4(scope: Construct) {
  // Creating a Redshift cluster with null VPC
  const vpcValue = null;
  
  // ruleid: typescript-cdk-redshift-cluster-in-vpc
  const cluster = new redshift.Cluster(scope, 'RedshiftClusterNullVpc', {
    masterUsername: 'admin',
    masterPassword: cdk.SecretValue.secretsManager('db/password'),
    nodeType: redshift.NodeType.DC2_LARGE,
    vpc: vpcValue,
    clusterType: redshift.ClusterType.MULTI_NODE,
    numberOfNodes: 3,
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_5(scope: Construct) {
  // Creating a Redshift cluster with optional chaining that could be undefined
  const config = getClusterConfig();
  
  // ruleid: typescript-cdk-redshift-cluster-in-vpc
  const cluster = new redshift.Cluster(scope, 'RedshiftClusterOptionalVpc', {
    masterUsername: 'admin',
    masterPassword: cdk.SecretValue.secretsManager('db/password'),
    nodeType: redshift.NodeType.DC2_LARGE,
    vpc: config?.vpc,
    clusterType: redshift.ClusterType.MULTI_NODE,
    numberOfNodes: 3,
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_6(scope: Construct) {
  // Creating a Redshift cluster with conditional that could be undefined
  const useVpc = false;
  
  // ruleid: typescript-cdk-redshift-cluster-in-vpc
  const cluster = new redshift.Cluster(scope, 'RedshiftClusterConditionalVpc', {
    masterUsername: 'admin',
    masterPassword: cdk.SecretValue.secretsManager('db/password'),
    nodeType: redshift.NodeType.DC2_LARGE,
    vpc: useVpc ? getVpc() : undefined,
    clusterType: redshift.ClusterType.MULTI_NODE,
    numberOfNodes: 3,
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_7(scope: Construct) {
  // Creating a Redshift cluster with empty props object and adding properties later
  const props: redshift.ClusterProps = {
    masterUsername: 'admin',
    masterPassword: cdk.SecretValue.secretsManager('db/password'),
    nodeType: redshift.NodeType.DC2_LARGE,
    clusterType: redshift.ClusterType.MULTI_NODE,
    numberOfNodes: 3,
  };
  
  // ruleid: typescript-cdk-redshift-cluster-in-vpc
  const cluster = new redshift.Cluster(scope, 'RedshiftClusterEmptyProps', props);
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_8(scope: Construct) {
  // Creating a Redshift cluster with destructured props
  const baseProps = {
    masterUsername: 'admin',
    masterPassword: cdk.SecretValue.secretsManager('db/password'),
    nodeType: redshift.NodeType.DC2_LARGE,
  };
  
  // ruleid: typescript-cdk-redshift-cluster-in-vpc
  const cluster = new redshift.Cluster(scope, 'RedshiftClusterDestructuredProps', {
    ...baseProps,
    clusterType: redshift.ClusterType.MULTI_NODE,
    numberOfNodes: 3,
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_9(scope: Construct, stackProps: cdk.StackProps) {
  // Creating a Redshift cluster in a stack without VPC
  class RedshiftStack extends cdk.Stack {
    constructor(scope: Construct, id: string, props?: cdk.StackProps) {
      super(scope, id, props);
      
      // ruleid: typescript-cdk-redshift-cluster-in-vpc
      const cluster = new redshift.Cluster(this, 'RedshiftClusterInStack', {
        masterUsername: 'admin',
        masterPassword: cdk.SecretValue.secretsManager('db/password'),
        nodeType: redshift.NodeType.DC2_LARGE,
        clusterType: redshift.ClusterType.MULTI_NODE,
        numberOfNodes: 3,
      });
    }
  }
  
  const stack = new RedshiftStack(scope, 'MyRedshiftStack', stackProps);
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_10(scope: Construct) {
  // Creating a Redshift cluster with a function that returns undefined for VPC
  function getVpcConfig(): ec2.IVpc | undefined {
    return undefined;
  }
  
  // ruleid: typescript-cdk-redshift-cluster-in-vpc
  const cluster = new redshift.Cluster(scope, 'RedshiftClusterFunctionVpc', {
    masterUsername: 'admin',
    masterPassword: cdk.SecretValue.secretsManager('db/password'),
    nodeType: redshift.NodeType.DC2_LARGE,
    vpc: getVpcConfig(),
    clusterType: redshift.ClusterType.MULTI_NODE,
    numberOfNodes: 3,
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_11(scope: Construct) {
  // Creating a Redshift cluster with complex conditional logic that could result in no VPC
  const env = process.env.ENVIRONMENT;
  let vpcConfig;
  
  if (env === 'production') {
    vpcConfig = getProductionVpc();
  } else if (env === 'staging') {
    vpcConfig = getStagingVpc();
  }
  
  // ruleid: typescript-cdk-redshift-cluster-in-vpc
  const cluster = new redshift.Cluster(scope, 'RedshiftClusterComplexConditional', {
    masterUsername: 'admin',
    masterPassword: cdk.SecretValue.secretsManager('db/password'),
    nodeType: redshift.NodeType.DC2_LARGE,
    vpc: vpcConfig,
    clusterType: redshift.ClusterType.MULTI_NODE,
    numberOfNodes: 3,
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_12(scope: Construct) {
  // Creating a Redshift cluster with a factory pattern that doesn't set VPC
  class RedshiftClusterFactory {
    createCluster(scope: Construct, id: string): redshift.Cluster {
      // ruleid: typescript-cdk-redshift-cluster-in-vpc
      return new redshift.Cluster(scope, id, {
        masterUsername: 'admin',
        masterPassword: cdk.SecretValue.secretsManager('db/password'),
        nodeType: redshift.NodeType.DC2_LARGE,
        clusterType: redshift.ClusterType.MULTI_NODE,
        numberOfNodes: 3,
      });
    }
  }
  
  const factory = new RedshiftClusterFactory();
  const cluster = factory.createCluster(scope, 'FactoryRedshiftCluster');
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_13(scope: Construct) {
  // Creating a Redshift cluster with a builder pattern that doesn't set VPC
  class RedshiftClusterBuilder {
    private props: any = {};
    
    withMasterUsername(username: string): RedshiftClusterBuilder {
      this.props.masterUsername = username;
      return this;
    }
    
    withMasterPassword(password: cdk.SecretValue): RedshiftClusterBuilder {
      this.props.masterPassword = password;
      return this;
    }
    
    withNodeType(nodeType: redshift.NodeType): RedshiftClusterBuilder {
      this.props.nodeType = nodeType;
      return this;
    }
    
    withClusterType(clusterType: redshift.ClusterType): RedshiftClusterBuilder {
      this.props.clusterType = clusterType;
      return this;
    }
    
    withNumberOfNodes(numberOfNodes: number): RedshiftClusterBuilder {
      this.props.numberOfNodes = numberOfNodes;
      return this;
    }
    
    build(scope: Construct, id: string): redshift.Cluster {
      // ruleid: typescript-cdk-redshift-cluster-in-vpc
      return new redshift.Cluster(scope, id, this.props);
    }
  }
  
  const builder = new RedshiftClusterBuilder();
  const cluster = builder
    .withMasterUsername('admin')
    .withMasterPassword(cdk.SecretValue.secretsManager('db/password'))
    .withNodeType(redshift.NodeType.DC2_LARGE)
    .withClusterType(redshift.ClusterType.MULTI_NODE)
    .withNumberOfNodes(3)
    .build(scope, 'BuilderRedshiftCluster');
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_14(scope: Construct) {
  // Creating a Redshift cluster with a dynamic property bag that doesn't include VPC
  const dynamicProps: Record<string, any> = {};
  dynamicProps.masterUsername = 'admin';
  dynamicProps.masterPassword = cdk.SecretValue.secretsManager('db/password');
  dynamicProps.nodeType = redshift.NodeType.DC2_LARGE;
  dynamicProps.clusterType = redshift.ClusterType.MULTI_NODE;
  dynamicProps.numberOfNodes = 3;
  
  // ruleid: typescript-cdk-redshift-cluster-in-vpc
  const cluster = new redshift.Cluster(scope, 'DynamicPropsRedshiftCluster', dynamicProps as redshift.ClusterProps);
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_15(scope: Construct) {
  // Creating a Redshift cluster with try/catch that might not set VPC
  let vpcConfig;
  
  try {
    vpcConfig = getVpcFromExternalService();
  } catch (error) {
    console.error('Failed to get VPC configuration, proceeding without VPC');
  }
  
  // ruleid: typescript-cdk-redshift-cluster-in-vpc
  const cluster = new redshift.Cluster(scope, 'TryCatchRedshiftCluster', {
    masterUsername: 'admin',
    masterPassword: cdk.SecretValue.secretsManager('db/password'),
    nodeType: redshift.NodeType.DC2_LARGE,
    vpc: vpcConfig,
    clusterType: redshift.ClusterType.MULTI_NODE,
    numberOfNodes: 3,
  });
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_1(scope: Construct) {
  // Creating a Redshift cluster with a VPC
  const vpc = new ec2.Vpc(scope, 'RedshiftVPC', {
    maxAzs: 2
  });
  
  // ok: typescript-cdk-redshift-cluster-in-vpc
  const cluster = new redshift.Cluster(scope, 'RedshiftClusterWithVpc', {
    masterUsername: 'admin',
    masterPassword: cdk.SecretValue.secretsManager('redshift/password'),
    nodeType: redshift.NodeType.RA3_4XLARGE,
    vpc: vpc,
    clusterType: redshift.ClusterType.MULTI_NODE,
    numberOfNodes: 2,
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_2(scope: Construct) {
  // Creating a Redshift cluster with an existing VPC
  const vpc = ec2.Vpc.fromLookup(scope, 'ImportedVPC', {
    vpcId: 'vpc-12345678'
  });
  
  // ok: typescript-cdk-redshift-cluster-in-vpc
  const cluster = new redshift.Cluster(scope, 'RedshiftClusterWithImportedVpc', {
    masterUsername: 'admin',
    masterPassword: cdk.SecretValue.secretsManager('db/password'),
    nodeType: redshift.NodeType.RA3_XLPLUS,
    vpc: vpc,
    clusterType: redshift.ClusterType.SINGLE_NODE,
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_3(scope: Construct) {
  // Creating a Redshift cluster with a VPC and specific subnets
  const vpc = new ec2.Vpc(scope, 'CustomVPC', {
    maxAzs: 3
  });
  
  const subnetGroup = new redshift.ClusterSubnetGroup(scope, 'RedshiftSubnetGroup', {
    description: 'Redshift Subnet Group',
    vpc: vpc,
    vpcSubnets: {
      subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS
    }
  });
  
  // ok: typescript-cdk-redshift-cluster-in-vpc
  const cluster = new redshift.Cluster(scope, 'RedshiftClusterWithSubnetGroup', {
    masterUsername: 'admin',
    masterPassword: cdk.SecretValue.secretsManager('db/password'),
    nodeType: redshift.NodeType.DC2_LARGE,
    vpc: vpc,
    clusterType: redshift.ClusterType.MULTI_NODE,
    numberOfNodes: 3,
    subnetGroup: subnetGroup,
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_4(scope: Construct) {
  // Creating a Redshift cluster with a VPC and security group
  const vpc = new ec2.Vpc(scope, 'RedshiftVpcWithSG', {
    maxAzs: 2
  });
  
  const securityGroup = new ec2.SecurityGroup(scope, 'RedshiftSG', {
    vpc: vpc,
    description: 'Security group for Redshift cluster',
    allowAllOutbound: false
  });
  
  securityGroup.addIngressRule(
    ec2.Peer.ipv4('10.0.0.0/16'),
    ec2.Port.tcp(5439),
    'Allow access from corporate network'
  );
  
  // ok: typescript-cdk-redshift-cluster-in-vpc
  const cluster = new redshift.Cluster(scope, 'RedshiftClusterWithSG', {
    masterUsername: 'admin',
    masterPassword: cdk.SecretValue.secretsManager('db/password'),
    nodeType: redshift.NodeType.DC2_LARGE,
    vpc: vpc,
    clusterType: redshift.ClusterType.MULTI_NODE,
    numberOfNodes: 3,
    securityGroups: [securityGroup],
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_5(scope: Construct) {
  // Creating a Redshift cluster with a VPC using a factory function
  function createVpc(scope: Construct): ec2.Vpc {
    return new ec2.Vpc(scope, 'FactoryVPC', {
      maxAzs: 2
    });
  }
  
  const vpc = createVpc(scope);
  
  // ok: typescript-cdk-redshift-cluster-in-vpc
  const cluster = new redshift.Cluster(scope, 'RedshiftClusterWithFactoryVpc', {
    masterUsername: 'admin',
    masterPassword: cdk.SecretValue.secretsManager('db/password'),
    nodeType: redshift.NodeType.DC2_LARGE,
    vpc: vpc,
    clusterType: redshift.ClusterType.MULTI_NODE,
    numberOfNodes: 3,
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_6(scope: Construct) {
  // Creating a Redshift cluster with a VPC using environment variables
  const vpcId = process.env.VPC_ID || 'vpc-default';
  const vpc = ec2.Vpc.fromLookup(scope, 'EnvVPC', {
    vpcId: vpcId
  });
  
  // ok: typescript-cdk-redshift-cluster-in-vpc
  const cluster = new redshift.Cluster(scope, 'RedshiftClusterWithEnvVpc', {
    masterUsername: 'admin',
    masterPassword: cdk.SecretValue.secretsManager('db/password'),
    nodeType: redshift.NodeType.DC2_LARGE,
    vpc: vpc,
    clusterType: redshift.ClusterType.MULTI_NODE,
    numberOfNodes: 3,
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_7(scope: Construct) {
  // Creating a Redshift cluster with a VPC using a builder pattern
  class RedshiftClusterBuilder {
    private props: any = {};
    
    withMasterUsername(username: string): RedshiftClusterBuilder {
      this.props.masterUsername = username;
      return this;
    }
    
    withMasterPassword(password: cdk.SecretValue): RedshiftClusterBuilder {
      this.props.masterPassword = password;
      return this;
    }
    
    withNodeType(nodeType: redshift.NodeType): RedshiftClusterBuilder {
      this.props.nodeType = nodeType;
      return this;
    }
    
    withVpc(vpc: ec2.IVpc): RedshiftClusterBuilder {
      this.props.vpc = vpc;
      return this;
    }
    
    withClusterType(clusterType: redshift.ClusterType): RedshiftClusterBuilder {
      this.props.clusterType = clusterType;
      return this;
    }
    
    withNumberOfNodes(numberOfNodes: number): RedshiftClusterBuilder {
      this.props.numberOfNodes = numberOfNodes;
      return this;
    }
    
    build(scope: Construct, id: string): redshift.Cluster {
      return new redshift.Cluster(scope, id, this.props);
    }
  }
  
  const vpc = new ec2.Vpc(scope, 'BuilderVPC', {
    maxAzs: 2
  });
  
  const builder = new RedshiftClusterBuilder();
  // ok: typescript-cdk-redshift-cluster-in-vpc
  const cluster = builder
    .withMasterUsername('admin')
    .withMasterPassword(cdk.SecretValue.secretsManager('db/password'))
    .withNodeType(redshift.NodeType.DC2_LARGE)
    .withVpc(vpc)
    .withClusterType(redshift.ClusterType.MULTI_NODE)
    .withNumberOfNodes(3)
    .build(scope, 'BuilderRedshiftClusterWithVpc');
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_8(scope: Construct) {
  // Creating a Redshift cluster with a VPC in a stack
  class SecureRedshiftStack extends cdk.Stack {
    constructor(scope: Construct, id: string, props?: cdk.StackProps) {
      super(scope, id, props);
      
      const vpc = new ec2.Vpc(this, 'StackVPC', {
        maxAzs: 2
      });
      
      // ok: typescript-cdk-redshift-cluster-in-vpc
      const cluster = new redshift.Cluster(this, 'RedshiftClusterInStackWithVpc', {
        masterUsername: 'admin',
        masterPassword: cdk.SecretValue.secretsManager('db/password'),
        nodeType: redshift.NodeType.DC2_LARGE,
        vpc: vpc,
        clusterType: redshift.ClusterType.MULTI_NODE,
        numberOfNodes: 3,
      });
    }
  }
  
  const stack = new SecureRedshiftStack(scope, 'MySecureRedshiftStack');
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_9(scope: Construct) {
  // Creating a Redshift cluster with a VPC using a factory
  class SecureRedshiftClusterFactory {
    createCluster(scope: Construct, id: string): redshift.Cluster {
      const vpc = new ec2.Vpc(scope, `${id}VPC`, {
        maxAzs: 2
      });
      
      // ok: typescript-cdk-redshift-cluster-in-vpc
      return new redshift.Cluster(scope, id, {
        masterUsername: 'admin',
        masterPassword: cdk.SecretValue.secretsManager('db/password'),
        nodeType: redshift.NodeType.DC2_LARGE,
        vpc: vpc,
        clusterType: redshift.ClusterType.MULTI_NODE,
        numberOfNodes: 3,
      });
    }
  }
  
  const factory = new SecureRedshiftClusterFactory();
  const cluster = factory.createCluster(scope, 'FactoryRedshiftClusterWithVpc');
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_10(scope: Construct) {
  // Creating a Redshift cluster with a VPC using conditional logic
  const env = process.env.ENVIRONMENT || 'development';
  let vpc: ec2.IVpc;
  
  if (env === 'production') {
    vpc = ec2.Vpc.fromLookup(scope, 'ProductionVPC', {
      vpcId: 'vpc-prod12345'
    });
  } else if (env === 'staging') {
    vpc = ec2.Vpc.fromLookup(scope, 'StagingVPC', {
      vpcId: 'vpc-stage12345'
    });
  } else {
    vpc = new ec2.Vpc(scope, 'DevelopmentVPC', {
      maxAzs: 2
    });
  }
  
  // ok: typescript-cdk-redshift-cluster-in-vpc
  const cluster = new redshift.Cluster(scope, 'RedshiftClusterWithConditionalVpc', {
    masterUsername: 'admin',
    masterPassword: cdk.SecretValue.secretsManager('db/password'),
    nodeType: redshift.NodeType.DC2_LARGE,
    vpc: vpc,
    clusterType: redshift.ClusterType.MULTI_NODE,
    numberOfNodes: 3,
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_11(scope: Construct) {
  // Creating a Redshift cluster with a VPC using a dynamic property bag
  const vpc = new ec2.Vpc(scope, 'DynamicPropsVPC', {
    maxAzs: 2
  });
  
  const dynamicProps: Record<string, any> = {};
  dynamicProps.masterUsername = 'admin';
  dynamicProps.masterPassword = cdk.SecretValue.secretsManager('db/password');
  dynamicProps.nodeType = redshift.NodeType.DC2_LARGE;
  dynamicProps.vpc = vpc;
  dynamicProps.clusterType = redshift.ClusterType.MULTI_NODE;
  dynamicProps.numberOfNodes = 3;
  
  // ok: typescript-cdk-redshift-cluster-in-vpc
  const cluster = new redshift.Cluster(scope, 'DynamicPropsRedshiftClusterWithVpc', dynamicProps as redshift.ClusterProps);
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_12(scope: Construct) {
  // Creating a Redshift cluster with a VPC using try/catch with fallback
  let vpc: ec2.IVpc;
  
  try {
    vpc = getVpcFromExternalService();
  } catch (error) {
    console.error('Failed to get VPC configuration, using default VPC');
    vpc = new ec2.Vpc(scope, 'FallbackVPC', {
      maxAzs: 2
    });
  }
  
  // ok: typescript-cdk-redshift-cluster-in-vpc
  const cluster = new redshift.Cluster(scope, 'TryCatchRedshiftClusterWithVpc', {
    masterUsername: 'admin',
    masterPassword: cdk.SecretValue.secretsManager('db/password'),
    nodeType: redshift.NodeType.DC2_LARGE,
    vpc: vpc,
    clusterType: redshift.ClusterType.MULTI_NODE,
    numberOfNodes: 3,
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_13(scope: Construct) {
  // Creating a Redshift cluster with a VPC and custom subnet selection
  const vpc = new ec2.Vpc(scope, 'CustomSubnetVPC', {
    maxAzs: 3,
    subnetConfiguration: [
      {
        cidrMask: 24,
        name: 'ingress',
        subnetType: ec2.SubnetType.PUBLIC,
      },
      {
        cidrMask: 24,
        name: 'application',
        subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
      },
      {
        cidrMask: 28,
        name: 'database',
        subnetType: ec2.SubnetType.PRIVATE_ISOLATED,
      }
    ]
  });
  
  // ok: typescript-cdk-redshift-cluster-in-vpc
  const cluster = new redshift.Cluster(scope, 'RedshiftClusterWithCustomSubnets', {
    masterUsername: 'admin',
    masterPassword: cdk.SecretValue.secretsManager('db/password'),
    nodeType: redshift.NodeType.DC2_LARGE,
    vpc: vpc,
    vpcSubnets: {
      subnetType: ec2.SubnetType.PRIVATE_ISOLATED,
      onePerAz: true
    },
    clusterType: redshift.ClusterType.MULTI_NODE,
    numberOfNodes: 3,
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_14(scope: Construct) {
  // Creating a Redshift cluster with a VPC and encryption
  const vpc = new ec2.Vpc(scope, 'EncryptedRedshiftVPC', {
    maxAzs: 2
  });
  
  const kmsKey = new cdk.aws_kms.Key(scope, 'RedshiftEncryptionKey', {
    enableKeyRotation: true,
    description: 'KMS key for Redshift cluster encryption'
  });
  
  // ok: typescript-cdk-redshift-cluster-in-vpc
  const cluster = new redshift.Cluster(scope, 'EncryptedRedshiftClusterWithVpc', {
    masterUsername: 'admin',
    masterPassword: cdk.SecretValue.secretsManager('db/password'),
    nodeType: redshift.NodeType.DC2_LARGE,
    vpc: vpc,
    clusterType: redshift.ClusterType.MULTI_NODE,
    numberOfNodes: 3,
    encrypted: true,
    encryptionKey: kmsKey
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_15(scope: Construct) {
  // Creating a Redshift cluster with a VPC and enhanced VPC routing
  const vpc = new ec2.Vpc(scope, 'EnhancedRoutingVPC', {
    maxAzs: 2
  });
  
  // ok: typescript-cdk-redshift-cluster-in-vpc
  const cluster = new redshift.Cluster(scope, 'RedshiftClusterWithEnhancedRouting', {
    masterUsername: 'admin',
    masterPassword: cdk.SecretValue.secretsManager('db/password'),
    nodeType: redshift.NodeType.DC2_LARGE,
    vpc: vpc,
    clusterType: redshift.ClusterType.MULTI_NODE,
    numberOfNodes: 3,
    enhancedVpcRouting: true
  });
}
// {/fact}

// Helper functions to avoid TypeScript errors
function getClusterConfig(): { vpc?: ec2.IVpc } {
  return {};
}

function getVpc(): ec2.IVpc {
  throw new Error('Not implemented');
}

function getProductionVpc(): ec2.IVpc {
  throw new Error('Not implemented');
}

function getStagingVpc(): ec2.IVpc {
  throw new Error('Not implemented');
}

function getVpcFromExternalService(): ec2.IVpc {
  throw new Error('Not implemented');
}