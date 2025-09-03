import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as eks from 'aws-cdk-lib/aws-eks';
import * as ec2 from 'aws-cdk-lib/aws-ec2';

// True Positive Examples (Vulnerable Code)

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_1(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript_cdk_eks_public_access_enabled
  const cluster = new eks.Cluster(scope, 'EksCluster', {
    vpc,
    version: eks.KubernetesVersion.V1_21,
    endpointAccess: eks.EndpointAccess.PUBLIC,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_2(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript_cdk_eks_public_access_enabled
  const cluster = new eks.CfnCluster(scope, 'EksCluster', {
    resourcesVpcConfig: {
      subnetIds: ['subnet-1234', 'subnet-5678'],
      endpointPublicAccess: true,
      endpointPrivateAccess: false,
    },
    roleArn: 'arn:aws:iam::123456789012:role/eks-cluster-role',
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_3(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  const publicAccess = true;
  
  // ruleid: typescript_cdk_eks_public_access_enabled
  const cluster = new eks.CfnCluster(scope, 'EksCluster', {
    resourcesVpcConfig: {
      subnetIds: ['subnet-1234', 'subnet-5678'],
      endpointPublicAccess: publicAccess,
      endpointPrivateAccess: true,
    },
    roleArn: 'arn:aws:iam::123456789012:role/eks-cluster-role',
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_4(scope: Construct, stackProps: cdk.StackProps) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  const accessType = eks.EndpointAccess.PUBLIC;
  
  // ruleid: typescript_cdk_eks_public_access_enabled
  const cluster = new eks.Cluster(scope, 'EksCluster', {
    vpc,
    version: eks.KubernetesVersion.V1_22,
    endpointAccess: accessType,
    defaultCapacity: 2,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_5(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript_cdk_eks_public_access_enabled
  const cluster = new eks.CfnCluster(scope, 'EksCluster', {
    resourcesVpcConfig: {
      subnetIds: ['subnet-1234', 'subnet-5678'],
      endpointPublicAccess: true,
      securityGroupIds: ['sg-12345'],
    },
    roleArn: 'arn:aws:iam::123456789012:role/eks-cluster-role',
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_6(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  const clusterConfig = {
    vpc,
    version: eks.KubernetesVersion.V1_21,
    endpointAccess: eks.EndpointAccess.PUBLIC,
  };
  
  // ruleid: typescript_cdk_eks_public_access_enabled
  const cluster = new eks.Cluster(scope, 'EksCluster', clusterConfig);
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_7(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  let endpointAccess = eks.EndpointAccess.PRIVATE;
  
  if (process.env.ENVIRONMENT === 'dev') {
    endpointAccess = eks.EndpointAccess.PUBLIC;
  }
  
  // ruleid: typescript_cdk_eks_public_access_enabled
  const cluster = new eks.Cluster(scope, 'EksCluster', {
    vpc,
    version: eks.KubernetesVersion.V1_23,
    endpointAccess: endpointAccess,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_8(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  const publicSubnets = vpc.selectSubnets({ subnetType: ec2.SubnetType.PUBLIC });
  
  // ruleid: typescript_cdk_eks_public_access_enabled
  const cluster = new eks.CfnCluster(scope, 'EksCluster', {
    resourcesVpcConfig: {
      subnetIds: publicSubnets.subnetIds,
      endpointPublicAccess: true,
    },
    roleArn: 'arn:aws:iam::123456789012:role/eks-cluster-role',
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_9(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  const accessConfig = {
    endpointAccess: eks.EndpointAccess.PUBLIC,
  };
  
  // ruleid: typescript_cdk_eks_public_access_enabled
  const cluster = new eks.Cluster(scope, 'EksCluster', {
    vpc,
    version: eks.KubernetesVersion.V1_24,
    ...accessConfig,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_10(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript_cdk_eks_public_access_enabled
  const cluster = new eks.CfnCluster(scope, 'EksCluster', {
    resourcesVpcConfig: {
      subnetIds: ['subnet-1234', 'subnet-5678'],
      endpointPublicAccess: true,
      publicAccessCidrs: ['0.0.0.0/0'], // Still vulnerable even with CIDR restrictions
    },
    roleArn: 'arn:aws:iam::123456789012:role/eks-cluster-role',
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_11(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  const clusterProps = {
    vpc,
    version: eks.KubernetesVersion.V1_25,
  };
  
  // Adding endpoint access separately
  clusterProps['endpointAccess'] = eks.EndpointAccess.PUBLIC;
  
  // ruleid: typescript_cdk_eks_public_access_enabled
  const cluster = new eks.Cluster(scope, 'EksCluster', clusterProps);
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_12(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  const vpcConfig: any = {
    subnetIds: ['subnet-1234', 'subnet-5678'],
    endpointPrivateAccess: false,
  };
  
  // Adding public access separately
  vpcConfig.endpointPublicAccess = true;
  
  // ruleid: typescript_cdk_eks_public_access_enabled
  const cluster = new eks.CfnCluster(scope, 'EksCluster', {
    resourcesVpcConfig: vpcConfig,
    roleArn: 'arn:aws:iam::123456789012:role/eks-cluster-role',
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_13(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  function getEndpointAccess() {
    return eks.EndpointAccess.PUBLIC;
  }
  
  // ruleid: typescript_cdk_eks_public_access_enabled
  const cluster = new eks.Cluster(scope, 'EksCluster', {
    vpc,
    version: eks.KubernetesVersion.V1_26,
    endpointAccess: getEndpointAccess(),
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_14(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  const isPublic = true;
  
  // ruleid: typescript_cdk_eks_public_access_enabled
  const cluster = new eks.CfnCluster(scope, 'EksCluster', {
    resourcesVpcConfig: {
      subnetIds: ['subnet-1234', 'subnet-5678'],
      endpointPublicAccess: isPublic ? true : false,
    },
    roleArn: 'arn:aws:iam::123456789012:role/eks-cluster-role',
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_15(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  const accessTypes = [eks.EndpointAccess.PRIVATE, eks.EndpointAccess.PUBLIC];
  const selectedAccess = accessTypes[1]; // Selecting PUBLIC access
  
  // ruleid: typescript_cdk_eks_public_access_enabled
  const cluster = new eks.Cluster(scope, 'EksCluster', {
    vpc,
    version: eks.KubernetesVersion.V1_27,
    endpointAccess: selectedAccess,
  });
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_1(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript_cdk_eks_public_access_enabled
  const cluster = new eks.Cluster(scope, 'EksCluster', {
    vpc,
    version: eks.KubernetesVersion.V1_21,
    endpointAccess: eks.EndpointAccess.PRIVATE,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_2(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript_cdk_eks_public_access_enabled
  const cluster = new eks.CfnCluster(scope, 'EksCluster', {
    resourcesVpcConfig: {
      subnetIds: ['subnet-1234', 'subnet-5678'],
      endpointPublicAccess: false,
      endpointPrivateAccess: true,
    },
    roleArn: 'arn:aws:iam::123456789012:role/eks-cluster-role',
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_3(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript_cdk_eks_public_access_enabled
  const cluster = new eks.Cluster(scope, 'EksCluster', {
    vpc,
    version: eks.KubernetesVersion.V1_22,
    endpointAccess: eks.EndpointAccess.PUBLIC_AND_PRIVATE,
    vpcSubnets: [{ subnetType: ec2.SubnetType.PRIVATE_WITH_NAT }],
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_4(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  const privateAccess = true;
  const publicAccess = false;
  
  // ok: typescript_cdk_eks_public_access_enabled
  const cluster = new eks.CfnCluster(scope, 'EksCluster', {
    resourcesVpcConfig: {
      subnetIds: ['subnet-1234', 'subnet-5678'],
      endpointPublicAccess: publicAccess,
      endpointPrivateAccess: privateAccess,
    },
    roleArn: 'arn:aws:iam::123456789012:role/eks-cluster-role',
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_5(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  const accessType = eks.EndpointAccess.PRIVATE;
  
  // ok: typescript_cdk_eks_public_access_enabled
  const cluster = new eks.Cluster(scope, 'EksCluster', {
    vpc,
    version: eks.KubernetesVersion.V1_23,
    endpointAccess: accessType,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_6(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  const privateSubnets = vpc.selectSubnets({ subnetType: ec2.SubnetType.PRIVATE_WITH_NAT });
  
  // ok: typescript_cdk_eks_public_access_enabled
  const cluster = new eks.CfnCluster(scope, 'EksCluster', {
    resourcesVpcConfig: {
      subnetIds: privateSubnets.subnetIds,
      endpointPublicAccess: false,
      endpointPrivateAccess: true,
    },
    roleArn: 'arn:aws:iam::123456789012:role/eks-cluster-role',
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_7(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  const clusterConfig = {
    vpc,
    version: eks.KubernetesVersion.V1_24,
    endpointAccess: eks.EndpointAccess.PRIVATE,
  };
  
  // ok: typescript_cdk_eks_public_access_enabled
  const cluster = new eks.Cluster(scope, 'EksCluster', clusterConfig);
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_8(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  let endpointAccess = eks.EndpointAccess.PUBLIC;
  
  // Overriding with secure configuration
  endpointAccess = eks.EndpointAccess.PRIVATE;
  
  // ok: typescript_cdk_eks_public_access_enabled
  const cluster = new eks.Cluster(scope, 'EksCluster', {
    vpc,
    version: eks.KubernetesVersion.V1_25,
    endpointAccess: endpointAccess,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_9(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  const vpcConfig: any = {
    subnetIds: ['subnet-1234', 'subnet-5678'],
    endpointPrivateAccess: true,
  };
  
  // Explicitly setting public access to false
  vpcConfig.endpointPublicAccess = false;
  
  // ok: typescript_cdk_eks_public_access_enabled
  const cluster = new eks.CfnCluster(scope, 'EksCluster', {
    resourcesVpcConfig: vpcConfig,
    roleArn: 'arn:aws:iam::123456789012:role/eks-cluster-role',
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_10(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  function getEndpointAccess() {
    return eks.EndpointAccess.PRIVATE;
  }
  
  // ok: typescript_cdk_eks_public_access_enabled
  const cluster = new eks.Cluster(scope, 'EksCluster', {
    vpc,
    version: eks.KubernetesVersion.V1_26,
    endpointAccess: getEndpointAccess(),
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_11(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  const isProduction = true;
  
  // ok: typescript_cdk_eks_public_access_enabled
  const cluster = new eks.CfnCluster(scope, 'EksCluster', {
    resourcesVpcConfig: {
      subnetIds: ['subnet-1234', 'subnet-5678'],
      endpointPublicAccess: false,
      endpointPrivateAccess: isProduction ? true : false,
    },
    roleArn: 'arn:aws:iam::123456789012:role/eks-cluster-role',
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_12(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  const accessTypes = [eks.EndpointAccess.PRIVATE, eks.EndpointAccess.PUBLIC];
  const selectedAccess = accessTypes[0]; // Selecting PRIVATE access
  
  // ok: typescript_cdk_eks_public_access_enabled
  const cluster = new eks.Cluster(scope, 'EksCluster', {
    vpc,
    version: eks.KubernetesVersion.V1_27,
    endpointAccess: selectedAccess,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_13(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // Using PUBLIC_AND_PRIVATE with CIDR restrictions
  // ok: typescript_cdk_eks_public_access_enabled
  const cluster = new eks.Cluster(scope, 'EksCluster', {
    vpc,
    version: eks.KubernetesVersion.V1_28,
    endpointAccess: eks.EndpointAccess.PUBLIC_AND_PRIVATE,
    endpointPublicAccess: false,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_14(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript_cdk_eks_public_access_enabled
  const cluster = new eks.CfnCluster(scope, 'EksCluster', {
    resourcesVpcConfig: {
      subnetIds: ['subnet-1234', 'subnet-5678'],
      // Not specifying endpointPublicAccess defaults to false in some CDK versions
      endpointPrivateAccess: true,
    },
    roleArn: 'arn:aws:iam::123456789012:role/eks-cluster-role',
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_15(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  const accessProps = {};
  
  // Creating a cluster with default settings and then modifying
  // ok: typescript_cdk_eks_public_access_enabled
  const cluster = new eks.Cluster(scope, 'EksCluster', {
    vpc,
    version: eks.KubernetesVersion.V1_29,
    endpointAccess: eks.EndpointAccess.PRIVATE,
  });
}
// {/fact}