import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as eks from 'aws-cdk-lib/aws-eks';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as iam from 'aws-cdk-lib/aws-iam';

// TRUE POSITIVES (Vulnerable Code)

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_1(scope: Construct) {
  // Creating an EKS cluster without any logging configuration
  // ruleid: typescript-cdk-eks-cluster-control-plane-logs
  const cluster = new eks.Cluster(scope, 'MyCluster', {
    version: eks.KubernetesVersion.V1_21,
    defaultCapacity: 2,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_2(scope: Construct) {
  // Creating an EKS cluster with empty logging configuration
  // ruleid: typescript-cdk-eks-cluster-control-plane-logs
  const cluster = new eks.Cluster(scope, 'MyCluster', {
    version: eks.KubernetesVersion.V1_21,
    defaultCapacity: 2,
    clusterLogging: [],
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_3(scope: Construct) {
  // Creating an EKS cluster with incomplete logging configuration (missing audit)
  // ruleid: typescript-cdk-eks-cluster-control-plane-logs
  const cluster = new eks.Cluster(scope, 'MyCluster', {
    version: eks.KubernetesVersion.V1_21,
    defaultCapacity: 2,
    clusterLogging: [
      eks.ClusterLoggingTypes.API,
      eks.ClusterLoggingTypes.AUTHENTICATOR,
      eks.ClusterLoggingTypes.CONTROLLER_MANAGER,
      eks.ClusterLoggingTypes.SCHEDULER,
    ],
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_4(scope: Construct, vpc: ec2.Vpc) {
  // Creating an EKS cluster with only API logging enabled
  // ruleid: typescript-cdk-eks-cluster-control-plane-logs
  const cluster = new eks.Cluster(scope, 'MyCluster', {
    version: eks.KubernetesVersion.V1_21,
    vpc,
    clusterLogging: [
      eks.ClusterLoggingTypes.API,
    ],
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_5(scope: Construct) {
  // Using CfnCluster directly without logging configuration
  // ruleid: typescript-cdk-eks-cluster-control-plane-logs
  const cfnCluster = new eks.CfnCluster(scope, 'MyCfnCluster', {
    resourcesVpcConfig: {
      subnetIds: ['subnet-1234', 'subnet-5678'],
    },
    roleArn: 'arn:aws:iam::123456789012:role/EksClusterRole',
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_6(scope: Construct) {
  // Using CfnCluster with empty logging configuration
  // ruleid: typescript-cdk-eks-cluster-control-plane-logs
  const cfnCluster = new eks.CfnCluster(scope, 'MyCfnCluster', {
    resourcesVpcConfig: {
      subnetIds: ['subnet-1234', 'subnet-5678'],
    },
    roleArn: 'arn:aws:iam::123456789012:role/EksClusterRole',
    logging: {
      clusterLogging: [],
    },
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_7(scope: Construct) {
  // Using CfnCluster with disabled logging
  // ruleid: typescript-cdk-eks-cluster-control-plane-logs
  const cfnCluster = new eks.CfnCluster(scope, 'MyCfnCluster', {
    resourcesVpcConfig: {
      subnetIds: ['subnet-1234', 'subnet-5678'],
    },
    roleArn: 'arn:aws:iam::123456789012:role/EksClusterRole',
    logging: {
      clusterLogging: [{
        enabled: false,
        types: ['api', 'audit', 'authenticator', 'controllerManager', 'scheduler'],
      }],
    },
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_8(scope: Construct) {
  // Using CfnCluster with incomplete logging types
  // ruleid: typescript-cdk-eks-cluster-control-plane-logs
  const cfnCluster = new eks.CfnCluster(scope, 'MyCfnCluster', {
    resourcesVpcConfig: {
      subnetIds: ['subnet-1234', 'subnet-5678'],
    },
    roleArn: 'arn:aws:iam::123456789012:role/EksClusterRole',
    logging: {
      clusterLogging: [{
        enabled: true,
        types: ['api', 'authenticator'],
      }],
    },
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_9(scope: Construct, vpc: ec2.Vpc) {
  // Creating an EKS cluster with custom capacity but no logging
  // ruleid: typescript-cdk-eks-cluster-control-plane-logs
  const cluster = new eks.Cluster(scope, 'MyCluster', {
    version: eks.KubernetesVersion.V1_21,
    vpc,
    defaultCapacity: 0,
  });
  
  cluster.addNodegroupCapacity('custom-node-group', {
    instanceTypes: [new ec2.InstanceType('t3.medium')],
    minSize: 2,
    maxSize: 4,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_10(scope: Construct) {
  // Creating an EKS cluster with Fargate profile but no logging
  // ruleid: typescript-cdk-eks-cluster-control-plane-logs
  const cluster = new eks.Cluster(scope, 'MyFargateCluster', {
    version: eks.KubernetesVersion.V1_21,
    defaultCapacity: 0,
  });
  
  cluster.addFargateProfile('FargateProfile', {
    selectors: [{ namespace: 'default' }],
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_11(scope: Construct, vpc: ec2.Vpc) {
  // Creating an EKS cluster with custom security group but no logging
  // ruleid: typescript-cdk-eks-cluster-control-plane-logs
  const securityGroup = new ec2.SecurityGroup(scope, 'ClusterSG', {
    vpc,
    description: 'EKS Cluster Security Group',
  });
  
  const cluster = new eks.Cluster(scope, 'MyCluster', {
    version: eks.KubernetesVersion.V1_21,
    vpc,
    securityGroup,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_12(scope: Construct) {
  // Creating an EKS cluster with custom role but no logging
  // ruleid: typescript-cdk-eks-cluster-control-plane-logs
  const role = new iam.Role(scope, 'ClusterRole', {
    assumedBy: new iam.ServicePrincipal('eks.amazonaws.com'),
    managedPolicies: [
      iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonEKSClusterPolicy'),
    ],
  });
  
  const cluster = new eks.Cluster(scope, 'MyCluster', {
    version: eks.KubernetesVersion.V1_21,
    role,
    defaultCapacity: 2,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_13(scope: Construct, vpc: ec2.Vpc) {
  // Creating an EKS cluster with custom endpoint access but no logging
  // ruleid: typescript-cdk-eks-cluster-control-plane-logs
  const cluster = new eks.Cluster(scope, 'MyCluster', {
    version: eks.KubernetesVersion.V1_21,
    vpc,
    endpointAccess: eks.EndpointAccess.PRIVATE,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_14(scope: Construct) {
  // Creating an EKS cluster with custom KMS key but no logging
  // ruleid: typescript-cdk-eks-cluster-control-plane-logs
  const key = new cdk.aws_kms.Key(scope, 'ClusterKey');
  
  const cluster = new eks.Cluster(scope, 'MyCluster', {
    version: eks.KubernetesVersion.V1_21,
    secretsEncryptionKey: key,
    defaultCapacity: 2,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_15(scope: Construct) {
  // Creating an EKS cluster with custom bootstrap options but no logging
  // ruleid: typescript-cdk-eks-cluster-control-plane-logs
  const cluster = new eks.Cluster(scope, 'MyCluster', {
    version: eks.KubernetesVersion.V1_21,
    defaultCapacity: 2,
    bootstrapEnabled: true,
    bootstrapOptions: {
      useMaxPods: false,
    },
  });
}
// {/fact}

// TRUE NEGATIVES (Secure Code)

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_1(scope: Construct) {
  // Creating an EKS cluster with all required logging types
  // ok: typescript-cdk-eks-cluster-control-plane-logs
  const cluster = new eks.Cluster(scope, 'MyCluster', {
    version: eks.KubernetesVersion.V1_21,
    defaultCapacity: 2,
    clusterLogging: [
      eks.ClusterLoggingTypes.API,
      eks.ClusterLoggingTypes.AUDIT,
      eks.ClusterLoggingTypes.AUTHENTICATOR,
      eks.ClusterLoggingTypes.CONTROLLER_MANAGER,
      eks.ClusterLoggingTypes.SCHEDULER,
    ],
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_2(scope: Construct) {
  // Using CfnCluster with all required logging types enabled
  // ok: typescript-cdk-eks-cluster-control-plane-logs
  const cfnCluster = new eks.CfnCluster(scope, 'MyCfnCluster', {
    resourcesVpcConfig: {
      subnetIds: ['subnet-1234', 'subnet-5678'],
    },
    roleArn: 'arn:aws:iam::123456789012:role/EksClusterRole',
    logging: {
      clusterLogging: [{
        enabled: true,
        types: ['api', 'audit', 'authenticator', 'controllerManager', 'scheduler'],
      }],
    },
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_3(scope: Construct, vpc: ec2.Vpc) {
  // Creating an EKS cluster with custom capacity and all required logging
  // ok: typescript-cdk-eks-cluster-control-plane-logs
  const cluster = new eks.Cluster(scope, 'MyCluster', {
    version: eks.KubernetesVersion.V1_21,
    vpc,
    defaultCapacity: 0,
    clusterLogging: [
      eks.ClusterLoggingTypes.API,
      eks.ClusterLoggingTypes.AUDIT,
      eks.ClusterLoggingTypes.AUTHENTICATOR,
      eks.ClusterLoggingTypes.CONTROLLER_MANAGER,
      eks.ClusterLoggingTypes.SCHEDULER,
    ],
  });
  
  cluster.addNodegroupCapacity('custom-node-group', {
    instanceTypes: [new ec2.InstanceType('t3.medium')],
    minSize: 2,
    maxSize: 4,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_4(scope: Construct) {
  // Creating an EKS cluster with Fargate profile and all required logging
  // ok: typescript-cdk-eks-cluster-control-plane-logs
  const cluster = new eks.Cluster(scope, 'MyFargateCluster', {
    version: eks.KubernetesVersion.V1_21,
    defaultCapacity: 0,
    clusterLogging: [
      eks.ClusterLoggingTypes.API,
      eks.ClusterLoggingTypes.AUDIT,
      eks.ClusterLoggingTypes.AUTHENTICATOR,
      eks.ClusterLoggingTypes.CONTROLLER_MANAGER,
      eks.ClusterLoggingTypes.SCHEDULER,
    ],
  });
  
  cluster.addFargateProfile('FargateProfile', {
    selectors: [{ namespace: 'default' }],
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_5(scope: Construct, vpc: ec2.Vpc) {
  // Creating an EKS cluster with custom security group and all required logging
  // ok: typescript-cdk-eks-cluster-control-plane-logs
  const securityGroup = new ec2.SecurityGroup(scope, 'ClusterSG', {
    vpc,
    description: 'EKS Cluster Security Group',
  });
  
  const cluster = new eks.Cluster(scope, 'MyCluster', {
    version: eks.KubernetesVersion.V1_21,
    vpc,
    securityGroup,
    clusterLogging: [
      eks.ClusterLoggingTypes.API,
      eks.ClusterLoggingTypes.AUDIT,
      eks.ClusterLoggingTypes.AUTHENTICATOR,
      eks.ClusterLoggingTypes.CONTROLLER_MANAGER,
      eks.ClusterLoggingTypes.SCHEDULER,
    ],
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_6(scope: Construct) {
  // Creating an EKS cluster with custom role and all required logging
  // ok: typescript-cdk-eks-cluster-control-plane-logs
  const role = new iam.Role(scope, 'ClusterRole', {
    assumedBy: new iam.ServicePrincipal('eks.amazonaws.com'),
    managedPolicies: [
      iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonEKSClusterPolicy'),
    ],
  });
  
  const cluster = new eks.Cluster(scope, 'MyCluster', {
    version: eks.KubernetesVersion.V1_21,
    role,
    defaultCapacity: 2,
    clusterLogging: [
      eks.ClusterLoggingTypes.API,
      eks.ClusterLoggingTypes.AUDIT,
      eks.ClusterLoggingTypes.AUTHENTICATOR,
      eks.ClusterLoggingTypes.CONTROLLER_MANAGER,
      eks.ClusterLoggingTypes.SCHEDULER,
    ],
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_7(scope: Construct, vpc: ec2.Vpc) {
  // Creating an EKS cluster with custom endpoint access and all required logging
  // ok: typescript-cdk-eks-cluster-control-plane-logs
  const cluster = new eks.Cluster(scope, 'MyCluster', {
    version: eks.KubernetesVersion.V1_21,
    vpc,
    endpointAccess: eks.EndpointAccess.PRIVATE,
    clusterLogging: [
      eks.ClusterLoggingTypes.API,
      eks.ClusterLoggingTypes.AUDIT,
      eks.ClusterLoggingTypes.AUTHENTICATOR,
      eks.ClusterLoggingTypes.CONTROLLER_MANAGER,
      eks.ClusterLoggingTypes.SCHEDULER,
    ],
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_8(scope: Construct) {
  // Creating an EKS cluster with custom KMS key and all required logging
  // ok: typescript-cdk-eks-cluster-control-plane-logs
  const key = new cdk.aws_kms.Key(scope, 'ClusterKey');
  
  const cluster = new eks.Cluster(scope, 'MyCluster', {
    version: eks.KubernetesVersion.V1_21,
    secretsEncryptionKey: key,
    defaultCapacity: 2,
    clusterLogging: [
      eks.ClusterLoggingTypes.API,
      eks.ClusterLoggingTypes.AUDIT,
      eks.ClusterLoggingTypes.AUTHENTICATOR,
      eks.ClusterLoggingTypes.CONTROLLER_MANAGER,
      eks.ClusterLoggingTypes.SCHEDULER,
    ],
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_9(scope: Construct) {
  // Creating an EKS cluster with custom bootstrap options and all required logging
  // ok: typescript-cdk-eks-cluster-control-plane-logs
  const cluster = new eks.Cluster(scope, 'MyCluster', {
    version: eks.KubernetesVersion.V1_21,
    defaultCapacity: 2,
    bootstrapEnabled: true,
    bootstrapOptions: {
      useMaxPods: false,
    },
    clusterLogging: [
      eks.ClusterLoggingTypes.API,
      eks.ClusterLoggingTypes.AUDIT,
      eks.ClusterLoggingTypes.AUTHENTICATOR,
      eks.ClusterLoggingTypes.CONTROLLER_MANAGER,
      eks.ClusterLoggingTypes.SCHEDULER,
    ],
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_10(scope: Construct) {
  // Using CfnCluster with all required logging types and additional properties
  // ok: typescript-cdk-eks-cluster-control-plane-logs
  const cfnCluster = new eks.CfnCluster(scope, 'MyCfnCluster', {
    resourcesVpcConfig: {
      subnetIds: ['subnet-1234', 'subnet-5678'],
      securityGroupIds: ['sg-1234'],
      endpointPublicAccess: false,
      endpointPrivateAccess: true,
    },
    roleArn: 'arn:aws:iam::123456789012:role/EksClusterRole',
    encryptionConfig: [{
      provider: {
        keyArn: 'arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012',
      },
      resources: ['secrets'],
    }],
    logging: {
      clusterLogging: [{
        enabled: true,
        types: ['api', 'audit', 'authenticator', 'controllerManager', 'scheduler'],
      }],
    },
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_11(scope: Construct, vpc: ec2.Vpc) {
  // Creating an EKS cluster with spot instances and all required logging
  // ok: typescript-cdk-eks-cluster-control-plane-logs
  const cluster = new eks.Cluster(scope, 'MyCluster', {
    version: eks.KubernetesVersion.V1_21,
    vpc,
    defaultCapacity: 0,
    clusterLogging: [
      eks.ClusterLoggingTypes.API,
      eks.ClusterLoggingTypes.AUDIT,
      eks.ClusterLoggingTypes.AUTHENTICATOR,
      eks.ClusterLoggingTypes.CONTROLLER_MANAGER,
      eks.ClusterLoggingTypes.SCHEDULER,
    ],
  });
  
  cluster.addNodegroupCapacity('spot-node-group', {
    instanceTypes: [
      new ec2.InstanceType('t3.medium'),
      new ec2.InstanceType('t3.large'),
    ],
    minSize: 2,
    maxSize: 10,
    capacityType: eks.CapacityType.SPOT,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_12(scope: Construct) {
  // Creating an EKS cluster with all logging types and specific version
  // ok: typescript-cdk-eks-cluster-control-plane-logs
  const cluster = new eks.Cluster(scope, 'MyCluster', {
    version: eks.KubernetesVersion.V1_24,
    defaultCapacity: 3,
    defaultCapacityInstance: new ec2.InstanceType('m5.large'),
    clusterLogging: [
      eks.ClusterLoggingTypes.API,
      eks.ClusterLoggingTypes.AUDIT,
      eks.ClusterLoggingTypes.AUTHENTICATOR,
      eks.ClusterLoggingTypes.CONTROLLER_MANAGER,
      eks.ClusterLoggingTypes.SCHEDULER,
    ],
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_13(scope: Construct, vpc: ec2.Vpc) {
  // Creating an EKS cluster with all logging types and custom subnets
  // ok: typescript-cdk-eks-cluster-control-plane-logs
  const cluster = new eks.Cluster(scope, 'MyCluster', {
    version: eks.KubernetesVersion.V1_21,
    vpc,
    vpcSubnets: [{ subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS }],
    defaultCapacity: 2,
    clusterLogging: [
      eks.ClusterLoggingTypes.API,
      eks.ClusterLoggingTypes.AUDIT,
      eks.ClusterLoggingTypes.AUTHENTICATOR,
      eks.ClusterLoggingTypes.CONTROLLER_MANAGER,
      eks.ClusterLoggingTypes.SCHEDULER,
    ],
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_14(scope: Construct) {
  // Creating an EKS cluster with all logging types and service account
  // ok: typescript-cdk-eks-cluster-control-plane-logs
  const cluster = new eks.Cluster(scope, 'MyCluster', {
    version: eks.KubernetesVersion.V1_21,
    defaultCapacity: 2,
    serviceIpv4Cidr: '10.100.0.0/16',
    clusterLogging: [
      eks.ClusterLoggingTypes.API,
      eks.ClusterLoggingTypes.AUDIT,
      eks.ClusterLoggingTypes.AUTHENTICATOR,
      eks.ClusterLoggingTypes.CONTROLLER_MANAGER,
      eks.ClusterLoggingTypes.SCHEDULER,
    ],
  });
  
  cluster.addServiceAccount('MyServiceAccount', {
    name: 'app-service-account',
    namespace: 'default',
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_15(scope: Construct, vpc: ec2.Vpc) {
  // Creating an EKS cluster with all logging types and helm chart
  // ok: typescript-cdk-eks-cluster-control-plane-logs
  const cluster = new eks.Cluster(scope, 'MyCluster', {
    version: eks.KubernetesVersion.V1_21,
    vpc,
    defaultCapacity: 2,
    clusterLogging: [
      eks.ClusterLoggingTypes.API,
      eks.ClusterLoggingTypes.AUDIT,
      eks.ClusterLoggingTypes.AUTHENTICATOR,
      eks.ClusterLoggingTypes.CONTROLLER_MANAGER,
      eks.ClusterLoggingTypes.SCHEDULER,
    ],
  });
  
  new eks.HelmChart(scope, 'MyChart', {
    cluster,
    chart: 'nginx-ingress',
    repository: 'https://charts.helm.sh/stable',
    namespace: 'kube-system',
  });
}
// {/fact}