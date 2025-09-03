import * as cdk from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as emr from 'aws-cdk-lib/aws-emr';
import * as iam from 'aws-cdk-lib/aws-iam';
import { Construct } from 'constructs';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import * as ssm from 'aws-cdk-lib/aws-ssm';

// True Positive Examples (Vulnerable Code)

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_1(scope: Construct) {
  // Creating EMR cluster without proper authentication
  // ruleid: typescript-cdk-emr-auth-ec-2-key-pair-or-kerberos
  const cluster = new emr.CfnCluster(scope, 'MyEmrCluster', {
    name: 'MyCluster',
    releaseLabel: 'emr-6.2.0',
    instances: {
      masterInstanceType: 'm5.xlarge',
      slaveInstanceType: 'm5.large',
      instanceCount: 3,
      ec2KeyName: '', // Empty key name
    },
    jobFlowRole: 'EMR_EC2_DefaultRole',
    serviceRole: 'EMR_DefaultRole',
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_2(scope: Construct) {
  // Creating EMR cluster with a hardcoded key pair name
  // ruleid: typescript-cdk-emr-auth-ec-2-key-pair-or-kerberos
  const cluster = new emr.CfnCluster(scope, 'MyEmrCluster', {
    name: 'MyCluster',
    releaseLabel: 'emr-6.2.0',
    instances: {
      masterInstanceType: 'm5.xlarge',
      slaveInstanceType: 'm5.large',
      instanceCount: 3,
      ec2KeyName: 'default-key', // Using a default key name
    },
    jobFlowRole: 'EMR_EC2_DefaultRole',
    serviceRole: 'EMR_DefaultRole',
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_3(scope: Construct) {
  // Creating EMR cluster without specifying any authentication method
  // ruleid: typescript-cdk-emr-auth-ec-2-key-pair-or-kerberos
  const cluster = new emr.CfnCluster(scope, 'MyEmrCluster', {
    name: 'MyCluster',
    releaseLabel: 'emr-6.2.0',
    instances: {
      masterInstanceType: 'm5.xlarge',
      slaveInstanceType: 'm5.large',
      instanceCount: 3,
      // No ec2KeyName or Kerberos configuration
    },
    jobFlowRole: 'EMR_EC2_DefaultRole',
    serviceRole: 'EMR_DefaultRole',
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_4(scope: Construct) {
  // Creating EMR cluster with incomplete Kerberos configuration
  // ruleid: typescript-cdk-emr-auth-ec-2-key-pair-or-kerberos
  const cluster = new emr.CfnCluster(scope, 'MyEmrCluster', {
    name: 'MyCluster',
    releaseLabel: 'emr-6.2.0',
    instances: {
      masterInstanceType: 'm5.xlarge',
      slaveInstanceType: 'm5.large',
      instanceCount: 3,
    },
    kerberosAttributes: {
      realm: 'EC2.INTERNAL',
      // Missing required attributes for proper Kerberos setup
    },
    jobFlowRole: 'EMR_EC2_DefaultRole',
    serviceRole: 'EMR_DefaultRole',
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_5(scope: Construct) {
  // Creating EMR cluster with weak Kerberos configuration
  // ruleid: typescript-cdk-emr-auth-ec-2-key-pair-or-kerberos
  const cluster = new emr.CfnCluster(scope, 'MyEmrCluster', {
    name: 'MyCluster',
    releaseLabel: 'emr-6.2.0',
    instances: {
      masterInstanceType: 'm5.xlarge',
      slaveInstanceType: 'm5.large',
      instanceCount: 3,
    },
    kerberosAttributes: {
      realm: 'EC2.INTERNAL',
      kdcAdminPassword: 'admin123', // Hardcoded weak password
      crossRealmTrustPrincipalPassword: 'trust123', // Hardcoded weak password
    },
    jobFlowRole: 'EMR_EC2_DefaultRole',
    serviceRole: 'EMR_DefaultRole',
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_6(scope: Construct) {
  // Creating EMR cluster with public key pair
  // ruleid: typescript-cdk-emr-auth-ec-2-key-pair-or-kerberos
  const cluster = new emr.CfnCluster(scope, 'MyEmrCluster', {
    name: 'MyCluster',
    releaseLabel: 'emr-6.2.0',
    instances: {
      masterInstanceType: 'm5.xlarge',
      slaveInstanceType: 'm5.large',
      instanceCount: 3,
      ec2KeyName: 'public-key-pair',
      additionalMasterSecurityGroups: ['sg-12345'], // Using a potentially public security group
    },
    jobFlowRole: 'EMR_EC2_DefaultRole',
    serviceRole: 'EMR_DefaultRole',
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_7(scope: Construct) {
  // Creating EMR cluster with insecure configurations
  // ruleid: typescript-cdk-emr-auth-ec-2-key-pair-or-kerberos
  const cluster = new emr.CfnCluster(scope, 'MyEmrCluster', {
    name: 'MyCluster',
    releaseLabel: 'emr-6.2.0',
    instances: {
      masterInstanceType: 'm5.xlarge',
      slaveInstanceType: 'm5.large',
      instanceCount: 3,
      ec2KeyName: 'my-key',
      keepJobFlowAliveWhenNoSteps: true,
      terminationProtected: false, // No termination protection
    },
    jobFlowRole: 'EMR_EC2_DefaultRole',
    serviceRole: 'EMR_DefaultRole',
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_8(scope: Construct) {
  // Creating EMR cluster with Kerberos but missing critical configurations
  // ruleid: typescript-cdk-emr-auth-ec-2-key-pair-or-kerberos
  const cluster = new emr.CfnCluster(scope, 'MyEmrCluster', {
    name: 'MyCluster',
    releaseLabel: 'emr-6.2.0',
    instances: {
      masterInstanceType: 'm5.xlarge',
      slaveInstanceType: 'm5.large',
      instanceCount: 3,
    },
    kerberosAttributes: {
      realm: 'EC2.INTERNAL',
      kdcAdminPassword: 'password123',
      // Missing adDomainJoinPassword and other security configurations
    },
    jobFlowRole: 'EMR_EC2_DefaultRole',
    serviceRole: 'EMR_DefaultRole',
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_9(scope: Construct) {
  // Creating EMR cluster with insecure security configuration
  // ruleid: typescript-cdk-emr-auth-ec-2-key-pair-or-kerberos
  const securityConfig = new emr.CfnSecurityConfiguration(scope, 'MySecurityConfig', {
    name: 'MySecurityConfig',
    securityConfiguration: {
      encryptionConfiguration: {
        enableInTransitEncryption: false, // Transit encryption disabled
        enableAtRestEncryption: false, // At-rest encryption disabled
      },
    },
  });
  
  const cluster = new emr.CfnCluster(scope, 'MyEmrCluster', {
    name: 'MyCluster',
    releaseLabel: 'emr-6.2.0',
    instances: {
      masterInstanceType: 'm5.xlarge',
      slaveInstanceType: 'm5.large',
      instanceCount: 3,
      ec2KeyName: 'my-key',
    },
    securityConfiguration: securityConfig.name,
    jobFlowRole: 'EMR_EC2_DefaultRole',
    serviceRole: 'EMR_DefaultRole',
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_10(scope: Construct) {
  // Creating EMR cluster with shared key pair
  // ruleid: typescript-cdk-emr-auth-ec-2-key-pair-or-kerberos
  const cluster = new emr.CfnCluster(scope, 'MyEmrCluster', {
    name: 'MyCluster',
    releaseLabel: 'emr-6.2.0',
    instances: {
      masterInstanceType: 'm5.xlarge',
      slaveInstanceType: 'm5.large',
      instanceCount: 3,
      ec2KeyName: 'shared-team-key', // Using a shared key that might be known by multiple people
    },
    jobFlowRole: 'EMR_EC2_DefaultRole',
    serviceRole: 'EMR_DefaultRole',
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_11(scope: Construct) {
  // Creating EMR cluster with both weak key pair and incomplete Kerberos
  // ruleid: typescript-cdk-emr-auth-ec-2-key-pair-or-kerberos
  const cluster = new emr.CfnCluster(scope, 'MyEmrCluster', {
    name: 'MyCluster',
    releaseLabel: 'emr-6.2.0',
    instances: {
      masterInstanceType: 'm5.xlarge',
      slaveInstanceType: 'm5.large',
      instanceCount: 3,
      ec2KeyName: 'weak-key',
    },
    kerberosAttributes: {
      realm: 'EC2.INTERNAL',
      // Missing critical Kerberos configurations
    },
    jobFlowRole: 'EMR_EC2_DefaultRole',
    serviceRole: 'EMR_DefaultRole',
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_12(scope: Construct) {
  // Creating EMR cluster with insecure network configuration
  // ruleid: typescript-cdk-emr-auth-ec-2-key-pair-or-kerberos
  const vpc = new ec2.Vpc(scope, 'MyVpc', {
    maxAzs: 2,
  });
  
  const cluster = new emr.CfnCluster(scope, 'MyEmrCluster', {
    name: 'MyCluster',
    releaseLabel: 'emr-6.2.0',
    instances: {
      masterInstanceType: 'm5.xlarge',
      slaveInstanceType: 'm5.large',
      instanceCount: 3,
      ec2KeyName: 'my-key',
      ec2SubnetId: vpc.publicSubnets[0].subnetId, // Using public subnet
    },
    jobFlowRole: 'EMR_EC2_DefaultRole',
    serviceRole: 'EMR_DefaultRole',
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_13(scope: Construct) {
  // Creating EMR cluster with hardcoded Kerberos passwords
  // ruleid: typescript-cdk-emr-auth-ec-2-key-pair-or-kerberos
  const cluster = new emr.CfnCluster(scope, 'MyEmrCluster', {
    name: 'MyCluster',
    releaseLabel: 'emr-6.2.0',
    instances: {
      masterInstanceType: 'm5.xlarge',
      slaveInstanceType: 'm5.large',
      instanceCount: 3,
    },
    kerberosAttributes: {
      realm: 'EC2.INTERNAL',
      kdcAdminPassword: 'Admin@123',
      adDomainJoinPassword: 'Domain@123',
      crossRealmTrustPrincipalPassword: 'Trust@123',
    },
    jobFlowRole: 'EMR_EC2_DefaultRole',
    serviceRole: 'EMR_DefaultRole',
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_14(scope: Construct) {
  // Creating EMR cluster with insecure bootstrap actions
  // ruleid: typescript-cdk-emr-auth-ec-2-key-pair-or-kerberos
  const cluster = new emr.CfnCluster(scope, 'MyEmrCluster', {
    name: 'MyCluster',
    releaseLabel: 'emr-6.2.0',
    instances: {
      masterInstanceType: 'm5.xlarge',
      slaveInstanceType: 'm5.large',
      instanceCount: 3,
      ec2KeyName: 'my-key',
    },
    bootstrapActions: [
      {
        name: 'DisableSecurity',
        scriptBootstrapAction: {
          path: 's3://mybucket/disable-security.sh', // Script that might disable security features
        },
      },
    ],
    jobFlowRole: 'EMR_EC2_DefaultRole',
    serviceRole: 'EMR_DefaultRole',
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_15(scope: Construct) {
  // Creating EMR cluster with overly permissive IAM roles
  // ruleid: typescript-cdk-emr-auth-ec-2-key-pair-or-kerberos
  const role = new iam.Role(scope, 'EMRRole', {
    assumedBy: new iam.ServicePrincipal('elasticmapreduce.amazonaws.com'),
    managedPolicies: [
      iam.ManagedPolicy.fromAwsManagedPolicyName('AdministratorAccess'), // Overly permissive
    ],
  });
  
  const cluster = new emr.CfnCluster(scope, 'MyEmrCluster', {
    name: 'MyCluster',
    releaseLabel: 'emr-6.2.0',
    instances: {
      masterInstanceType: 'm5.xlarge',
      slaveInstanceType: 'm5.large',
      instanceCount: 3,
      ec2KeyName: 'my-key',
    },
    jobFlowRole: role.roleName,
    serviceRole: role.roleName,
  });
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_1(scope: Construct) {
  // Creating EMR cluster with proper key pair from parameter store
  const keyPairParam = ssm.StringParameter.fromStringParameterAttributes(scope, 'KeyPairParam', {
    parameterName: '/emr/keypair/name',
  });
  
  // ok: typescript-cdk-emr-auth-ec-2-key-pair-or-kerberos
  const cluster = new emr.CfnCluster(scope, 'MyEmrCluster', {
    name: 'MyCluster',
    releaseLabel: 'emr-6.2.0',
    instances: {
      masterInstanceType: 'm5.xlarge',
      slaveInstanceType: 'm5.large',
      instanceCount: 3,
      ec2KeyName: keyPairParam.stringValue,
      terminationProtected: true,
    },
    jobFlowRole: 'EMR_EC2_DefaultRole',
    serviceRole: 'EMR_DefaultRole',
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_2(scope: Construct) {
  // Creating EMR cluster with properly configured Kerberos authentication
  const kdcPasswordSecret = secretsmanager.Secret.fromSecretNameV2(scope, 'KdcPassword', 'emr/kerberos/kdc-password');
  
  // ok: typescript-cdk-emr-auth-ec-2-key-pair-or-kerberos
  const cluster = new emr.CfnCluster(scope, 'MyEmrCluster', {
    name: 'MyCluster',
    releaseLabel: 'emr-6.2.0',
    instances: {
      masterInstanceType: 'm5.xlarge',
      slaveInstanceType: 'm5.large',
      instanceCount: 3,
    },
    kerberosAttributes: {
      realm: 'EC2.INTERNAL',
      kdcAdminPassword: kdcPasswordSecret.secretValue.toString(),
      crossRealmTrustPrincipalPassword: secretsmanager.Secret.fromSecretNameV2(scope, 'TrustPassword', 'emr/kerberos/trust-password').secretValue.toString(),
      adDomainJoinPassword: secretsmanager.Secret.fromSecretNameV2(scope, 'DomainPassword', 'emr/kerberos/domain-password').secretValue.toString(),
      adDomainJoinUser: 'admin',
    },
    jobFlowRole: 'EMR_EC2_DefaultRole',
    serviceRole: 'EMR_DefaultRole',
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_3(scope: Construct) {
  // Creating EMR cluster with secure network configuration
  const vpc = new ec2.Vpc(scope, 'MyVpc', {
    maxAzs: 2,
  });
  
  const securityGroup = new ec2.SecurityGroup(scope, 'EmrSG', {
    vpc,
    description: 'Security group for EMR cluster',
    allowAllOutbound: false,
  });
  
  // ok: typescript-cdk-emr-auth-ec-2-key-pair-or-kerberos
  const cluster = new emr.CfnCluster(scope, 'MyEmrCluster', {
    name: 'MyCluster',
    releaseLabel: 'emr-6.2.0',
    instances: {
      masterInstanceType: 'm5.xlarge',
      slaveInstanceType: 'm5.large',
      instanceCount: 3,
      ec2KeyName: ssm.StringParameter.valueForStringParameter(scope, '/emr/keypair/name'),
      ec2SubnetId: vpc.privateSubnets[0].subnetId, // Using private subnet
      additionalMasterSecurityGroups: [securityGroup.securityGroupId],
    },
    jobFlowRole: 'EMR_EC2_DefaultRole',
    serviceRole: 'EMR_DefaultRole',
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_4(scope: Construct) {
  // Creating EMR cluster with secure security configuration
  const securityConfig = new emr.CfnSecurityConfiguration(scope, 'MySecurityConfig', {
    name: 'MySecurityConfig',
    securityConfiguration: {
      encryptionConfiguration: {
        enableInTransitEncryption: true,
        enableAtRestEncryption: true,
        atRestEncryptionConfiguration: {
          s3EncryptionConfiguration: {
            encryptionMode: 'SSE-KMS',
          },
          localDiskEncryptionConfiguration: {
            encryptionKeyProviderType: 'KMS',
            awsKmsKey: 'arn:aws:kms:region:account-id:key/key-id',
          },
        },
      },
    },
  });
  
  // ok: typescript-cdk-emr-auth-ec-2-key-pair-or-kerberos
  const cluster = new emr.CfnCluster(scope, 'MyEmrCluster', {
    name: 'MyCluster',
    releaseLabel: 'emr-6.2.0',
    instances: {
      masterInstanceType: 'm5.xlarge',
      slaveInstanceType: 'm5.large',
      instanceCount: 3,
      ec2KeyName: ssm.StringParameter.valueForStringParameter(scope, '/emr/keypair/name'),
    },
    securityConfiguration: securityConfig.name,
    jobFlowRole: 'EMR_EC2_DefaultRole',
    serviceRole: 'EMR_DefaultRole',
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_5(scope: Construct) {
  // Creating EMR cluster with proper IAM roles and secure configurations
  const jobFlowRole = new iam.Role(scope, 'EMRJobFlowRole', {
    assumedBy: new iam.ServicePrincipal('ec2.amazonaws.com'),
    managedPolicies: [
      iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AmazonElasticMapReduceforEC2Role'),
    ],
  });
  
  const serviceRole = new iam.Role(scope, 'EMRServiceRole', {
    assumedBy: new iam.ServicePrincipal('elasticmapreduce.amazonaws.com'),
    managedPolicies: [
      iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AmazonEMRServicePolicy'),
    ],
  });
  
  // ok: typescript-cdk-emr-auth-ec-2-key-pair-or-kerberos
  const cluster = new emr.CfnCluster(scope, 'MyEmrCluster', {
    name: 'MyCluster',
    releaseLabel: 'emr-6.2.0',
    instances: {
      masterInstanceType: 'm5.xlarge',
      slaveInstanceType: 'm5.large',
      instanceCount: 3,
      ec2KeyName: ssm.StringParameter.valueForStringParameter(scope, '/emr/keypair/name'),
      terminationProtected: true,
    },
    jobFlowRole: jobFlowRole.roleName,
    serviceRole: serviceRole.roleName,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_6(scope: Construct) {
  // Creating EMR cluster with secure bootstrap actions
  // ok: typescript-cdk-emr-auth-ec-2-key-pair-or-kerberos
  const cluster = new emr.CfnCluster(scope, 'MyEmrCluster', {
    name: 'MyCluster',
    releaseLabel: 'emr-6.2.0',
    instances: {
      masterInstanceType: 'm5.xlarge',
      slaveInstanceType: 'm5.large',
      instanceCount: 3,
      ec2KeyName: ssm.StringParameter.valueForStringParameter(scope, '/emr/keypair/name'),
    },
    bootstrapActions: [
      {
        name: 'EnhanceSecurity',
        scriptBootstrapAction: {
          path: 's3://mybucket/enhance-security.sh',
          args: ['--enable-encryption', '--apply-security-patches'],
        },
      },
    ],
    jobFlowRole: 'EMR_EC2_DefaultRole',
    serviceRole: 'EMR_DefaultRole',
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_7(scope: Construct) {
  // Creating EMR cluster with secure Kerberos configuration using Active Directory
  // ok: typescript-cdk-emr-auth-ec-2-key-pair-or-kerberos
  const cluster = new emr.CfnCluster(scope, 'MyEmrCluster', {
    name: 'MyCluster',
    releaseLabel: 'emr-6.2.0',
    instances: {
      masterInstanceType: 'm5.xlarge',
      slaveInstanceType: 'm5.large',
      instanceCount: 3,
    },
    kerberosAttributes: {
      realm: 'CORP.EXAMPLE.COM',
      kdcAdminPassword: secretsmanager.Secret.fromSecretNameV2(scope, 'KdcPassword', 'emr/kerberos/kdc-password').secretValue.toString(),
      adDomainJoinUser: 'admin',
      adDomainJoinPassword: secretsmanager.Secret.fromSecretNameV2(scope, 'DomainPassword', 'emr/kerberos/domain-password').secretValue.toString(),
      adDomain: 'corp.example.com',
    },
    jobFlowRole: 'EMR_EC2_DefaultRole',
    serviceRole: 'EMR_DefaultRole',
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_8(scope: Construct) {
  // Creating EMR cluster with both secure key pair and Kerberos
  const keyPairParam = ssm.StringParameter.fromStringParameterAttributes(scope, 'KeyPairParam', {
    parameterName: '/emr/keypair/name',
  });
  
  // ok: typescript-cdk-emr-auth-ec-2-key-pair-or-kerberos
  const cluster = new emr.CfnCluster(scope, 'MyEmrCluster', {
    name: 'MyCluster',
    releaseLabel: 'emr-6.2.0',
    instances: {
      masterInstanceType: 'm5.xlarge',
      slaveInstanceType: 'm5.large',
      instanceCount: 3,
      ec2KeyName: keyPairParam.stringValue,
    },
    kerberosAttributes: {
      realm: 'EC2.INTERNAL',
      kdcAdminPassword: secretsmanager.Secret.fromSecretNameV2(scope, 'KdcPassword', 'emr/kerberos/kdc-password').secretValue.toString(),
    },
    jobFlowRole: 'EMR_EC2_DefaultRole',
    serviceRole: 'EMR_DefaultRole',
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_9(scope: Construct) {
  // Creating EMR cluster with secure configurations and logging
  // ok: typescript-cdk-emr-auth-ec-2-key-pair-or-kerberos
  const cluster = new emr.CfnCluster(scope, 'MyEmrCluster', {
    name: 'MyCluster',
    releaseLabel: 'emr-6.2.0',
    instances: {
      masterInstanceType: 'm5.xlarge',
      slaveInstanceType: 'm5.large',
      instanceCount: 3,
      ec2KeyName: ssm.StringParameter.valueForStringParameter(scope, '/emr/keypair/name'),
    },
    logUri: 's3://my-secure-bucket/logs/',
    configurations: [
      {
        classification: 'hadoop-env',
        configurations: [
          {
            classification: 'export',
            configurationProperties: {
              'HADOOP_NAMENODE_OPTS': '-Dhadoop.security.authentication=kerberos',
            },
          },
        ],
      },
    ],
    jobFlowRole: 'EMR_EC2_DefaultRole',
    serviceRole: 'EMR_DefaultRole',
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_10(scope: Construct) {
  // Creating EMR cluster with secure step configurations
  // ok: typescript-cdk-emr-auth-ec-2-key-pair-or-kerberos
  const cluster = new emr.CfnCluster(scope, 'MyEmrCluster', {
    name: 'MyCluster',
    releaseLabel: 'emr-6.2.0',
    instances: {
      masterInstanceType: 'm5.xlarge',
      slaveInstanceType: 'm5.large',
      instanceCount: 3,
      ec2KeyName: ssm.StringParameter.valueForStringParameter(scope, '/emr/keypair/name'),
    },
    steps: [
      {
        name: 'SetupSecurity',
        actionOnFailure: 'TERMINATE_CLUSTER',
        hadoopJarStep: {
          jar: 'command-runner.jar',
          args: ['sudo', 'bash', '-c', 'yum update -y && yum install -y security-tools'],
        },
      },
    ],
    jobFlowRole: 'EMR_EC2_DefaultRole',
    serviceRole: 'EMR_DefaultRole',
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_11(scope: Construct) {
  // Creating EMR cluster with secure instance fleet configuration
  // ok: typescript-cdk-emr-auth-ec-2-key-pair-or-kerberos
  const vpc = new ec2.Vpc(scope, 'MyVpc', { maxAzs: 2 });
  
  const cluster = new emr.CfnCluster(scope, 'MyEmrCluster', {
    name: 'MyCluster',
    releaseLabel: 'emr-6.2.0',
    instances: {
      ec2KeyName: ssm.StringParameter.valueForStringParameter(scope, '/emr/keypair/name'),
      instanceFleets: [
        {
          instanceFleetType: 'MASTER',
          targetOnDemandCapacity: 1,
          instanceTypeConfigs: [
            {
              instanceType: 'm5.xlarge',
              ebsConfiguration: {
                ebsBlockDeviceConfigs: [
                  {
                    volumeSpecification: {
                      sizeInGB: 100,
                      volumeType: 'gp2',
                      encrypted: true, // Ensure EBS volumes are encrypted
                    },
                    volumesPerInstance: 1,
                  },
                ],
              },
            },
          ],
        },
      ],
      ec2SubnetIds: vpc.privateSubnets.map(subnet => subnet.subnetId),
    },
    jobFlowRole: 'EMR_EC2_DefaultRole',
    serviceRole: 'EMR_DefaultRole',
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_12(scope: Construct) {
  // Creating EMR cluster with secure configurations and applications
  // ok: typescript-cdk-emr-auth-ec-2-key-pair-or-kerberos
  const cluster = new emr.CfnCluster(scope, 'MyEmrCluster', {
    name: 'MyCluster',
    releaseLabel: 'emr-6.2.0',
    instances: {
      masterInstanceType: 'm5.xlarge',
      slaveInstanceType: 'm5.large',
      instanceCount: 3,
      ec2KeyName: ssm.StringParameter.valueForStringParameter(scope, '/emr/keypair/name'),
    },
    applications: [
      { name: 'Hadoop' },
      { name: 'Spark' },
      { name: 'Hive' },
      { name: 'Tez' },
    ],
    configurations: [
      {
        classification: 'spark-defaults',
        configurationProperties: {
          'spark.authenticate': 'true',
          'spark.network.crypto.enabled': 'true',
        },
      },
    ],
    jobFlowRole: 'EMR_EC2_DefaultRole',
    serviceRole: 'EMR_DefaultRole',
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_13(scope: Construct) {
  // Creating EMR cluster with secure auto-scaling configuration
  // ok: typescript-cdk-emr-auth-ec-2-key-pair-or-kerberos
  const cluster = new emr.CfnCluster(scope, 'MyEmrCluster', {
    name: 'MyCluster',
    releaseLabel: 'emr-6.2.0',
    instances: {
      masterInstanceType: 'm5.xlarge',
      slaveInstanceType: 'm5.large',
      instanceCount: 3,
      ec2KeyName: ssm.StringParameter.valueForStringParameter(scope, '/emr/keypair/name'),
    },
    autoScalingRole: 'EMR_AutoScaling_DefaultRole',
    configurations: [
      {
        classification: 'hadoop-env',
        properties: {
          'hadoop.security.authentication': 'kerberos',
          'hadoop.security.authorization': 'true',
        },
      },
    ],
    jobFlowRole: 'EMR_EC2_DefaultRole',
    serviceRole: 'EMR_DefaultRole',
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_14(scope: Construct) {
  // Creating EMR cluster with secure tags and metadata
  // ok: typescript-cdk-emr-auth-ec-2-key-pair-or-kerberos
  const cluster = new emr.CfnCluster(scope, 'MyEmrCluster', {
    name: 'MyCluster',
    releaseLabel: 'emr-6.2.0',
    instances: {
      masterInstanceType: 'm5.xlarge',
      slaveInstanceType: 'm5.large',
      instanceCount: 3,
      ec2KeyName: ssm.StringParameter.valueForStringParameter(scope, '/emr/keypair/name'),
    },
    tags: [
      {
        key: 'Environment',
        value: 'Production',
      },
      {
        key: 'SecurityLevel',
        value: 'High',
      },
    ],
    jobFlowRole: 'EMR_EC2_DefaultRole',
    serviceRole: 'EMR_DefaultRole',
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_15(scope: Construct) {
  // Creating EMR cluster with custom AMI and secure configurations
  const customAmiId = ssm.StringParameter.valueForStringParameter(scope, '/emr/custom-ami/id');
  
  // ok: typescript-cdk-emr-auth-ec-2-key-pair-or-kerberos
  const cluster = new emr.CfnCluster(scope, 'MyEmrCluster', {
    name: 'MyCluster',
    releaseLabel: 'emr-6.2.0',
    customAmiId: customAmiId,
    instances: {
      masterInstanceType: 'm5.xlarge',
      slaveInstanceType: 'm5.large',
      instanceCount: 3,
      ec2KeyName: ssm.StringParameter.valueForStringParameter(scope, '/emr/keypair/name'),
    },
    securityConfiguration: 'SecureEMRConfig',
    configurations: [
      {
        classification: 'emrfs-site',
        properties: {
          'fs.s3.enableServerSideEncryption': 'true',
          'fs.s3.serverSideEncryptionAlgorithm': 'AES256',
        },
      },
    ],
    jobFlowRole: 'EMR_EC2_DefaultRole',
    serviceRole: 'EMR_DefaultRole',
  });
}
// {/fact}