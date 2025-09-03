import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as opensearch from 'aws-cdk-lib/aws-opensearch';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as iam from 'aws-cdk-lib/aws-iam';

class OpenSearchStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);
  }
}

// True Positive Examples (Vulnerable Code)

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_1(scope: Construct) {
  // Creating OpenSearch domain without IP allowlisting
  // ruleid: typescript-cdk-open-search-allowlisted-ips
  const domain = new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
    ebs: {
      volumeSize: 10,
    },
    nodeToNodeEncryption: true,
    encryptionAtRest: {
      enabled: true,
    },
    // Missing access policies or IP restrictions
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_2(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // Creating OpenSearch domain with VPC but no IP restrictions
  // ruleid: typescript-cdk-open-search-allowlisted-ips
  const domain = new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    vpc,
    vpcSubnets: [{ subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS }],
    capacity: {
      dataNodes: 3,
      dataNodeInstanceType: 'm5.large.search',
    },
    // Missing access policies or IP restrictions
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_3(scope: Construct) {
  // OpenSearch domain with fine-grained access control but no IP restrictions
  // ruleid: typescript-cdk-open-search-allowlisted-ips
  const domain = new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 1,
      dataNodeInstanceType: 't3.small.search',
    },
    fineGrainedAccessControl: {
      masterUserName: 'admin',
      masterUserPassword: cdk.SecretValue.secretsManager('opensearch/masteruser'),
    },
    enforceHttps: true,
    // Missing IP restrictions
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_4(scope: Construct) {
  // OpenSearch domain with encryption but no IP restrictions
  // ruleid: typescript-cdk-open-search-allowlisted-ips
  const domain = new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 'r5.large.search',
    },
    encryptionAtRest: {
      enabled: true,
    },
    nodeToNodeEncryption: true,
    // Missing IP restrictions
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_5(scope: Construct) {
  // OpenSearch domain with IAM auth but no IP restrictions
  // ruleid: typescript-cdk-open-search-allowlisted-ips
  const domain = new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 1,
      dataNodeInstanceType: 't3.small.search',
    },
    accessPolicies: new iam.PolicyDocument({
      statements: [
        new iam.PolicyStatement({
          actions: ['es:*'],
          resources: ['*'],
          principals: [new iam.ArnPrincipal('arn:aws:iam::123456789012:user/admin')],
        }),
      ],
    }),
    // Missing IP restrictions
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_6(scope: Construct) {
  // OpenSearch domain with custom domain but no IP restrictions
  // ruleid: typescript-cdk-open-search-allowlisted-ips
  const domain = new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.medium.search',
    },
    customEndpoint: {
      domainName: 'search.example.com',
    },
    // Missing IP restrictions
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_7(scope: Construct) {
  // OpenSearch domain with advanced options but no IP restrictions
  // ruleid: typescript-cdk-open-search-allowlisted-ips
  const domain = new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 3,
      dataNodeInstanceType: 'm5.large.search',
    },
    advancedOptions: {
      'rest.action.multi.allow_explicit_index': 'true',
      'indices.fielddata.cache.size': '40',
    },
    // Missing IP restrictions
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_8(scope: Construct) {
  // OpenSearch domain with zone awareness but no IP restrictions
  // ruleid: typescript-cdk-open-search-allowlisted-ips
  const domain = new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 4,
      dataNodeInstanceType: 'r5.large.search',
    },
    zoneAwareness: {
      enabled: true,
      availabilityZoneCount: 2,
    },
    // Missing IP restrictions
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_9(scope: Construct) {
  // OpenSearch domain with logging enabled but no IP restrictions
  // ruleid: typescript-cdk-open-search-allowlisted-ips
  const domain = new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
    logging: {
      slowSearchLogEnabled: true,
      appLogEnabled: true,
      slowIndexLogEnabled: true,
    },
    // Missing IP restrictions
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_10(scope: Construct) {
  // OpenSearch domain with UltraWarm storage but no IP restrictions
  // ruleid: typescript-cdk-open-search-allowlisted-ips
  const domain = new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 'r5.large.search',
      warmNodes: 2,
      warmInstanceType: 'ultrawarm1.medium.search',
    },
    // Missing IP restrictions
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_11(scope: Construct) {
  // OpenSearch domain with cold storage but no IP restrictions
  // ruleid: typescript-cdk-open-search-allowlisted-ips
  const domain = new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 'r5.large.search',
    },
    coldStorage: {
      enabled: true,
    },
    // Missing IP restrictions
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_12(scope: Construct) {
  // OpenSearch domain with auto-tune but no IP restrictions
  // ruleid: typescript-cdk-open-search-allowlisted-ips
  const domain = new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 'm5.large.search',
    },
    autoTune: {
      desiredState: 'ENABLED',
    },
    // Missing IP restrictions
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_13(scope: Construct) {
  // OpenSearch domain with specific version but no IP restrictions
  // ruleid: typescript-cdk-open-search-allowlisted-ips
  const domain = new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.ELASTICSEARCH_7_10,
    capacity: {
      dataNodes: 1,
      dataNodeInstanceType: 't3.small.search',
    },
    // Missing IP restrictions
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_14(scope: Construct) {
  // OpenSearch domain with custom KMS key but no IP restrictions
  // ruleid: typescript-cdk-open-search-allowlisted-ips
  const kmsKey = new cdk.aws_kms.Key(scope, 'Key');
  
  const domain = new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
    encryptionAtRest: {
      enabled: true,
      kmsKey: kmsKey,
    },
    // Missing IP restrictions
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_15(scope: Construct) {
  // OpenSearch domain with cognito auth but no IP restrictions
  // ruleid: typescript-cdk-open-search-allowlisted-ips
  const userPool = new cdk.aws_cognito.UserPool(scope, 'UserPool');
  const identityPool = new cdk.aws_cognito.CfnIdentityPool(scope, 'IdentityPool', {
    allowUnauthenticatedIdentities: false,
  });
  
  const domain = new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
    cognitoDashboardsAuth: {
      identityPoolId: identityPool.ref,
      userPoolId: userPool.userPoolId,
      role: new iam.Role(scope, 'CognitoRole', {
        assumedBy: new iam.ServicePrincipal('es.amazonaws.com'),
      }),
    },
    // Missing IP restrictions
  });
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_1(scope: Construct) {
  // OpenSearch domain with IP allowlisting
  // ok: typescript-cdk-open-search-allowlisted-ips
  const domain = new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
    ebs: {
      volumeSize: 10,
    },
    nodeToNodeEncryption: true,
    encryptionAtRest: {
      enabled: true,
    },
    accessPolicies: new iam.PolicyDocument({
      statements: [
        new iam.PolicyStatement({
          actions: ['es:*'],
          resources: ['*'],
          principals: [new iam.AnyPrincipal()],
          conditions: {
            IpAddress: {
              'aws:SourceIp': ['192.168.0.0/24', '10.0.0.0/16'],
            },
          },
        }),
      ],
    }),
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_2(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // OpenSearch domain with VPC and security group restrictions
  // ok: typescript-cdk-open-search-allowlisted-ips
  const securityGroup = new ec2.SecurityGroup(scope, 'SecurityGroup', {
    vpc,
    description: 'Allow access to OpenSearch',
  });
  
  securityGroup.addIngressRule(
    ec2.Peer.ipv4('10.0.0.0/16'),
    ec2.Port.tcp(443),
    'Allow HTTPS from corporate network'
  );
  
  const domain = new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    vpc,
    vpcSubnets: [{ subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS }],
    securityGroups: [securityGroup],
    capacity: {
      dataNodes: 3,
      dataNodeInstanceType: 'm5.large.search',
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_3(scope: Construct) {
  // OpenSearch domain with fine-grained access control and IP restrictions
  // ok: typescript-cdk-open-search-allowlisted-ips
  const domain = new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 1,
      dataNodeInstanceType: 't3.small.search',
    },
    fineGrainedAccessControl: {
      masterUserName: 'admin',
      masterUserPassword: cdk.SecretValue.secretsManager('opensearch/masteruser'),
    },
    enforceHttps: true,
    accessPolicies: new iam.PolicyDocument({
      statements: [
        new iam.PolicyStatement({
          actions: ['es:ESHttp*'],
          resources: ['*'],
          principals: [new iam.AnyPrincipal()],
          conditions: {
            IpAddress: {
              'aws:SourceIp': ['192.168.1.0/24'],
            },
          },
        }),
      ],
    }),
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_4(scope: Construct) {
  // OpenSearch domain with encryption and IP restrictions
  // ok: typescript-cdk-open-search-allowlisted-ips
  const domain = new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 'r5.large.search',
    },
    encryptionAtRest: {
      enabled: true,
    },
    nodeToNodeEncryption: true,
    accessPolicies: new iam.PolicyDocument({
      statements: [
        new iam.PolicyStatement({
          actions: ['es:*'],
          resources: ['*'],
          principals: [new iam.ArnPrincipal('arn:aws:iam::123456789012:role/ESAdmin')],
          conditions: {
            IpAddress: {
              'aws:SourceIp': ['10.20.30.0/24', '172.16.0.0/16'],
            },
          },
        }),
      ],
    }),
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_5(scope: Construct) {
  // OpenSearch domain with IAM auth and IP restrictions
  // ok: typescript-cdk-open-search-allowlisted-ips
  const domain = new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 1,
      dataNodeInstanceType: 't3.small.search',
    },
    accessPolicies: new iam.PolicyDocument({
      statements: [
        new iam.PolicyStatement({
          actions: ['es:*'],
          resources: ['*'],
          principals: [new iam.ArnPrincipal('arn:aws:iam::123456789012:user/admin')],
          conditions: {
            IpAddress: {
              'aws:SourceIp': ['203.0.113.0/24'],
            },
          },
        }),
      ],
    }),
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_6(scope: Construct) {
  // OpenSearch domain with custom domain and IP restrictions
  // ok: typescript-cdk-open-search-allowlisted-ips
  const domain = new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.medium.search',
    },
    customEndpoint: {
      domainName: 'search.example.com',
    },
    accessPolicies: new iam.PolicyDocument({
      statements: [
        new iam.PolicyStatement({
          actions: ['es:*'],
          resources: ['*'],
          principals: [new iam.AnyPrincipal()],
          conditions: {
            IpAddress: {
              'aws:SourceIp': ['192.168.0.0/16'],
            },
          },
        }),
      ],
    }),
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_7(scope: Construct) {
  // OpenSearch domain with advanced options and IP restrictions
  // ok: typescript-cdk-open-search-allowlisted-ips
  const domain = new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 3,
      dataNodeInstanceType: 'm5.large.search',
    },
    advancedOptions: {
      'rest.action.multi.allow_explicit_index': 'true',
      'indices.fielddata.cache.size': '40',
    },
    accessPolicies: new iam.PolicyDocument({
      statements: [
        new iam.PolicyStatement({
          actions: ['es:*'],
          resources: ['*'],
          principals: [new iam.AnyPrincipal()],
          conditions: {
            IpAddress: {
              'aws:SourceIp': ['10.0.0.0/8', '172.16.0.0/12'],
            },
          },
        }),
      ],
    }),
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_8(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // OpenSearch domain with VPC endpoint access
  // ok: typescript-cdk-open-search-allowlisted-ips
  const domain = new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    vpc,
    vpcSubnets: [{ subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS }],
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.medium.search',
    },
    securityGroups: [
      new ec2.SecurityGroup(scope, 'ESSecurityGroup', {
        vpc,
        description: 'Allow access to OpenSearch',
        allowAllOutbound: true,
      }),
    ],
  });
  
  // Adding VPC endpoint for secure access
  const endpoint = new ec2.InterfaceVpcEndpoint(scope, 'ESEndpoint', {
    vpc,
    service: ec2.InterfaceVpcEndpointAwsService.ELASTICSEARCH,
    privateDnsEnabled: true,
    subnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_9(scope: Construct) {
  // OpenSearch domain with logging and IP restrictions
  // ok: typescript-cdk-open-search-allowlisted-ips
  const domain = new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
    logging: {
      slowSearchLogEnabled: true,
      appLogEnabled: true,
      slowIndexLogEnabled: true,
    },
    accessPolicies: new iam.PolicyDocument({
      statements: [
        new iam.PolicyStatement({
          actions: ['es:*'],
          resources: ['*'],
          principals: [new iam.AnyPrincipal()],
          conditions: {
            IpAddress: {
              'aws:SourceIp': ['198.51.100.0/24'],
            },
          },
        }),
      ],
    }),
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_10(scope: Construct) {
  // OpenSearch domain with UltraWarm storage and IP restrictions
  // ok: typescript-cdk-open-search-allowlisted-ips
  const domain = new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 'r5.large.search',
      warmNodes: 2,
      warmInstanceType: 'ultrawarm1.medium.search',
    },
    accessPolicies: new iam.PolicyDocument({
      statements: [
        new iam.PolicyStatement({
          actions: ['es:*'],
          resources: ['*'],
          principals: [new iam.AnyPrincipal()],
          conditions: {
            IpAddress: {
              'aws:SourceIp': ['192.0.2.0/24', '203.0.113.0/24'],
            },
          },
        }),
      ],
    }),
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_11(scope: Construct) {
  // OpenSearch domain with cold storage and IP restrictions
  // ok: typescript-cdk-open-search-allowlisted-ips
  const domain = new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 'r5.large.search',
    },
    coldStorage: {
      enabled: true,
    },
    accessPolicies: new iam.PolicyDocument({
      statements: [
        new iam.PolicyStatement({
          actions: ['es:*'],
          resources: ['*'],
          principals: [new iam.AnyPrincipal()],
          conditions: {
            IpAddress: {
              'aws:SourceIp': ['10.10.0.0/16'],
            },
          },
        }),
      ],
    }),
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_12(scope: Construct) {
  // OpenSearch domain with auto-tune and IP restrictions
  // ok: typescript-cdk-open-search-allowlisted-ips
  const domain = new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 'm5.large.search',
    },
    autoTune: {
      desiredState: 'ENABLED',
    },
    accessPolicies: new iam.PolicyDocument({
      statements: [
        new iam.PolicyStatement({
          actions: ['es:*'],
          resources: ['*'],
          principals: [new iam.AnyPrincipal()],
          conditions: {
            IpAddress: {
              'aws:SourceIp': ['172.31.0.0/16'],
            },
          },
        }),
      ],
    }),
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_13(scope: Construct) {
  // OpenSearch domain with specific version and IP restrictions
  // ok: typescript-cdk-open-search-allowlisted-ips
  const domain = new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.ELASTICSEARCH_7_10,
    capacity: {
      dataNodes: 1,
      dataNodeInstanceType: 't3.small.search',
    },
    accessPolicies: new iam.PolicyDocument({
      statements: [
        new iam.PolicyStatement({
          actions: ['es:*'],
          resources: ['*'],
          principals: [new iam.AnyPrincipal()],
          conditions: {
            IpAddress: {
              'aws:SourceIp': ['192.168.100.0/24'],
            },
          },
        }),
      ],
    }),
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_14(scope: Construct) {
  // OpenSearch domain with custom KMS key and IP restrictions
  // ok: typescript-cdk-open-search-allowlisted-ips
  const kmsKey = new cdk.aws_kms.Key(scope, 'Key');
  
  const domain = new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
    encryptionAtRest: {
      enabled: true,
      kmsKey: kmsKey,
    },
    accessPolicies: new iam.PolicyDocument({
      statements: [
        new iam.PolicyStatement({
          actions: ['es:*'],
          resources: ['*'],
          principals: [new iam.AnyPrincipal()],
          conditions: {
            IpAddress: {
              'aws:SourceIp': ['10.100.0.0/16', '10.200.0.0/16'],
            },
          },
        }),
      ],
    }),
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_15(scope: Construct) {
  // OpenSearch domain with cognito auth and IP restrictions
  // ok: typescript-cdk-open-search-allowlisted-ips
  const userPool = new cdk.aws_cognito.UserPool(scope, 'UserPool');
  const identityPool = new cdk.aws_cognito.CfnIdentityPool(scope, 'IdentityPool', {
    allowUnauthenticatedIdentities: false,
  });
  
  const domain = new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
    cognitoDashboardsAuth: {
      identityPoolId: identityPool.ref,
      userPoolId: userPool.userPoolId,
      role: new iam.Role(scope, 'CognitoRole', {
        assumedBy: new iam.ServicePrincipal('es.amazonaws.com'),
      }),
    },
    accessPolicies: new iam.PolicyDocument({
      statements: [
        new iam.PolicyStatement({
          actions: ['es:ESHttp*'],
          resources: ['*'],
          principals: [new iam.AnyPrincipal()],
          conditions: {
            IpAddress: {
              'aws:SourceIp': ['192.168.200.0/24'],
            },
          },
        }),
      ],
    }),
  });
}
// {/fact}