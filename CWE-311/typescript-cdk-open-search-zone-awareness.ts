import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as opensearch from 'aws-cdk-lib/aws-opensearch';
import * as ec2 from 'aws-cdk-lib/aws-ec2';

// True Positive Examples (Vulnerable Code)

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_1(scope: Construct) {
  // Creating an OpenSearch domain without zone awareness
  // ruleid: typescript-cdk-open-search-zone-awareness
  new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      masterNodes: 3,
    },
    ebs: {
      volumeSize: 20,
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_2(scope: Construct) {
  // Creating an OpenSearch domain with zone awareness explicitly disabled
  // ruleid: typescript-cdk-open-search-zone-awareness
  new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_2,
    capacity: {
      dataNodes: 4,
      masterNodes: 3,
      dataNodeInstanceType: 't3.small.search',
      masterNodeInstanceType: 't3.small.search',
    },
    zoneAwareness: {
      enabled: false,
    },
    ebs: {
      volumeSize: 100,
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_3(scope: Construct) {
  // Creating an OpenSearch domain with zone awareness not specified in a production environment
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript-cdk-open-search-zone-awareness
  new opensearch.Domain(scope, 'ProductionDomain', {
    version: opensearch.EngineVersion.OPENSEARCH_2_3,
    capacity: {
      dataNodes: 6,
      masterNodes: 3,
    },
    vpc,
    vpcSubnets: [{ subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS }],
    ebs: {
      volumeSize: 500,
    },
    encryptionAtRest: {
      enabled: true,
    },
    nodeToNodeEncryption: true,
    enforceHttps: true,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_4(scope: Construct) {
  // Creating an OpenSearch domain with minimal configuration
  // ruleid: typescript-cdk-open-search-zone-awareness
  const domain = new opensearch.Domain(scope, 'MinimalDomain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 1,
    },
    ebs: {
      volumeSize: 10,
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_5(scope: Construct) {
  // Creating an OpenSearch domain with zone awareness disabled and custom settings
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript-cdk-open-search-zone-awareness
  const domain = new opensearch.Domain(scope, 'CustomDomain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_3,
    capacity: {
      dataNodes: 3,
      masterNodes: 3,
    },
    zoneAwareness: {
      enabled: false,
      availabilityZoneCount: 2, // This won't have effect since enabled is false
    },
    vpc,
    vpcSubnets: [{ subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS }],
    ebs: {
      volumeSize: 100,
      volumeType: ec2.EbsDeviceVolumeType.GP3,
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_6(scope: Construct, stack: cdk.Stack) {
  // Creating an OpenSearch domain with zone awareness not specified and using variables
  const dataNodeCount = 4;
  const volumeSize = 200;
  
  // ruleid: typescript-cdk-open-search-zone-awareness
  new opensearch.Domain(scope, 'VariableDomain', {
    version: opensearch.EngineVersion.OPENSEARCH_2_5,
    capacity: {
      dataNodes: dataNodeCount,
      dataNodeInstanceType: 'r6g.large.search',
    },
    ebs: {
      volumeSize: volumeSize,
    },
    encryptionAtRest: {
      enabled: true,
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_7(scope: Construct) {
  // Creating an OpenSearch domain with conditional configuration but no zone awareness
  const isProd = process.env.ENVIRONMENT === 'production';
  
  // ruleid: typescript-cdk-open-search-zone-awareness
  new opensearch.Domain(scope, 'ConditionalDomain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: isProd ? 6 : 2,
      masterNodes: isProd ? 3 : undefined,
      dataNodeInstanceType: isProd ? 'r6g.xlarge.search' : 't3.small.search',
    },
    ebs: {
      volumeSize: isProd ? 500 : 100,
    },
    encryptionAtRest: {
      enabled: isProd,
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_8(scope: Construct) {
  // Creating an OpenSearch domain with advanced options but no zone awareness
  // ruleid: typescript-cdk-open-search-zone-awareness
  new opensearch.Domain(scope, 'AdvancedDomain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 3,
      masterNodes: 3,
    },
    ebs: {
      volumeSize: 100,
    },
    advancedOptions: {
      'rest.action.multi.allow_explicit_index': 'true',
      'indices.fielddata.cache.size': '40',
    },
    accessPolicies: new cdk.aws_iam.PolicyDocument({
      statements: [
        new cdk.aws_iam.PolicyStatement({
          actions: ['es:*'],
          resources: ['*'],
          principals: [new cdk.aws_iam.AnyPrincipal()],
        }),
      ],
    }),
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_9(scope: Construct) {
  // Creating an OpenSearch domain with logging enabled but no zone awareness
  // ruleid: typescript-cdk-open-search-zone-awareness
  new opensearch.Domain(scope, 'LoggingDomain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      masterNodes: 3,
    },
    ebs: {
      volumeSize: 100,
    },
    logging: {
      slowSearchLogEnabled: true,
      appLogEnabled: true,
      slowIndexLogEnabled: true,
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_10(scope: Construct) {
  // Creating an OpenSearch domain with fine-grained access control but no zone awareness
  // ruleid: typescript-cdk-open-search-zone-awareness
  new opensearch.Domain(scope, 'SecureDomain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      masterNodes: 3,
    },
    ebs: {
      volumeSize: 100,
    },
    enforceHttps: true,
    nodeToNodeEncryption: true,
    encryptionAtRest: {
      enabled: true,
    },
    fineGrainedAccessControl: {
      masterUserName: 'admin',
      masterUserPassword: cdk.SecretValue.secretsManager('opensearch/masteruser'),
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_11(scope: Construct) {
  // Creating an OpenSearch domain with custom endpoint but no zone awareness
  // ruleid: typescript-cdk-open-search-zone-awareness
  new opensearch.Domain(scope, 'CustomEndpointDomain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      masterNodes: 3,
    },
    ebs: {
      volumeSize: 100,
    },
    customEndpoint: {
      domainName: 'search.example.com',
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_12(scope: Construct) {
  // Creating an OpenSearch domain with UltraWarm storage but no zone awareness
  // ruleid: typescript-cdk-open-search-zone-awareness
  new opensearch.Domain(scope, 'UltraWarmDomain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      masterNodes: 3,
      warmNodes: 2,
      warmInstanceType: 'ultrawarm1.medium.search',
    },
    ebs: {
      volumeSize: 100,
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_13(scope: Construct) {
  // Creating an OpenSearch domain with automated snapshot configuration but no zone awareness
  // ruleid: typescript-cdk-open-search-zone-awareness
  new opensearch.Domain(scope, 'SnapshotDomain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      masterNodes: 3,
    },
    ebs: {
      volumeSize: 100,
    },
    automatedSnapshotStartHour: 3,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_14(scope: Construct) {
  // Creating an OpenSearch domain with domain name specified but no zone awareness
  // ruleid: typescript-cdk-open-search-zone-awareness
  new opensearch.Domain(scope, 'NamedDomain', {
    domainName: 'my-search-domain',
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      masterNodes: 3,
    },
    ebs: {
      volumeSize: 100,
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_15(scope: Construct) {
  // Creating an OpenSearch domain with cognito authentication but no zone awareness
  const userPool = new cdk.aws_cognito.UserPool(scope, 'UserPool');
  const identityPool = new cdk.aws_cognito.CfnIdentityPool(scope, 'IdentityPool', {
    allowUnauthenticatedIdentities: false,
  });
  
  // ruleid: typescript-cdk-open-search-zone-awareness
  new opensearch.Domain(scope, 'CognitoDomain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      masterNodes: 3,
    },
    ebs: {
      volumeSize: 100,
    },
    cognitoDashboardsAuth: {
      identityPoolId: identityPool.ref,
      userPoolId: userPool.userPoolId,
      role: new cdk.aws_iam.Role(scope, 'CognitoRole', {
        assumedBy: new cdk.aws_iam.ServicePrincipal('opensearchservice.amazonaws.com'),
      }),
    },
  });
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_1(scope: Construct) {
  // Creating an OpenSearch domain with zone awareness enabled
  // ok: typescript-cdk-open-search-zone-awareness
  new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      masterNodes: 3,
    },
    zoneAwareness: {
      enabled: true,
    },
    ebs: {
      volumeSize: 20,
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_2(scope: Construct) {
  // Creating an OpenSearch domain with zone awareness enabled and availability zone count specified
  // ok: typescript-cdk-open-search-zone-awareness
  new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_2,
    capacity: {
      dataNodes: 4,
      masterNodes: 3,
      dataNodeInstanceType: 't3.small.search',
      masterNodeInstanceType: 't3.small.search',
    },
    zoneAwareness: {
      enabled: true,
      availabilityZoneCount: 3,
    },
    ebs: {
      volumeSize: 100,
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_3(scope: Construct) {
  // Creating an OpenSearch domain with zone awareness enabled in a VPC
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript-cdk-open-search-zone-awareness
  new opensearch.Domain(scope, 'ProductionDomain', {
    version: opensearch.EngineVersion.OPENSEARCH_2_3,
    capacity: {
      dataNodes: 6,
      masterNodes: 3,
    },
    zoneAwareness: {
      enabled: true,
      availabilityZoneCount: 2,
    },
    vpc,
    vpcSubnets: [{ subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS }],
    ebs: {
      volumeSize: 500,
    },
    encryptionAtRest: {
      enabled: true,
    },
    nodeToNodeEncryption: true,
    enforceHttps: true,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_4(scope: Construct) {
  // Creating an OpenSearch domain with zone awareness enabled using variables
  const isZoneAwarenessEnabled = true;
  const azCount = 3;
  
  // ok: typescript-cdk-open-search-zone-awareness
  const domain = new opensearch.Domain(scope, 'VariableDomain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 6,
    },
    zoneAwareness: {
      enabled: isZoneAwarenessEnabled,
      availabilityZoneCount: azCount,
    },
    ebs: {
      volumeSize: 100,
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_5(scope: Construct) {
  // Creating an OpenSearch domain with zone awareness enabled and custom settings
  // ok: typescript-cdk-open-search-zone-awareness
  const domain = new opensearch.Domain(scope, 'CustomDomain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_3,
    capacity: {
      dataNodes: 6,
      masterNodes: 3,
    },
    zoneAwareness: {
      enabled: true,
      availabilityZoneCount: 2,
    },
    ebs: {
      volumeSize: 100,
      volumeType: ec2.EbsDeviceVolumeType.GP3,
    },
    encryptionAtRest: {
      enabled: true,
    },
    nodeToNodeEncryption: true,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_6(scope: Construct, stack: cdk.Stack) {
  // Creating an OpenSearch domain with zone awareness enabled and using environment variables
  const dataNodeCount = parseInt(process.env.DATA_NODE_COUNT || '4');
  const azCount = parseInt(process.env.AZ_COUNT || '2');
  
  // ok: typescript-cdk-open-search-zone-awareness
  new opensearch.Domain(scope, 'EnvVarDomain', {
    version: opensearch.EngineVersion.OPENSEARCH_2_5,
    capacity: {
      dataNodes: dataNodeCount,
      dataNodeInstanceType: 'r6g.large.search',
    },
    zoneAwareness: {
      enabled: true,
      availabilityZoneCount: azCount,
    },
    ebs: {
      volumeSize: 200,
    },
    encryptionAtRest: {
      enabled: true,
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_7(scope: Construct) {
  // Creating an OpenSearch domain with conditional zone awareness configuration
  const isProd = process.env.ENVIRONMENT === 'production';
  
  // ok: typescript-cdk-open-search-zone-awareness
  new opensearch.Domain(scope, 'ConditionalDomain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: isProd ? 6 : 2,
      masterNodes: isProd ? 3 : undefined,
      dataNodeInstanceType: isProd ? 'r6g.xlarge.search' : 't3.small.search',
    },
    zoneAwareness: {
      enabled: true,
      availabilityZoneCount: isProd ? 3 : 2,
    },
    ebs: {
      volumeSize: isProd ? 500 : 100,
    },
    encryptionAtRest: {
      enabled: isProd,
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_8(scope: Construct) {
  // Creating an OpenSearch domain with advanced options and zone awareness
  // ok: typescript-cdk-open-search-zone-awareness
  new opensearch.Domain(scope, 'AdvancedDomain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 4,
      masterNodes: 3,
    },
    zoneAwareness: {
      enabled: true,
      availabilityZoneCount: 2,
    },
    ebs: {
      volumeSize: 100,
    },
    advancedOptions: {
      'rest.action.multi.allow_explicit_index': 'true',
      'indices.fielddata.cache.size': '40',
    },
    accessPolicies: new cdk.aws_iam.PolicyDocument({
      statements: [
        new cdk.aws_iam.PolicyStatement({
          actions: ['es:*'],
          resources: ['*'],
          principals: [new cdk.aws_iam.AnyPrincipal()],
        }),
      ],
    }),
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_9(scope: Construct) {
  // Creating an OpenSearch domain with logging enabled and zone awareness
  // ok: typescript-cdk-open-search-zone-awareness
  new opensearch.Domain(scope, 'LoggingDomain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 4,
      masterNodes: 3,
    },
    zoneAwareness: {
      enabled: true,
    },
    ebs: {
      volumeSize: 100,
    },
    logging: {
      slowSearchLogEnabled: true,
      appLogEnabled: true,
      slowIndexLogEnabled: true,
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_10(scope: Construct) {
  // Creating an OpenSearch domain with fine-grained access control and zone awareness
  // ok: typescript-cdk-open-search-zone-awareness
  new opensearch.Domain(scope, 'SecureDomain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 4,
      masterNodes: 3,
    },
    zoneAwareness: {
      enabled: true,
      availabilityZoneCount: 2,
    },
    ebs: {
      volumeSize: 100,
    },
    enforceHttps: true,
    nodeToNodeEncryption: true,
    encryptionAtRest: {
      enabled: true,
    },
    fineGrainedAccessControl: {
      masterUserName: 'admin',
      masterUserPassword: cdk.SecretValue.secretsManager('opensearch/masteruser'),
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_11(scope: Construct) {
  // Creating an OpenSearch domain with custom endpoint and zone awareness
  // ok: typescript-cdk-open-search-zone-awareness
  new opensearch.Domain(scope, 'CustomEndpointDomain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 4,
      masterNodes: 3,
    },
    zoneAwareness: {
      enabled: true,
    },
    ebs: {
      volumeSize: 100,
    },
    customEndpoint: {
      domainName: 'search.example.com',
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_12(scope: Construct) {
  // Creating an OpenSearch domain with UltraWarm storage and zone awareness
  // ok: typescript-cdk-open-search-zone-awareness
  new opensearch.Domain(scope, 'UltraWarmDomain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 4,
      masterNodes: 3,
      warmNodes: 2,
      warmInstanceType: 'ultrawarm1.medium.search',
    },
    zoneAwareness: {
      enabled: true,
      availabilityZoneCount: 2,
    },
    ebs: {
      volumeSize: 100,
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_13(scope: Construct) {
  // Creating an OpenSearch domain with automated snapshot configuration and zone awareness
  // ok: typescript-cdk-open-search-zone-awareness
  new opensearch.Domain(scope, 'SnapshotDomain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 4,
      masterNodes: 3,
    },
    zoneAwareness: {
      enabled: true,
    },
    ebs: {
      volumeSize: 100,
    },
    automatedSnapshotStartHour: 3,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_14(scope: Construct) {
  // Creating an OpenSearch domain with domain name specified and zone awareness
  // ok: typescript-cdk-open-search-zone-awareness
  new opensearch.Domain(scope, 'NamedDomain', {
    domainName: 'my-search-domain',
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 4,
      masterNodes: 3,
    },
    zoneAwareness: {
      enabled: true,
      availabilityZoneCount: 2,
    },
    ebs: {
      volumeSize: 100,
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_15(scope: Construct) {
  // Creating an OpenSearch domain with cognito authentication and zone awareness
  const userPool = new cdk.aws_cognito.UserPool(scope, 'UserPool');
  const identityPool = new cdk.aws_cognito.CfnIdentityPool(scope, 'IdentityPool', {
    allowUnauthenticatedIdentities: false,
  });
  
  // ok: typescript-cdk-open-search-zone-awareness
  new opensearch.Domain(scope, 'CognitoDomain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 4,
      masterNodes: 3,
    },
    zoneAwareness: {
      enabled: true,
      availabilityZoneCount: 2,
    },
    ebs: {
      volumeSize: 100,
    },
    cognitoDashboardsAuth: {
      identityPoolId: identityPool.ref,
      userPoolId: userPool.userPoolId,
      role: new cdk.aws_iam.Role(scope, 'CognitoRole', {
        assumedBy: new cdk.aws_iam.ServicePrincipal('opensearchservice.amazonaws.com'),
      }),
    },
  });
}
// {/fact}