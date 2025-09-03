import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as opensearch from 'aws-cdk-lib/aws-opensearch';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as iam from 'aws-cdk-lib/aws-iam';

// True Positive Examples (Vulnerable Code)

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_1(scope: Construct) {
  // Creating an OpenSearch domain without VPC configuration
  // ruleid: typescript-cdk-open-search-in-vpc-only
  const domain = new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
    ebs: {
      volumeSize: 10,
    },
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_2(scope: Construct) {
  // Creating an OpenSearch domain with explicit public access
  // ruleid: typescript-cdk-open-search-in-vpc-only
  const domain = new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_2,
    capacity: {
      dataNodes: 3,
      dataNodeInstanceType: 'm5.large.search',
    },
    ebs: {
      volumeSize: 20,
    },
    enforceHttps: true,
    nodeToNodeEncryption: true,
    encryptionAtRest: {
      enabled: true,
    },
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_3(scope: Construct) {
  // Creating an OpenSearch domain with fine-grained access control but no VPC
  // ruleid: typescript-cdk-open-search-in-vpc-only
  const domain = new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_3,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 'r5.large.search',
    },
    ebs: {
      volumeSize: 100,
    },
    fineGrainedAccessControl: {
      masterUserName: 'admin',
      masterUserPassword: cdk.SecretValue.secretsManager('opensearch/masteruser'),
    },
    encryptionAtRest: {
      enabled: true,
    },
    nodeToNodeEncryption: true,
    enforceHttps: true,
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_4(scope: Construct, stack: cdk.Stack) {
  // Creating an OpenSearch domain with advanced options but no VPC
  // ruleid: typescript-cdk-open-search-in-vpc-only
  const domain = new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_2_3,
    capacity: {
      dataNodes: 4,
      dataNodeInstanceType: 'c5.large.search',
    },
    ebs: {
      volumeSize: 50,
    },
    zoneAwareness: {
      enabled: true,
      availabilityZoneCount: 2,
    },
    logging: {
      slowSearchLogEnabled: true,
      appLogEnabled: true,
      slowIndexLogEnabled: true,
    },
    advancedOptions: {
      'rest.action.multi.allow_explicit_index': 'true',
      'indices.fielddata.cache.size': '40',
    },
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_5(scope: Construct) {
  // Creating an OpenSearch domain with custom domain name but no VPC
  // ruleid: typescript-cdk-open-search-in-vpc-only
  const domain = new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 1,
      dataNodeInstanceType: 't3.small.search',
    },
    ebs: {
      volumeSize: 10,
    },
    customEndpoint: {
      domainName: 'search.example.com',
    },
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_6(scope: Construct) {
  // Creating an OpenSearch domain with encryption but no VPC
  // ruleid: typescript-cdk-open-search-in-vpc-only
  const domain = new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_1,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 'm5.large.search',
    },
    ebs: {
      volumeSize: 20,
    },
    encryptionAtRest: {
      enabled: true,
    },
    nodeToNodeEncryption: true,
    enforceHttps: true,
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_7(scope: Construct) {
  // Creating an OpenSearch domain with access policies but no VPC
  // ruleid: typescript-cdk-open-search-in-vpc-only
  const domain = new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
    ebs: {
      volumeSize: 10,
    },
    accessPolicies: new iam.PolicyDocument({
      statements: [
        new iam.PolicyStatement({
          actions: ['es:ESHttp*'],
          resources: ['*'],
          principals: [new iam.AnyPrincipal()],
          conditions: {
            'IpAddress': {
              'aws:SourceIp': ['192.0.2.0/24']
            }
          }
        }),
      ],
    }),
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_8(scope: Construct) {
  // Creating an OpenSearch domain with automated snapshot configuration but no VPC
  // ruleid: typescript-cdk-open-search-in-vpc-only
  const domain = new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
    ebs: {
      volumeSize: 10,
    },
    automatedSnapshotStartHour: 3,
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_9(scope: Construct) {
  // Creating an OpenSearch domain with warm nodes but no VPC
  // ruleid: typescript-cdk-open-search-in-vpc-only
  const domain = new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 'r5.large.search',
      warmNodes: 2,
      warmInstanceType: 'ultrawarm1.medium.search',
    },
    ebs: {
      volumeSize: 10,
    },
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_10(scope: Construct) {
  // Creating an OpenSearch domain with custom KMS key but no VPC
  // ruleid: typescript-cdk-open-search-in-vpc-only
  const kmsKey = new cdk.aws_kms.Key(scope, 'Key');
  const domain = new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
    ebs: {
      volumeSize: 10,
    },
    encryptionAtRest: {
      enabled: true,
      kmsKey: kmsKey,
    },
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_11(scope: Construct) {
  // Creating an OpenSearch domain with cognito authentication but no VPC
  // ruleid: typescript-cdk-open-search-in-vpc-only
  const domain = new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
    ebs: {
      volumeSize: 10,
    },
    cognitoDashboardsAuth: {
      identityPoolId: 'us-east-1:12345678-1234-1234-1234-123456789012',
      userPoolId: 'us-east-1_ABCDEFGHI',
      role: new iam.Role(scope, 'CognitoRole', {
        assumedBy: new iam.ServicePrincipal('es.amazonaws.com'),
      }),
    },
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_12(scope: Construct) {
  // Creating an OpenSearch domain with tags but no VPC
  // ruleid: typescript-cdk-open-search-in-vpc-only
  const domain = new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
    ebs: {
      volumeSize: 10,
    },
  });
  
  cdk.Tags.of(domain).add('Environment', 'Production');
  cdk.Tags.of(domain).add('Owner', 'DataTeam');
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_13(scope: Construct) {
  // Creating an OpenSearch domain with UltraWarm and Cold storage but no VPC
  // ruleid: typescript-cdk-open-search-in-vpc-only
  const domain = new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_3,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 'r6g.large.search',
      warmNodes: 2,
      warmInstanceType: 'ultrawarm1.medium.search',
      coldStorageEnabled: true,
    },
    ebs: {
      volumeSize: 100,
    },
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_14(scope: Construct) {
  // Creating an OpenSearch domain with custom endpoint and certificate but no VPC
  // ruleid: typescript-cdk-open-search-in-vpc-only
  const domain = new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
    ebs: {
      volumeSize: 10,
    },
    customEndpoint: {
      domainName: 'search.example.com',
      certificate: cdk.aws_certificatemanager.Certificate.fromCertificateArn(
        scope,
        'Certificate',
        'arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012'
      ),
    },
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_15(scope: Construct) {
  // Creating an OpenSearch domain with advanced security options but no VPC
  // ruleid: typescript-cdk-open-search-in-vpc-only
  const domain = new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 'r5.large.search',
    },
    ebs: {
      volumeSize: 10,
    },
    nodeToNodeEncryption: true,
    encryptionAtRest: {
      enabled: true,
    },
    enforceHttps: true,
    tlsSecurityPolicy: opensearch.TLSSecurityPolicy.TLS_1_2,
  });
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=object-presence@v1.0 defects=0}
function good_case_1(scope: Construct) {
  // Creating an OpenSearch domain with VPC configuration
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript-cdk-open-search-in-vpc-only
  const domain = new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
    ebs: {
      volumeSize: 10,
    },
    vpc,
    vpcSubnets: [{ subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS }],
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_2(scope: Construct) {
  // Creating an OpenSearch domain with VPC and security groups
  const vpc = new ec2.Vpc(scope, 'VPC');
  const securityGroup = new ec2.SecurityGroup(scope, 'SecurityGroup', { vpc });
  
  // ok: typescript-cdk-open-search-in-vpc-only
  const domain = new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_2,
    capacity: {
      dataNodes: 3,
      dataNodeInstanceType: 'm5.large.search',
    },
    ebs: {
      volumeSize: 20,
    },
    vpc,
    vpcSubnets: [{ subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS }],
    securityGroups: [securityGroup],
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_3(scope: Construct) {
  // Creating an OpenSearch domain with VPC and fine-grained access control
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript-cdk-open-search-in-vpc-only
  const domain = new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_3,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 'r5.large.search',
    },
    ebs: {
      volumeSize: 100,
    },
    vpc,
    vpcSubnets: [{ subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS }],
    fineGrainedAccessControl: {
      masterUserName: 'admin',
      masterUserPassword: cdk.SecretValue.secretsManager('opensearch/masteruser'),
    },
    encryptionAtRest: {
      enabled: true,
    },
    nodeToNodeEncryption: true,
    enforceHttps: true,
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_4(scope: Construct) {
  // Creating an OpenSearch domain with VPC and advanced options
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript-cdk-open-search-in-vpc-only
  const domain = new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_2_3,
    capacity: {
      dataNodes: 4,
      dataNodeInstanceType: 'c5.large.search',
    },
    ebs: {
      volumeSize: 50,
    },
    vpc,
    vpcSubnets: [{ subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS }],
    zoneAwareness: {
      enabled: true,
      availabilityZoneCount: 2,
    },
    logging: {
      slowSearchLogEnabled: true,
      appLogEnabled: true,
      slowIndexLogEnabled: true,
    },
    advancedOptions: {
      'rest.action.multi.allow_explicit_index': 'true',
      'indices.fielddata.cache.size': '40',
    },
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_5(scope: Construct) {
  // Creating an OpenSearch domain with VPC and custom domain name
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript-cdk-open-search-in-vpc-only
  const domain = new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 1,
      dataNodeInstanceType: 't3.small.search',
    },
    ebs: {
      volumeSize: 10,
    },
    vpc,
    vpcSubnets: [{ subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS }],
    customEndpoint: {
      domainName: 'search.example.com',
    },
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_6(scope: Construct) {
  // Creating an OpenSearch domain with VPC and encryption
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript-cdk-open-search-in-vpc-only
  const domain = new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_1,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 'm5.large.search',
    },
    ebs: {
      volumeSize: 20,
    },
    vpc,
    vpcSubnets: [{ subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS }],
    encryptionAtRest: {
      enabled: true,
    },
    nodeToNodeEncryption: true,
    enforceHttps: true,
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_7(scope: Construct) {
  // Creating an OpenSearch domain with VPC and access policies
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript-cdk-open-search-in-vpc-only
  const domain = new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
    ebs: {
      volumeSize: 10,
    },
    vpc,
    vpcSubnets: [{ subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS }],
    accessPolicies: new iam.PolicyDocument({
      statements: [
        new iam.PolicyStatement({
          actions: ['es:ESHttp*'],
          resources: ['*'],
          principals: [new iam.AnyPrincipal()],
        }),
      ],
    }),
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_8(scope: Construct) {
  // Creating an OpenSearch domain with VPC and automated snapshot configuration
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript-cdk-open-search-in-vpc-only
  const domain = new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
    ebs: {
      volumeSize: 10,
    },
    vpc,
    vpcSubnets: [{ subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS }],
    automatedSnapshotStartHour: 3,
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_9(scope: Construct) {
  // Creating an OpenSearch domain with VPC and warm nodes
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript-cdk-open-search-in-vpc-only
  const domain = new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 'r5.large.search',
      warmNodes: 2,
      warmInstanceType: 'ultrawarm1.medium.search',
    },
    ebs: {
      volumeSize: 10,
    },
    vpc,
    vpcSubnets: [{ subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS }],
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_10(scope: Construct) {
  // Creating an OpenSearch domain with VPC and custom KMS key
  const vpc = new ec2.Vpc(scope, 'VPC');
  const kmsKey = new cdk.aws_kms.Key(scope, 'Key');
  
  // ok: typescript-cdk-open-search-in-vpc-only
  const domain = new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
    ebs: {
      volumeSize: 10,
    },
    vpc,
    vpcSubnets: [{ subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS }],
    encryptionAtRest: {
      enabled: true,
      kmsKey: kmsKey,
    },
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_11(scope: Construct) {
  // Creating an OpenSearch domain with VPC and specific availability zones
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript-cdk-open-search-in-vpc-only
  const domain = new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
    ebs: {
      volumeSize: 10,
    },
    vpc,
    vpcSubnets: [{ 
      subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
      availabilityZones: ['us-east-1a', 'us-east-1b']
    }],
    zoneAwareness: {
      enabled: true,
      availabilityZoneCount: 2,
    },
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_12(scope: Construct) {
  // Creating an OpenSearch domain with VPC and tags
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript-cdk-open-search-in-vpc-only
  const domain = new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
    ebs: {
      volumeSize: 10,
    },
    vpc,
    vpcSubnets: [{ subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS }],
  });
  
  cdk.Tags.of(domain).add('Environment', 'Production');
  cdk.Tags.of(domain).add('Owner', 'DataTeam');
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_13(scope: Construct) {
  // Creating an OpenSearch domain with VPC and UltraWarm and Cold storage
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript-cdk-open-search-in-vpc-only
  const domain = new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_3,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 'r6g.large.search',
      warmNodes: 2,
      warmInstanceType: 'ultrawarm1.medium.search',
      coldStorageEnabled: true,
    },
    ebs: {
      volumeSize: 100,
    },
    vpc,
    vpcSubnets: [{ subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS }],
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_14(scope: Construct) {
  // Creating an OpenSearch domain with VPC and custom endpoint and certificate
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript-cdk-open-search-in-vpc-only
  const domain = new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
    ebs: {
      volumeSize: 10,
    },
    vpc,
    vpcSubnets: [{ subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS }],
    customEndpoint: {
      domainName: 'search.example.com',
      certificate: cdk.aws_certificatemanager.Certificate.fromCertificateArn(
        scope,
        'Certificate',
        'arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012'
      ),
    },
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_15(scope: Construct) {
  // Creating an OpenSearch domain with VPC and advanced security options
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript-cdk-open-search-in-vpc-only
  const domain = new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 'r5.large.search',
    },
    ebs: {
      volumeSize: 10,
    },
    vpc,
    vpcSubnets: [{ subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS }],
    nodeToNodeEncryption: true,
    encryptionAtRest: {
      enabled: true,
    },
    enforceHttps: true,
    tlsSecurityPolicy: opensearch.TLSSecurityPolicy.TLS_1_2,
  });
}
// {/fact}