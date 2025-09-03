import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as opensearch from 'aws-cdk-lib/aws-opensearch';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as ec2 from 'aws-cdk-lib/aws-ec2';

// True Positive Examples (Vulnerable Code)

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_1(scope: Construct) {
  // Creating an OpenSearch domain without configuring access policies
  // ruleid: typescript-cdk-open-search-no-unsigned-or-anonymous-access
  new opensearch.Domain(scope, 'MyDomain1', {
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

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_2(scope: Construct) {
  // Creating an OpenSearch domain with explicit anonymous access
  const domain = new opensearch.Domain(scope, 'MyDomain2', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
  });
  
  // ruleid: typescript-cdk-open-search-no-unsigned-or-anonymous-access
  domain.addAccessPolicy(new iam.PolicyStatement({
    actions: ['es:*'],
    principals: [new iam.AnyPrincipal()],
    resources: ['*'],
  }));
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_3(scope: Construct) {
  // Creating an OpenSearch domain with fine-grained access control disabled
  // ruleid: typescript-cdk-open-search-no-unsigned-or-anonymous-access
  new opensearch.Domain(scope, 'MyDomain3', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
    fineGrainedAccessControl: {
      enabled: false
    },
    nodeToNodeEncryption: true,
    encryptionAtRest: {
      enabled: true,
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_4(scope: Construct) {
  // Creating an OpenSearch domain with anonymous access policy
  const domain = new opensearch.Domain(scope, 'MyDomain4', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 1,
      dataNodeInstanceType: 't3.small.search',
    },
  });
  
  // ruleid: typescript-cdk-open-search-no-unsigned-or-anonymous-access
  const accessPolicy = new iam.PolicyDocument({
    statements: [
      new iam.PolicyStatement({
        actions: ['es:ESHttp*'],
        resources: ['*'],
        principals: [new iam.AnyPrincipal()],
      }),
    ],
  });
  
  domain.accessPolicies = accessPolicy;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_5(scope: Construct) {
  // Creating an OpenSearch domain with anonymous access through resource policy
  // ruleid: typescript-cdk-open-search-no-unsigned-or-anonymous-access
  new opensearch.Domain(scope, 'MyDomain5', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
    accessPolicies: new iam.PolicyDocument({
      statements: [
        new iam.PolicyStatement({
          actions: ['es:*'],
          resources: ['*'],
          principals: [new iam.AnyPrincipal()],
        }),
      ],
    }),
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_6(scope: Construct) {
  // Creating an OpenSearch domain with public access and no authentication
  const vpc = new ec2.Vpc(scope, 'MyVpc');
  
  // ruleid: typescript-cdk-open-search-no-unsigned-or-anonymous-access
  new opensearch.Domain(scope, 'MyDomain6', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 1,
      dataNodeInstanceType: 't3.small.search',
    },
    vpc,
    enforceHttps: false,
    nodeToNodeEncryption: false,
    encryptionAtRest: {
      enabled: false,
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_7(scope: Construct) {
  // Creating an OpenSearch domain with public endpoint and no IAM authentication
  // ruleid: typescript-cdk-open-search-no-unsigned-or-anonymous-access
  new opensearch.Domain(scope, 'MyDomain7', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
    enforceHttps: true,
    nodeToNodeEncryption: true,
    encryptionAtRest: {
      enabled: true,
    },
    useUnsignedBasicAuth: true,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_8(scope: Construct) {
  // Creating an OpenSearch domain with explicit public access
  const domain = new opensearch.Domain(scope, 'MyDomain8', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 1,
      dataNodeInstanceType: 't3.small.search',
    },
  });
  
  // ruleid: typescript-cdk-open-search-no-unsigned-or-anonymous-access
  domain.addAccessPolicy(new iam.PolicyStatement({
    actions: ['es:ESHttp*'],
    principals: [new iam.AnyPrincipal()],
    resources: [`${domain.domainArn}/*`],
  }));
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_9(scope: Construct) {
  // Creating an OpenSearch domain with anonymous access through condition
  // ruleid: typescript-cdk-open-search-no-unsigned-or-anonymous-access
  new opensearch.Domain(scope, 'MyDomain9', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
    accessPolicies: new iam.PolicyDocument({
      statements: [
        new iam.PolicyStatement({
          actions: ['es:ESHttp*'],
          resources: ['*'],
          principals: [new iam.AnyPrincipal()],
          conditions: {
            'IpAddress': {
              'aws:SourceIp': '192.0.2.0/24'
            }
          }
        }),
      ],
    }),
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_10(scope: Construct) {
  // Creating an OpenSearch domain with anonymous access through multiple statements
  const accessPolicy = new iam.PolicyDocument({
    statements: [
      new iam.PolicyStatement({
        actions: ['es:ESHttpGet'],
        resources: ['*'],
        principals: [new iam.ServicePrincipal('lambda.amazonaws.com')],
      }),
      // ruleid: typescript-cdk-open-search-no-unsigned-or-anonymous-access
      new iam.PolicyStatement({
        actions: ['es:ESHttpPost', 'es:ESHttpPut'],
        resources: ['*'],
        principals: [new iam.AnyPrincipal()],
      }),
    ],
  });
  
  new opensearch.Domain(scope, 'MyDomain10', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 1,
      dataNodeInstanceType: 't3.small.search',
    },
    accessPolicies: accessPolicy,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_11(scope: Construct) {
  // Creating an OpenSearch domain with anonymous access through wildcards
  // ruleid: typescript-cdk-open-search-no-unsigned-or-anonymous-access
  new opensearch.Domain(scope, 'MyDomain11', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
    accessPolicies: new iam.PolicyDocument({
      statements: [
        new iam.PolicyStatement({
          actions: ['es:*'],
          resources: ['*'],
          principals: [new iam.AnyPrincipal()],
        }),
      ],
    }),
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_12(scope: Construct, stackName: string) {
  // Creating an OpenSearch domain with anonymous access through string literals
  const policyJson = {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Principal": {
          "AWS": "*"  // This allows anonymous access
        },
        "Action": "es:*",
        "Resource": `arn:aws:es:us-west-2:123456789012:domain/${stackName}-domain/*`
      }
    ]
  };
  
  // ruleid: typescript-cdk-open-search-no-unsigned-or-anonymous-access
  new opensearch.Domain(scope, 'MyDomain12', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 1,
      dataNodeInstanceType: 't3.small.search',
    },
    accessPolicies: iam.PolicyDocument.fromJson(policyJson),
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_13(scope: Construct) {
  // Creating an OpenSearch domain with anonymous access through variable
  const anyPrincipal = new iam.AnyPrincipal();
  const accessPolicy = new iam.PolicyDocument({
    statements: [
      // ruleid: typescript-cdk-open-search-no-unsigned-or-anonymous-access
      new iam.PolicyStatement({
        actions: ['es:ESHttp*'],
        resources: ['*'],
        principals: [anyPrincipal],
      }),
    ],
  });
  
  new opensearch.Domain(scope, 'MyDomain13', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
    accessPolicies: accessPolicy,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_14(scope: Construct) {
  // Creating an OpenSearch domain with anonymous access through condition with IP range
  // ruleid: typescript-cdk-open-search-no-unsigned-or-anonymous-access
  new opensearch.Domain(scope, 'MyDomain14', {
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
          principals: [new iam.AnyPrincipal()],
          conditions: {
            'IpAddress': {
              'aws:SourceIp': '0.0.0.0/0'  // Allows access from any IP
            }
          }
        }),
      ],
    }),
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_15(scope: Construct) {
  // Creating an OpenSearch domain with anonymous access and no HTTPS enforcement
  // ruleid: typescript-cdk-open-search-no-unsigned-or-anonymous-access
  new opensearch.Domain(scope, 'MyDomain15', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
    enforceHttps: false,
    accessPolicies: new iam.PolicyDocument({
      statements: [
        new iam.PolicyStatement({
          actions: ['es:*'],
          resources: ['*'],
          principals: [new iam.AnyPrincipal()],
        }),
      ],
    }),
  });
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_1(scope: Construct) {
  // Creating an OpenSearch domain with IAM authentication
  const vpc = new ec2.Vpc(scope, 'MyVpc');
  
  // ok: typescript-cdk-open-search-no-unsigned-or-anonymous-access
  new opensearch.Domain(scope, 'MyDomain1', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
    vpc,
    enforceHttps: true,
    nodeToNodeEncryption: true,
    encryptionAtRest: {
      enabled: true,
    },
    fineGrainedAccessControl: {
      masterUserName: 'master-user',
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_2(scope: Construct) {
  // Creating an OpenSearch domain with specific IAM role access
  const role = new iam.Role(scope, 'OpenSearchRole', {
    assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
  });
  
  // ok: typescript-cdk-open-search-no-unsigned-or-anonymous-access
  new opensearch.Domain(scope, 'MyDomain2', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 1,
      dataNodeInstanceType: 't3.small.search',
    },
    accessPolicies: new iam.PolicyDocument({
      statements: [
        new iam.PolicyStatement({
          actions: ['es:ESHttp*'],
          resources: ['*'],
          principals: [role],
        }),
      ],
    }),
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_3(scope: Construct) {
  // Creating an OpenSearch domain with fine-grained access control enabled
  // ok: typescript-cdk-open-search-no-unsigned-or-anonymous-access
  new opensearch.Domain(scope, 'MyDomain3', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
    enforceHttps: true,
    nodeToNodeEncryption: true,
    encryptionAtRest: {
      enabled: true,
    },
    fineGrainedAccessControl: {
      enabled: true,
      masterUserName: 'admin',
      masterUserPassword: cdk.SecretValue.secretsManager('opensearch/masteruser'),
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_4(scope: Construct) {
  // Creating an OpenSearch domain with specific service principal access
  // ok: typescript-cdk-open-search-no-unsigned-or-anonymous-access
  new opensearch.Domain(scope, 'MyDomain4', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 1,
      dataNodeInstanceType: 't3.small.search',
    },
    accessPolicies: new iam.PolicyDocument({
      statements: [
        new iam.PolicyStatement({
          actions: ['es:ESHttp*'],
          resources: ['*'],
          principals: [new iam.ServicePrincipal('lambda.amazonaws.com')],
        }),
      ],
    }),
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_5(scope: Construct) {
  // Creating an OpenSearch domain with VPC access and IAM authentication
  const vpc = new ec2.Vpc(scope, 'MyVpc');
  const securityGroup = new ec2.SecurityGroup(scope, 'OpenSearchSG', { vpc });
  
  // ok: typescript-cdk-open-search-no-unsigned-or-anonymous-access
  new opensearch.Domain(scope, 'MyDomain5', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
    vpc,
    vpcSubnets: [{ subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS }],
    securityGroups: [securityGroup],
    enforceHttps: true,
    nodeToNodeEncryption: true,
    encryptionAtRest: {
      enabled: true,
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_6(scope: Construct) {
  // Creating an OpenSearch domain with specific IAM user access
  const user = new iam.User(scope, 'OpenSearchUser');
  
  // ok: typescript-cdk-open-search-no-unsigned-or-anonymous-access
  new opensearch.Domain(scope, 'MyDomain6', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 1,
      dataNodeInstanceType: 't3.small.search',
    },
    accessPolicies: new iam.PolicyDocument({
      statements: [
        new iam.PolicyStatement({
          actions: ['es:ESHttp*'],
          resources: ['*'],
          principals: [new iam.ArnPrincipal(user.userArn)],
        }),
      ],
    }),
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_7(scope: Construct) {
  // Creating an OpenSearch domain with Cognito authentication
  const vpc = new ec2.Vpc(scope, 'MyVpc');
  
  // ok: typescript-cdk-open-search-no-unsigned-or-anonymous-access
  new opensearch.Domain(scope, 'MyDomain7', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
    vpc,
    enforceHttps: true,
    nodeToNodeEncryption: true,
    encryptionAtRest: {
      enabled: true,
    },
    cognitoDashboardsAuth: {
      identityPoolId: 'us-east-1:12345678-1234-1234-1234-123456789012',
      userPoolId: 'us-east-1_abcdefghi',
      role: new iam.Role(scope, 'CognitoAccessForOpenSearch', {
        assumedBy: new iam.ServicePrincipal('opensearchservice.amazonaws.com'),
      }),
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_8(scope: Construct) {
  // Creating an OpenSearch domain with specific account access
  // ok: typescript-cdk-open-search-no-unsigned-or-anonymous-access
  new opensearch.Domain(scope, 'MyDomain8', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 1,
      dataNodeInstanceType: 't3.small.search',
    },
    accessPolicies: new iam.PolicyDocument({
      statements: [
        new iam.PolicyStatement({
          actions: ['es:ESHttp*'],
          resources: ['*'],
          principals: [new iam.AccountPrincipal('123456789012')],
        }),
      ],
    }),
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_9(scope: Construct) {
  // Creating an OpenSearch domain with multiple specific IAM roles
  const role1 = new iam.Role(scope, 'OpenSearchRole1', {
    assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
  });
  
  const role2 = new iam.Role(scope, 'OpenSearchRole2', {
    assumedBy: new iam.ServicePrincipal('ec2.amazonaws.com'),
  });
  
  // ok: typescript-cdk-open-search-no-unsigned-or-anonymous-access
  new opensearch.Domain(scope, 'MyDomain9', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
    accessPolicies: new iam.PolicyDocument({
      statements: [
        new iam.PolicyStatement({
          actions: ['es:ESHttpGet', 'es:ESHttpPost'],
          resources: ['*'],
          principals: [role1, role2],
        }),
      ],
    }),
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_10(scope: Construct) {
  // Creating an OpenSearch domain with specific IAM group access
  const group = new iam.Group(scope, 'OpenSearchGroup');
  
  // ok: typescript-cdk-open-search-no-unsigned-or-anonymous-access
  new opensearch.Domain(scope, 'MyDomain10', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 1,
      dataNodeInstanceType: 't3.small.search',
    },
    accessPolicies: new iam.PolicyDocument({
      statements: [
        new iam.PolicyStatement({
          actions: ['es:ESHttp*'],
          resources: ['*'],
          principals: [new iam.ArnPrincipal(group.groupArn)],
        }),
      ],
    }),
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_11(scope: Construct) {
  // Creating an OpenSearch domain with fine-grained access control and SAML
  // ok: typescript-cdk-open-search-no-unsigned-or-anonymous-access
  new opensearch.Domain(scope, 'MyDomain11', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
    enforceHttps: true,
    nodeToNodeEncryption: true,
    encryptionAtRest: {
      enabled: true,
    },
    fineGrainedAccessControl: {
      enabled: true,
      masterUserName: 'admin',
      masterUserPassword: cdk.SecretValue.secretsManager('opensearch/masteruser'),
      samlOptions: {
        enabled: true,
        idpEntityId: 'https://idp.example.com/saml',
        idpMetadataContent: cdk.SecretValue.secretsManager('opensearch/saml-metadata'),
        masterBackendRole: 'admin',
        rolesKey: 'roles',
        sessionTimeoutMinutes: 60,
        subjectKey: 'email',
      },
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_12(scope: Construct) {
  // Creating an OpenSearch domain with specific service and user principals
  const user = new iam.User(scope, 'OpenSearchUser');
  
  // ok: typescript-cdk-open-search-no-unsigned-or-anonymous-access
  new opensearch.Domain(scope, 'MyDomain12', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 1,
      dataNodeInstanceType: 't3.small.search',
    },
    accessPolicies: new iam.PolicyDocument({
      statements: [
        new iam.PolicyStatement({
          actions: ['es:ESHttpGet'],
          resources: ['*'],
          principals: [new iam.ServicePrincipal('lambda.amazonaws.com')],
        }),
        new iam.PolicyStatement({
          actions: ['es:ESHttpPost', 'es:ESHttpPut'],
          resources: ['*'],
          principals: [new iam.ArnPrincipal(user.userArn)],
        }),
      ],
    }),
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_13(scope: Construct) {
  // Creating an OpenSearch domain with VPC access and security groups
  const vpc = new ec2.Vpc(scope, 'MyVpc');
  const securityGroup = new ec2.SecurityGroup(scope, 'OpenSearchSG', { vpc });
  
  // ok: typescript-cdk-open-search-no-unsigned-or-anonymous-access
  const domain = new opensearch.Domain(scope, 'MyDomain13', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
    vpc,
    vpcSubnets: [{ subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS }],
    securityGroups: [securityGroup],
    enforceHttps: true,
    nodeToNodeEncryption: true,
    encryptionAtRest: {
      enabled: true,
    },
  });
  
  // Add specific access policy
  const role = new iam.Role(scope, 'OpenSearchAccessRole', {
    assumedBy: new iam.ServicePrincipal('ec2.amazonaws.com'),
  });
  
  domain.addAccessPolicy(new iam.PolicyStatement({
    actions: ['es:ESHttp*'],
    resources: [`${domain.domainArn}/*`],
    principals: [role],
  }));
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_14(scope: Construct) {
  // Creating an OpenSearch domain with specific organization access
  // ok: typescript-cdk-open-search-no-unsigned-or-anonymous-access
  new opensearch.Domain(scope, 'MyDomain14', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 1,
      dataNodeInstanceType: 't3.small.search',
    },
    accessPolicies: new iam.PolicyDocument({
      statements: [
        new iam.PolicyStatement({
          actions: ['es:ESHttp*'],
          resources: ['*'],
          principals: [new iam.OrganizationPrincipal('o-exampleorgid')],
        }),
      ],
    }),
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_15(scope: Construct) {
  // Creating an OpenSearch domain with advanced security options
  // ok: typescript-cdk-open-search-no-unsigned-or-anonymous-access
  new opensearch.Domain(scope, 'MyDomain15', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
    enforceHttps: true,
    tlsSecurityPolicy: opensearch.TLSSecurityPolicy.TLS_1_2,
    nodeToNodeEncryption: true,
    encryptionAtRest: {
      enabled: true,
    },
    fineGrainedAccessControl: {
      enabled: true,
      masterUserName: 'admin',
      masterUserPassword: cdk.SecretValue.secretsManager('opensearch/masteruser'),
    },
    advancedSecurityOptions: {
      enabled: true,
      internalUserDatabaseEnabled: true,
      masterUserName: 'admin',
      masterUserPassword: cdk.SecretValue.secretsManager('opensearch/masteruser'),
    },
  });
}
// {/fact}