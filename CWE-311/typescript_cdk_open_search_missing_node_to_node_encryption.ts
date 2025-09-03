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

// True Positives (Vulnerable Code)

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_1() {
  const stack = new cdk.Stack();
  
  // ruleid: typescript_cdk_open_search_missing_node_to_node_encryption
  new opensearch.Domain(stack, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
    ebs: {
      volumeSize: 10,
    },
    // Missing node-to-node encryption
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_2() {
  const stack = new cdk.Stack();
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ruleid: typescript_cdk_open_search_missing_node_to_node_encryption
  new opensearch.Domain(stack, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_2,
    capacity: {
      dataNodes: 3,
      dataNodeInstanceType: 'm5.large.search',
    },
    vpc,
    // Explicitly setting node-to-node encryption to false
    nodeToNodeEncryption: false,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_3() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'OpenSearchStack');
  
  // ruleid: typescript_cdk_open_search_missing_node_to_node_encryption
  const domain = new opensearch.Domain(stack, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_3,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 'r5.large.search',
    },
    encryptionAtRest: {
      enabled: true,
    },
    // Node-to-node encryption is missing despite having encryption at rest
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_4() {
  const stack = new cdk.Stack();
  
  const domainProps: opensearch.DomainProps = {
    version: opensearch.EngineVersion.OPENSEARCH_2_3,
    capacity: {
      dataNodes: 4,
      dataNodeInstanceType: 'c5.large.search',
    },
    // No node-to-node encryption in props
  };
  
  // ruleid: typescript_cdk_open_search_missing_node_to_node_encryption
  new opensearch.Domain(stack, 'Domain', domainProps);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_5() {
  const stack = new cdk.Stack();
  
  // ruleid: typescript_cdk_open_search_missing_node_to_node_encryption
  const domain = new opensearch.Domain(stack, 'Domain', {
    version: opensearch.EngineVersion.ELASTICSEARCH_7_10,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.medium.search',
    },
    enforceHttps: true,
    // Missing node-to-node encryption despite enforcing HTTPS
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_6() {
  const stack = new cdk.Stack();
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ruleid: typescript_cdk_open_search_missing_node_to_node_encryption
  new opensearch.Domain(stack, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    vpc,
    zoneAwareness: {
      enabled: true,
      availabilityZoneCount: 3,
    },
    capacity: {
      dataNodes: 6,
      dataNodeInstanceType: 'r5.xlarge.search',
    },
    // Missing node-to-node encryption in a multi-AZ deployment
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_7() {
  const stack = new cdk.Stack();
  
  // ruleid: typescript_cdk_open_search_missing_node_to_node_encryption
  const domain = new opensearch.Domain(stack, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_1,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 'm5.large.search',
    },
    fineGrainedAccessControl: {
      masterUserName: 'admin',
      masterUserPassword: cdk.SecretValue.secretsManager('opensearch/masteruser'),
    },
    // Missing node-to-node encryption despite having fine-grained access control
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_8() {
  const stack = new cdk.Stack();
  
  const securityOptions = {
    tls: true,
    enforceHttps: true,
  };
  
  // ruleid: typescript_cdk_open_search_missing_node_to_node_encryption
  new opensearch.Domain(stack, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 3,
      dataNodeInstanceType: 'c5.large.search',
    },
    enforceHttps: securityOptions.enforceHttps,
    // Missing node-to-node encryption despite other security options
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_9() {
  const stack = new cdk.Stack();
  
  // ruleid: typescript_cdk_open_search_missing_node_to_node_encryption
  const domain = new opensearch.Domain(stack, 'Domain', {
    version: opensearch.EngineVersion.ELASTICSEARCH_7_9,
    capacity: {
      masterNodes: 3,
      masterNodeInstanceType: 'c5.large.search',
      dataNodes: 2,
      dataNodeInstanceType: 'm5.large.search',
    },
    // Missing node-to-node encryption in a domain with dedicated master nodes
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_10() {
  const stack = new cdk.Stack();
  
  // ruleid: typescript_cdk_open_search_missing_node_to_node_encryption
  new opensearch.Domain(stack, 'Domain', {
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
    // Missing node-to-node encryption despite having logging enabled
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_11() {
  const stack = new cdk.Stack();
  
  // ruleid: typescript_cdk_open_search_missing_node_to_node_encryption
  const domain = new opensearch.Domain(stack, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
    useUnsignedBasicAuth: true,
    // Missing node-to-node encryption despite using basic auth
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_12() {
  const stack = new cdk.Stack();
  
  // ruleid: typescript_cdk_open_search_missing_node_to_node_encryption
  new opensearch.Domain(stack, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
    encryptionAtRest: {
      enabled: false,
    },
    // Both node-to-node encryption and encryption at rest are missing
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_13() {
  const stack = new cdk.Stack();
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ruleid: typescript_cdk_open_search_missing_node_to_node_encryption
  const domain = new opensearch.Domain(stack, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
    vpc,
    vpcSubnets: [{ subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS }],
    // Missing node-to-node encryption despite being in a private subnet
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_14() {
  const stack = new cdk.Stack();
  
  const customEndpoint = {
    domainName: 'search.example.com',
    certificate: new cdk.aws_certificatemanager.Certificate(stack, 'Cert', {
      domainName: 'search.example.com',
    }),
  };
  
  // ruleid: typescript_cdk_open_search_missing_node_to_node_encryption
  new opensearch.Domain(stack, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
    customEndpoint: customEndpoint,
    // Missing node-to-node encryption despite having a custom endpoint with TLS
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_15() {
  const stack = new cdk.Stack();
  
  // ruleid: typescript_cdk_open_search_missing_node_to_node_encryption
  const domain = new opensearch.Domain(stack, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
    automatedSnapshotStartHour: 3,
    // Missing node-to-node encryption despite configuring automated snapshots
  });
}
// {/fact}

// True Negatives (Secure Code)

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_1() {
  const stack = new cdk.Stack();
  
  // ok: typescript_cdk_open_search_missing_node_to_node_encryption
  new opensearch.Domain(stack, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
    ebs: {
      volumeSize: 10,
    },
    nodeToNodeEncryption: true,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_2() {
  const stack = new cdk.Stack();
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ok: typescript_cdk_open_search_missing_node_to_node_encryption
  new opensearch.Domain(stack, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_2,
    capacity: {
      dataNodes: 3,
      dataNodeInstanceType: 'm5.large.search',
    },
    vpc,
    nodeToNodeEncryption: true,
    encryptionAtRest: {
      enabled: true,
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_3() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'OpenSearchStack');
  
  // ok: typescript_cdk_open_search_missing_node_to_node_encryption
  const domain = new opensearch.Domain(stack, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_3,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 'r5.large.search',
    },
    encryptionAtRest: {
      enabled: true,
    },
    nodeToNodeEncryption: true,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_4() {
  const stack = new cdk.Stack();
  
  const domainProps: opensearch.DomainProps = {
    version: opensearch.EngineVersion.OPENSEARCH_2_3,
    capacity: {
      dataNodes: 4,
      dataNodeInstanceType: 'c5.large.search',
    },
    nodeToNodeEncryption: true,
  };
  
  // ok: typescript_cdk_open_search_missing_node_to_node_encryption
  new opensearch.Domain(stack, 'Domain', domainProps);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_5() {
  const stack = new cdk.Stack();
  
  // ok: typescript_cdk_open_search_missing_node_to_node_encryption
  const domain = new opensearch.Domain(stack, 'Domain', {
    version: opensearch.EngineVersion.ELASTICSEARCH_7_10,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.medium.search',
    },
    enforceHttps: true,
    nodeToNodeEncryption: true,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_6() {
  const stack = new cdk.Stack();
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ok: typescript_cdk_open_search_missing_node_to_node_encryption
  new opensearch.Domain(stack, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    vpc,
    zoneAwareness: {
      enabled: true,
      availabilityZoneCount: 3,
    },
    capacity: {
      dataNodes: 6,
      dataNodeInstanceType: 'r5.xlarge.search',
    },
    nodeToNodeEncryption: true,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_7() {
  const stack = new cdk.Stack();
  
  // ok: typescript_cdk_open_search_missing_node_to_node_encryption
  const domain = new opensearch.Domain(stack, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_1,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 'm5.large.search',
    },
    fineGrainedAccessControl: {
      masterUserName: 'admin',
      masterUserPassword: cdk.SecretValue.secretsManager('opensearch/masteruser'),
    },
    nodeToNodeEncryption: true,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_8() {
  const stack = new cdk.Stack();
  
  const securityOptions = {
    tls: true,
    enforceHttps: true,
    nodeToNodeEncryption: true,
  };
  
  // ok: typescript_cdk_open_search_missing_node_to_node_encryption
  new opensearch.Domain(stack, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 3,
      dataNodeInstanceType: 'c5.large.search',
    },
    enforceHttps: securityOptions.enforceHttps,
    nodeToNodeEncryption: securityOptions.nodeToNodeEncryption,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_9() {
  const stack = new cdk.Stack();
  
  // ok: typescript_cdk_open_search_missing_node_to_node_encryption
  const domain = new opensearch.Domain(stack, 'Domain', {
    version: opensearch.EngineVersion.ELASTICSEARCH_7_9,
    capacity: {
      masterNodes: 3,
      masterNodeInstanceType: 'c5.large.search',
      dataNodes: 2,
      dataNodeInstanceType: 'm5.large.search',
    },
    nodeToNodeEncryption: true,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_10() {
  const stack = new cdk.Stack();
  
  // ok: typescript_cdk_open_search_missing_node_to_node_encryption
  new opensearch.Domain(stack, 'Domain', {
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
    nodeToNodeEncryption: true,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_11() {
  const stack = new cdk.Stack();
  
  const securityConfig = {
    nodeToNodeEncryption: true,
    encryptionAtRest: true,
    enforceHttps: true,
  };
  
  // ok: typescript_cdk_open_search_missing_node_to_node_encryption
  const domain = new opensearch.Domain(stack, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
    nodeToNodeEncryption: securityConfig.nodeToNodeEncryption,
    encryptionAtRest: {
      enabled: securityConfig.encryptionAtRest,
    },
    enforceHttps: securityConfig.enforceHttps,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_12() {
  const stack = new cdk.Stack();
  
  // Create a comprehensive security configuration
  function createSecureOpenSearchDomain(id: string) {
    // ok: typescript_cdk_open_search_missing_node_to_node_encryption
    return new opensearch.Domain(stack, id, {
      version: opensearch.EngineVersion.OPENSEARCH_1_0,
      capacity: {
        dataNodes: 2,
        dataNodeInstanceType: 't3.small.search',
      },
      nodeToNodeEncryption: true,
      encryptionAtRest: {
        enabled: true,
      },
      enforceHttps: true,
    });
  }
  
  const domain = createSecureOpenSearchDomain('Domain');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_13() {
  const stack = new cdk.Stack();
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ok: typescript_cdk_open_search_missing_node_to_node_encryption
  const domain = new opensearch.Domain(stack, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
    vpc,
    vpcSubnets: [{ subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS }],
    nodeToNodeEncryption: true,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_14() {
  const stack = new cdk.Stack();
  
  const customEndpoint = {
    domainName: 'search.example.com',
    certificate: new cdk.aws_certificatemanager.Certificate(stack, 'Cert', {
      domainName: 'search.example.com',
    }),
  };
  
  // ok: typescript_cdk_open_search_missing_node_to_node_encryption
  new opensearch.Domain(stack, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
    customEndpoint: customEndpoint,
    nodeToNodeEncryption: true,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_15() {
  const stack = new cdk.Stack();
  
  // ok: typescript_cdk_open_search_missing_node_to_node_encryption
  const domain = new opensearch.Domain(stack, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
    automatedSnapshotStartHour: 3,
    nodeToNodeEncryption: true,
  });
}
// {/fact}