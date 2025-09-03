import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as opensearch from 'aws-cdk-lib/aws-opensearch';
import * as kms from 'aws-cdk-lib/aws-kms';

// True Positives (Vulnerable Code)

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_1(stack: cdk.Stack) {
  // ruleid: typescript_cdk_open_search_encrypted_at_rest
  new opensearch.Domain(stack, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 1,
      dataNodeInstanceType: 'r5.large.search',
    },
    // Missing encryption at rest configuration
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_2(stack: cdk.Stack) {
  // ruleid: typescript_cdk_open_search_encrypted_at_rest
  const domain = new opensearch.Domain(stack, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_2,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.medium.search',
    },
    ebs: {
      volumeSize: 10,
    },
    // No encryption configuration specified
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_3(stack: cdk.Stack) {
  const props = {
    version: opensearch.EngineVersion.OPENSEARCH_1_1,
    capacity: {
      dataNodes: 3,
      dataNodeInstanceType: 'c5.large.search',
    },
  };
  
  // ruleid: typescript_cdk_open_search_encrypted_at_rest
  new opensearch.Domain(stack, 'DomainWithoutEncryption', props);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_4(stack: cdk.Stack) {
  // ruleid: typescript_cdk_open_search_encrypted_at_rest
  new opensearch.Domain(stack, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_3,
    capacity: {
      dataNodes: 1,
      dataNodeInstanceType: 'r5.large.search',
    },
    encryptionAtRest: {
      enabled: false, // Explicitly disabled encryption
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_5(stack: cdk.Stack) {
  const encryptionConfig = {
    enabled: false, // Explicitly disabled
  };
  
  // ruleid: typescript_cdk_open_search_encrypted_at_rest
  new opensearch.Domain(stack, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_2_3,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 'm5.large.search',
    },
    encryptionAtRest: encryptionConfig,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_6(stack: cdk.Stack) {
  const isProduction = false;
  
  // ruleid: typescript_cdk_open_search_encrypted_at_rest
  new opensearch.Domain(stack, 'ConditionalDomain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 1,
      dataNodeInstanceType: 't3.small.search',
    },
    encryptionAtRest: isProduction ? { enabled: true } : undefined,
    // In this case, encryption is undefined because isProduction is false
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_7(stack: cdk.Stack) {
  const domainProps: opensearch.DomainProps = {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 'r5.large.search',
    },
  };
  
  // ruleid: typescript_cdk_open_search_encrypted_at_rest
  new opensearch.Domain(stack, 'DomainFromProps', domainProps);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_8(stack: cdk.Stack) {
  const config = getConfig(); // Assume this returns a configuration object
  
  // ruleid: typescript_cdk_open_search_encrypted_at_rest
  new opensearch.Domain(stack, 'DomainFromConfig', {
    version: config.version || opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: config.nodes || 1,
      dataNodeInstanceType: config.instanceType || 't3.medium.search',
    },
    // No encryption configuration
  });
  
  function getConfig() {
    return {
      version: opensearch.EngineVersion.OPENSEARCH_1_2,
      nodes: 2,
      instanceType: 'm5.large.search',
    };
  }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_9(stack: cdk.Stack) {
  // ruleid: typescript_cdk_open_search_encrypted_at_rest
  const domain = new opensearch.CfnDomain(stack, 'CfnDomain', {
    engineVersion: 'OpenSearch_1.0',
    clusterConfig: {
      instanceType: 'r5.large.search',
      instanceCount: 1,
    },
    ebsOptions: {
      ebsEnabled: true,
      volumeSize: 10,
    },
    // Missing encryptionAtRestOptions
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_10(stack: cdk.Stack) {
  // ruleid: typescript_cdk_open_search_encrypted_at_rest
  const domain = new opensearch.CfnDomain(stack, 'CfnDomain', {
    engineVersion: 'OpenSearch_1.2',
    clusterConfig: {
      instanceType: 'm5.large.search',
      instanceCount: 2,
    },
    ebsOptions: {
      ebsEnabled: true,
      volumeSize: 20,
    },
    encryptionAtRestOptions: {
      enabled: false, // Explicitly disabled
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_11(stack: cdk.Stack) {
  const domainName = 'my-domain';
  
  // ruleid: typescript_cdk_open_search_encrypted_at_rest
  new opensearch.Domain(stack, domainName, {
    domainName: domainName,
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 1,
      dataNodeInstanceType: 'r5.large.search',
    },
    // No encryption configuration
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_12(stack: cdk.Stack) {
  const environments = ['dev', 'staging', 'prod'];
  
  for (const env of environments) {
    // ruleid: typescript_cdk_open_search_encrypted_at_rest
    new opensearch.Domain(stack, `Domain-${env}`, {
      domainName: `domain-${env}`,
      version: opensearch.EngineVersion.OPENSEARCH_1_0,
      capacity: {
        dataNodes: env === 'prod' ? 3 : 1,
        dataNodeInstanceType: env === 'prod' ? 'r5.large.search' : 't3.small.search',
      },
      // No encryption configuration for any environment
    });
  }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_13(stack: cdk.Stack) {
  const createDomain = (id: string) => {
    // ruleid: typescript_cdk_open_search_encrypted_at_rest
    return new opensearch.Domain(stack, id, {
      version: opensearch.EngineVersion.OPENSEARCH_1_0,
      capacity: {
        dataNodes: 1,
        dataNodeInstanceType: 't3.small.search',
      },
      // Missing encryption configuration
    });
  };
  
  createDomain('DomainFromFactory');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_14(stack: cdk.Stack) {
  // ruleid: typescript_cdk_open_search_encrypted_at_rest
  const domain = new opensearch.Domain(stack, 'DomainWithNodeToNodeEncryption', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 'r5.large.search',
    },
    nodeToNodeEncryption: true, // Node-to-node encryption is enabled, but not encryption at rest
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_15(stack: cdk.Stack) {
  // ruleid: typescript_cdk_open_search_encrypted_at_rest
  const domain = new opensearch.Domain(stack, 'DomainWithTLSButNoEncryptionAtRest', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 'r5.large.search',
    },
    tlsSecurityPolicy: opensearch.TLSSecurityPolicy.TLS_1_2, // TLS security policy is set, but not encryption at rest
  });
}
// {/fact}

// True Negatives (Secure Code)

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_1(stack: cdk.Stack) {
  // ok: typescript_cdk_open_search_encrypted_at_rest
  new opensearch.Domain(stack, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 1,
      dataNodeInstanceType: 'r5.large.search',
    },
    encryptionAtRest: {
      enabled: true, // Encryption at rest is enabled
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_2(stack: cdk.Stack) {
  const key = new kms.Key(stack, 'OpenSearchKey');
  
  // ok: typescript_cdk_open_search_encrypted_at_rest
  new opensearch.Domain(stack, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_2,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.medium.search',
    },
    encryptionAtRest: {
      enabled: true,
      kmsKey: key, // Using a custom KMS key for encryption
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_3(stack: cdk.Stack) {
  const props = {
    version: opensearch.EngineVersion.OPENSEARCH_1_1,
    capacity: {
      dataNodes: 3,
      dataNodeInstanceType: 'c5.large.search',
    },
    encryptionAtRest: {
      enabled: true, // Encryption at rest is enabled
    },
  };
  
  // ok: typescript_cdk_open_search_encrypted_at_rest
  new opensearch.Domain(stack, 'DomainWithEncryption', props);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_4(stack: cdk.Stack) {
  const isProduction = true;
  
  // ok: typescript_cdk_open_search_encrypted_at_rest
  new opensearch.Domain(stack, 'ConditionalDomain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: isProduction ? 3 : 1,
      dataNodeInstanceType: isProduction ? 'r5.large.search' : 't3.small.search',
    },
    encryptionAtRest: {
      enabled: true, // Always enable encryption regardless of environment
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_5(stack: cdk.Stack) {
  const domainProps: opensearch.DomainProps = {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 'r5.large.search',
    },
    encryptionAtRest: {
      enabled: true, // Encryption at rest is enabled
    },
  };
  
  // ok: typescript_cdk_open_search_encrypted_at_rest
  new opensearch.Domain(stack, 'DomainFromProps', domainProps);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_6(stack: cdk.Stack) {
  const config = getConfig(); // Assume this returns a configuration object
  
  // ok: typescript_cdk_open_search_encrypted_at_rest
  new opensearch.Domain(stack, 'DomainFromConfig', {
    version: config.version || opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: config.nodes || 1,
      dataNodeInstanceType: config.instanceType || 't3.medium.search',
    },
    encryptionAtRest: {
      enabled: true, // Encryption at rest is enabled
    },
  });
  
  function getConfig() {
    return {
      version: opensearch.EngineVersion.OPENSEARCH_1_2,
      nodes: 2,
      instanceType: 'm5.large.search',
    };
  }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_7(stack: cdk.Stack) {
  const key = new kms.Key(stack, 'OpenSearchKey');
  
  // ok: typescript_cdk_open_search_encrypted_at_rest
  const domain = new opensearch.CfnDomain(stack, 'CfnDomain', {
    engineVersion: 'OpenSearch_1.0',
    clusterConfig: {
      instanceType: 'r5.large.search',
      instanceCount: 1,
    },
    ebsOptions: {
      ebsEnabled: true,
      volumeSize: 10,
    },
    encryptionAtRestOptions: {
      enabled: true, // Encryption at rest is enabled
      kmsKeyId: key.keyId,
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_8(stack: cdk.Stack) {
  const domainName = 'my-domain';
  
  // ok: typescript_cdk_open_search_encrypted_at_rest
  new opensearch.Domain(stack, domainName, {
    domainName: domainName,
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 1,
      dataNodeInstanceType: 'r5.large.search',
    },
    encryptionAtRest: {
      enabled: true, // Encryption at rest is enabled
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_9(stack: cdk.Stack) {
  const environments = ['dev', 'staging', 'prod'];
  
  for (const env of environments) {
    // ok: typescript_cdk_open_search_encrypted_at_rest
    new opensearch.Domain(stack, `Domain-${env}`, {
      domainName: `domain-${env}`,
      version: opensearch.EngineVersion.OPENSEARCH_1_0,
      capacity: {
        dataNodes: env === 'prod' ? 3 : 1,
        dataNodeInstanceType: env === 'prod' ? 'r5.large.search' : 't3.small.search',
      },
      encryptionAtRest: {
        enabled: true, // Encryption at rest is enabled for all environments
      },
    });
  }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_10(stack: cdk.Stack) {
  const createDomain = (id: string) => {
    // ok: typescript_cdk_open_search_encrypted_at_rest
    return new opensearch.Domain(stack, id, {
      version: opensearch.EngineVersion.OPENSEARCH_1_0,
      capacity: {
        dataNodes: 1,
        dataNodeInstanceType: 't3.small.search',
      },
      encryptionAtRest: {
        enabled: true, // Encryption at rest is enabled
      },
    });
  };
  
  createDomain('DomainFromFactory');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_11(stack: cdk.Stack) {
  // ok: typescript_cdk_open_search_encrypted_at_rest
  const domain = new opensearch.Domain(stack, 'DomainWithAllEncryption', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 'r5.large.search',
    },
    encryptionAtRest: {
      enabled: true, // Encryption at rest is enabled
    },
    nodeToNodeEncryption: true, // Node-to-node encryption is also enabled
    tlsSecurityPolicy: opensearch.TLSSecurityPolicy.TLS_1_2, // TLS security policy is set
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_12(stack: cdk.Stack) {
  const encryptionConfig = {
    enabled: true, // Explicitly enabled
  };
  
  // ok: typescript_cdk_open_search_encrypted_at_rest
  new opensearch.Domain(stack, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_2_3,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 'm5.large.search',
    },
    encryptionAtRest: encryptionConfig,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_13(stack: cdk.Stack) {
  const getEncryptionConfig = () => {
    return {
      enabled: true,
    };
  };
  
  // ok: typescript_cdk_open_search_encrypted_at_rest
  new opensearch.Domain(stack, 'DomainWithDynamicConfig', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 1,
      dataNodeInstanceType: 'r5.large.search',
    },
    encryptionAtRest: getEncryptionConfig(),
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_14(stack: cdk.Stack) {
  const defaultProps = {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 1,
      dataNodeInstanceType: 'r5.large.search',
    },
  };
  
  // ok: typescript_cdk_open_search_encrypted_at_rest
  new opensearch.Domain(stack, 'DomainWithSpreadProps', {
    ...defaultProps,
    encryptionAtRest: {
      enabled: true, // Encryption at rest is enabled
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_15(stack: cdk.Stack) {
  const key = kms.Key.fromKeyArn(stack, 'ImportedKey', 'arn:aws:kms:us-west-2:123456789012:key/abcd1234-ab12-cd34-ef56-abcdef123456');
  
  // ok: typescript_cdk_open_search_encrypted_at_rest
  new opensearch.Domain(stack, 'DomainWithImportedKey', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 'r5.large.search',
    },
    encryptionAtRest: {
      enabled: true,
      kmsKey: key, // Using an imported KMS key for encryption
    },
  });
}
// {/fact}