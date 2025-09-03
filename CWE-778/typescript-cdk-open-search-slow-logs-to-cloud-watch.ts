import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as opensearch from 'aws-cdk-lib/aws-opensearch';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as iam from 'aws-cdk-lib/aws-iam';

// True Positives (Vulnerable Code - Missing or incomplete slow logs configuration)

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_1(scope: Construct) {
  // No logging configuration at all
  // ruleid: typescript-cdk-open-search-slow-logs-to-cloud-watch
  new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_2(scope: Construct) {
  // Only configuring search slow logs, missing index slow logs
  // ruleid: typescript-cdk-open-search-slow-logs-to-cloud-watch
  new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
    logging: {
      slowSearchLogEnabled: true,
    },
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_3(scope: Construct) {
  // Only configuring index slow logs, missing search slow logs
  // ruleid: typescript-cdk-open-search-slow-logs-to-cloud-watch
  new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
    logging: {
      slowIndexLogEnabled: true,
    },
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_4(scope: Construct) {
  // Both logs explicitly disabled
  // ruleid: typescript-cdk-open-search-slow-logs-to-cloud-watch
  new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
    logging: {
      slowIndexLogEnabled: false,
      slowSearchLogEnabled: false,
    },
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_5(scope: Construct) {
  // Configuring other logs but not slow logs
  // ruleid: typescript-cdk-open-search-slow-logs-to-cloud-watch
  new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
    logging: {
      appLogEnabled: true,
      auditLogEnabled: true,
    },
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_6(scope: Construct) {
  // Using a variable but still missing slow logs
  const domainProps = {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
  };
  
  // ruleid: typescript-cdk-open-search-slow-logs-to-cloud-watch
  new opensearch.Domain(scope, 'Domain', domainProps);
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_7(scope: Construct) {
  // Using a variable with incomplete logging config
  const domainProps = {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
    logging: {
      slowIndexLogEnabled: true,
      // Missing slowSearchLogEnabled
    }
  };
  
  // ruleid: typescript-cdk-open-search-slow-logs-to-cloud-watch
  new opensearch.Domain(scope, 'Domain', domainProps);
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_8(scope: Construct) {
  // Using a separate logging config object but still incomplete
  const loggingConfig = {
    appLogEnabled: true,
    // Missing slow logs configuration
  };
  
  // ruleid: typescript-cdk-open-search-slow-logs-to-cloud-watch
  new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
    logging: loggingConfig,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_9(scope: Construct) {
  // Using conditional logic but still missing slow logs
  const enableAuditLogs = true;
  
  // ruleid: typescript-cdk-open-search-slow-logs-to-cloud-watch
  new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
    logging: {
      auditLogEnabled: enableAuditLogs,
      // Missing slow logs configuration
    },
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_10(scope: Construct) {
  // Using a function to create the domain but still missing slow logs
  function createDomain(id: string) {
    // ruleid: typescript-cdk-open-search-slow-logs-to-cloud-watch
    return new opensearch.Domain(scope, id, {
      version: opensearch.EngineVersion.OPENSEARCH_1_0,
      capacity: {
        dataNodes: 2,
        dataNodeInstanceType: 't3.small.search',
      },
    });
  }
  
  createDomain('Domain');
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_11(scope: Construct, stack: cdk.Stack) {
  // Using CloudFormation parameters but still missing slow logs
  const instanceType = new cdk.CfnParameter(stack, 'InstanceType', {
    type: 'String',
    default: 't3.small.search',
  });
  
  // ruleid: typescript-cdk-open-search-slow-logs-to-cloud-watch
  new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: instanceType.valueAsString,
    },
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_12(scope: Construct) {
  // Using a class to create the domain but still missing slow logs
  class OpenSearchDomainStack extends cdk.Stack {
    constructor(scope: Construct, id: string, props?: cdk.StackProps) {
      super(scope, id, props);
      
      // ruleid: typescript-cdk-open-search-slow-logs-to-cloud-watch
      new opensearch.Domain(this, 'Domain', {
        version: opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity: {
          dataNodes: 2,
          dataNodeInstanceType: 't3.small.search',
        },
      });
    }
  }
  
  new OpenSearchDomainStack(scope, 'OpenSearchStack');
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_13(scope: Construct) {
  // Using a different version but still missing slow logs
  // ruleid: typescript-cdk-open-search-slow-logs-to-cloud-watch
  new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.ELASTICSEARCH_7_10,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_14(scope: Construct) {
  // Using a different constructor pattern but still missing slow logs
  const domainProps: opensearch.DomainProps = {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
  };
  
  // ruleid: typescript-cdk-open-search-slow-logs-to-cloud-watch
  const domain = new opensearch.Domain(scope, 'Domain', domainProps);
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_15(scope: Construct) {
  // Using environment variables for configuration but still missing slow logs
  const nodeCount = process.env.NODE_COUNT ? parseInt(process.env.NODE_COUNT) : 2;
  
  // ruleid: typescript-cdk-open-search-slow-logs-to-cloud-watch
  new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: nodeCount,
      dataNodeInstanceType: 't3.small.search',
    },
  });
}
// {/fact}

// True Negatives (Secure Code - Properly configured slow logs)

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_1(scope: Construct) {
  // Properly configuring both slow logs
  // ok: typescript-cdk-open-search-slow-logs-to-cloud-watch
  new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
    logging: {
      slowIndexLogEnabled: true,
      slowSearchLogEnabled: true,
    },
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_2(scope: Construct) {
  // Properly configuring both slow logs along with other logs
  // ok: typescript-cdk-open-search-slow-logs-to-cloud-watch
  new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
    logging: {
      slowIndexLogEnabled: true,
      slowSearchLogEnabled: true,
      appLogEnabled: true,
      auditLogEnabled: true,
    },
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_3(scope: Construct) {
  // Using a variable with proper logging configuration
  const domainProps = {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
    logging: {
      slowIndexLogEnabled: true,
      slowSearchLogEnabled: true,
    }
  };
  
  // ok: typescript-cdk-open-search-slow-logs-to-cloud-watch
  new opensearch.Domain(scope, 'Domain', domainProps);
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_4(scope: Construct) {
  // Using a separate logging config object with proper configuration
  const loggingConfig = {
    slowIndexLogEnabled: true,
    slowSearchLogEnabled: true,
    appLogEnabled: true,
  };
  
  // ok: typescript-cdk-open-search-slow-logs-to-cloud-watch
  new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
    logging: loggingConfig,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_5(scope: Construct) {
  // Using conditional logic with proper slow logs
  const enableAuditLogs = true;
  
  // ok: typescript-cdk-open-search-slow-logs-to-cloud-watch
  new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
    logging: {
      slowIndexLogEnabled: true,
      slowSearchLogEnabled: true,
      auditLogEnabled: enableAuditLogs,
    },
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_6(scope: Construct) {
  // Using a function to create the domain with proper slow logs
  function createDomain(id: string) {
    // ok: typescript-cdk-open-search-slow-logs-to-cloud-watch
    return new opensearch.Domain(scope, id, {
      version: opensearch.EngineVersion.OPENSEARCH_1_0,
      capacity: {
        dataNodes: 2,
        dataNodeInstanceType: 't3.small.search',
      },
      logging: {
        slowIndexLogEnabled: true,
        slowSearchLogEnabled: true,
      },
    });
  }
  
  createDomain('Domain');
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_7(scope: Construct, stack: cdk.Stack) {
  // Using CloudFormation parameters with proper slow logs
  const instanceType = new cdk.CfnParameter(stack, 'InstanceType', {
    type: 'String',
    default: 't3.small.search',
  });
  
  // ok: typescript-cdk-open-search-slow-logs-to-cloud-watch
  new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: instanceType.valueAsString,
    },
    logging: {
      slowIndexLogEnabled: true,
      slowSearchLogEnabled: true,
    },
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_8(scope: Construct) {
  // Using a class to create the domain with proper slow logs
  class OpenSearchDomainStack extends cdk.Stack {
    constructor(scope: Construct, id: string, props?: cdk.StackProps) {
      super(scope, id, props);
      
      // ok: typescript-cdk-open-search-slow-logs-to-cloud-watch
      new opensearch.Domain(this, 'Domain', {
        version: opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity: {
          dataNodes: 2,
          dataNodeInstanceType: 't3.small.search',
        },
        logging: {
          slowIndexLogEnabled: true,
          slowSearchLogEnabled: true,
        },
      });
    }
  }
  
  new OpenSearchDomainStack(scope, 'OpenSearchStack');
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_9(scope: Construct) {
  // Using a different version with proper slow logs
  // ok: typescript-cdk-open-search-slow-logs-to-cloud-watch
  new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.ELASTICSEARCH_7_10,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
    logging: {
      slowIndexLogEnabled: true,
      slowSearchLogEnabled: true,
    },
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_10(scope: Construct) {
  // Using a different constructor pattern with proper slow logs
  const domainProps: opensearch.DomainProps = {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
    logging: {
      slowIndexLogEnabled: true,
      slowSearchLogEnabled: true,
    },
  };
  
  // ok: typescript-cdk-open-search-slow-logs-to-cloud-watch
  const domain = new opensearch.Domain(scope, 'Domain', domainProps);
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_11(scope: Construct) {
  // Using environment variables for configuration with proper slow logs
  const nodeCount = process.env.NODE_COUNT ? parseInt(process.env.NODE_COUNT) : 2;
  
  // ok: typescript-cdk-open-search-slow-logs-to-cloud-watch
  new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: nodeCount,
      dataNodeInstanceType: 't3.small.search',
    },
    logging: {
      slowIndexLogEnabled: true,
      slowSearchLogEnabled: true,
    },
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_12(scope: Construct) {
  // Using log group configuration with proper slow logs
  const logGroup = new logs.LogGroup(scope, 'OpenSearchLogs');
  
  // ok: typescript-cdk-open-search-slow-logs-to-cloud-watch
  new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
    logging: {
      slowIndexLogEnabled: true,
      slowSearchLogEnabled: true,
      slowIndexLogGroup: logGroup,
      slowSearchLogGroup: logGroup,
    },
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_13(scope: Construct) {
  // Using variables for log settings with proper slow logs
  const enableSlowLogs = true;
  
  // ok: typescript-cdk-open-search-slow-logs-to-cloud-watch
  new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
    logging: {
      slowIndexLogEnabled: enableSlowLogs,
      slowSearchLogEnabled: enableSlowLogs,
    },
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_14(scope: Construct) {
  // Using a factory function to create logging config with proper slow logs
  function createLoggingConfig() {
    return {
      slowIndexLogEnabled: true,
      slowSearchLogEnabled: true,
      appLogEnabled: false,
    };
  }
  
  // ok: typescript-cdk-open-search-slow-logs-to-cloud-watch
  new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
    logging: createLoggingConfig(),
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_15(scope: Construct) {
  // Using a more complex setup with proper slow logs
  const role = new iam.Role(scope, 'OpenSearchRole', {
    assumedBy: new iam.ServicePrincipal('opensearchservice.amazonaws.com'),
  });
  
  // ok: typescript-cdk-open-search-slow-logs-to-cloud-watch
  new opensearch.Domain(scope, 'Domain', {
    version: opensearch.EngineVersion.OPENSEARCH_1_0,
    capacity: {
      dataNodes: 2,
      dataNodeInstanceType: 't3.small.search',
    },
    logging: {
      slowIndexLogEnabled: true,
      slowSearchLogEnabled: true,
    },
    encryptionAtRest: {
      enabled: true,
    },
    nodeToNodeEncryption: true,
    enforceHttps: true,
    fineGrainedAccessControl: {
      masterUserArn: role.roleArn,
    },
  });
}
// {/fact}