import { Stack, StackProps, App } from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as appsync from 'aws-cdk-lib/aws-appsync';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as iam from 'aws-cdk-lib/aws-iam';

// True Positive Examples (Vulnerable Code)

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_1(): void {
  const stack = new Stack();
  
  // ruleid: typescript_cdk_app_sync_graph_ql_request_logging
  new appsync.GraphqlApi(stack, 'api', {
    name: 'api',
    schema: appsync.SchemaFile.fromAsset('schema.graphql'),
    authorizationConfig: {
      defaultAuthorization: {
        authorizationType: appsync.AuthorizationType.API_KEY,
      },
    },
    // Missing logConfig
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_2(): void {
  const stack = new Stack();
  
  // ruleid: typescript_cdk_app_sync_graph_ql_request_logging
  const api = new appsync.GraphqlApi(stack, 'api', {
    name: 'demo-api',
    schema: appsync.SchemaFile.fromAsset('schema.graphql'),
    authorizationConfig: {
      defaultAuthorization: {
        authorizationType: appsync.AuthorizationType.IAM,
      },
    },
  });
  
  // Adding a data source but still no logging
  api.addDynamoDbDataSource('ddbDataSource', dynamoDbTable);
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_3(): void {
  class MyStack extends Stack {
    constructor(scope: Construct, id: string, props?: StackProps) {
      super(scope, id, props);
      
      // ruleid: typescript_cdk_app_sync_graph_ql_request_logging
      const api = new appsync.GraphqlApi(this, 'GraphQLAPI', {
        name: 'production-api',
        schema: appsync.SchemaFile.fromAsset('schema.graphql'),
        authorizationConfig: {
          defaultAuthorization: {
            authorizationType: appsync.AuthorizationType.USER_POOL,
            userPoolConfig: {
              userPool: userPool,
            },
          },
        },
        // No logging configuration
      });
    }
  }
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_4(): void {
  const stack = new Stack();
  
  // ruleid: typescript_cdk_app_sync_graph_ql_request_logging
  const api = new appsync.GraphqlApi(stack, 'api', {
    name: 'api-with-lambda',
    schema: appsync.SchemaFile.fromAsset('schema.graphql'),
    authorizationConfig: {
      defaultAuthorization: {
        authorizationType: appsync.AuthorizationType.API_KEY,
      },
    },
    xrayEnabled: true, // XRay enabled but still no logging
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_5(): void {
  const stack = new Stack();
  
  // ruleid: typescript_cdk_app_sync_graph_ql_request_logging
  const api = new appsync.GraphqlApi(stack, 'api', {
    name: 'api',
    schema: appsync.Schema.fromAsset('schema.graphql'),
    authorizationConfig: {
      defaultAuthorization: {
        authorizationType: appsync.AuthorizationType.API_KEY,
      },
    },
  });
  
  // Adding resolvers but no logging
  const ddbDataSource = api.addDynamoDbDataSource('ddbDataSource', dynamoDbTable);
  ddbDataSource.createResolver({
    typeName: 'Query',
    fieldName: 'getItems',
    requestMappingTemplate: appsync.MappingTemplate.dynamoDbScanTable(),
    responseMappingTemplate: appsync.MappingTemplate.dynamoDbResultList(),
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_6(): void {
  const stack = new Stack();
  
  // ruleid: typescript_cdk_app_sync_graph_ql_request_logging
  const api = new appsync.GraphqlApi(stack, 'api', {
    name: 'api-with-multiple-auth',
    schema: appsync.SchemaFile.fromAsset('schema.graphql'),
    authorizationConfig: {
      defaultAuthorization: {
        authorizationType: appsync.AuthorizationType.API_KEY,
      },
      additionalAuthorizationModes: [
        {
          authorizationType: appsync.AuthorizationType.IAM,
        },
      ],
    },
    // No logging configuration despite complex auth setup
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_7(): void {
  const stack = new Stack();
  
  const logGroup = new logs.LogGroup(stack, 'LogGroup');
  
  // ruleid: typescript_cdk_app_sync_graph_ql_request_logging
  const api = new appsync.GraphqlApi(stack, 'api', {
    name: 'api',
    schema: appsync.SchemaFile.fromAsset('schema.graphql'),
    authorizationConfig: {
      defaultAuthorization: {
        authorizationType: appsync.AuthorizationType.API_KEY,
      },
    },
    // Creating a log group but not using it for API logging
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_8(): void {
  const stack = new Stack();
  
  // ruleid: typescript_cdk_app_sync_graph_ql_request_logging
  const api = new appsync.GraphqlApi(stack, 'api', {
    name: 'api',
    schema: appsync.SchemaFile.fromAsset('schema.graphql'),
    authorizationConfig: {
      defaultAuthorization: {
        authorizationType: appsync.AuthorizationType.API_KEY,
      },
    },
    logConfig: {
      // Missing fieldLogLevel and excludeVerboseContent
      // This is incomplete and won't enable proper request logging
    },
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_9(): void {
  class GraphQLStack extends Stack {
    constructor(scope: Construct, id: string, props?: StackProps) {
      super(scope, id, props);
      
      // ruleid: typescript_cdk_app_sync_graph_ql_request_logging
      const api = new appsync.GraphqlApi(this, 'GraphQLAPI', {
        name: 'api',
        schema: appsync.SchemaFile.fromAsset('schema.graphql'),
        authorizationConfig: {
          defaultAuthorization: {
            authorizationType: appsync.AuthorizationType.API_KEY,
          },
        },
        logConfig: {
          // Missing cloudWatchLogsRole and logGroup
          fieldLogLevel: appsync.FieldLogLevel.ERROR,
        },
      });
    }
  }
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_10(): void {
  const stack = new Stack();
  
  // ruleid: typescript_cdk_app_sync_graph_ql_request_logging
  const apiConfig: appsync.GraphqlApiProps = {
    name: 'api',
    schema: appsync.SchemaFile.fromAsset('schema.graphql'),
    authorizationConfig: {
      defaultAuthorization: {
        authorizationType: appsync.AuthorizationType.API_KEY,
      },
    },
    // No logging configuration in the props
  };
  
  const api = new appsync.GraphqlApi(stack, 'api', apiConfig);
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_11(): void {
  const stack = new Stack();
  
  // ruleid: typescript_cdk_app_sync_graph_ql_request_logging
  let apiProps: appsync.GraphqlApiProps = {
    name: 'api',
    schema: appsync.SchemaFile.fromAsset('schema.graphql'),
    authorizationConfig: {
      defaultAuthorization: {
        authorizationType: appsync.AuthorizationType.API_KEY,
      },
    },
  };
  
  if (process.env.ENABLE_XRAY === 'true') {
    apiProps = {
      ...apiProps,
      xrayEnabled: true,
    };
  }
  
  // Still no logging configuration
  const api = new appsync.GraphqlApi(stack, 'api', apiProps);
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_12(): void {
  const stack = new Stack();
  
  // ruleid: typescript_cdk_app_sync_graph_ql_request_logging
  const api = new appsync.GraphqlApi(stack, 'api', {
    name: 'api',
    schema: appsync.SchemaFile.fromAsset('schema.graphql'),
    authorizationConfig: {
      defaultAuthorization: {
        authorizationType: appsync.AuthorizationType.API_KEY,
      },
    },
    logConfig: {
      fieldLogLevel: appsync.FieldLogLevel.NONE, // This effectively disables logging
    },
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_13(): void {
  const createGraphQLApi = (stack: Stack): appsync.GraphqlApi => {
    // ruleid: typescript_cdk_app_sync_graph_ql_request_logging
    return new appsync.GraphqlApi(stack, 'api', {
      name: 'api',
      schema: appsync.SchemaFile.fromAsset('schema.graphql'),
      authorizationConfig: {
        defaultAuthorization: {
          authorizationType: appsync.AuthorizationType.API_KEY,
        },
      },
      // Factory function creating API without logging
    });
  };
  
  const stack = new Stack();
  const api = createGraphQLApi(stack);
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_14(): void {
  const stack = new Stack();
  
  const logGroup = new logs.LogGroup(stack, 'LogGroup');
  const logRole = new iam.Role(stack, 'LogRole', {
    assumedBy: new iam.ServicePrincipal('appsync.amazonaws.com'),
  });
  
  // ruleid: typescript_cdk_app_sync_graph_ql_request_logging
  const api = new appsync.GraphqlApi(stack, 'api', {
    name: 'api',
    schema: appsync.SchemaFile.fromAsset('schema.graphql'),
    authorizationConfig: {
      defaultAuthorization: {
        authorizationType: appsync.AuthorizationType.API_KEY,
      },
    },
    // Created log group and role but not using them for API logging
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_15(): void {
  const stack = new Stack();
  
  // ruleid: typescript_cdk_app_sync_graph_ql_request_logging
  const api = new appsync.CfnGraphQLApi(stack, 'api', {
    name: 'api',
    authenticationType: 'API_KEY',
    // Using CfnGraphQLApi (L1 construct) without logging configuration
  });
  
  new appsync.CfnGraphQLSchema(stack, 'schema', {
    apiId: api.attrApiId,
    definition: 'type Query { hello: String }',
  });
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_1(): void {
  const stack = new Stack();
  
  // ok: typescript_cdk_app_sync_graph_ql_request_logging
  new appsync.GraphqlApi(stack, 'api', {
    name: 'api',
    schema: appsync.SchemaFile.fromAsset('schema.graphql'),
    authorizationConfig: {
      defaultAuthorization: {
        authorizationType: appsync.AuthorizationType.API_KEY,
      },
    },
    logConfig: {
      fieldLogLevel: appsync.FieldLogLevel.ALL,
    },
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_2(): void {
  const stack = new Stack();
  
  const logGroup = new logs.LogGroup(stack, 'LogGroup');
  const logRole = new iam.Role(stack, 'LogRole', {
    assumedBy: new iam.ServicePrincipal('appsync.amazonaws.com'),
  });
  
  // ok: typescript_cdk_app_sync_graph_ql_request_logging
  const api = new appsync.GraphqlApi(stack, 'api', {
    name: 'api',
    schema: appsync.SchemaFile.fromAsset('schema.graphql'),
    authorizationConfig: {
      defaultAuthorization: {
        authorizationType: appsync.AuthorizationType.API_KEY,
      },
    },
    logConfig: {
      fieldLogLevel: appsync.FieldLogLevel.ALL,
      cloudWatchLogsRole: logRole,
      excludeVerboseContent: false,
    },
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_3(): void {
  class MyStack extends Stack {
    constructor(scope: Construct, id: string, props?: StackProps) {
      super(scope, id, props);
      
      // ok: typescript_cdk_app_sync_graph_ql_request_logging
      const api = new appsync.GraphqlApi(this, 'GraphQLAPI', {
        name: 'production-api',
        schema: appsync.SchemaFile.fromAsset('schema.graphql'),
        authorizationConfig: {
          defaultAuthorization: {
            authorizationType: appsync.AuthorizationType.USER_POOL,
            userPoolConfig: {
              userPool: userPool,
            },
          },
        },
        logConfig: {
          fieldLogLevel: appsync.FieldLogLevel.ERROR,
        },
      });
    }
  }
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_4(): void {
  const stack = new Stack();
  
  // ok: typescript_cdk_app_sync_graph_ql_request_logging
  const api = new appsync.GraphqlApi(stack, 'api', {
    name: 'api-with-lambda',
    schema: appsync.SchemaFile.fromAsset('schema.graphql'),
    authorizationConfig: {
      defaultAuthorization: {
        authorizationType: appsync.AuthorizationType.API_KEY,
      },
    },
    xrayEnabled: true,
    logConfig: {
      fieldLogLevel: appsync.FieldLogLevel.INFO,
    },
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_5(): void {
  const stack = new Stack();
  
  // ok: typescript_cdk_app_sync_graph_ql_request_logging
  const api = new appsync.GraphqlApi(stack, 'api', {
    name: 'api',
    schema: appsync.Schema.fromAsset('schema.graphql'),
    authorizationConfig: {
      defaultAuthorization: {
        authorizationType: appsync.AuthorizationType.API_KEY,
      },
    },
    logConfig: {
      fieldLogLevel: appsync.FieldLogLevel.ALL,
    },
  });
  
  const ddbDataSource = api.addDynamoDbDataSource('ddbDataSource', dynamoDbTable);
  ddbDataSource.createResolver({
    typeName: 'Query',
    fieldName: 'getItems',
    requestMappingTemplate: appsync.MappingTemplate.dynamoDbScanTable(),
    responseMappingTemplate: appsync.MappingTemplate.dynamoDbResultList(),
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_6(): void {
  const stack = new Stack();
  
  // ok: typescript_cdk_app_sync_graph_ql_request_logging
  const api = new appsync.GraphqlApi(stack, 'api', {
    name: 'api-with-multiple-auth',
    schema: appsync.SchemaFile.fromAsset('schema.graphql'),
    authorizationConfig: {
      defaultAuthorization: {
        authorizationType: appsync.AuthorizationType.API_KEY,
      },
      additionalAuthorizationModes: [
        {
          authorizationType: appsync.AuthorizationType.IAM,
        },
      ],
    },
    logConfig: {
      fieldLogLevel: appsync.FieldLogLevel.ERROR,
    },
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_7(): void {
  const stack = new Stack();
  
  const logGroup = new logs.LogGroup(stack, 'LogGroup');
  
  // ok: typescript_cdk_app_sync_graph_ql_request_logging
  const api = new appsync.GraphqlApi(stack, 'api', {
    name: 'api',
    schema: appsync.SchemaFile.fromAsset('schema.graphql'),
    authorizationConfig: {
      defaultAuthorization: {
        authorizationType: appsync.AuthorizationType.API_KEY,
      },
    },
    logConfig: {
      fieldLogLevel: appsync.FieldLogLevel.ALL,
      logGroup: logGroup,
    },
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_8(): void {
  const stack = new Stack();
  
  // ok: typescript_cdk_app_sync_graph_ql_request_logging
  const api = new appsync.GraphqlApi(stack, 'api', {
    name: 'api',
    schema: appsync.SchemaFile.fromAsset('schema.graphql'),
    authorizationConfig: {
      defaultAuthorization: {
        authorizationType: appsync.AuthorizationType.API_KEY,
      },
    },
    logConfig: {
      fieldLogLevel: appsync.FieldLogLevel.ALL,
      excludeVerboseContent: true,
    },
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_9(): void {
  class GraphQLStack extends Stack {
    constructor(scope: Construct, id: string, props?: StackProps) {
      super(scope, id, props);
      
      const logRole = new iam.Role(this, 'LogRole', {
        assumedBy: new iam.ServicePrincipal('appsync.amazonaws.com'),
      });
      
      // ok: typescript_cdk_app_sync_graph_ql_request_logging
      const api = new appsync.GraphqlApi(this, 'GraphQLAPI', {
        name: 'api',
        schema: appsync.SchemaFile.fromAsset('schema.graphql'),
        authorizationConfig: {
          defaultAuthorization: {
            authorizationType: appsync.AuthorizationType.API_KEY,
          },
        },
        logConfig: {
          fieldLogLevel: appsync.FieldLogLevel.ERROR,
          cloudWatchLogsRole: logRole,
        },
      });
    }
  }
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_10(): void {
  const stack = new Stack();
  
  // ok: typescript_cdk_app_sync_graph_ql_request_logging
  const apiConfig: appsync.GraphqlApiProps = {
    name: 'api',
    schema: appsync.SchemaFile.fromAsset('schema.graphql'),
    authorizationConfig: {
      defaultAuthorization: {
        authorizationType: appsync.AuthorizationType.API_KEY,
      },
    },
    logConfig: {
      fieldLogLevel: appsync.FieldLogLevel.INFO,
    },
  };
  
  const api = new appsync.GraphqlApi(stack, 'api', apiConfig);
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_11(): void {
  const stack = new Stack();
  
  // ok: typescript_cdk_app_sync_graph_ql_request_logging
  let apiProps: appsync.GraphqlApiProps = {
    name: 'api',
    schema: appsync.SchemaFile.fromAsset('schema.graphql'),
    authorizationConfig: {
      defaultAuthorization: {
        authorizationType: appsync.AuthorizationType.API_KEY,
      },
    },
    logConfig: {
      fieldLogLevel: appsync.FieldLogLevel.ALL,
    },
  };
  
  if (process.env.ENABLE_XRAY === 'true') {
    apiProps = {
      ...apiProps,
      xrayEnabled: true,
    };
  }
  
  const api = new appsync.GraphqlApi(stack, 'api', apiProps);
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_12(): void {
  const stack = new Stack();
  
  const logGroup = new logs.LogGroup(stack, 'LogGroup', {
    retention: logs.RetentionDays.ONE_WEEK,
  });
  
  // ok: typescript_cdk_app_sync_graph_ql_request_logging
  const api = new appsync.GraphqlApi(stack, 'api', {
    name: 'api',
    schema: appsync.SchemaFile.fromAsset('schema.graphql'),
    authorizationConfig: {
      defaultAuthorization: {
        authorizationType: appsync.AuthorizationType.API_KEY,
      },
    },
    logConfig: {
      fieldLogLevel: appsync.FieldLogLevel.ALL,
      logGroup: logGroup,
    },
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_13(): void {
  const createGraphQLApi = (stack: Stack): appsync.GraphqlApi => {
    // ok: typescript_cdk_app_sync_graph_ql_request_logging
    return new appsync.GraphqlApi(stack, 'api', {
      name: 'api',
      schema: appsync.SchemaFile.fromAsset('schema.graphql'),
      authorizationConfig: {
        defaultAuthorization: {
          authorizationType: appsync.AuthorizationType.API_KEY,
        },
      },
      logConfig: {
        fieldLogLevel: appsync.FieldLogLevel.ERROR,
      },
    });
  };
  
  const stack = new Stack();
  const api = createGraphQLApi(stack);
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_14(): void {
  const stack = new Stack();
  
  // ok: typescript_cdk_app_sync_graph_ql_request_logging
  const api = new appsync.CfnGraphQLApi(stack, 'api', {
    name: 'api',
    authenticationType: 'API_KEY',
    logConfig: {
      fieldLogLevel: 'ALL',
      cloudWatchLogsRoleArn: logRole.roleArn,
    },
  });
  
  new appsync.CfnGraphQLSchema(stack, 'schema', {
    apiId: api.attrApiId,
    definition: 'type Query { hello: String }',
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_15(): void {
  const stack = new Stack();
  
  const environmentName = process.env.ENVIRONMENT || 'dev';
  const logLevel = environmentName === 'prod' ? appsync.FieldLogLevel.ERROR : appsync.FieldLogLevel.ALL;
  
  // ok: typescript_cdk_app_sync_graph_ql_request_logging
  const api = new appsync.GraphqlApi(stack, 'api', {
    name: `api-${environmentName}`,
    schema: appsync.SchemaFile.fromAsset('schema.graphql'),
    authorizationConfig: {
      defaultAuthorization: {
        authorizationType: appsync.AuthorizationType.API_KEY,
      },
    },
    logConfig: {
      fieldLogLevel: logLevel,
    },
  });
}
// {/fact}