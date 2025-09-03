import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as apigateway from 'aws-cdk-lib/aws-apigateway';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as lambda from 'aws-cdk-lib/aws-lambda';

// TRUE POSITIVES (Vulnerable code - logging disabled)

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_1(scope: Construct) {
  // Creating an API Gateway without access logging
  // ruleid: typescript_cdk_api_logging_disabled
  const api = new apigateway.RestApi(scope, 'ApiWithoutLogging', {
    deployOptions: {
      stageName: 'prod',
    },
  });
  
  const integration = new apigateway.LambdaIntegration(
    new lambda.Function(scope, 'MyFunction', {
      runtime: lambda.Runtime.NODEJS_14_X,
      handler: 'index.handler',
      code: lambda.Code.fromInline('exports.handler = async () => { return { statusCode: 200, body: "Hello" }; }'),
    })
  );
  
  api.root.addMethod('GET', integration);
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_2(scope: Construct) {
  // Creating an API Gateway with empty deployOptions
  // ruleid: typescript_cdk_api_logging_disabled
  const api = new apigateway.RestApi(scope, 'ApiWithEmptyDeployOptions', {
    deployOptions: {},
  });
  
  const integration = new apigateway.LambdaIntegration(
    new lambda.Function(scope, 'MyFunction', {
      runtime: lambda.Runtime.NODEJS_14_X,
      handler: 'index.handler',
      code: lambda.Code.fromInline('exports.handler = async () => { return { statusCode: 200, body: "Hello" }; }'),
    })
  );
  
  api.root.addMethod('POST', integration);
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_3(scope: Construct) {
  // Creating an API Gateway with explicit undefined accessLogSettings
  // ruleid: typescript_cdk_api_logging_disabled
  const api = new apigateway.RestApi(scope, 'ApiWithUndefinedLogging', {
    deployOptions: {
      stageName: 'dev',
      accessLogSettings: undefined,
    },
  });
  
  const integration = new apigateway.LambdaIntegration(
    new lambda.Function(scope, 'MyFunction', {
      runtime: lambda.Runtime.NODEJS_14_X,
      handler: 'index.handler',
      code: lambda.Code.fromInline('exports.handler = async () => { return { statusCode: 200, body: "Hello" }; }'),
    })
  );
  
  api.root.addMethod('DELETE', integration);
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_4(scope: Construct) {
  // Creating an API Gateway with minimal configuration
  // ruleid: typescript_cdk_api_logging_disabled
  const api = new apigateway.RestApi(scope, 'MinimalApi', {});
  
  const integration = new apigateway.LambdaIntegration(
    new lambda.Function(scope, 'MyFunction', {
      runtime: lambda.Runtime.NODEJS_14_X,
      handler: 'index.handler',
      code: lambda.Code.fromInline('exports.handler = async () => { return { statusCode: 200, body: "Hello" }; }'),
    })
  );
  
  api.root.addMethod('PUT', integration);
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_5(scope: Construct) {
  // Creating an API Gateway with stage name but no logging
  // ruleid: typescript_cdk_api_logging_disabled
  const api = new apigateway.RestApi(scope, 'ApiWithStageOnly', {
    deployOptions: {
      stageName: 'test',
      cachingEnabled: true,
    },
  });
  
  const integration = new apigateway.LambdaIntegration(
    new lambda.Function(scope, 'MyFunction', {
      runtime: lambda.Runtime.NODEJS_14_X,
      handler: 'index.handler',
      code: lambda.Code.fromInline('exports.handler = async () => { return { statusCode: 200, body: "Hello" }; }'),
    })
  );
  
  api.root.addMethod('PATCH', integration);
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_6(scope: Construct) {
  // Creating an API Gateway with separate deployment but no logging
  // ruleid: typescript_cdk_api_logging_disabled
  const api = new apigateway.RestApi(scope, 'ApiWithSeparateDeployment');
  
  const deployment = new apigateway.Deployment(scope, 'Deployment', {
    api,
  });
  
  new apigateway.Stage(scope, 'Stage', {
    deployment,
    stageName: 'prod',
  });
  
  const integration = new apigateway.LambdaIntegration(
    new lambda.Function(scope, 'MyFunction', {
      runtime: lambda.Runtime.NODEJS_14_X,
      handler: 'index.handler',
      code: lambda.Code.fromInline('exports.handler = async () => { return { statusCode: 200, body: "Hello" }; }'),
    })
  );
  
  api.root.addMethod('GET', integration);
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_7(scope: Construct) {
  // Creating an HTTP API without logging
  // ruleid: typescript_cdk_api_logging_disabled
  const httpApi = new apigateway.HttpApi(scope, 'HttpApiWithoutLogging', {
    createDefaultStage: true,
  });
  
  const integration = new apigateway.HttpLambdaIntegration('Integration', 
    new lambda.Function(scope, 'MyFunction', {
      runtime: lambda.Runtime.NODEJS_14_X,
      handler: 'index.handler',
      code: lambda.Code.fromInline('exports.handler = async () => { return { statusCode: 200, body: "Hello" }; }'),
    })
  );
  
  httpApi.addRoutes({
    path: '/items',
    methods: [apigateway.HttpMethod.GET],
    integration,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_8(scope: Construct) {
  // Creating a SpecRestApi without logging
  // ruleid: typescript_cdk_api_logging_disabled
  const api = new apigateway.SpecRestApi(scope, 'SpecApiWithoutLogging', {
    apiDefinition: apigateway.ApiDefinition.fromInline({
      openapi: '3.0.0',
      info: {
        title: 'My API',
        version: '1.0.0',
      },
      paths: {},
    }),
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_9(scope: Construct) {
  // Creating a RestApi with methodOptions but no logging
  // ruleid: typescript_cdk_api_logging_disabled
  const api = new apigateway.RestApi(scope, 'ApiWithMethodOptions', {
    defaultMethodOptions: {
      authorizationType: apigateway.AuthorizationType.IAM,
    },
  });
  
  const integration = new apigateway.LambdaIntegration(
    new lambda.Function(scope, 'MyFunction', {
      runtime: lambda.Runtime.NODEJS_14_X,
      handler: 'index.handler',
      code: lambda.Code.fromInline('exports.handler = async () => { return { statusCode: 200, body: "Hello" }; }'),
    })
  );
  
  api.root.addMethod('GET', integration);
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_10(scope: Construct) {
  // Creating a RestApi with endpointConfiguration but no logging
  // ruleid: typescript_cdk_api_logging_disabled
  const api = new apigateway.RestApi(scope, 'ApiWithEndpointConfig', {
    endpointConfiguration: {
      types: [apigateway.EndpointType.REGIONAL],
    },
  });
  
  const integration = new apigateway.LambdaIntegration(
    new lambda.Function(scope, 'MyFunction', {
      runtime: lambda.Runtime.NODEJS_14_X,
      handler: 'index.handler',
      code: lambda.Code.fromInline('exports.handler = async () => { return { statusCode: 200, body: "Hello" }; }'),
    })
  );
  
  api.root.addMethod('GET', integration);
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_11(scope: Construct) {
  // Creating a RestApi with deploy set to false
  // ruleid: typescript_cdk_api_logging_disabled
  const api = new apigateway.RestApi(scope, 'ApiWithDeployFalse', {
    deploy: false,
  });
  
  const integration = new apigateway.LambdaIntegration(
    new lambda.Function(scope, 'MyFunction', {
      runtime: lambda.Runtime.NODEJS_14_X,
      handler: 'index.handler',
      code: lambda.Code.fromInline('exports.handler = async () => { return { statusCode: 200, body: "Hello" }; }'),
    })
  );
  
  api.root.addMethod('GET', integration);
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_12(scope: Construct) {
  // Creating a RestApi with cloudWatchRole but no logging
  // ruleid: typescript_cdk_api_logging_disabled
  const api = new apigateway.RestApi(scope, 'ApiWithCloudWatchRole', {
    cloudWatchRole: true,
  });
  
  const integration = new apigateway.LambdaIntegration(
    new lambda.Function(scope, 'MyFunction', {
      runtime: lambda.Runtime.NODEJS_14_X,
      handler: 'index.handler',
      code: lambda.Code.fromInline('exports.handler = async () => { return { statusCode: 200, body: "Hello" }; }'),
    })
  );
  
  api.root.addMethod('GET', integration);
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_13(scope: Construct) {
  // Creating a RestApi with API key but no logging
  // ruleid: typescript_cdk_api_logging_disabled
  const api = new apigateway.RestApi(scope, 'ApiWithApiKey', {
    defaultMethodOptions: {
      apiKeyRequired: true,
    },
  });
  
  const integration = new apigateway.LambdaIntegration(
    new lambda.Function(scope, 'MyFunction', {
      runtime: lambda.Runtime.NODEJS_14_X,
      handler: 'index.handler',
      code: lambda.Code.fromInline('exports.handler = async () => { return { statusCode: 200, body: "Hello" }; }'),
    })
  );
  
  api.root.addMethod('GET', integration);
  
  const plan = api.addUsagePlan('UsagePlan', {
    name: 'Easy',
    throttle: {
      rateLimit: 10,
      burstLimit: 2,
    },
  });
  
  const key = api.addApiKey('ApiKey');
  plan.addApiKey(key);
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_14(scope: Construct) {
  // Creating a RestApi with CORS but no logging
  // ruleid: typescript_cdk_api_logging_disabled
  const api = new apigateway.RestApi(scope, 'ApiWithCors', {
    defaultCorsPreflightOptions: {
      allowOrigins: ['*'],
      allowMethods: ['GET', 'POST'],
    },
  });
  
  const integration = new apigateway.LambdaIntegration(
    new lambda.Function(scope, 'MyFunction', {
      runtime: lambda.Runtime.NODEJS_14_X,
      handler: 'index.handler',
      code: lambda.Code.fromInline('exports.handler = async () => { return { statusCode: 200, body: "Hello" }; }'),
    })
  );
  
  api.root.addMethod('GET', integration);
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_15(scope: Construct) {
  // Creating a RestApi with binary media types but no logging
  // ruleid: typescript_cdk_api_logging_disabled
  const api = new apigateway.RestApi(scope, 'ApiWithBinaryMediaTypes', {
    binaryMediaTypes: ['application/octet-stream', 'image/jpeg'],
  });
  
  const integration = new apigateway.LambdaIntegration(
    new lambda.Function(scope, 'MyFunction', {
      runtime: lambda.Runtime.NODEJS_14_X,
      handler: 'index.handler',
      code: lambda.Code.fromInline('exports.handler = async () => { return { statusCode: 200, body: "Hello" }; }'),
    })
  );
  
  api.root.addMethod('GET', integration);
}
// {/fact}

// TRUE NEGATIVES (Secure code - logging enabled)

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_1(scope: Construct) {
  // Creating an API Gateway with access logging enabled
  const logGroup = new logs.LogGroup(scope, 'ApiGatewayAccessLogs');
  
  // ok: typescript_cdk_api_logging_disabled
  const api = new apigateway.RestApi(scope, 'ApiWithLogging', {
    deployOptions: {
      stageName: 'prod',
      accessLogSettings: {
        destinationArn: logGroup.logGroupArn,
        format: apigateway.AccessLogFormat.clf(),
      },
    },
  });
  
  const integration = new apigateway.LambdaIntegration(
    new lambda.Function(scope, 'MyFunction', {
      runtime: lambda.Runtime.NODEJS_14_X,
      handler: 'index.handler',
      code: lambda.Code.fromInline('exports.handler = async () => { return { statusCode: 200, body: "Hello" }; }'),
    })
  );
  
  api.root.addMethod('GET', integration);
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_2(scope: Construct) {
  // Creating an API Gateway with custom access log format
  const logGroup = new logs.LogGroup(scope, 'ApiGatewayAccessLogs');
  
  // ok: typescript_cdk_api_logging_disabled
  const api = new apigateway.RestApi(scope, 'ApiWithCustomLogFormat', {
    deployOptions: {
      stageName: 'dev',
      accessLogSettings: {
        destinationArn: logGroup.logGroupArn,
        format: apigateway.AccessLogFormat.custom(
          '{"requestTime":"$context.requestTime","requestId":"$context.requestId","httpMethod":"$context.httpMethod","path":"$context.path","resourcePath":"$context.resourcePath","status":$context.status,"responseLength":$context.responseLength}'
        ),
      },
    },
  });
  
  const integration = new apigateway.LambdaIntegration(
    new lambda.Function(scope, 'MyFunction', {
      runtime: lambda.Runtime.NODEJS_14_X,
      handler: 'index.handler',
      code: lambda.Code.fromInline('exports.handler = async () => { return { statusCode: 200, body: "Hello" }; }'),
    })
  );
  
  api.root.addMethod('POST', integration);
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_3(scope: Construct) {
  // Creating an API Gateway with JSON access log format
  const logGroup = new logs.LogGroup(scope, 'ApiGatewayAccessLogs');
  
  // ok: typescript_cdk_api_logging_disabled
  const api = new apigateway.RestApi(scope, 'ApiWithJsonLogFormat', {
    deployOptions: {
      stageName: 'test',
      accessLogSettings: {
        destinationArn: logGroup.logGroupArn,
        format: apigateway.AccessLogFormat.jsonWithStandardFields(),
      },
    },
  });
  
  const integration = new apigateway.LambdaIntegration(
    new lambda.Function(scope, 'MyFunction', {
      runtime: lambda.Runtime.NODEJS_14_X,
      handler: 'index.handler',
      code: lambda.Code.fromInline('exports.handler = async () => { return { statusCode: 200, body: "Hello" }; }'),
    })
  );
  
  api.root.addMethod('DELETE', integration);
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_4(scope: Construct) {
  // Creating an API Gateway with separate deployment and stage with logging
  const api = new apigateway.RestApi(scope, 'ApiWithSeparateDeploymentAndLogging');
  
  const deployment = new apigateway.Deployment(scope, 'Deployment', {
    api,
  });
  
  const logGroup = new logs.LogGroup(scope, 'ApiGatewayAccessLogs');
  
  // ok: typescript_cdk_api_logging_disabled
  new apigateway.Stage(scope, 'Stage', {
    deployment,
    stageName: 'prod',
    accessLogSettings: {
      destinationArn: logGroup.logGroupArn,
      format: apigateway.AccessLogFormat.clf(),
    },
  });
  
  const integration = new apigateway.LambdaIntegration(
    new lambda.Function(scope, 'MyFunction', {
      runtime: lambda.Runtime.NODEJS_14_X,
      handler: 'index.handler',
      code: lambda.Code.fromInline('exports.handler = async () => { return { statusCode: 200, body: "Hello" }; }'),
    })
  );
  
  api.root.addMethod('PUT', integration);
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_5(scope: Construct) {
  // Creating an HTTP API with logging
  const logGroup = new logs.LogGroup(scope, 'HttpApiAccessLogs');
  
  // ok: typescript_cdk_api_logging_disabled
  const httpApi = new apigateway.HttpApi(scope, 'HttpApiWithLogging', {
    createDefaultStage: true,
    defaultStageOptions: {
      accessLogSettings: {
        destinationArn: logGroup.logGroupArn,
        format: '$context.identity.sourceIp - - [$context.requestTime] "$context.httpMethod $context.routeKey $context.protocol" $context.status $context.responseLength $context.requestId $context.integrationErrorMessage',
      },
    },
  });
  
  const integration = new apigateway.HttpLambdaIntegration('Integration', 
    new lambda.Function(scope, 'MyFunction', {
      runtime: lambda.Runtime.NODEJS_14_X,
      handler: 'index.handler',
      code: lambda.Code.fromInline('exports.handler = async () => { return { statusCode: 200, body: "Hello" }; }'),
    })
  );
  
  httpApi.addRoutes({
    path: '/items',
    methods: [apigateway.HttpMethod.GET],
    integration,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_6(scope: Construct) {
  // Creating a SpecRestApi with logging
  const logGroup = new logs.LogGroup(scope, 'SpecApiAccessLogs');
  
  // ok: typescript_cdk_api_logging_disabled
  const api = new apigateway.SpecRestApi(scope, 'SpecApiWithLogging', {
    apiDefinition: apigateway.ApiDefinition.fromInline({
      openapi: '3.0.0',
      info: {
        title: 'My API',
        version: '1.0.0',
      },
      paths: {},
    }),
    deployOptions: {
      accessLogSettings: {
        destinationArn: logGroup.logGroupArn,
        format: apigateway.AccessLogFormat.clf(),
      },
    },
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_7(scope: Construct) {
  // Creating a RestApi with method options and logging
  const logGroup = new logs.LogGroup(scope, 'ApiGatewayAccessLogs');
  
  // ok: typescript_cdk_api_logging_disabled
  const api = new apigateway.RestApi(scope, 'ApiWithMethodOptionsAndLogging', {
    defaultMethodOptions: {
      authorizationType: apigateway.AuthorizationType.IAM,
    },
    deployOptions: {
      accessLogSettings: {
        destinationArn: logGroup.logGroupArn,
        format: apigateway.AccessLogFormat.clf(),
      },
    },
  });
  
  const integration = new apigateway.LambdaIntegration(
    new lambda.Function(scope, 'MyFunction', {
      runtime: lambda.Runtime.NODEJS_14_X,
      handler: 'index.handler',
      code: lambda.Code.fromInline('exports.handler = async () => { return { statusCode: 200, body: "Hello" }; }'),
    })
  );
  
  api.root.addMethod('GET', integration);
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_8(scope: Construct) {
  // Creating a RestApi with endpoint configuration and logging
  const logGroup = new logs.LogGroup(scope, 'ApiGatewayAccessLogs');
  
  // ok: typescript_cdk_api_logging_disabled
  const api = new apigateway.RestApi(scope, 'ApiWithEndpointConfigAndLogging', {
    endpointConfiguration: {
      types: [apigateway.EndpointType.REGIONAL],
    },
    deployOptions: {
      accessLogSettings: {
        destinationArn: logGroup.logGroupArn,
        format: apigateway.AccessLogFormat.clf(),
      },
    },
  });
  
  const integration = new apigateway.LambdaIntegration(
    new lambda.Function(scope, 'MyFunction', {
      runtime: lambda.Runtime.NODEJS_14_X,
      handler: 'index.handler',
      code: lambda.Code.fromInline('exports.handler = async () => { return { statusCode: 200, body: "Hello" }; }'),
    })
  );
  
  api.root.addMethod('GET', integration);
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_9(scope: Construct) {
  // Creating a RestApi with cloudWatchRole and logging
  const logGroup = new logs.LogGroup(scope, 'ApiGatewayAccessLogs');
  
  // ok: typescript_cdk_api_logging_disabled
  const api = new apigateway.RestApi(scope, 'ApiWithCloudWatchRoleAndLogging', {
    cloudWatchRole: true,
    deployOptions: {
      accessLogSettings: {
        destinationArn: logGroup.logGroupArn,
        format: apigateway.AccessLogFormat.clf(),
      },
    },
  });
  
  const integration = new apigateway.LambdaIntegration(
    new lambda.Function(scope, 'MyFunction', {
      runtime: lambda.Runtime.NODEJS_14_X,
      handler: 'index.handler',
      code: lambda.Code.fromInline('exports.handler = async () => { return { statusCode: 200, body: "Hello" }; }'),
    })
  );
  
  api.root.addMethod('GET', integration);
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_10(scope: Construct) {
  // Creating a RestApi with API key and logging
  const logGroup = new logs.LogGroup(scope, 'ApiGatewayAccessLogs');
  
  // ok: typescript_cdk_api_logging_disabled
  const api = new apigateway.RestApi(scope, 'ApiWithApiKeyAndLogging', {
    defaultMethodOptions: {
      apiKeyRequired: true,
    },
    deployOptions: {
      accessLogSettings: {
        destinationArn: logGroup.logGroupArn,
        format: apigateway.AccessLogFormat.clf(),
      },
    },
  });
  
  const integration = new apigateway.LambdaIntegration(
    new lambda.Function(scope, 'MyFunction', {
      runtime: lambda.Runtime.NODEJS_14_X,
      handler: 'index.handler',
      code: lambda.Code.fromInline('exports.handler = async () => { return { statusCode: 200, body: "Hello" }; }'),
    })
  );
  
  api.root.addMethod('GET', integration);
  
  const plan = api.addUsagePlan('UsagePlan', {
    name: 'Easy',
    throttle: {
      rateLimit: 10,
      burstLimit: 2,
    },
  });
  
  const key = api.addApiKey('ApiKey');
  plan.addApiKey(key);
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_11(scope: Construct) {
  // Creating a RestApi with CORS and logging
  const logGroup = new logs.LogGroup(scope, 'ApiGatewayAccessLogs');
  
  // ok: typescript_cdk_api_logging_disabled
  const api = new apigateway.RestApi(scope, 'ApiWithCorsAndLogging', {
    defaultCorsPreflightOptions: {
      allowOrigins: ['*'],
      allowMethods: ['GET', 'POST'],
    },
    deployOptions: {
      accessLogSettings: {
        destinationArn: logGroup.logGroupArn,
        format: apigateway.AccessLogFormat.clf(),
      },
    },
  });
  
  const integration = new apigateway.LambdaIntegration(
    new lambda.Function(scope, 'MyFunction', {
      runtime: lambda.Runtime.NODEJS_14_X,
      handler: 'index.handler',
      code: lambda.Code.fromInline('exports.handler = async () => { return { statusCode: 200, body: "Hello" }; }'),
    })
  );
  
  api.root.addMethod('GET', integration);
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_12(scope: Construct) {
  // Creating a RestApi with binary media types and logging
  const logGroup = new logs.LogGroup(scope, 'ApiGatewayAccessLogs');
  
  // ok: typescript_cdk_api_logging_disabled
  const api = new apigateway.RestApi(scope, 'ApiWithBinaryMediaTypesAndLogging', {
    binaryMediaTypes: ['application/octet-stream', 'image/jpeg'],
    deployOptions: {
      accessLogSettings: {
        destinationArn: logGroup.logGroupArn,
        format: apigateway.AccessLogFormat.clf(),
      },
    },
  });
  
  const integration = new apigateway.LambdaIntegration(
    new lambda.Function(scope, 'MyFunction', {
      runtime: lambda.Runtime.NODEJS_14_X,
      handler: 'index.handler',
      code: lambda.Code.fromInline('exports.handler = async () => { return { statusCode: 200, body: "Hello" }; }'),
    })
  );
  
  api.root.addMethod('GET', integration);
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_13(scope: Construct) {
  // Creating a RestApi with logging and custom domain
  const logGroup = new logs.LogGroup(scope, 'ApiGatewayAccessLogs');
  
  // ok: typescript_cdk_api_logging_disabled
  const api = new apigateway.RestApi(scope, 'ApiWithLoggingAndCustomDomain', {
    deployOptions: {
      stageName: 'prod',
      accessLogSettings: {
        destinationArn: logGroup.logGroupArn,
        format: apigateway.AccessLogFormat.clf(),
      },
    },
  });
  
  const domainName = new apigateway.DomainName(scope, 'DomainName', {
    domainName: 'api.example.com',
    certificate: {
      certificateArn: 'arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012',
    },
  });
  
  domainName.addBasePathMapping(api, {
    basePath: 'v1',
  });
  
  const integration = new apigateway.LambdaIntegration(
    new lambda.Function(scope, 'MyFunction', {
      runtime: lambda.Runtime.NODEJS_14_X,
      handler: 'index.handler',
      code: lambda.Code.fromInline('exports.handler = async () => { return { statusCode: 200, body: "Hello" }; }'),
    })
  );
  
  api.root.addMethod('GET', integration);
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_14(scope: Construct) {
  // Creating a RestApi with logging and throttling
  const logGroup = new logs.LogGroup(scope, 'ApiGatewayAccessLogs');
  
  // ok: typescript_cdk_api_logging_disabled
  const api = new apigateway.RestApi(scope, 'ApiWithLoggingAndThrottling', {
    deployOptions: {
      stageName: 'prod',
      accessLogSettings: {
        destinationArn: logGroup.logGroupArn,
        format: apigateway.AccessLogFormat.clf(),
      },
      throttlingRateLimit: 100,
      throttlingBurstLimit: 20,
    },
  });
  
  const integration = new apigateway.LambdaIntegration(
    new lambda.Function(scope, 'MyFunction', {
      runtime: lambda.Runtime.NODEJS_14_X,
      handler: 'index.handler',
      code: lambda.Code.fromInline('exports.handler = async () => { return { statusCode: 200, body: "Hello" }; }'),
    })
  );
  
  api.root.addMethod('GET', integration);
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_15(scope: Construct) {
  // Creating a RestApi with logging and caching
  const logGroup = new logs.LogGroup(scope, 'ApiGatewayAccessLogs');
  
  // ok: typescript_cdk_api_logging_disabled
  const api = new apigateway.RestApi(scope, 'ApiWithLoggingAndCaching', {
    deployOptions: {
      stageName: 'prod',
      accessLogSettings: {
        destinationArn: logGroup.logGroupArn,
        format: apigateway.AccessLogFormat.clf(),
      },
      cachingEnabled: true,
      cacheTtl: cdk.Duration.minutes(5),
    },
  });
  
  const integration = new apigateway.LambdaIntegration(
    new lambda.Function(scope, 'MyFunction', {
      runtime: lambda.Runtime.NODEJS_14_X,
      handler: 'index.handler',
      code: lambda.Code.fromInline('exports.handler = async () => { return { statusCode: 200, body: "Hello" }; }'),
    })
  );
  
  api.root.addMethod('GET', integration);
}
// {/fact}