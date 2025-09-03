# Understanding the Rule

The rule `typescript_cdk_apigw_authorization` is designed to detect when AWS CDK (Cloud Development Kit) API Gateway resources are created without proper authorization mechanisms. This is a configuration/usage issue related to CWE-285: Improper Authorization.

The rule checks if API Gateway resources are configured with appropriate authorization methods such as:
- IAM authorization
- Cognito User Pools
- Lambda authorizers (custom authorizers)
- JWT authorizers
- Other valid authorization mechanisms

Let me create examples for this specific AWS CDK configuration issue.

```typescript
import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as apigateway from 'aws-cdk-lib/aws-apigateway';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as cognito from 'aws-cdk-lib/aws-cognito';
import * as iam from 'aws-cdk-lib/aws-iam';

// TRUE POSITIVES (Vulnerable Code)

// {fact rule=improper-authentication@v1.0 defects=1}
function bad_case_1(scope: Construct) {
  // Creating API Gateway without any authorization
  // ruleid: typescript_cdk_apigw_authorization
  const api = new apigateway.RestApi(scope, 'MyApi', {
    restApiName: 'My API Service',
    description: 'This is my API service',
  });
  
  const integration = new apigateway.LambdaIntegration(new lambda.Function(scope, 'MyFunction', {
    runtime: lambda.Runtime.NODEJS_14_X,
    handler: 'index.handler',
    code: lambda.Code.fromAsset('lambda'),
  }));
  
  api.root.addMethod('GET', integration);
}
// {/fact}

// {fact rule=improper-authentication@v1.0 defects=1}
function bad_case_2(scope: Construct) {
  // Creating API Gateway with explicit NONE authorization
  const api = new apigateway.RestApi(scope, 'MyApi', {
    restApiName: 'My API Service',
  });
  
  const integration = new apigateway.LambdaIntegration(new lambda.Function(scope, 'MyFunction', {
    runtime: lambda.Runtime.NODEJS_14_X,
    handler: 'index.handler',
    code: lambda.Code.fromAsset('lambda'),
  }));
  
  // ruleid: typescript_cdk_apigw_authorization
  api.root.addMethod('GET', integration, {
    authorizationType: apigateway.AuthorizationType.NONE,
  });
}
// {/fact}

// {fact rule=improper-authentication@v1.0 defects=1}
function bad_case_3(scope: Construct) {
  // Creating API Gateway with OPTIONS method without authorization
  const api = new apigateway.RestApi(scope, 'MyApi', {
    restApiName: 'My CORS API',
  });
  
  const integration = new apigateway.LambdaIntegration(new lambda.Function(scope, 'MyFunction', {
    runtime: lambda.Runtime.NODEJS_14_X,
    handler: 'index.handler',
    code: lambda.Code.fromAsset('lambda'),
  }));
  
  // ruleid: typescript_cdk_apigw_authorization
  api.root.addMethod('OPTIONS', integration);
}
// {/fact}

// {fact rule=improper-authentication@v1.0 defects=1}
function bad_case_4(scope: Construct) {
  // Creating HTTP API without authorization
  // ruleid: typescript_cdk_apigw_authorization
  const httpApi = new apigateway.HttpApi(scope, 'MyHttpApi', {
    apiName: 'my-http-api',
    description: 'HTTP API example',
  });
  
  const integration = new apigateway.HttpLambdaIntegration('MyIntegration', new lambda.Function(scope, 'MyFunction', {
    runtime: lambda.Runtime.NODEJS_14_X,
    handler: 'index.handler',
    code: lambda.Code.fromAsset('lambda'),
  }));
  
  httpApi.addRoutes({
    path: '/items',
    methods: [apigateway.HttpMethod.GET],
    integration,
  });
}
// {/fact}

// {fact rule=improper-authentication@v1.0 defects=1}
function bad_case_5(scope: Construct) {
  // Creating API Gateway with defaultMethodOptions but no authorization
  // ruleid: typescript_cdk_apigw_authorization
  const api = new apigateway.RestApi(scope, 'MyApi', {
    restApiName: 'My API Service',
    defaultMethodOptions: {
      methodResponses: [{ statusCode: '200' }],
    },
  });
  
  const integration = new apigateway.LambdaIntegration(new lambda.Function(scope, 'MyFunction', {
    runtime: lambda.Runtime.NODEJS_14_X,
    handler: 'index.handler',
    code: lambda.Code.fromAsset('lambda'),
  }));
  
  api.root.addMethod('GET', integration);
}
// {/fact}

// {fact rule=improper-authentication@v1.0 defects=1}
function bad_case_6(scope: Construct) {
  // Creating API Gateway resource with multiple methods, all without authorization
  const api = new apigateway.RestApi(scope, 'MyApi', {
    restApiName: 'My API Service',
  });
  
  const integration = new apigateway.LambdaIntegration(new lambda.Function(scope, 'MyFunction', {
    runtime: lambda.Runtime.NODEJS_14_X,
    handler: 'index.handler',
    code: lambda.Code.fromAsset('lambda'),
  }));
  
  const resource = api.root.addResource('items');
  
  // ruleid: typescript_cdk_apigw_authorization
  resource.addMethod('GET', integration);
  // ruleid: typescript_cdk_apigw_authorization
  resource.addMethod('POST', integration);
}
// {/fact}

// {fact rule=improper-authentication@v1.0 defects=1}
function bad_case_7(scope: Construct) {
  // Creating API Gateway with proxy resource without authorization
  const api = new apigateway.RestApi(scope, 'MyApi', {
    restApiName: 'My API Service',
  });
  
  const integration = new apigateway.LambdaIntegration(new lambda.Function(scope, 'MyFunction', {
    runtime: lambda.Runtime.NODEJS_14_X,
    handler: 'index.handler',
    code: lambda.Code.fromAsset('lambda'),
  }));
  
  // ruleid: typescript_cdk_apigw_authorization
  api.root.addProxy({
    defaultIntegration: integration,
  });
}
// {/fact}

// {fact rule=improper-authentication@v1.0 defects=1}
function bad_case_8(scope: Construct) {
  // Creating API Gateway with resource method using MockIntegration without authorization
  const api = new apigateway.RestApi(scope, 'MyApi', {
    restApiName: 'My API Service',
  });
  
  const mockIntegration = new apigateway.MockIntegration({
    integrationResponses: [{
      statusCode: '200',
      responseTemplates: {
        'application/json': '{ "statusCode": 200, "message": "OK" }',
      },
    }],
    passthroughBehavior: apigateway.PassthroughBehavior.NEVER,
    requestTemplates: {
      'application/json': '{ "statusCode": 200 }',
    },
  });
  
  // ruleid: typescript_cdk_apigw_authorization
  api.root.addMethod('GET', mockIntegration);
}
// {/fact}

// {fact rule=improper-authentication@v1.0 defects=1}
function bad_case_9(scope: Construct) {
  // Creating API Gateway with AWS integration without authorization
  const api = new apigateway.RestApi(scope, 'MyApi', {
    restApiName: 'My API Service',
  });
  
  const awsIntegration = new apigateway.AwsIntegration({
    service: 'dynamodb',
    action: 'GetItem',
    options: {
      credentialsRole: new iam.Role(scope, 'ApiRole', {
        assumedBy: new iam.ServicePrincipal('apigateway.amazonaws.com'),
      }),
      requestTemplates: {
        'application/json': JSON.stringify({
          TableName: 'my-table',
          Key: { id: { S: "$input.params('id')" } },
        }),
      },
      integrationResponses: [{
        statusCode: '200',
      }],
    },
  });
  
  // ruleid: typescript_cdk_apigw_authorization
  api.root.addMethod('GET', awsIntegration);
}
// {/fact}

// {fact rule=improper-authentication@v1.0 defects=1}
function bad_case_10(scope: Construct) {
  // Creating API Gateway with HTTP integration without authorization
  const api = new apigateway.RestApi(scope, 'MyApi', {
    restApiName: 'My API Service',
  });
  
  const httpIntegration = new apigateway.HttpIntegration('https://api.example.com', {
    httpMethod: 'GET',
    options: {
      integrationResponses: [{
        statusCode: '200',
      }],
    },
  });
  
  // ruleid: typescript_cdk_apigw_authorization
  api.root.addMethod('GET', httpIntegration);
}
// {/fact}

// {fact rule=improper-authentication@v1.0 defects=1}
function bad_case_11(scope: Construct) {
  // Creating API Gateway with defaultCorsPreflightOptions but no authorization on methods
  const api = new apigateway.RestApi(scope, 'MyApi', {
    restApiName: 'My API Service',
    defaultCorsPreflightOptions: {
      allowOrigins: apigateway.Cors.ALL_ORIGINS,
      allowMethods: apigateway.Cors.ALL_METHODS,
    },
  });
  
  const integration = new apigateway.LambdaIntegration(new lambda.Function(scope, 'MyFunction', {
    runtime: lambda.Runtime.NODEJS_14_X,
    handler: 'index.handler',
    code: lambda.Code.fromAsset('lambda'),
  }));
  
  // ruleid: typescript_cdk_apigw_authorization
  api.root.addMethod('GET', integration);
}
// {/fact}

// {fact rule=improper-authentication@v1.0 defects=1}
function bad_case_12(scope: Construct) {
  // Creating API Gateway with deployment options but no authorization
  const api = new apigateway.RestApi(scope, 'MyApi', {
    restApiName: 'My API Service',
    deploy: true,
    deployOptions: {
      stageName: 'prod',
      description: 'Production stage',
      loggingLevel: apigateway.MethodLoggingLevel.INFO,
    },
  });
  
  const integration = new apigateway.LambdaIntegration(new lambda.Function(scope, 'MyFunction', {
    runtime: lambda.Runtime.NODEJS_14_X,
    handler: 'index.handler',
    code: lambda.Code.fromAsset('lambda'),
  }));
  
  // ruleid: typescript_cdk_apigw_authorization
  api.root.addMethod('GET', integration);
}
// {/fact}

// {fact rule=improper-authentication@v1.0 defects=1}
function bad_case_13(scope: Construct) {
  // Creating API Gateway with endpoint configuration but no authorization
  const api = new apigateway.RestApi(scope, 'MyApi', {
    restApiName: 'My API Service',
    endpointConfiguration: {
      types: [apigateway.EndpointType.PRIVATE],
    },
  });
  
  const integration = new apigateway.LambdaIntegration(new lambda.Function(scope, 'MyFunction', {
    runtime: lambda.Runtime.NODEJS_14_X,
    handler: 'index.handler',
    code: lambda.Code.fromAsset('lambda'),
  }));
  
  // ruleid: typescript_cdk_apigw_authorization
  api.root.addMethod('GET', integration);
}
// {/fact}

// {fact rule=improper-authentication@v1.0 defects=1}
function bad_case_14(scope: Construct) {
  // Creating API Gateway with resource policy but no method authorization
  const api = new apigateway.RestApi(scope, 'MyApi', {
    restApiName: 'My API Service',
    policy: new iam.PolicyDocument({
      statements: [
        new iam.PolicyStatement({
          actions: ['execute-api:Invoke'],
          resources: ['*'],
          principals: [new iam.AnyPrincipal()],
          conditions: {
            'IpAddress': {
              'aws:SourceIp': ['192.168.0.0/24'],
            },
          },
        }),
      ],
    }),
  });
  
  const integration = new apigateway.LambdaIntegration(new lambda.Function(scope, 'MyFunction', {
    runtime: lambda.Runtime.NODEJS_14_X,
    handler: 'index.handler',
    code: lambda.Code.fromAsset('lambda'),
  }));
  
  // ruleid: typescript_cdk_apigw_authorization
  api.root.addMethod('GET', integration);
}
// {/fact}

// {fact rule=improper-authentication@v1.0 defects=1}
function bad_case_15(scope: Construct) {
  // Creating API Gateway with API key but no authorization type
  const api = new apigateway.RestApi(scope, 'MyApi', {
    restApiName: 'My API Service',
  });
  
  const plan = api.addUsagePlan('UsagePlan', {
    name: 'Easy',
    throttle: {
      rateLimit: 10,
      burstLimit: 2,
    },
  });
  
  const key = api.addApiKey('ApiKey');
  plan.addApiKey(key);
  
  const integration = new apigateway.LambdaIntegration(new lambda.Function(scope, 'MyFunction', {
    runtime: lambda.Runtime.NODEJS_14_X,
    handler: 'index.handler',
    code: lambda.Code.fromAsset('lambda'),
  }));
  
  // API key requirement without proper authorization is still vulnerable
  // ruleid: typescript_cdk_apigw_authorization
  api.root.addMethod('GET', integration, {
    apiKeyRequired: true,
  });
}
// {/fact}

// TRUE NEGATIVES (Secure Code)

// {fact rule=improper-authentication@v1.0 defects=0}
function good_case_1(scope: Construct) {
  // Creating API Gateway with IAM authorization
  const api = new apigateway.RestApi(scope, 'MyApi', {
    restApiName: 'My API Service',
  });
  
  const integration = new apigateway.LambdaIntegration(new lambda.Function(scope, 'MyFunction', {
    runtime: lambda.Runtime.NODEJS_14_X,
    handler: 'index.handler',
    code: lambda.Code.fromAsset('lambda'),
  }));
  
  // ok: typescript_cdk_apigw_authorization
  api.root.addMethod('GET', integration, {
    authorizationType: apigateway.AuthorizationType.IAM,
  });
}
// {/fact}

// {fact rule=improper-authentication@v1.0 defects=0}
function good_case_2(scope: Construct) {
  // Creating API Gateway with Cognito User Pool authorizer
  const api = new apigateway.RestApi(scope, 'MyApi', {
    restApiName: 'My API Service',
  });
  
  const userPool = new cognito.UserPool(scope, 'UserPool', {
    selfSignUpEnabled: true,
    userVerification: {
      emailSubject: 'Verify your email for our app!',
      emailBody: 'Hello {username}, Thanks for signing up! Your verification code is {####}',
      emailStyle: cognito.VerificationEmailStyle.CODE,
    },
  });
  
  const authorizer = new apigateway.CognitoUserPoolsAuthorizer(scope, 'CognitoAuthorizer', {
    cognitoUserPools: [userPool],
  });
  
  const integration = new apigateway.LambdaIntegration(new lambda.Function(scope, 'MyFunction', {
    runtime: lambda.Runtime.NODEJS_14_X,
    handler: 'index.handler',
    code: lambda.Code.fromAsset('lambda'),
  }));
  
  // ok: typescript_cdk_apigw_authorization
  api.root.addMethod('GET', integration, {
    authorizer,
    authorizationType: apigateway.AuthorizationType.COGNITO,
  });
}
// {/fact}

// {fact rule=improper-authentication@v1.0 defects=0}
function good_case_3(scope: Construct) {
  // Creating API Gateway with Lambda authorizer
  const api = new apigateway.RestApi(scope, 'MyApi', {
    restApiName: 'My API Service',
  });
  
  const authorizerFn = new lambda.Function(scope, 'AuthorizerFunction', {
    runtime: lambda.Runtime.NODEJS_14_X,
    handler: 'index.handler',
    code: lambda.Code.fromAsset('lambda-authorizer'),
  });
  
  const authorizer = new apigateway.TokenAuthorizer(scope, 'TokenAuthorizer', {
    handler: authorizerFn,
  });
  
  const integration = new apigateway.LambdaIntegration(new lambda.Function(scope, 'MyFunction', {
    runtime: lambda.Runtime.NODEJS_14_X,
    handler: 'index.handler',
    code: lambda.Code.fromAsset('lambda'),
  }));
  
  // ok: typescript_cdk_apigw_authorization
  api.root.addMethod('GET', integration, {
    authorizer,
    authorizationType: apigateway.AuthorizationType.CUSTOM,
  });
}
// {/fact}

// {fact rule=improper-authentication@v1.0 defects=0}
function good_case_4(scope: Construct) {
  // Creating API Gateway with default method options including IAM authorization
  const api = new apigateway.RestApi(scope, 'MyApi', {
    restApiName: 'My API Service',
    defaultMethodOptions: {
      authorizationType: apigateway.AuthorizationType.IAM,
    },
  });
  
  const integration = new apigateway.LambdaIntegration(new lambda.Function(scope, 'MyFunction', {
    runtime: lambda.Runtime.NODEJS_14_X,
    handler: 'index.handler',
    code: lambda.Code.fromAsset('lambda'),
  }));
  
  // ok: typescript_cdk_apigw_authorization
  api.root.addMethod('GET', integration);
}
// {/fact}

// {fact rule=improper-authentication@v1.0 defects=0}
function good_case_5(scope: Construct) {
  // Creating HTTP API with JWT authorizer
  const httpApi = new apigateway.HttpApi(scope, 'MyHttpApi', {
    apiName: 'my-http-api',
  });
  
  const jwtAuthorizer = new apigateway.HttpJwtAuthorizer('JwtAuthorizer', 'https://auth.example.com', {
    jwtAudience: ['audience1', 'audience2'],
  });
  
  const integration = new apigateway.HttpLambdaIntegration('MyIntegration', new lambda.Function(scope, 'MyFunction', {
    runtime: lambda.Runtime.NODEJS_14_X,
    handler: 'index.handler',
    code: lambda.Code.fromAsset('lambda'),
  }));
  
  // ok: typescript_cdk_apigw_authorization
  httpApi.addRoutes({
    path: '/items',
    methods: [apigateway.HttpMethod.GET],
    integration,
    authorizer: jwtAuthorizer,
  });
}
// {/fact}

// {fact rule=improper-authentication@v1.0 defects=0}
function good_case_6(scope: Construct) {
  // Creating API Gateway with Lambda request authorizer
  const api = new apigateway.RestApi(scope, 'MyApi', {
    restApiName: 'My API Service',
  });
  
  const authorizerFn = new lambda.Function(scope, 'AuthorizerFunction', {
    runtime: lambda.Runtime.NODEJS_14_X,
    handler: 'index.handler',
    code: lambda.Code.fromAsset('lambda-authorizer'),
  });
  
  const authorizer = new apigateway.RequestAuthorizer(scope, 'RequestAuthorizer', {
    handler: authorizerFn,
    identitySources: [apigateway.IdentitySource.header('Authorization')],
  });
  
  const integration = new apigateway.LambdaIntegration(new lambda.Function(scope, 'MyFunction', {
    runtime: lambda.Runtime.NODEJS_14_X,
    handler: 'index.handler',
    code: lambda.Code.fromAsset('lambda'),
  }));
  
  // ok: typescript_cdk_apigw_authorization
  api.root.addMethod('GET', integration, {
    authorizer,
    authorizationType: apigateway.AuthorizationType.CUSTOM,
  });
}
// {/fact}

// {fact rule=improper-authentication@v1.0 defects=0}
function good_case_7(scope: Construct) {
  // Creating API Gateway with multiple methods, all with authorization
  const api = new apigateway.RestApi(scope, 'MyApi', {
    restApiName: 'My API Service',
  });
  
  const integration = new apigateway.LambdaIntegration(new lambda.Function(scope, 'MyFunction', {
    runtime: lambda.Runtime.NODEJS_14_X,
    handler: 'index.handler',
    code: lambda.Code.fromAsset('lambda'),
  }));
  
  const resource = api.root.addResource('items');
  
  // ok: typescript_cdk_apigw_authorization
  resource.addMethod('GET', integration, {
    authorizationType: apigateway.AuthorizationType.IAM,
  });
  
  // ok: typescript_cdk_apigw_authorization
  resource.addMethod('POST', integration, {
    authorizationType: apigateway.AuthorizationType.IAM,
  });
}
// {/fact}

// {fact rule=improper-authentication@v1.0 defects=0}
function good_case_8(scope: Construct) {
  // Creating API Gateway with proxy resource with authorization
  const api = new apigateway.RestApi(scope, 'MyApi', {
    restApiName: 'My API Service',
  });
  
  const integration = new apigateway.LambdaIntegration(new lambda.Function(scope, 'MyFunction', {
    runtime: lambda.Runtime.NODEJS_14_X,
    handler: 'index.handler',
    code: lambda.Code.fromAsset('lambda'),
  }));
  
  // ok: typescript_cdk_apigw_authorization
  api.root.addProxy({
    defaultIntegration: integration,
    defaultMethodOptions: {
      authorizationType: apigateway.AuthorizationType.IAM,
    },
  });
}
// {/fact}

// {fact rule=improper-authentication@v1.0 defects=0}
function good_case_9(scope: Construct) {
  // Creating HTTP API with Lambda authorizer
  const httpApi = new apigateway.HttpApi(scope, 'MyHttpApi', {
    apiName: 'my-http-api',
  });
  
  const authorizerFn = new lambda.Function(scope, 'AuthorizerFunction', {
    runtime: lambda.Runtime.NODEJS_14_X,
    handler: 'index.handler',
    code: lambda.Code.fromAsset('lambda-authorizer'),
  });
  
  const lambdaAuthorizer = new apigateway.HttpLambdaAuthorizer('LambdaAuthorizer', authorizerFn, {
    authorizerName: 'my-lambda-authorizer',
    identitySource: ['$request.header.Authorization'],
  });
  
  const integration = new apigateway.HttpLambdaIntegration('MyIntegration', new lambda.Function(scope, 'MyFunction', {
    runtime: lambda.Runtime.NODEJS_14_X,
    handler: 'index.handler',
    code: lambda.Code.fromAsset('lambda'),
  }));
  
  // ok: typescript_cdk_apigw_authorization
  httpApi.addRoutes({
    path: '/items',
    methods: [apigateway.HttpMethod.GET],
    integration,
    authorizer: lambdaAuthorizer,
  });
}
// {/fact}

// {fact rule=improper-authentication@v1.0 defects=0}
function good_case_10(scope: Construct) {
  // Creating API Gateway with OPTIONS method with NONE authorization (acceptable for CORS)
  const api = new apigateway.RestApi(scope, 'MyApi', {
    restApiName: 'My CORS API',
  });
  
  const integration = new apigateway.LambdaIntegration(new lambda.Function(scope, 'MyFunction', {
    runtime: lambda.Runtime.NODEJS_14_X,
    handler: 'index.handler',
    code: lambda.Code.fromAsset('lambda'),
  }));
  
  // OPTIONS method can have NONE authorization for CORS
  // ok: typescript_cdk_apigw_authorization
  api.root.addMethod('OPTIONS', integration, {
    authorizationType: apigateway.AuthorizationType.NONE,
  });
  
  // But other methods should have authorization
  // ok: typescript_cdk_apigw_authorization
  api.root.addMethod('GET', integration, {
    authorizationType: apigateway.AuthorizationType.IAM,
  });
}
// {/fact}

// {fact rule=improper-authentication@v1.0 defects=0}
function good_case_11(scope: Construct) {
  // Creating API Gateway with resource policy and method authorization
  const api = new apigateway.RestApi(scope, 'MyApi', {
    restApiName: 'My API Service',
    policy: new iam.PolicyDocument({
      statements: [
        new iam.PolicyStatement({
          actions: ['execute-api:Invoke'],
          resources: ['*'],
          principals: [new iam.AnyPrincipal()],
          conditions: {
            'IpAddress': {
              'aws:SourceIp': ['192.168.0.0/24'],
            },
          },
        }),
      ],
    }),
  });
  
  const integration = new apigateway.LambdaIntegration(new lambda.Function(scope, 'MyFunction', {
    runtime: lambda.Runtime.NODEJS_14_X,
    handler: 'index.handler',
    code: lambda.Code.fromAsset('lambda'),
  }));
  
  // ok: typescript_cdk_apigw_authorization
  api.root.addMethod('GET', integration, {
    authorizationType: apigateway.AuthorizationType.IAM,
  });
}
// {/fact}

// {fact rule=improper-authentication@v1.0 defects=0}
function good_case_12(scope: Construct) {
  // Creating API Gateway with API key and IAM authorization
  const api = new apigateway.RestApi(scope, 'MyApi', {
    restApiName: 'My API Service',
  });
  
  const plan = api.addUsagePlan('UsagePlan', {
    name: 'Easy',
    throttle: {
      rateLimit: 10,
      burstLimit: 2,
    },
  });
  
  const key = api.addApiKey('ApiKey');
  plan.addApiKey(key);
  
  const integration = new apigateway.LambdaIntegration(new lambda.Function(scope, 'MyFunction', {
    runtime: lambda.Runtime.NODEJS_14_X,
    handler: 'index.handler',
    code: lambda.Code.fromAsset('lambda'),
  }));
  
  // ok: typescript_cdk_apigw_authorization
  api.root.addMethod('GET', integration, {
    apiKeyRequired: true,
    authorizationType: apigateway.AuthorizationType.IAM,
  });
}
// {/fact}

// {fact rule=improper-authentication@v1.0 defects=0}
function good_case_13(scope: Construct) {
  // Creating API Gateway with OAuth2 scopes for JWT authorizer
  const httpApi = new apigateway.HttpApi(scope, 'MyHttpApi', {
    apiName: 'my-http-api',
  });
  
  const jwtAuthorizer = new apigateway.HttpJwtAuthorizer('JwtAuthorizer', 'https://auth.example.com', {
    jwtAudience: ['audience1'],
    jwtScopes: ['read:items', 'write:items'],
  });
  
  const integration = new apigateway.HttpLambdaIntegration('MyIntegration', new lambda.Function(scope, 'MyFunction', {
    runtime: lambda.Runtime.NODEJS_14_X,
    handler: 'index.handler',
    code: lambda.Code.fromAsset('lambda'),
  }));
  
  // ok: typescript_cdk_apigw_authorization
  httpApi.addRoutes({
    path: '/items',
    methods: [apigateway.HttpMethod.GET],
    integration,
    authorizer: jwtAuthorizer,
  });
}
// {/fact}

// {fact rule=improper-authentication@v1.0 defects=0}
function good_case_14(scope: Construct) {
  // Creating API Gateway with different authorizers for different methods
  const api = new apigateway.RestApi(scope, 'MyApi', {
    restApiName: 'My API Service',
  });
  
  const integration = new apigateway.LambdaIntegration(new lambda.Function(scope, 'MyFunction', {
    runtime: lambda.Runtime.NODEJS_14_X,
    handler: 'index.handler',
    code: lambda.Code.fromAsset('lambda'),
  }));
  
  // IAM authorization for GET
  // ok: typescript_cdk_apigw_authorization
  api.root.addMethod('GET', integration, {
    authorizationType: apigateway.AuthorizationType.IAM,
  });
  
  // Cognito authorization for POST
  const userPool = new cognito.UserPool(scope, 'UserPool', {
    selfSignUpEnabled: true,
  });
  
  const authorizer = new apigateway.CognitoUserPoolsAuthorizer(scope, 'CognitoAuthorizer', {
    cognitoUserPools: [userPool],
  });
  
  // ok: typescript_cdk_apigw_authorization
  api.root.addMethod('POST', integration, {
    authorizer,
    authorizationType: apigateway.AuthorizationType.COGNITO,
  });
}
// {/fact}

// {fact rule=improper-authentication@v1.0 defects=0}
function good_case_15(scope: Construct) {
  // Creating API Gateway with default authorization type for all methods
  const api = new apigateway.RestApi(scope, 'MyApi', {
    restApiName: 'My API Service',
    defaultMethodOptions: {
      authorizationType: apigateway.AuthorizationType.IAM,
    },
  });
  
  const integration = new apigateway.LambdaIntegration(new lambda.Function(scope, 'MyFunction', {
    runtime: lambda.Runtime.NODEJS_14_X,
    handler: 'index.handler',
    code: lambda.Code.fromAsset('lambda'),
  }));
  
  // These methods inherit the default IAM authorization
  // ok: typescript_cdk_apigw_authorization
  api.root.addMethod('GET', integration);
  
  const items = api.root.addResource('items');
  // ok: typescript_cdk_apigw_authorization
  items.addMethod('GET', integration);
  // ok: typescript_cdk_apigw_authorization
  items.addMethod('POST', integration);
}
// {/fact}