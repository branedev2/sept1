import { Stack, StackProps } from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as apigateway from 'aws-cdk-lib/aws-apigateway';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as iam from 'aws-cdk-lib/aws-iam';

// True Positive Examples (Vulnerable Code)

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_1(scope: Construct) {
  // API Gateway without request validation
  // ruleid: typescript_cdk_apigateway_missingreq_validation_enabled
  const api = new apigateway.RestApi(scope, 'MyApi', {
    restApiName: 'My API Service'
  });
  
  const integration = new apigateway.LambdaIntegration(
    new lambda.Function(scope, 'MyFunction', {
      runtime: lambda.Runtime.NODEJS_14_X,
      handler: 'index.handler',
      code: lambda.Code.fromAsset('lambda')
    })
  );
  
  api.root.addMethod('GET', integration);
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_2(scope: Construct) {
  // API Gateway with explicit false validation settings
  // ruleid: typescript_cdk_apigateway_missingreq_validation_enabled
  const api = new apigateway.RestApi(scope, 'MyApi', {
    restApiName: 'My API Service',
    deployOptions: {
      loggingLevel: apigateway.MethodLoggingLevel.INFO,
    }
  });
  
  const validator = new apigateway.RequestValidator(scope, 'DefaultValidator', {
    restApi: api,
    validateRequestBody: false,
    validateRequestParameters: false
  });
  
  const integration = new apigateway.LambdaIntegration(
    new lambda.Function(scope, 'MyFunction', {
      runtime: lambda.Runtime.NODEJS_14_X,
      handler: 'index.handler',
      code: lambda.Code.fromAsset('lambda')
    })
  );
  
  api.root.addMethod('POST', integration, {
    requestValidator: validator
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_3(scope: Construct) {
  // API Gateway with only body validation but not parameters
  // ruleid: typescript_cdk_apigateway_missingreq_validation_enabled
  const api = new apigateway.RestApi(scope, 'MyApi', {
    restApiName: 'My API Service'
  });
  
  const validator = new apigateway.RequestValidator(scope, 'BodyOnlyValidator', {
    restApi: api,
    validateRequestBody: true,
    validateRequestParameters: false
  });
  
  const integration = new apigateway.LambdaIntegration(
    new lambda.Function(scope, 'MyFunction', {
      runtime: lambda.Runtime.NODEJS_14_X,
      handler: 'index.handler',
      code: lambda.Code.fromAsset('lambda')
    })
  );
  
  api.root.addMethod('POST', integration, {
    requestValidator: validator
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_4(scope: Construct) {
  // API Gateway with only parameter validation but not body
  // ruleid: typescript_cdk_apigateway_missingreq_validation_enabled
  const api = new apigateway.RestApi(scope, 'MyApi', {
    restApiName: 'My API Service'
  });
  
  const validator = new apigateway.RequestValidator(scope, 'ParamsOnlyValidator', {
    restApi: api,
    validateRequestBody: false,
    validateRequestParameters: true
  });
  
  const integration = new apigateway.LambdaIntegration(
    new lambda.Function(scope, 'MyFunction', {
      runtime: lambda.Runtime.NODEJS_14_X,
      handler: 'index.handler',
      code: lambda.Code.fromAsset('lambda')
    })
  );
  
  api.root.addMethod('POST', integration, {
    requestValidator: validator
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_5(scope: Construct) {
  // API Gateway with HTTP integration missing validation
  // ruleid: typescript_cdk_apigateway_missingreq_validation_enabled
  const api = new apigateway.RestApi(scope, 'MyApi', {
    restApiName: 'External API Integration'
  });
  
  const integration = new apigateway.HttpIntegration('https://api.example.com', {
    httpMethod: 'GET',
    proxy: true
  });
  
  api.root.addMethod('GET', integration);
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_6(scope: Construct) {
  // API Gateway with mock integration missing validation
  // ruleid: typescript_cdk_apigateway_missingreq_validation_enabled
  const api = new apigateway.RestApi(scope, 'MyApi', {
    restApiName: 'Mock API'
  });
  
  const integration = new apigateway.MockIntegration({
    integrationResponses: [{
      statusCode: '200',
      responseTemplates: {
        'application/json': '{"statusCode": 200, "message": "OK"}'
      }
    }]
  });
  
  api.root.addMethod('GET', integration);
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_7(scope: Construct) {
  // API Gateway with AWS integration missing validation
  // ruleid: typescript_cdk_apigateway_missingreq_validation_enabled
  const api = new apigateway.RestApi(scope, 'MyApi', {
    restApiName: 'AWS Service Integration'
  });
  
  const role = new iam.Role(scope, 'ApiRole', {
    assumedBy: new iam.ServicePrincipal('apigateway.amazonaws.com')
  });
  
  const integration = new apigateway.AwsIntegration({
    service: 'dynamodb',
    action: 'GetItem',
    options: {
      credentialsRole: role
    }
  });
  
  api.root.addMethod('GET', integration);
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_8(scope: Construct) {
  // API Gateway with proxy resource missing validation
  // ruleid: typescript_cdk_apigateway_missingreq_validation_enabled
  const api = new apigateway.RestApi(scope, 'MyApi', {
    restApiName: 'Proxy Resource API'
  });
  
  const integration = new apigateway.LambdaIntegration(
    new lambda.Function(scope, 'MyFunction', {
      runtime: lambda.Runtime.NODEJS_14_X,
      handler: 'index.handler',
      code: lambda.Code.fromAsset('lambda')
    })
  );
  
  const proxy = api.root.addResource('{proxy+}');
  proxy.addMethod('ANY', integration);
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_9(scope: Construct) {
  // API Gateway with request models but no validation enabled
  // ruleid: typescript_cdk_apigateway_missingreq_validation_enabled
  const api = new apigateway.RestApi(scope, 'MyApi', {
    restApiName: 'Model API'
  });
  
  const model = api.addModel('UserModel', {
    contentType: 'application/json',
    modelName: 'UserModel',
    schema: {
      type: apigateway.JsonSchemaType.OBJECT,
      properties: {
        name: { type: apigateway.JsonSchemaType.STRING },
        email: { type: apigateway.JsonSchemaType.STRING }
      },
      required: ['name', 'email']
    }
  });
  
  const integration = new apigateway.LambdaIntegration(
    new lambda.Function(scope, 'MyFunction', {
      runtime: lambda.Runtime.NODEJS_14_X,
      handler: 'index.handler',
      code: lambda.Code.fromAsset('lambda')
    })
  );
  
  api.root.addMethod('POST', integration, {
    requestModels: {
      'application/json': model
    }
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_10(scope: Construct) {
  // API Gateway with method options but no validation
  // ruleid: typescript_cdk_apigateway_missingreq_validation_enabled
  const api = new apigateway.RestApi(scope, 'MyApi', {
    restApiName: 'Method Options API'
  });
  
  const integration = new apigateway.LambdaIntegration(
    new lambda.Function(scope, 'MyFunction', {
      runtime: lambda.Runtime.NODEJS_14_X,
      handler: 'index.handler',
      code: lambda.Code.fromAsset('lambda')
    })
  );
  
  api.root.addMethod('POST', integration, {
    apiKeyRequired: true,
    methodResponses: [
      {
        statusCode: '200',
        responseModels: {
          'application/json': apigateway.Model.EMPTY_MODEL
        }
      }
    ]
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_11(scope: Construct) {
  // HTTP API (v2) without validation
  // ruleid: typescript_cdk_apigateway_missingreq_validation_enabled
  const httpApi = new apigateway.HttpApi(scope, 'HttpApi', {
    apiName: 'My HTTP API'
  });
  
  const integration = new apigateway.HttpLambdaIntegration('LambdaIntegration',
    new lambda.Function(scope, 'MyFunction', {
      runtime: lambda.Runtime.NODEJS_14_X,
      handler: 'index.handler',
      code: lambda.Code.fromAsset('lambda')
    })
  );
  
  httpApi.addRoutes({
    path: '/items',
    methods: [apigateway.HttpMethod.GET],
    integration: integration
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_12(scope: Construct) {
  // API Gateway with authorizer but no validation
  // ruleid: typescript_cdk_apigateway_missingreq_validation_enabled
  const api = new apigateway.RestApi(scope, 'MyApi', {
    restApiName: 'Authorized API'
  });
  
  const authorizer = new apigateway.RequestAuthorizer(scope, 'MyAuthorizer', {
    handler: new lambda.Function(scope, 'AuthorizerFunction', {
      runtime: lambda.Runtime.NODEJS_14_X,
      handler: 'index.handler',
      code: lambda.Code.fromAsset('lambda')
    }),
    identitySources: [apigateway.IdentitySource.header('Authorization')]
  });
  
  const integration = new apigateway.LambdaIntegration(
    new lambda.Function(scope, 'MyFunction', {
      runtime: lambda.Runtime.NODEJS_14_X,
      handler: 'index.handler',
      code: lambda.Code.fromAsset('lambda')
    })
  );
  
  api.root.addMethod('GET', integration, {
    authorizer: authorizer
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_13(scope: Construct) {
  // API Gateway with CORS but no validation
  // ruleid: typescript_cdk_apigateway_missingreq_validation_enabled
  const api = new apigateway.RestApi(scope, 'MyApi', {
    restApiName: 'CORS API',
    defaultCorsPreflightOptions: {
      allowOrigins: apigateway.Cors.ALL_ORIGINS,
      allowMethods: apigateway.Cors.ALL_METHODS
    }
  });
  
  const integration = new apigateway.LambdaIntegration(
    new lambda.Function(scope, 'MyFunction', {
      runtime: lambda.Runtime.NODEJS_14_X,
      handler: 'index.handler',
      code: lambda.Code.fromAsset('lambda')
    })
  );
  
  api.root.addMethod('GET', integration);
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_14(scope: Construct) {
  // API Gateway with custom domain but no validation
  // ruleid: typescript_cdk_apigateway_missingreq_validation_enabled
  const api = new apigateway.RestApi(scope, 'MyApi', {
    restApiName: 'Custom Domain API'
  });
  
  new apigateway.DomainName(scope, 'ApiDomain', {
    domainName: 'api.example.com',
    certificate: apigateway.Certificate.fromCertificateArn(scope, 'Cert', 'arn:aws:acm:us-east-1:123456789012:certificate/abcdef')
  });
  
  const integration = new apigateway.LambdaIntegration(
    new lambda.Function(scope, 'MyFunction', {
      runtime: lambda.Runtime.NODEJS_14_X,
      handler: 'index.handler',
      code: lambda.Code.fromAsset('lambda')
    })
  );
  
  api.root.addMethod('GET', integration);
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_15(scope: Construct) {
  // API Gateway with API key but no validation
  // ruleid: typescript_cdk_apigateway_missingreq_validation_enabled
  const api = new apigateway.RestApi(scope, 'MyApi', {
    restApiName: 'API Key API'
  });
  
  const plan = api.addUsagePlan('UsagePlan', {
    name: 'Standard',
    throttle: {
      rateLimit: 10,
      burstLimit: 2
    }
  });
  
  const key = api.addApiKey('ApiKey');
  plan.addApiKey(key);
  
  const integration = new apigateway.LambdaIntegration(
    new lambda.Function(scope, 'MyFunction', {
      runtime: lambda.Runtime.NODEJS_14_X,
      handler: 'index.handler',
      code: lambda.Code.fromAsset('lambda')
    })
  );
  
  api.root.addMethod('GET', integration, {
    apiKeyRequired: true
  });
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_1(scope: Construct) {
  // API Gateway with full request validation
  const api = new apigateway.RestApi(scope, 'MyApi', {
    restApiName: 'My API Service'
  });
  
  // ok: typescript_cdk_apigateway_missingreq_validation_enabled
  const validator = new apigateway.RequestValidator(scope, 'DefaultValidator', {
    restApi: api,
    validateRequestBody: true,
    validateRequestParameters: true
  });
  
  const integration = new apigateway.LambdaIntegration(
    new lambda.Function(scope, 'MyFunction', {
      runtime: lambda.Runtime.NODEJS_14_X,
      handler: 'index.handler',
      code: lambda.Code.fromAsset('lambda')
    })
  );
  
  api.root.addMethod('POST', integration, {
    requestValidator: validator
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_2(scope: Construct) {
  // API Gateway with full validation and models
  const api = new apigateway.RestApi(scope, 'MyApi', {
    restApiName: 'Model API'
  });
  
  const model = api.addModel('UserModel', {
    contentType: 'application/json',
    modelName: 'UserModel',
    schema: {
      type: apigateway.JsonSchemaType.OBJECT,
      properties: {
        name: { type: apigateway.JsonSchemaType.STRING },
        email: { type: apigateway.JsonSchemaType.STRING }
      },
      required: ['name', 'email']
    }
  });
  
  // ok: typescript_cdk_apigateway_missingreq_validation_enabled
  const validator = new apigateway.RequestValidator(scope, 'FullValidator', {
    restApi: api,
    validateRequestBody: true,
    validateRequestParameters: true
  });
  
  const integration = new apigateway.LambdaIntegration(
    new lambda.Function(scope, 'MyFunction', {
      runtime: lambda.Runtime.NODEJS_14_X,
      handler: 'index.handler',
      code: lambda.Code.fromAsset('lambda')
    })
  );
  
  api.root.addMethod('POST', integration, {
    requestValidator: validator,
    requestModels: {
      'application/json': model
    }
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_3(scope: Construct) {
  // API Gateway with validation and required request parameters
  const api = new apigateway.RestApi(scope, 'MyApi', {
    restApiName: 'Parameters API'
  });
  
  // ok: typescript_cdk_apigateway_missingreq_validation_enabled
  const validator = new apigateway.RequestValidator(scope, 'ParamsValidator', {
    restApi: api,
    validateRequestBody: true,
    validateRequestParameters: true
  });
  
  const integration = new apigateway.LambdaIntegration(
    new lambda.Function(scope, 'MyFunction', {
      runtime: lambda.Runtime.NODEJS_14_X,
      handler: 'index.handler',
      code: lambda.Code.fromAsset('lambda')
    })
  );
  
  api.root.addMethod('GET', integration, {
    requestValidator: validator,
    requestParameters: {
      'method.request.querystring.id': true,
      'method.request.header.Authorization': true
    }
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_4(scope: Construct) {
  // API Gateway with validation and proxy resource
  const api = new apigateway.RestApi(scope, 'MyApi', {
    restApiName: 'Proxy Resource API'
  });
  
  // ok: typescript_cdk_apigateway_missingreq_validation_enabled
  const validator = new apigateway.RequestValidator(scope, 'ProxyValidator', {
    restApi: api,
    validateRequestBody: true,
    validateRequestParameters: true
  });
  
  const integration = new apigateway.LambdaIntegration(
    new lambda.Function(scope, 'MyFunction', {
      runtime: lambda.Runtime.NODEJS_14_X,
      handler: 'index.handler',
      code: lambda.Code.fromAsset('lambda')
    })
  );
  
  const proxy = api.root.addResource('{proxy+}');
  proxy.addMethod('ANY', integration, {
    requestValidator: validator
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_5(scope: Construct) {
  // API Gateway with validation and authorizer
  const api = new apigateway.RestApi(scope, 'MyApi', {
    restApiName: 'Authorized API'
  });
  
  const authorizer = new apigateway.RequestAuthorizer(scope, 'MyAuthorizer', {
    handler: new lambda.Function(scope, 'AuthorizerFunction', {
      runtime: lambda.Runtime.NODEJS_14_X,
      handler: 'index.handler',
      code: lambda.Code.fromAsset('lambda')
    }),
    identitySources: [apigateway.IdentitySource.header('Authorization')]
  });
  
  // ok: typescript_cdk_apigateway_missingreq_validation_enabled
  const validator = new apigateway.RequestValidator(scope, 'AuthValidator', {
    restApi: api,
    validateRequestBody: true,
    validateRequestParameters: true
  });
  
  const integration = new apigateway.LambdaIntegration(
    new lambda.Function(scope, 'MyFunction', {
      runtime: lambda.Runtime.NODEJS_14_X,
      handler: 'index.handler',
      code: lambda.Code.fromAsset('lambda')
    })
  );
  
  api.root.addMethod('GET', integration, {
    authorizer: authorizer,
    requestValidator: validator
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_6(scope: Construct) {
  // API Gateway with validation and CORS
  const api = new apigateway.RestApi(scope, 'MyApi', {
    restApiName: 'CORS API',
    defaultCorsPreflightOptions: {
      allowOrigins: apigateway.Cors.ALL_ORIGINS,
      allowMethods: apigateway.Cors.ALL_METHODS
    }
  });
  
  // ok: typescript_cdk_apigateway_missingreq_validation_enabled
  const validator = new apigateway.RequestValidator(scope, 'CorsValidator', {
    restApi: api,
    validateRequestBody: true,
    validateRequestParameters: true
  });
  
  const integration = new apigateway.LambdaIntegration(
    new lambda.Function(scope, 'MyFunction', {
      runtime: lambda.Runtime.NODEJS_14_X,
      handler: 'index.handler',
      code: lambda.Code.fromAsset('lambda')
    })
  );
  
  api.root.addMethod('POST', integration, {
    requestValidator: validator
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_7(scope: Construct) {
  // API Gateway with validation and AWS integration
  const api = new apigateway.RestApi(scope, 'MyApi', {
    restApiName: 'AWS Service Integration'
  });
  
  const role = new iam.Role(scope, 'ApiRole', {
    assumedBy: new iam.ServicePrincipal('apigateway.amazonaws.com')
  });
  
  // ok: typescript_cdk_apigateway_missingreq_validation_enabled
  const validator = new apigateway.RequestValidator(scope, 'AwsIntegrationValidator', {
    restApi: api,
    validateRequestBody: true,
    validateRequestParameters: true
  });
  
  const integration = new apigateway.AwsIntegration({
    service: 'dynamodb',
    action: 'GetItem',
    options: {
      credentialsRole: role
    }
  });
  
  api.root.addMethod('GET', integration, {
    requestValidator: validator,
    requestParameters: {
      'method.request.querystring.id': true
    }
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_8(scope: Construct) {
  // API Gateway with validation and HTTP integration
  const api = new apigateway.RestApi(scope, 'MyApi', {
    restApiName: 'External API Integration'
  });
  
  // ok: typescript_cdk_apigateway_missingreq_validation_enabled
  const validator = new apigateway.RequestValidator(scope, 'HttpIntegrationValidator', {
    restApi: api,
    validateRequestBody: true,
    validateRequestParameters: true
  });
  
  const integration = new apigateway.HttpIntegration('https://api.example.com', {
    httpMethod: 'GET',
    proxy: true
  });
  
  api.root.addMethod('GET', integration, {
    requestValidator: validator
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_9(scope: Construct) {
  // API Gateway with validation and mock integration
  const api = new apigateway.RestApi(scope, 'MyApi', {
    restApiName: 'Mock API'
  });
  
  // ok: typescript_cdk_apigateway_missingreq_validation_enabled
  const validator = new apigateway.RequestValidator(scope, 'MockValidator', {
    restApi: api,
    validateRequestBody: true,
    validateRequestParameters: true
  });
  
  const integration = new apigateway.MockIntegration({
    integrationResponses: [{
      statusCode: '200',
      responseTemplates: {
        'application/json': '{"statusCode": 200, "message": "OK"}'
      }
    }]
  });
  
  api.root.addMethod('GET', integration, {
    requestValidator: validator
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_10(scope: Construct) {
  // API Gateway with validation and API key
  const api = new apigateway.RestApi(scope, 'MyApi', {
    restApiName: 'API Key API'
  });
  
  const plan = api.addUsagePlan('UsagePlan', {
    name: 'Standard',
    throttle: {
      rateLimit: 10,
      burstLimit: 2
    }
  });
  
  const key = api.addApiKey('ApiKey');
  plan.addApiKey(key);
  
  // ok: typescript_cdk_apigateway_missingreq_validation_enabled
  const validator = new apigateway.RequestValidator(scope, 'ApiKeyValidator', {
    restApi: api,
    validateRequestBody: true,
    validateRequestParameters: true
  });
  
  const integration = new apigateway.LambdaIntegration(
    new lambda.Function(scope, 'MyFunction', {
      runtime: lambda.Runtime.NODEJS_14_X,
      handler: 'index.handler',
      code: lambda.Code.fromAsset('lambda')
    })
  );
  
  api.root.addMethod('GET', integration, {
    apiKeyRequired: true,
    requestValidator: validator
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_11(scope: Construct) {
  // API Gateway with validation and custom domain
  const api = new apigateway.RestApi(scope, 'MyApi', {
    restApiName: 'Custom Domain API'
  });
  
  new apigateway.DomainName(scope, 'ApiDomain', {
    domainName: 'api.example.com',
    certificate: apigateway.Certificate.fromCertificateArn(scope, 'Cert', 'arn:aws:acm:us-east-1:123456789012:certificate/abcdef')
  });
  
  // ok: typescript_cdk_apigateway_missingreq_validation_enabled
  const validator = new apigateway.RequestValidator(scope, 'DomainValidator', {
    restApi: api,
    validateRequestBody: true,
    validateRequestParameters: true
  });
  
  const integration = new apigateway.LambdaIntegration(
    new lambda.Function(scope, 'MyFunction', {
      runtime: lambda.Runtime.NODEJS_14_X,
      handler: 'index.handler',
      code: lambda.Code.fromAsset('lambda')
    })
  );
  
  api.root.addMethod('GET', integration, {
    requestValidator: validator
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_12(scope: Construct) {
  // API Gateway with validation and method options
  const api = new apigateway.RestApi(scope, 'MyApi', {
    restApiName: 'Method Options API'
  });
  
  // ok: typescript_cdk_apigateway_missingreq_validation_enabled
  const validator = new apigateway.RequestValidator(scope, 'MethodOptionsValidator', {
    restApi: api,
    validateRequestBody: true,
    validateRequestParameters: true
  });
  
  const integration = new apigateway.LambdaIntegration(
    new lambda.Function(scope, 'MyFunction', {
      runtime: lambda.Runtime.NODEJS_14_X,
      handler: 'index.handler',
      code: lambda.Code.fromAsset('lambda')
    })
  );
  
  api.root.addMethod('POST', integration, {
    requestValidator: validator,
    methodResponses: [
      {
        statusCode: '200',
        responseModels: {
          'application/json': apigateway.Model.EMPTY_MODEL
        }
      }
    ]
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_13(scope: Construct) {
  // API Gateway with default validator configured at the API level
  // ok: typescript_cdk_apigateway_missingreq_validation_enabled
  const api = new apigateway.RestApi(scope, 'MyApi', {
    restApiName: 'Default Validator API',
    defaultMethodOptions: {
      requestValidator: new apigateway.RequestValidator(scope, 'DefaultApiValidator', {
        restApi: api,
        validateRequestBody: true,
        validateRequestParameters: true
      })
    }
  });
  
  const integration = new apigateway.LambdaIntegration(
    new lambda.Function(scope, 'MyFunction', {
      runtime: lambda.Runtime.NODEJS_14_X,
      handler: 'index.handler',
      code: lambda.Code.fromAsset('lambda')
    })
  );
  
  api.root.addMethod('POST', integration);
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_14(scope: Construct) {
  // API Gateway with validation and resource-specific models
  const api = new apigateway.RestApi(scope, 'MyApi', {
    restApiName: 'Resource Models API'
  });
  
  const userModel = api.addModel('UserModel', {
    contentType: 'application/json',
    modelName: 'UserModel',
    schema: {
      type: apigateway.JsonSchemaType.OBJECT,
      properties: {
        name: { type: apigateway.JsonSchemaType.STRING },
        email: { type: apigateway.JsonSchemaType.STRING }
      },
      required: ['name', 'email']
    }
  });
  
  // ok: typescript_cdk_apigateway_missingreq_validation_enabled
  const validator = new apigateway.RequestValidator(scope, 'ResourceValidator', {
    restApi: api,
    validateRequestBody: true,
    validateRequestParameters: true
  });
  
  const integration = new apigateway.LambdaIntegration(
    new lambda.Function(scope, 'MyFunction', {
      runtime: lambda.Runtime.NODEJS_14_X,
      handler: 'index.handler',
      code: lambda.Code.fromAsset('lambda')
    })
  );
  
  const users = api.root.addResource('users');
  users.addMethod('POST', integration, {
    requestValidator: validator,
    requestModels: {
      'application/json': userModel
    }
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_15(scope: Construct) {
  // API Gateway with validation and multiple resources
  const api = new apigateway.RestApi(scope, 'MyApi', {
    restApiName: 'Multi-Resource API'
  });
  
  // ok: typescript_cdk_apigateway_missingreq_validation_enabled
  const validator = new apigateway.RequestValidator(scope, 'MultiResourceValidator', {
    restApi: api,
    validateRequestBody: true,
    validateRequestParameters: true
  });
  
  const integration = new apigateway.LambdaIntegration(
    new lambda.Function(scope, 'MyFunction', {
      runtime: lambda.Runtime.NODEJS_14_X,
      handler: 'index.handler',
      code: lambda.Code.fromAsset('lambda')
    })
  );
  
  const users = api.root.addResource('users');
  users.addMethod('GET', integration, {
    requestValidator: validator,
    requestParameters: {
      'method.request.querystring.page': true
    }
  });
  
  const user = users.addResource('{userId}');
  user.addMethod('GET', integration, {
    requestValidator: validator,
    requestParameters: {
      'method.request.path.userId': true
    }
  });
  
  const posts = user.addResource('posts');
  posts.addMethod('POST', integration, {
    requestValidator: validator
  });
}
// {/fact}