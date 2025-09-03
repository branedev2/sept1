import { 
  aws_apigateway as apigateway,
  aws_cognito as cognito,
  Stack, 
  App 
} from 'aws-cdk-lib';
import { Construct } from 'constructs';

// True Positive Examples (Vulnerable Code)

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_1() {
  const stack = new Stack();
  const api = new apigateway.RestApi(stack, 'MyApi');
  const resource = api.root.addResource('items');
  
  // ruleid: typescript_cdk_apigateway_missing_cognito_auth
  resource.addMethod('GET', new apigateway.HttpIntegration('http://example.com'), {
    authorizationType: apigateway.AuthorizationType.NONE
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_2() {
  const stack = new Stack();
  const api = new apigateway.RestApi(stack, 'MyApi');
  const resource = api.root.addResource('users');
  
  // ruleid: typescript_cdk_apigateway_missing_cognito_auth
  resource.addMethod('POST', new apigateway.LambdaIntegration(myFunction), {
    // No authorizationType specified, defaults to NONE
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_3() {
  const stack = new Stack();
  const api = new apigateway.RestApi(stack, 'MyApi');
  const resource = api.root.addResource('data');
  
  // ruleid: typescript_cdk_apigateway_missing_cognito_auth
  resource.addMethod('PUT', new apigateway.MockIntegration({
    integrationResponses: [{
      statusCode: '200',
    }],
    passthroughBehavior: apigateway.PassthroughBehavior.NEVER,
    requestTemplates: {
      'application/json': '{ "statusCode": 200 }'
    },
  }));
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_4() {
  class ApiStack extends Stack {
    constructor(scope: Construct, id: string) {
      super(scope, id);
      
      const api = new apigateway.RestApi(this, 'MyApi');
      const resource = api.root.addResource('payments');
      
      // ruleid: typescript_cdk_apigateway_missing_cognito_auth
      resource.addMethod('DELETE', new apigateway.HttpIntegration('http://payment-service.example.com'), {
        authorizationType: apigateway.AuthorizationType.IAM
      });
    }
  }
  
  const app = new App();
  new ApiStack(app, 'ApiStack');
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_5() {
  const stack = new Stack();
  const api = new apigateway.RestApi(stack, 'MyApi');
  const resource = api.root.addResource('orders');
  
  // ruleid: typescript_cdk_apigateway_missing_cognito_auth
  resource.addMethod('GET', new apigateway.HttpIntegration('http://orders-api.example.com'), {
    authorizationType: apigateway.AuthorizationType.CUSTOM,
    authorizer: new apigateway.TokenAuthorizer(stack, 'CustomAuthorizer', {
      handler: myFunction
    })
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_6() {
  const stack = new Stack();
  const api = new apigateway.RestApi(stack, 'MyApi', {
    deployOptions: {
      stageName: 'prod',
    }
  });
  
  const resource = api.root.addResource('products');
  const subResource = resource.addResource('{id}');
  
  // ruleid: typescript_cdk_apigateway_missing_cognito_auth
  subResource.addMethod('PATCH', new apigateway.LambdaIntegration(updateProductFunction));
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_7() {
  const stack = new Stack();
  const api = new apigateway.RestApi(stack, 'MyApi');
  
  // Create multiple resources
  const users = api.root.addResource('users');
  const orders = api.root.addResource('orders');
  const products = api.root.addResource('products');
  
  // ruleid: typescript_cdk_apigateway_missing_cognito_auth
  users.addMethod('GET', new apigateway.LambdaIntegration(getUsersFunction), {
    authorizationType: apigateway.AuthorizationType.NONE
  });
  
  // ruleid: typescript_cdk_apigateway_missing_cognito_auth
  orders.addMethod('POST', new apigateway.LambdaIntegration(createOrderFunction), {
    authorizationType: apigateway.AuthorizationType.NONE
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_8() {
  const stack = new Stack();
  const api = new apigateway.RestApi(stack, 'MyApi');
  const resource = api.root.addResource('files');
  
  // Define method options without Cognito
  const methodOptions = {
    methodResponses: [{ statusCode: '200' }],
    authorizationType: apigateway.AuthorizationType.NONE
  };
  
  // ruleid: typescript_cdk_apigateway_missing_cognito_auth
  resource.addMethod('GET', new apigateway.LambdaIntegration(getFilesFunction), methodOptions);
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_9() {
  const stack = new Stack();
  const api = new apigateway.RestApi(stack, 'MyApi');
  const resource = api.root.addResource('analytics');
  
  // Create a Lambda authorizer instead of Cognito
  const lambdaAuthorizer = new apigateway.TokenAuthorizer(stack, 'LambdaAuthorizer', {
    handler: authorizerFunction
  });
  
  // ruleid: typescript_cdk_apigateway_missing_cognito_auth
  resource.addMethod('GET', new apigateway.LambdaIntegration(analyticsFunction), {
    authorizationType: apigateway.AuthorizationType.CUSTOM,
    authorizer: lambdaAuthorizer
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_10() {
  const stack = new Stack();
  const api = new apigateway.RestApi(stack, 'PublicApi', {
    description: 'Public API with no authentication required'
  });
  
  // ruleid: typescript_cdk_apigateway_missing_cognito_auth
  api.root.addMethod('GET', new apigateway.LambdaIntegration(rootHandler), {
    authorizationType: apigateway.AuthorizationType.NONE
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_11() {
  const stack = new Stack();
  const api = new apigateway.RestApi(stack, 'MyApi');
  const v1 = api.root.addResource('v1');
  const users = v1.addResource('users');
  const userId = users.addResource('{userId}');
  
  // ruleid: typescript_cdk_apigateway_missing_cognito_auth
  userId.addMethod('GET', new apigateway.LambdaIntegration(getUserFunction));
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_12() {
  class ApiGatewayStack extends Stack {
    constructor(scope: Construct, id: string) {
      super(scope, id);
      
      const api = new apigateway.RestApi(this, 'api');
      
      // Create a resource for health checks
      const health = api.root.addResource('health');
      
      // ruleid: typescript_cdk_apigateway_missing_cognito_auth
      health.addMethod('GET', new apigateway.LambdaIntegration(healthCheckFunction), {
        authorizationType: apigateway.AuthorizationType.NONE
      });
    }
  }
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_13() {
  const stack = new Stack();
  const api = new apigateway.RestApi(stack, 'MyApi');
  
  // Create a proxy resource that forwards all requests
  const proxyResource = api.root.addResource('{proxy+}');
  
  // ruleid: typescript_cdk_apigateway_missing_cognito_auth
  proxyResource.addMethod('ANY', new apigateway.LambdaIntegration(proxyHandler));
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_14() {
  const stack = new Stack();
  const api = new apigateway.RestApi(stack, 'MyApi');
  
  // Define multiple HTTP methods for the same resource
  const resource = api.root.addResource('items');
  
  // ruleid: typescript_cdk_apigateway_missing_cognito_auth
  resource.addMethod('GET', new apigateway.LambdaIntegration(getItemsFunction), {
    authorizationType: apigateway.AuthorizationType.NONE
  });
  
  // ruleid: typescript_cdk_apigateway_missing_cognito_auth
  resource.addMethod('POST', new apigateway.LambdaIntegration(createItemFunction), {
    authorizationType: apigateway.AuthorizationType.NONE
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_15() {
  const stack = new Stack();
  const api = new apigateway.RestApi(stack, 'MyApi');
  
  // Create a resource with a request validator
  const resource = api.root.addResource('validated');
  
  const validator = new apigateway.RequestValidator(stack, 'DefaultValidator', {
    restApi: api,
    validateRequestBody: true,
    validateRequestParameters: true
  });
  
  // ruleid: typescript_cdk_apigateway_missing_cognito_auth
  resource.addMethod('POST', new apigateway.LambdaIntegration(validatedFunction), {
    requestValidator: validator,
    authorizationType: apigateway.AuthorizationType.NONE
  });
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_1() {
  const stack = new Stack();
  const api = new apigateway.RestApi(stack, 'MyApi');
  const resource = api.root.addResource('items');
  
  // Create a Cognito User Pool
  const userPool = new cognito.UserPool(stack, 'UserPool');
  
  // Create a Cognito Authorizer
  const authorizer = new apigateway.CognitoUserPoolsAuthorizer(stack, 'CognitoAuthorizer', {
    cognitoUserPools: [userPool]
  });
  
  // ok: typescript_cdk_apigateway_missing_cognito_auth
  resource.addMethod('GET', new apigateway.HttpIntegration('http://example.com'), {
    authorizationType: apigateway.AuthorizationType.COGNITO,
    authorizer: authorizer
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_2() {
  const stack = new Stack();
  const api = new apigateway.RestApi(stack, 'MyApi');
  const resource = api.root.addResource('users');
  
  // Create a Cognito User Pool
  const userPool = new cognito.UserPool(stack, 'UserPool');
  
  // Create a Cognito Authorizer
  const authorizer = new apigateway.CognitoUserPoolsAuthorizer(stack, 'CognitoAuthorizer', {
    cognitoUserPools: [userPool]
  });
  
  // ok: typescript_cdk_apigateway_missing_cognito_auth
  resource.addMethod('POST', new apigateway.LambdaIntegration(myFunction), {
    authorizationType: apigateway.AuthorizationType.COGNITO,
    authorizer: authorizer
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_3() {
  class ApiStack extends Stack {
    constructor(scope: Construct, id: string) {
      super(scope, id);
      
      const api = new apigateway.RestApi(this, 'MyApi');
      const resource = api.root.addResource('data');
      
      // Create a Cognito User Pool
      const userPool = new cognito.UserPool(this, 'UserPool');
      
      // Create a Cognito Authorizer
      const authorizer = new apigateway.CognitoUserPoolsAuthorizer(this, 'CognitoAuthorizer', {
        cognitoUserPools: [userPool]
      });
      
      // ok: typescript_cdk_apigateway_missing_cognito_auth
      resource.addMethod('PUT', new apigateway.MockIntegration({
        integrationResponses: [{
          statusCode: '200',
        }],
        passthroughBehavior: apigateway.PassthroughBehavior.NEVER,
        requestTemplates: {
          'application/json': '{ "statusCode": 200 }'
        },
      }), {
        authorizationType: apigateway.AuthorizationType.COGNITO,
        authorizer: authorizer
      });
    }
  }
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_4() {
  const stack = new Stack();
  const api = new apigateway.RestApi(stack, 'MyApi');
  const resource = api.root.addResource('payments');
  
  // Create a Cognito User Pool
  const userPool = new cognito.UserPool(stack, 'UserPool', {
    selfSignUpEnabled: true,
    userVerification: {
      emailSubject: 'Verify your email for our app!',
      emailBody: 'Hello {username}, Thanks for signing up! Your verification code is {####}',
      emailStyle: cognito.VerificationEmailStyle.CODE
    }
  });
  
  // Create a Cognito Authorizer
  const authorizer = new apigateway.CognitoUserPoolsAuthorizer(stack, 'CognitoAuthorizer', {
    cognitoUserPools: [userPool]
  });
  
  // ok: typescript_cdk_apigateway_missing_cognito_auth
  resource.addMethod('DELETE', new apigateway.HttpIntegration('http://payment-service.example.com'), {
    authorizationType: apigateway.AuthorizationType.COGNITO,
    authorizer: authorizer
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_5() {
  const stack = new Stack();
  const api = new apigateway.RestApi(stack, 'MyApi');
  const resource = api.root.addResource('orders');
  
  // Create a Cognito User Pool with advanced settings
  const userPool = new cognito.UserPool(stack, 'UserPool', {
    passwordPolicy: {
      minLength: 12,
      requireLowercase: true,
      requireUppercase: true,
      requireDigits: true,
      requireSymbols: true
    },
    advancedSecurityMode: cognito.AdvancedSecurityMode.ENFORCED
  });
  
  // Create a Cognito Authorizer
  const authorizer = new apigateway.CognitoUserPoolsAuthorizer(stack, 'CognitoAuthorizer', {
    cognitoUserPools: [userPool]
  });
  
  // ok: typescript_cdk_apigateway_missing_cognito_auth
  resource.addMethod('GET', new apigateway.HttpIntegration('http://orders-api.example.com'), {
    authorizationType: apigateway.AuthorizationType.COGNITO,
    authorizer: authorizer
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_6() {
  const stack = new Stack();
  const api = new apigateway.RestApi(stack, 'MyApi', {
    deployOptions: {
      stageName: 'prod',
    }
  });
  
  // Create a Cognito User Pool
  const userPool = new cognito.UserPool(stack, 'UserPool');
  
  // Create a Cognito Authorizer
  const authorizer = new apigateway.CognitoUserPoolsAuthorizer(stack, 'CognitoAuthorizer', {
    cognitoUserPools: [userPool]
  });
  
  const resource = api.root.addResource('products');
  const subResource = resource.addResource('{id}');
  
  // ok: typescript_cdk_apigateway_missing_cognito_auth
  subResource.addMethod('PATCH', new apigateway.LambdaIntegration(updateProductFunction), {
    authorizationType: apigateway.AuthorizationType.COGNITO,
    authorizer: authorizer
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_7() {
  const stack = new Stack();
  const api = new apigateway.RestApi(stack, 'MyApi');
  
  // Create a Cognito User Pool
  const userPool = new cognito.UserPool(stack, 'UserPool');
  
  // Create a Cognito Authorizer
  const authorizer = new apigateway.CognitoUserPoolsAuthorizer(stack, 'CognitoAuthorizer', {
    cognitoUserPools: [userPool]
  });
  
  // Create multiple resources
  const users = api.root.addResource('users');
  const orders = api.root.addResource('orders');
  
  // ok: typescript_cdk_apigateway_missing_cognito_auth
  users.addMethod('GET', new apigateway.LambdaIntegration(getUsersFunction), {
    authorizationType: apigateway.AuthorizationType.COGNITO,
    authorizer: authorizer
  });
  
  // ok: typescript_cdk_apigateway_missing_cognito_auth
  orders.addMethod('POST', new apigateway.LambdaIntegration(createOrderFunction), {
    authorizationType: apigateway.AuthorizationType.COGNITO,
    authorizer: authorizer
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_8() {
  const stack = new Stack();
  const api = new apigateway.RestApi(stack, 'MyApi');
  const resource = api.root.addResource('files');
  
  // Create a Cognito User Pool
  const userPool = new cognito.UserPool(stack, 'UserPool');
  
  // Create a Cognito Authorizer
  const authorizer = new apigateway.CognitoUserPoolsAuthorizer(stack, 'CognitoAuthorizer', {
    cognitoUserPools: [userPool]
  });
  
  // Define method options with Cognito
  const methodOptions = {
    methodResponses: [{ statusCode: '200' }],
    authorizationType: apigateway.AuthorizationType.COGNITO,
    authorizer: authorizer
  };
  
  // ok: typescript_cdk_apigateway_missing_cognito_auth
  resource.addMethod('GET', new apigateway.LambdaIntegration(getFilesFunction), methodOptions);
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_9() {
  const stack = new Stack();
  const api = new apigateway.RestApi(stack, 'MyApi');
  const resource = api.root.addResource('analytics');
  
  // Create a Cognito User Pool with MFA
  const userPool = new cognito.UserPool(stack, 'UserPool', {
    mfa: cognito.Mfa.REQUIRED,
    mfaSecondFactor: {
      sms: true,
      otp: true
    }
  });
  
  // Create a Cognito Authorizer
  const authorizer = new apigateway.CognitoUserPoolsAuthorizer(stack, 'CognitoAuthorizer', {
    cognitoUserPools: [userPool]
  });
  
  // ok: typescript_cdk_apigateway_missing_cognito_auth
  resource.addMethod('GET', new apigateway.LambdaIntegration(analyticsFunction), {
    authorizationType: apigateway.AuthorizationType.COGNITO,
    authorizer: authorizer
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_10() {
  const stack = new Stack();
  const api = new apigateway.RestApi(stack, 'SecureApi');
  
  // Create a Cognito User Pool
  const userPool = new cognito.UserPool(stack, 'UserPool');
  
  // Create a User Pool Client
  const userPoolClient = new cognito.UserPoolClient(stack, 'UserPoolClient', {
    userPool,
    generateSecret: true
  });
  
  // Create a Cognito Authorizer
  const authorizer = new apigateway.CognitoUserPoolsAuthorizer(stack, 'CognitoAuthorizer', {
    cognitoUserPools: [userPool]
  });
  
  // ok: typescript_cdk_apigateway_missing_cognito_auth
  api.root.addMethod('GET', new apigateway.LambdaIntegration(rootHandler), {
    authorizationType: apigateway.AuthorizationType.COGNITO,
    authorizer: authorizer
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_11() {
  const stack = new Stack();
  const api = new apigateway.RestApi(stack, 'MyApi');
  const v1 = api.root.addResource('v1');
  const users = v1.addResource('users');
  const userId = users.addResource('{userId}');
  
  // Create a Cognito User Pool
  const userPool = new cognito.UserPool(stack, 'UserPool');
  
  // Create a Cognito Authorizer
  const authorizer = new apigateway.CognitoUserPoolsAuthorizer(stack, 'CognitoAuthorizer', {
    cognitoUserPools: [userPool]
  });
  
  // ok: typescript_cdk_apigateway_missing_cognito_auth
  userId.addMethod('GET', new apigateway.LambdaIntegration(getUserFunction), {
    authorizationType: apigateway.AuthorizationType.COGNITO,
    authorizer: authorizer
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_12() {
  class ApiGatewayStack extends Stack {
    constructor(scope: Construct, id: string) {
      super(scope, id);
      
      const api = new apigateway.RestApi(this, 'api');
      
      // Create a Cognito User Pool
      const userPool = new cognito.UserPool(this, 'UserPool');
      
      // Create a Cognito Authorizer
      const authorizer = new apigateway.CognitoUserPoolsAuthorizer(this, 'CognitoAuthorizer', {
        cognitoUserPools: [userPool]
      });
      
      // Create a resource for health checks
      const health = api.root.addResource('health');
      
      // ok: typescript_cdk_apigateway_missing_cognito_auth
      health.addMethod('GET', new apigateway.LambdaIntegration(healthCheckFunction), {
        authorizationType: apigateway.AuthorizationType.COGNITO,
        authorizer: authorizer
      });
    }
  }
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_13() {
  const stack = new Stack();
  const api = new apigateway.RestApi(stack, 'MyApi');
  
  // Create a Cognito User Pool
  const userPool = new cognito.UserPool(stack, 'UserPool');
  
  // Create a Cognito Authorizer
  const authorizer = new apigateway.CognitoUserPoolsAuthorizer(stack, 'CognitoAuthorizer', {
    cognitoUserPools: [userPool]
  });
  
  // Create a proxy resource that forwards all requests
  const proxyResource = api.root.addResource('{proxy+}');
  
  // ok: typescript_cdk_apigateway_missing_cognito_auth
  proxyResource.addMethod('ANY', new apigateway.LambdaIntegration(proxyHandler), {
    authorizationType: apigateway.AuthorizationType.COGNITO,
    authorizer: authorizer
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_14() {
  const stack = new Stack();
  const api = new apigateway.RestApi(stack, 'MyApi');
  
  // Create a Cognito User Pool
  const userPool = new cognito.UserPool(stack, 'UserPool');
  
  // Create a Cognito Authorizer
  const authorizer = new apigateway.CognitoUserPoolsAuthorizer(stack, 'CognitoAuthorizer', {
    cognitoUserPools: [userPool]
  });
  
  // Define multiple HTTP methods for the same resource
  const resource = api.root.addResource('items');
  
  // ok: typescript_cdk_apigateway_missing_cognito_auth
  resource.addMethod('GET', new apigateway.LambdaIntegration(getItemsFunction), {
    authorizationType: apigateway.AuthorizationType.COGNITO,
    authorizer: authorizer
  });
  
  // ok: typescript_cdk_apigateway_missing_cognito_auth
  resource.addMethod('POST', new apigateway.LambdaIntegration(createItemFunction), {
    authorizationType: apigateway.AuthorizationType.COGNITO,
    authorizer: authorizer
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_15() {
  const stack = new Stack();
  const api = new apigateway.RestApi(stack, 'MyApi');
  
  // Create a Cognito User Pool with custom attributes
  const userPool = new cognito.UserPool(stack, 'UserPool', {
    standardAttributes: {
      email: {
        required: true,
        mutable: false
      },
      phoneNumber: {
        required: true
      }
    },
    customAttributes: {
      'tenantId': new cognito.StringAttribute({ mutable: false }),
      'role': new cognito.StringAttribute({ mutable: true })
    }
  });
  
  // Create a Cognito Authorizer
  const authorizer = new apigateway.CognitoUserPoolsAuthorizer(stack, 'CognitoAuthorizer', {
    cognitoUserPools: [userPool]
  });
  
  // Create a resource with a request validator
  const resource = api.root.addResource('validated');
  
  const validator = new apigateway.RequestValidator(stack, 'DefaultValidator', {
    restApi: api,
    validateRequestBody: true,
    validateRequestParameters: true
  });
  
  // ok: typescript_cdk_apigateway_missing_cognito_auth
  resource.addMethod('POST', new apigateway.LambdaIntegration(validatedFunction), {
    requestValidator: validator,
    authorizationType: apigateway.AuthorizationType.COGNITO,
    authorizer: authorizer
  });
}
// {/fact}