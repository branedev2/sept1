import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as apigateway from 'aws-cdk-lib/aws-apigateway';
import * as logs from 'aws-cdk-lib/aws-logs';

class ApiGatewayStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);
  }
}

// True Positives (Vulnerable Code)

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_1() {
  const stack = new cdk.Stack();
  const api = new apigateway.RestApi(stack, 'MyApi');
  
  // ruleid: typescript_cdk_apigw_execution_logging_enabled
  new apigateway.Stage(stack, 'prod', {
    deployment: new apigateway.Deployment(stack, 'Deployment', {
      api: api
    })
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_2() {
  const stack = new cdk.Stack();
  const api = new apigateway.RestApi(stack, 'MyApi');
  
  // ruleid: typescript_cdk_apigw_execution_logging_enabled
  api.deploymentStage = new apigateway.Stage(stack, 'dev', {
    deployment: new apigateway.Deployment(stack, 'Deployment', {
      api: api
    }),
    // No logging configuration
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_3() {
  const stack = new cdk.Stack();
  
  // ruleid: typescript_cdk_apigw_execution_logging_enabled
  const api = new apigateway.RestApi(stack, 'api', {
    deployOptions: {
      // Missing logging configuration
      stageName: 'prod',
      metricsEnabled: true,
    }
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_4() {
  const stack = new cdk.Stack();
  const api = new apigateway.RestApi(stack, 'MyApi');
  
  // ruleid: typescript_cdk_apigw_execution_logging_enabled
  new apigateway.Stage(stack, 'test', {
    deployment: new apigateway.Deployment(stack, 'Deployment', {
      api: api
    }),
    loggingLevel: apigateway.MethodLoggingLevel.OFF
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_5() {
  const stack = new cdk.Stack();
  
  // ruleid: typescript_cdk_apigw_execution_logging_enabled
  const api = new apigateway.RestApi(stack, 'api', {
    deployOptions: {
      stageName: 'prod',
      loggingLevel: apigateway.MethodLoggingLevel.OFF
    }
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_6() {
  const stack = new cdk.Stack();
  const api = new apigateway.RestApi(stack, 'MyApi');
  
  // ruleid: typescript_cdk_apigw_execution_logging_enabled
  api.addStage({
    stageName: 'v1',
    deployment: new apigateway.Deployment(stack, 'Deployment', {
      api: api
    })
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_7() {
  const stack = new cdk.Stack();
  
  // ruleid: typescript_cdk_apigw_execution_logging_enabled
  const api = new apigateway.RestApi(stack, 'api');
  const deployment = new apigateway.Deployment(stack, 'Deployment', {
    api: api
  });
  
  deployment.addStage({
    stageName: 'beta',
    // No logging configuration
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_8() {
  const stack = new cdk.Stack();
  
  // ruleid: typescript_cdk_apigw_execution_logging_enabled
  new apigateway.SpecRestApi(stack, 'SpecRestApi', {
    apiDefinition: apigateway.ApiDefinition.fromInline({
      // API definition content
    }),
    deployOptions: {
      stageName: 'v1',
      // Missing logging configuration
    }
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_9() {
  const stack = new cdk.Stack();
  
  // ruleid: typescript_cdk_apigw_execution_logging_enabled
  const api = new apigateway.RestApi(stack, 'api', {
    deployOptions: {
      stageName: 'prod',
      // Setting access logging but not execution logging
      accessLogDestination: new apigateway.LogGroupLogDestination(
        new logs.LogGroup(stack, 'ApiAccessLogs')
      ),
      accessLogFormat: apigateway.AccessLogFormat.clf()
    }
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_10() {
  const stack = new cdk.Stack();
  
  // ruleid: typescript_cdk_apigw_execution_logging_enabled
  const api = new apigateway.LambdaRestApi(stack, 'LambdaRestApi', {
    handler: {} as any, // Mock handler for example
    deployOptions: {
      stageName: 'prod',
      // No logging configuration
    }
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_11() {
  const stack = new cdk.Stack();
  
  // ruleid: typescript_cdk_apigw_execution_logging_enabled
  const api = new apigateway.RestApi(stack, 'api');
  const deployment = new apigateway.Deployment(stack, 'Deployment', {
    api: api
  });
  
  const stage = new apigateway.Stage(stack, 'prod', {
    deployment,
    // No logging configuration
  });
  
  api.deploymentStage = stage;
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_12() {
  const stack = new cdk.Stack();
  
  // ruleid: typescript_cdk_apigw_execution_logging_enabled
  const api = new apigateway.RestApi(stack, 'api');
  const deployment = new apigateway.Deployment(stack, 'Deployment', {
    api: api
  });
  
  const stage = new apigateway.Stage(stack, 'prod', {
    deployment,
    // Explicitly setting data trace but not method logging
    dataTraceEnabled: true
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_13() {
  const stack = new cdk.Stack();
  
  // ruleid: typescript_cdk_apigw_execution_logging_enabled
  const api = new apigateway.HttpApi(stack, 'HttpApi', {
    createDefaultStage: true,
    // No logging configuration for default stage
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_14() {
  const stack = new cdk.Stack();
  const api = new apigateway.RestApi(stack, 'api');
  
  // ruleid: typescript_cdk_apigw_execution_logging_enabled
  const deployment = new apigateway.Deployment(stack, 'Deployment', {
    api: api
  });
  
  const stageOptions = {
    stageName: 'prod',
    // Missing logging configuration
  };
  
  new apigateway.Stage(stack, 'Stage', {
    deployment,
    ...stageOptions
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_15() {
  const stack = new cdk.Stack();
  
  // ruleid: typescript_cdk_apigw_execution_logging_enabled
  const api = new apigateway.RestApi(stack, 'api');
  
  const deploymentConfig = {
    api,
    retainDeployments: true,
  };
  
  const deployment = new apigateway.Deployment(stack, 'Deployment', deploymentConfig);
  
  const stage = new apigateway.Stage(stack, 'stage', {
    deployment,
    // No logging configuration
  });
}
// {/fact}

// True Negatives (Secure Code)

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_1() {
  const stack = new cdk.Stack();
  const api = new apigateway.RestApi(stack, 'MyApi');
  
  // ok: typescript_cdk_apigw_execution_logging_enabled
  new apigateway.Stage(stack, 'prod', {
    deployment: new apigateway.Deployment(stack, 'Deployment', {
      api: api
    }),
    loggingLevel: apigateway.MethodLoggingLevel.INFO
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_2() {
  const stack = new cdk.Stack();
  const api = new apigateway.RestApi(stack, 'MyApi');
  
  // ok: typescript_cdk_apigw_execution_logging_enabled
  api.deploymentStage = new apigateway.Stage(stack, 'dev', {
    deployment: new apigateway.Deployment(stack, 'Deployment', {
      api: api
    }),
    loggingLevel: apigateway.MethodLoggingLevel.ERROR
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_3() {
  const stack = new cdk.Stack();
  
  // ok: typescript_cdk_apigw_execution_logging_enabled
  const api = new apigateway.RestApi(stack, 'api', {
    deployOptions: {
      stageName: 'prod',
      loggingLevel: apigateway.MethodLoggingLevel.INFO
    }
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_4() {
  const stack = new cdk.Stack();
  const api = new apigateway.RestApi(stack, 'MyApi');
  
  // ok: typescript_cdk_apigw_execution_logging_enabled
  new apigateway.Stage(stack, 'test', {
    deployment: new apigateway.Deployment(stack, 'Deployment', {
      api: api
    }),
    loggingLevel: apigateway.MethodLoggingLevel.INFO,
    accessLogDestination: new apigateway.LogGroupLogDestination(
      new logs.LogGroup(stack, 'ApiAccessLogs')
    ),
    accessLogFormat: apigateway.AccessLogFormat.clf()
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_5() {
  const stack = new cdk.Stack();
  
  // ok: typescript_cdk_apigw_execution_logging_enabled
  const api = new apigateway.RestApi(stack, 'api', {
    deployOptions: {
      stageName: 'prod',
      loggingLevel: apigateway.MethodLoggingLevel.ERROR,
      dataTraceEnabled: true
    }
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_6() {
  const stack = new cdk.Stack();
  const api = new apigateway.RestApi(stack, 'MyApi');
  
  // ok: typescript_cdk_apigw_execution_logging_enabled
  api.addStage({
    stageName: 'v1',
    deployment: new apigateway.Deployment(stack, 'Deployment', {
      api: api
    }),
    loggingLevel: apigateway.MethodLoggingLevel.INFO
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_7() {
  const stack = new cdk.Stack();
  
  // ok: typescript_cdk_apigw_execution_logging_enabled
  const api = new apigateway.RestApi(stack, 'api');
  const deployment = new apigateway.Deployment(stack, 'Deployment', {
    api: api
  });
  
  deployment.addStage({
    stageName: 'beta',
    loggingLevel: apigateway.MethodLoggingLevel.INFO
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_8() {
  const stack = new cdk.Stack();
  
  // ok: typescript_cdk_apigw_execution_logging_enabled
  new apigateway.SpecRestApi(stack, 'SpecRestApi', {
    apiDefinition: apigateway.ApiDefinition.fromInline({
      // API definition content
    }),
    deployOptions: {
      stageName: 'v1',
      loggingLevel: apigateway.MethodLoggingLevel.INFO
    }
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_9() {
  const stack = new cdk.Stack();
  
  // ok: typescript_cdk_apigw_execution_logging_enabled
  const api = new apigateway.RestApi(stack, 'api', {
    deployOptions: {
      stageName: 'prod',
      loggingLevel: apigateway.MethodLoggingLevel.INFO,
      accessLogDestination: new apigateway.LogGroupLogDestination(
        new logs.LogGroup(stack, 'ApiAccessLogs')
      ),
      accessLogFormat: apigateway.AccessLogFormat.clf()
    }
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_10() {
  const stack = new cdk.Stack();
  
  // ok: typescript_cdk_apigw_execution_logging_enabled
  const api = new apigateway.LambdaRestApi(stack, 'LambdaRestApi', {
    handler: {} as any, // Mock handler for example
    deployOptions: {
      stageName: 'prod',
      loggingLevel: apigateway.MethodLoggingLevel.ERROR
    }
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_11() {
  const stack = new cdk.Stack();
  
  // ok: typescript_cdk_apigw_execution_logging_enabled
  const api = new apigateway.RestApi(stack, 'api');
  const deployment = new apigateway.Deployment(stack, 'Deployment', {
    api: api
  });
  
  const stage = new apigateway.Stage(stack, 'prod', {
    deployment,
    loggingLevel: apigateway.MethodLoggingLevel.INFO
  });
  
  api.deploymentStage = stage;
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_12() {
  const stack = new cdk.Stack();
  
  // ok: typescript_cdk_apigw_execution_logging_enabled
  const api = new apigateway.RestApi(stack, 'api');
  const deployment = new apigateway.Deployment(stack, 'Deployment', {
    api: api
  });
  
  const stage = new apigateway.Stage(stack, 'prod', {
    deployment,
    dataTraceEnabled: true,
    loggingLevel: apigateway.MethodLoggingLevel.INFO
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_13() {
  const stack = new cdk.Stack();
  
  // ok: typescript_cdk_apigw_execution_logging_enabled
  const api = new apigateway.RestApi(stack, 'api');
  
  const logGroup = new logs.LogGroup(stack, 'ApiLogs');
  
  const stage = new apigateway.Stage(stack, 'prod', {
    deployment: new apigateway.Deployment(stack, 'Deployment', {
      api: api
    }),
    loggingLevel: apigateway.MethodLoggingLevel.INFO,
    accessLogDestination: new apigateway.LogGroupLogDestination(logGroup),
    accessLogFormat: apigateway.AccessLogFormat.jsonWithStandardFields()
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_14() {
  const stack = new cdk.Stack();
  const api = new apigateway.RestApi(stack, 'api');
  
  // ok: typescript_cdk_apigw_execution_logging_enabled
  const deployment = new apigateway.Deployment(stack, 'Deployment', {
    api: api
  });
  
  const stageOptions = {
    stageName: 'prod',
    loggingLevel: apigateway.MethodLoggingLevel.INFO
  };
  
  new apigateway.Stage(stack, 'Stage', {
    deployment,
    ...stageOptions
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_15() {
  const stack = new cdk.Stack();
  
  // ok: typescript_cdk_apigw_execution_logging_enabled
  const api = new apigateway.RestApi(stack, 'api', {
    cloudWatchRole: true,
    deployOptions: {
      loggingLevel: apigateway.MethodLoggingLevel.INFO,
      metricsEnabled: true,
      tracingEnabled: true,
      dataTraceEnabled: true
    }
  });
}
// {/fact}