import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as path from 'path';

// True Positive Examples (Vulnerable Code)

// {fact rule=unmaintained-third-party-components@v1.0 defects=1}
function bad_case_1(scope: Construct) {
  // ruleid: typescript-cdk-lambda-latest-version
  new lambda.Function(scope, 'NodeJsLambdaOutdated', {
    runtime: lambda.Runtime.NODEJS_14_X,
    handler: 'index.handler',
    code: lambda.Code.fromAsset(path.join(__dirname, 'lambda-handler')),
  });
}
// {/fact}

// {fact rule=unmaintained-third-party-components@v1.0 defects=1}
function bad_case_2(scope: Construct) {
  // ruleid: typescript-cdk-lambda-latest-version
  new lambda.Function(scope, 'PythonLambdaOutdated', {
    runtime: lambda.Runtime.PYTHON_3_8,
    handler: 'index.handler',
    code: lambda.Code.fromAsset(path.join(__dirname, 'lambda-handler')),
  });
}
// {/fact}

// {fact rule=unmaintained-third-party-components@v1.0 defects=1}
function bad_case_3(scope: Construct) {
  const outdatedRuntime = lambda.Runtime.JAVA_8;
  
  // ruleid: typescript-cdk-lambda-latest-version
  new lambda.Function(scope, 'JavaLambdaOutdated', {
    runtime: outdatedRuntime,
    handler: 'com.example.Handler',
    code: lambda.Code.fromAsset(path.join(__dirname, 'lambda-handler')),
  });
}
// {/fact}

// {fact rule=unmaintained-third-party-components@v1.0 defects=1}
function bad_case_4(scope: Construct) {
  // ruleid: typescript-cdk-lambda-latest-version
  const fn = new lambda.Function(scope, 'RubyLambdaOutdated', {
    runtime: lambda.Runtime.RUBY_2_7,
    handler: 'index.handler',
    code: lambda.Code.fromAsset(path.join(__dirname, 'lambda-handler')),
  });
}
// {/fact}

// {fact rule=unmaintained-third-party-components@v1.0 defects=1}
function bad_case_5(scope: Construct) {
  const props = {
    runtime: lambda.Runtime.DOTNET_CORE_3_1,
    handler: 'MyFunction::Function.Handler',
    code: lambda.Code.fromAsset(path.join(__dirname, 'lambda-handler')),
  };
  
  // ruleid: typescript-cdk-lambda-latest-version
  new lambda.Function(scope, 'DotNetLambdaOutdated', props);
}
// {/fact}

// {fact rule=unmaintained-third-party-components@v1.0 defects=1}
function bad_case_6(scope: Construct, stack: cdk.Stack) {
  // ruleid: typescript-cdk-lambda-latest-version
  const lambdaFn = new lambda.Function(stack, 'GoLambdaOutdated', {
    runtime: lambda.Runtime.GO_1_X,
    handler: 'main',
    code: lambda.Code.fromAsset(path.join(__dirname, 'lambda-handler')),
    environment: {
      REGION: stack.region,
    },
  });
}
// {/fact}

// {fact rule=unmaintained-third-party-components@v1.0 defects=1}
function bad_case_7(scope: Construct) {
  // ruleid: typescript-cdk-lambda-latest-version
  const lambdaFunction = new lambda.Function(scope, 'NodeJsOldLambda', {
    runtime: lambda.Runtime.NODEJS_12_X,
    handler: 'index.handler',
    code: lambda.Code.fromAsset(path.join(__dirname, 'lambda-handler')),
    memorySize: 512,
    timeout: cdk.Duration.seconds(30),
  });
}
// {/fact}

// {fact rule=unmaintained-third-party-components@v1.0 defects=1}
function bad_case_8(scope: Construct) {
  if (process.env.ENVIRONMENT === 'dev') {
    // ruleid: typescript-cdk-lambda-latest-version
    new lambda.Function(scope, 'DevPythonLambda', {
      runtime: lambda.Runtime.PYTHON_3_7,
      handler: 'index.handler',
      code: lambda.Code.fromAsset(path.join(__dirname, 'lambda-handler')),
    });
  }
}
// {/fact}

// {fact rule=unmaintained-third-party-components@v1.0 defects=1}
function bad_case_9(scope: Construct) {
  const runtimes = [
    lambda.Runtime.NODEJS_14_X,
    lambda.Runtime.PYTHON_3_8,
    lambda.Runtime.JAVA_8
  ];
  
  for (let i = 0; i < runtimes.length; i++) {
    // ruleid: typescript-cdk-lambda-latest-version
    new lambda.Function(scope, `OutdatedLambda${i}`, {
      runtime: runtimes[i],
      handler: 'index.handler',
      code: lambda.Code.fromAsset(path.join(__dirname, 'lambda-handler')),
    });
  }
}
// {/fact}

// {fact rule=unmaintained-third-party-components@v1.0 defects=1}
function bad_case_10(scope: Construct) {
  const createLambda = (id: string, runtime: lambda.Runtime) => {
    // ruleid: typescript-cdk-lambda-latest-version
    return new lambda.Function(scope, id, {
      runtime: runtime,
      handler: 'index.handler',
      code: lambda.Code.fromAsset(path.join(__dirname, 'lambda-handler')),
    });
  };
  
  createLambda('OutdatedNodeLambda', lambda.Runtime.NODEJS_10_X);
}
// {/fact}

// {fact rule=unmaintained-third-party-components@v1.0 defects=1}
function bad_case_11(scope: Construct) {
  const config = {
    runtime: lambda.Runtime.DOTNET_CORE_2_1,
    handler: 'MyFunction::Function.Handler',
  };
  
  // ruleid: typescript-cdk-lambda-latest-version
  new lambda.Function(scope, 'VeryOutdatedDotNetLambda', {
    ...config,
    code: lambda.Code.fromAsset(path.join(__dirname, 'lambda-handler')),
  });
}
// {/fact}

// {fact rule=unmaintained-third-party-components@v1.0 defects=1}
function bad_case_12(scope: Construct) {
  class LambdaConstruct extends Construct {
    constructor(scope: Construct, id: string) {
      super(scope, id);
      
      // ruleid: typescript-cdk-lambda-latest-version
      new lambda.Function(this, 'OutdatedLambdaInConstruct', {
        runtime: lambda.Runtime.PYTHON_2_7,
        handler: 'index.handler',
        code: lambda.Code.fromAsset(path.join(__dirname, 'lambda-handler')),
      });
    }
  }
  
  new LambdaConstruct(scope, 'CustomLambdaConstruct');
}
// {/fact}

// {fact rule=unmaintained-third-party-components@v1.0 defects=1}
function bad_case_13(scope: Construct) {
  const getRuntimeForEnvironment = (env: string): lambda.Runtime => {
    if (env === 'production') {
      return lambda.Runtime.NODEJS_14_X;
    }
    return lambda.Runtime.NODEJS_12_X;
  };
  
  // ruleid: typescript-cdk-lambda-latest-version
  new lambda.Function(scope, 'EnvironmentBasedLambda', {
    runtime: getRuntimeForEnvironment('staging'),
    handler: 'index.handler',
    code: lambda.Code.fromAsset(path.join(__dirname, 'lambda-handler')),
  });
}
// {/fact}

// {fact rule=unmaintained-third-party-components@v1.0 defects=1}
function bad_case_14(scope: Construct) {
  try {
    // ruleid: typescript-cdk-lambda-latest-version
    new lambda.Function(scope, 'TryBlockLambda', {
      runtime: lambda.Runtime.NODEJS_14_X,
      handler: 'index.handler',
      code: lambda.Code.fromAsset(path.join(__dirname, 'lambda-handler')),
    });
  } catch (error) {
    console.error('Failed to create Lambda function', error);
  }
}
// {/fact}

// {fact rule=unmaintained-third-party-components@v1.0 defects=1}
function bad_case_15(scope: Construct) {
  const lambdaProps = {
    runtime: lambda.Runtime.PROVIDED,
    handler: 'bootstrap',
    code: lambda.Code.fromAsset(path.join(__dirname, 'lambda-handler')),
  };
  
  // ruleid: typescript-cdk-lambda-latest-version
  new lambda.Function(scope, 'CustomRuntimeLambda', lambdaProps);
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=unmaintained-third-party-components@v1.0 defects=0}
function good_case_1(scope: Construct) {
  // ok: typescript-cdk-lambda-latest-version
  new lambda.Function(scope, 'NodeJsLambdaLatest', {
    runtime: lambda.Runtime.NODEJS_18_X,
    handler: 'index.handler',
    code: lambda.Code.fromAsset(path.join(__dirname, 'lambda-handler')),
  });
}
// {/fact}

// {fact rule=unmaintained-third-party-components@v1.0 defects=0}
function good_case_2(scope: Construct) {
  // ok: typescript-cdk-lambda-latest-version
  new lambda.Function(scope, 'PythonLambdaLatest', {
    runtime: lambda.Runtime.PYTHON_3_11,
    handler: 'index.handler',
    code: lambda.Code.fromAsset(path.join(__dirname, 'lambda-handler')),
  });
}
// {/fact}

// {fact rule=unmaintained-third-party-components@v1.0 defects=0}
function good_case_3(scope: Construct) {
  const latestRuntime = lambda.Runtime.JAVA_17;
  
  // ok: typescript-cdk-lambda-latest-version
  new lambda.Function(scope, 'JavaLambdaLatest', {
    runtime: latestRuntime,
    handler: 'com.example.Handler',
    code: lambda.Code.fromAsset(path.join(__dirname, 'lambda-handler')),
  });
}
// {/fact}

// {fact rule=unmaintained-third-party-components@v1.0 defects=0}
function good_case_4(scope: Construct) {
  // ok: typescript-cdk-lambda-latest-version
  const fn = new lambda.Function(scope, 'RubyLambdaLatest', {
    runtime: lambda.Runtime.RUBY_3_2,
    handler: 'index.handler',
    code: lambda.Code.fromAsset(path.join(__dirname, 'lambda-handler')),
  });
}
// {/fact}

// {fact rule=unmaintained-third-party-components@v1.0 defects=0}
function good_case_5(scope: Construct) {
  const props = {
    runtime: lambda.Runtime.DOTNET_6_0,
    handler: 'MyFunction::Function.Handler',
    code: lambda.Code.fromAsset(path.join(__dirname, 'lambda-handler')),
  };
  
  // ok: typescript-cdk-lambda-latest-version
  new lambda.Function(scope, 'DotNetLambdaLatest', props);
}
// {/fact}

// {fact rule=unmaintained-third-party-components@v1.0 defects=0}
function good_case_6(scope: Construct, stack: cdk.Stack) {
  // ok: typescript-cdk-lambda-latest-version
  const lambdaFn = new lambda.Function(stack, 'GoLambdaLatest', {
    runtime: lambda.Runtime.GO_1_X, // Assuming GO_1_X is the latest available in CDK
    handler: 'main',
    code: lambda.Code.fromAsset(path.join(__dirname, 'lambda-handler')),
    environment: {
      REGION: stack.region,
    },
  });
  
  // Ensure runtime is kept up to date with regular reviews
  cdk.Tags.of(lambdaFn).add('runtime-review-date', new Date().toISOString());
}
// {/fact}

// {fact rule=unmaintained-third-party-components@v1.0 defects=0}
function good_case_7(scope: Construct) {
  // ok: typescript-cdk-lambda-latest-version
  const lambdaFunction = new lambda.Function(scope, 'NodeJsLatestLambda', {
    runtime: lambda.Runtime.NODEJS_18_X,
    handler: 'index.handler',
    code: lambda.Code.fromAsset(path.join(__dirname, 'lambda-handler')),
    memorySize: 512,
    timeout: cdk.Duration.seconds(30),
  });
}
// {/fact}

// {fact rule=unmaintained-third-party-components@v1.0 defects=0}
function good_case_8(scope: Construct) {
  if (process.env.ENVIRONMENT === 'dev') {
    // ok: typescript-cdk-lambda-latest-version
    new lambda.Function(scope, 'DevPythonLatestLambda', {
      runtime: lambda.Runtime.PYTHON_3_11,
      handler: 'index.handler',
      code: lambda.Code.fromAsset(path.join(__dirname, 'lambda-handler')),
    });
  }
}
// {/fact}

// {fact rule=unmaintained-third-party-components@v1.0 defects=0}
function good_case_9(scope: Construct) {
  const latestRuntimes = [
    lambda.Runtime.NODEJS_18_X,
    lambda.Runtime.PYTHON_3_11,
    lambda.Runtime.JAVA_17
  ];
  
  for (let i = 0; i < latestRuntimes.length; i++) {
    // ok: typescript-cdk-lambda-latest-version
    new lambda.Function(scope, `LatestLambda${i}`, {
      runtime: latestRuntimes[i],
      handler: 'index.handler',
      code: lambda.Code.fromAsset(path.join(__dirname, 'lambda-handler')),
    });
  }
}
// {/fact}

// {fact rule=unmaintained-third-party-components@v1.0 defects=0}
function good_case_10(scope: Construct) {
  const createLambda = (id: string, runtime: lambda.Runtime) => {
    // ok: typescript-cdk-lambda-latest-version
    return new lambda.Function(scope, id, {
      runtime: runtime,
      handler: 'index.handler',
      code: lambda.Code.fromAsset(path.join(__dirname, 'lambda-handler')),
    });
  };
  
  createLambda('LatestNodeLambda', lambda.Runtime.NODEJS_18_X);
}
// {/fact}

// {fact rule=unmaintained-third-party-components@v1.0 defects=0}
function good_case_11(scope: Construct) {
  const config = {
    runtime: lambda.Runtime.DOTNET_6_0,
    handler: 'MyFunction::Function.Handler',
  };
  
  // ok: typescript-cdk-lambda-latest-version
  new lambda.Function(scope, 'LatestDotNetLambda', {
    ...config,
    code: lambda.Code.fromAsset(path.join(__dirname, 'lambda-handler')),
  });
}
// {/fact}

// {fact rule=unmaintained-third-party-components@v1.0 defects=0}
function good_case_12(scope: Construct) {
  class LambdaConstruct extends Construct {
    constructor(scope: Construct, id: string) {
      super(scope, id);
      
      // ok: typescript-cdk-lambda-latest-version
      new lambda.Function(this, 'LatestLambdaInConstruct', {
        runtime: lambda.Runtime.PYTHON_3_11,
        handler: 'index.handler',
        code: lambda.Code.fromAsset(path.join(__dirname, 'lambda-handler')),
      });
    }
  }
  
  new LambdaConstruct(scope, 'CustomLatestLambdaConstruct');
}
// {/fact}

// {fact rule=unmaintained-third-party-components@v1.0 defects=0}
function good_case_13(scope: Construct) {
  const getRuntimeForEnvironment = (env: string): lambda.Runtime => {
    if (env === 'production') {
      return lambda.Runtime.NODEJS_18_X;
    }
    return lambda.Runtime.NODEJS_18_X;
  };
  
  // ok: typescript-cdk-lambda-latest-version
  new lambda.Function(scope, 'EnvironmentBasedLatestLambda', {
    runtime: getRuntimeForEnvironment('staging'),
    handler: 'index.handler',
    code: lambda.Code.fromAsset(path.join(__dirname, 'lambda-handler')),
  });
}
// {/fact}

// {fact rule=unmaintained-third-party-components@v1.0 defects=0}
function good_case_14(scope: Construct) {
  try {
    // ok: typescript-cdk-lambda-latest-version
    new lambda.Function(scope, 'TryBlockLatestLambda', {
      runtime: lambda.Runtime.NODEJS_18_X,
      handler: 'index.handler',
      code: lambda.Code.fromAsset(path.join(__dirname, 'lambda-handler')),
    });
  } catch (error) {
    console.error('Failed to create Lambda function', error);
  }
}
// {/fact}

// {fact rule=unmaintained-third-party-components@v1.0 defects=0}
function good_case_15(scope: Construct) {
  // Using container image with latest base image
  // ok: typescript-cdk-lambda-latest-version
  new lambda.DockerImageFunction(scope, 'DockerLambda', {
    code: lambda.DockerImageCode.fromImageAsset(path.join(__dirname, 'docker-lambda')),
    // No runtime specified as it's determined by the Docker image
  });
}
// {/fact}