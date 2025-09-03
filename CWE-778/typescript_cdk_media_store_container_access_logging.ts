import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as mediastore from 'aws-cdk-lib/aws-mediastore';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as iam from 'aws-cdk-lib/aws-iam';

// True Positive Examples (Vulnerable Code)

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_1(scope: Construct) {
  // Creating a MediaStore container without access logging
  // ruleid: typescript_cdk_media_store_container_access_logging
  new mediastore.CfnContainer(scope, 'MyMediaStoreContainer1', {
    containerName: 'my-media-container-1',
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_2(scope: Construct) {
  // Creating a MediaStore container with empty properties
  // ruleid: typescript_cdk_media_store_container_access_logging
  new mediastore.CfnContainer(scope, 'MyMediaStoreContainer2', {
    containerName: 'my-media-container-2',
    // No access logging configuration
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_3(scope: Construct) {
  // Creating a MediaStore container with some properties but no logging
  const containerProps = {
    containerName: 'my-media-container-3',
    corsPolicy: [{
      allowedMethods: ['GET', 'HEAD'],
      allowedOrigins: ['*'],
      maxAgeSeconds: 3000
    }]
  };
  
  // ruleid: typescript_cdk_media_store_container_access_logging
  new mediastore.CfnContainer(scope, 'MyMediaStoreContainer3', containerProps);
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_4(scope: Construct) {
  // Creating multiple containers, all without logging
  for (let i = 1; i <= 3; i++) {
    // ruleid: typescript_cdk_media_store_container_access_logging
    new mediastore.CfnContainer(scope, `MyMediaStoreContainer4-${i}`, {
      containerName: `my-media-container-4-${i}`,
    });
  }
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_5(scope: Construct) {
  // Creating a container with conditional logic but no logging in any branch
  const isProd = process.env.ENVIRONMENT === 'production';
  
  const containerProps = {
    containerName: isProd ? 'prod-media-container' : 'dev-media-container',
    tags: [{ key: 'Environment', value: isProd ? 'Production' : 'Development' }]
  };
  
  // ruleid: typescript_cdk_media_store_container_access_logging
  new mediastore.CfnContainer(scope, 'MyMediaStoreContainer5', containerProps);
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_6(scope: Construct, stack: cdk.Stack) {
  // Creating a container with explicit null for container policy but no logging
  // ruleid: typescript_cdk_media_store_container_access_logging
  new mediastore.CfnContainer(scope, 'MyMediaStoreContainer6', {
    containerName: 'my-media-container-6',
    containerPolicy: null,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_7(scope: Construct) {
  // Creating a container with policy but no logging
  const policy = {
    Version: '2012-10-17',
    Statement: [{
      Sid: 'PublicReadGetObject',
      Effect: 'Allow',
      Principal: '*',
      Action: 'mediastore:GetObject',
      Resource: 'arn:aws:mediastore:*:*:container/my-container/*'
    }]
  };
  
  // ruleid: typescript_cdk_media_store_container_access_logging
  new mediastore.CfnContainer(scope, 'MyMediaStoreContainer7', {
    containerName: 'my-media-container-7',
    containerPolicy: JSON.stringify(policy),
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_8(scope: Construct) {
  // Creating a container with lifecycle policy but no logging
  // ruleid: typescript_cdk_media_store_container_access_logging
  new mediastore.CfnContainer(scope, 'MyMediaStoreContainer8', {
    containerName: 'my-media-container-8',
    lifecyclePolicy: JSON.stringify({
      rules: [{
        definition: {
          days_since_create: 365
        },
        action: 'EXPIRE'
      }]
    }),
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_9(scope: Construct) {
  // Creating a container with empty access logging config object
  // ruleid: typescript_cdk_media_store_container_access_logging
  new mediastore.CfnContainer(scope, 'MyMediaStoreContainer9', {
    containerName: 'my-media-container-9',
    accessLoggingEnabled: false,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_10(scope: Construct) {
  // Creating a container with explicitly disabled access logging
  const containerProps = {
    containerName: 'my-media-container-10',
    accessLoggingEnabled: false,
  };
  
  // ruleid: typescript_cdk_media_store_container_access_logging
  new mediastore.CfnContainer(scope, 'MyMediaStoreContainer10', containerProps);
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_11(scope: Construct) {
  // Creating a container with a variable that could be undefined
  const enableLogging = undefined;
  
  // ruleid: typescript_cdk_media_store_container_access_logging
  new mediastore.CfnContainer(scope, 'MyMediaStoreContainer11', {
    containerName: 'my-media-container-11',
    accessLoggingEnabled: enableLogging,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_12(scope: Construct) {
  // Creating a container with a function that returns undefined for logging
  const getLoggingConfig = () => undefined;
  
  // ruleid: typescript_cdk_media_store_container_access_logging
  new mediastore.CfnContainer(scope, 'MyMediaStoreContainer12', {
    containerName: 'my-media-container-12',
    accessLoggingEnabled: getLoggingConfig(),
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_13(scope: Construct) {
  // Creating a container with complex object structure but no logging
  const config = {
    basic: {
      name: 'my-media-container-13',
      tags: [{ key: 'Project', value: 'MediaProcessing' }]
    },
    advanced: {
      cors: [{
        allowedMethods: ['GET', 'HEAD'],
        allowedOrigins: ['*'],
        maxAgeSeconds: 3000
      }]
    }
  };
  
  // ruleid: typescript_cdk_media_store_container_access_logging
  new mediastore.CfnContainer(scope, 'MyMediaStoreContainer13', {
    containerName: config.basic.name,
    corsPolicy: config.advanced.cors,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_14(scope: Construct) {
  // Creating a container with object spread but no logging
  const baseConfig = {
    containerName: 'my-media-container-14',
  };
  
  const additionalConfig = {
    tags: [{ key: 'Department', value: 'Marketing' }]
  };
  
  // ruleid: typescript_cdk_media_store_container_access_logging
  new mediastore.CfnContainer(scope, 'MyMediaStoreContainer14', {
    ...baseConfig,
    ...additionalConfig,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_15(scope: Construct) {
  // Creating a container with conditional property assignment but no logging
  const isProd = process.env.ENVIRONMENT === 'production';
  
  const containerProps: any = {
    containerName: 'my-media-container-15',
  };
  
  if (isProd) {
    containerProps.tags = [{ key: 'Environment', value: 'Production' }];
  }
  
  // ruleid: typescript_cdk_media_store_container_access_logging
  new mediastore.CfnContainer(scope, 'MyMediaStoreContainer15', containerProps);
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_1(scope: Construct) {
  // Creating a MediaStore container with access logging enabled
  // ok: typescript_cdk_media_store_container_access_logging
  new mediastore.CfnContainer(scope, 'MyMediaStoreContainer1', {
    containerName: 'my-media-container-1',
    accessLoggingEnabled: true,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_2(scope: Construct) {
  // Creating a MediaStore container with access logging and other properties
  const containerProps = {
    containerName: 'my-media-container-2',
    corsPolicy: [{
      allowedMethods: ['GET', 'HEAD'],
      allowedOrigins: ['*'],
      maxAgeSeconds: 3000
    }],
    // ok: typescript_cdk_media_store_container_access_logging
    accessLoggingEnabled: true,
  };
  
  new mediastore.CfnContainer(scope, 'MyMediaStoreContainer2', containerProps);
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_3(scope: Construct) {
  // Creating multiple containers, all with logging enabled
  for (let i = 1; i <= 3; i++) {
    // ok: typescript_cdk_media_store_container_access_logging
    new mediastore.CfnContainer(scope, `MyMediaStoreContainer3-${i}`, {
      containerName: `my-media-container-3-${i}`,
      accessLoggingEnabled: true,
    });
  }
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_4(scope: Construct) {
  // Creating a container with conditional logic and logging in all branches
  const isProd = process.env.ENVIRONMENT === 'production';
  
  const containerProps = {
    containerName: isProd ? 'prod-media-container' : 'dev-media-container',
    tags: [{ key: 'Environment', value: isProd ? 'Production' : 'Development' }],
    // ok: typescript_cdk_media_store_container_access_logging
    accessLoggingEnabled: true,
  };
  
  new mediastore.CfnContainer(scope, 'MyMediaStoreContainer4', containerProps);
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_5(scope: Construct) {
  // Creating a container with policy and logging
  const policy = {
    Version: '2012-10-17',
    Statement: [{
      Sid: 'PublicReadGetObject',
      Effect: 'Allow',
      Principal: '*',
      Action: 'mediastore:GetObject',
      Resource: 'arn:aws:mediastore:*:*:container/my-container/*'
    }]
  };
  
  // ok: typescript_cdk_media_store_container_access_logging
  new mediastore.CfnContainer(scope, 'MyMediaStoreContainer5', {
    containerName: 'my-media-container-5',
    containerPolicy: JSON.stringify(policy),
    accessLoggingEnabled: true,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_6(scope: Construct) {
  // Creating a container with lifecycle policy and logging
  // ok: typescript_cdk_media_store_container_access_logging
  new mediastore.CfnContainer(scope, 'MyMediaStoreContainer6', {
    containerName: 'my-media-container-6',
    lifecyclePolicy: JSON.stringify({
      rules: [{
        definition: {
          days_since_create: 365
        },
        action: 'EXPIRE'
      }]
    }),
    accessLoggingEnabled: true,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_7(scope: Construct) {
  // Creating a container with a variable that is always true
  const enableLogging = true;
  
  // ok: typescript_cdk_media_store_container_access_logging
  new mediastore.CfnContainer(scope, 'MyMediaStoreContainer7', {
    containerName: 'my-media-container-7',
    accessLoggingEnabled: enableLogging,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_8(scope: Construct) {
  // Creating a container with a function that returns true for logging
  const getLoggingConfig = () => true;
  
  // ok: typescript_cdk_media_store_container_access_logging
  new mediastore.CfnContainer(scope, 'MyMediaStoreContainer8', {
    containerName: 'my-media-container-8',
    accessLoggingEnabled: getLoggingConfig(),
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_9(scope: Construct) {
  // Creating a container with complex object structure including logging
  const config = {
    basic: {
      name: 'my-media-container-9',
      tags: [{ key: 'Project', value: 'MediaProcessing' }]
    },
    advanced: {
      cors: [{
        allowedMethods: ['GET', 'HEAD'],
        allowedOrigins: ['*'],
        maxAgeSeconds: 3000
      }],
      logging: true
    }
  };
  
  // ok: typescript_cdk_media_store_container_access_logging
  new mediastore.CfnContainer(scope, 'MyMediaStoreContainer9', {
    containerName: config.basic.name,
    corsPolicy: config.advanced.cors,
    accessLoggingEnabled: config.advanced.logging,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_10(scope: Construct) {
  // Creating a container with object spread including logging
  const baseConfig = {
    containerName: 'my-media-container-10',
  };
  
  const additionalConfig = {
    tags: [{ key: 'Department', value: 'Marketing' }],
    accessLoggingEnabled: true
  };
  
  // ok: typescript_cdk_media_store_container_access_logging
  new mediastore.CfnContainer(scope, 'MyMediaStoreContainer10', {
    ...baseConfig,
    ...additionalConfig,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_11(scope: Construct) {
  // Creating a container with conditional property assignment including logging
  const isProd = process.env.ENVIRONMENT === 'production';
  
  const containerProps: any = {
    containerName: 'my-media-container-11',
    // ok: typescript_cdk_media_store_container_access_logging
    accessLoggingEnabled: true,
  };
  
  if (isProd) {
    containerProps.tags = [{ key: 'Environment', value: 'Production' }];
  }
  
  new mediastore.CfnContainer(scope, 'MyMediaStoreContainer11', containerProps);
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_12(scope: Construct) {
  // Creating a container with a ternary operator for logging that always results in true
  const isProd = process.env.ENVIRONMENT === 'production';
  
  // ok: typescript_cdk_media_store_container_access_logging
  new mediastore.CfnContainer(scope, 'MyMediaStoreContainer12', {
    containerName: 'my-media-container-12',
    accessLoggingEnabled: isProd ? true : true,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_13(scope: Construct) {
  // Creating a container with logging and using a higher-level construct
  const container = new mediastore.CfnContainer(scope, 'MyMediaStoreContainer13', {
    containerName: 'my-media-container-13',
    // ok: typescript_cdk_media_store_container_access_logging
    accessLoggingEnabled: true,
  });
  
  // Adding tags after creation
  cdk.Tags.of(container).add('Project', 'MediaProcessing');
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_14(scope: Construct) {
  // Creating a container with logging and a complex policy
  const policy = new iam.PolicyDocument({
    statements: [
      new iam.PolicyStatement({
        actions: ['mediastore:GetObject'],
        resources: ['*'],
        principals: [new iam.AnyPrincipal()],
      }),
    ],
  });
  
  // ok: typescript_cdk_media_store_container_access_logging
  new mediastore.CfnContainer(scope, 'MyMediaStoreContainer14', {
    containerName: 'my-media-container-14',
    containerPolicy: policy.toJSON(),
    accessLoggingEnabled: true,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_15(scope: Construct) {
  // Creating a container with logging and referencing other resources
  const logBucket = new s3.Bucket(scope, 'LogBucket');
  
  // ok: typescript_cdk_media_store_container_access_logging
  new mediastore.CfnContainer(scope, 'MyMediaStoreContainer15', {
    containerName: 'my-media-container-15',
    accessLoggingEnabled: true,
  });
  
  // Additional configuration that references the container
  new cdk.CfnOutput(scope, 'ContainerNameOutput', {
    value: 'my-media-container-15',
    description: 'The name of the MediaStore container with logging enabled',
  });
}
// {/fact}