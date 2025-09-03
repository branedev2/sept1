import * as cdk from 'aws-cdk-lib';
import * as ecs from 'aws-cdk-lib/aws-ecs';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as ssm from 'aws-cdk-lib/aws-ssm';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import { Construct } from 'constructs';

class TestStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // Common resources for examples
    const vpc = new ec2.Vpc(this, 'MyVpc', { maxAzs: 2 });
    const cluster = new ecs.Cluster(this, 'MyCluster', { vpc });
  }
}

// True Positive Examples (Vulnerable Code)

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_1(scope: Construct) {
  // Creating a task definition with plaintext environment variables
  // ruleid: typescript_cdk_ecs_task_definition_no_environment_variables
  const taskDefinition = new ecs.FargateTaskDefinition(scope, 'TaskDef');
  
  taskDefinition.addContainer('WebContainer', {
    image: ecs.ContainerImage.fromRegistry('nginx'),
    environment: {
      'API_KEY': 'secret-api-key-12345',
      'DATABASE_PASSWORD': 'super-secret-password'
    },
    memoryLimitMiB: 512,
  });
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_2(scope: Construct) {
  // Creating a task definition with plaintext environment variables including sensitive data
  // ruleid: typescript_cdk_ecs_task_definition_no_environment_variables
  const taskDefinition = new ecs.Ec2TaskDefinition(scope, 'TaskDef');
  
  taskDefinition.addContainer('AppContainer', {
    image: ecs.ContainerImage.fromRegistry('my-app:latest'),
    environment: {
      'JWT_SECRET': 'jwt-secret-token-for-auth',
      'ADMIN_PASSWORD': 'admin123',
      'DEBUG_MODE': 'true'
    },
    memoryLimitMiB: 1024,
  });
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_3(scope: Construct) {
  // Creating a task definition with plaintext environment variables in a service
  const taskDefinition = new ecs.FargateTaskDefinition(scope, 'ServiceTaskDef');
  
  // ruleid: typescript_cdk_ecs_task_definition_no_environment_variables
  const container = taskDefinition.addContainer('ServiceContainer', {
    image: ecs.ContainerImage.fromRegistry('service:v1'),
    environment: {
      'STRIPE_API_KEY': 'sk_test_abcdefghijklmnopqrstuvwxyz',
      'SMTP_PASSWORD': 'email-password-123'
    },
    memoryLimitMiB: 512,
  });
  
  container.addPortMappings({ containerPort: 8080 });
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_4(scope: Construct, cluster: ecs.Cluster) {
  // Creating a task definition with plaintext environment variables and using it in a service
  const taskDefinition = new ecs.FargateTaskDefinition(scope, 'WebTaskDef');
  
  // ruleid: typescript_cdk_ecs_task_definition_no_environment_variables
  const container = taskDefinition.addContainer('WebAppContainer', {
    image: ecs.ContainerImage.fromRegistry('webapp:latest'),
    environment: {
      'DATABASE_URL': 'postgres://user:password@hostname:5432/dbname',
      'REDIS_URL': 'redis://user:password@hostname:6379'
    },
    memoryLimitMiB: 1024,
  });
  
  container.addPortMappings({ containerPort: 3000 });
  
  new ecs.FargateService(scope, 'WebService', {
    cluster,
    taskDefinition,
    desiredCount: 2
  });
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_5(scope: Construct) {
  // Creating a task definition with plaintext environment variables using variable
  const envVars = {
    'AWS_ACCESS_KEY': 'AKIAIOSFODNN7EXAMPLE',
    'AWS_SECRET_KEY': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
  };
  
  const taskDefinition = new ecs.FargateTaskDefinition(scope, 'ApiTaskDef');
  
  // ruleid: typescript_cdk_ecs_task_definition_no_environment_variables
  taskDefinition.addContainer('ApiContainer', {
    image: ecs.ContainerImage.fromRegistry('api:v1'),
    environment: envVars,
    memoryLimitMiB: 512,
  });
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_6(scope: Construct) {
  // Creating multiple containers with plaintext environment variables
  const taskDefinition = new ecs.Ec2TaskDefinition(scope, 'MultiContainerTaskDef');
  
  // ruleid: typescript_cdk_ecs_task_definition_no_environment_variables
  taskDefinition.addContainer('FrontendContainer', {
    image: ecs.ContainerImage.fromRegistry('frontend:latest'),
    environment: {
      'API_ENDPOINT': 'https://api.example.com',
      'AUTH_TOKEN': 'secret-frontend-token'
    },
    memoryLimitMiB: 256,
  });
  
  // ruleid: typescript_cdk_ecs_task_definition_no_environment_variables
  taskDefinition.addContainer('BackendContainer', {
    image: ecs.ContainerImage.fromRegistry('backend:latest'),
    environment: {
      'DATABASE_PASSWORD': 'db-password-123',
      'CACHE_SECRET': 'cache-secret-key'
    },
    memoryLimitMiB: 512,
  });
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_7(scope: Construct) {
  // Creating a task definition with plaintext environment variables using constructor props
  // ruleid: typescript_cdk_ecs_task_definition_no_environment_variables
  const container = new ecs.ContainerDefinition(scope, 'ContainerDef', {
    taskDefinition: new ecs.FargateTaskDefinition(scope, 'TaskDef'),
    image: ecs.ContainerImage.fromRegistry('app:latest'),
    environment: {
      'SECRET_KEY': 'my-app-secret-key',
      'ENCRYPTION_KEY': 'AES256-encryption-key'
    },
    memoryLimitMiB: 512,
  });
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_8(scope: Construct) {
  // Creating a task definition with plaintext environment variables including connection strings
  const taskDefinition = new ecs.FargateTaskDefinition(scope, 'DbTaskDef');
  
  // ruleid: typescript_cdk_ecs_task_definition_no_environment_variables
  taskDefinition.addContainer('DbContainer', {
    image: ecs.ContainerImage.fromRegistry('db-service:v1'),
    environment: {
      'MONGODB_URI': 'mongodb://admin:password@mongodb:27017/database',
      'MYSQL_CONNECTION': 'mysql://root:rootpassword@mysql:3306/mydb'
    },
    memoryLimitMiB: 1024,
  });
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_9(scope: Construct, cluster: ecs.Cluster) {
  // Creating a task definition with plaintext environment variables in a scheduled task
  const taskDefinition = new ecs.FargateTaskDefinition(scope, 'ScheduledTaskDef');
  
  // ruleid: typescript_cdk_ecs_task_definition_no_environment_variables
  taskDefinition.addContainer('ScheduledJobContainer', {
    image: ecs.ContainerImage.fromRegistry('job-runner:latest'),
    environment: {
      'BACKUP_S3_KEY': 'AKIAIOSFODNN7EXAMPLE',
      'BACKUP_S3_SECRET': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
      'NOTIFICATION_API_KEY': 'notification-service-key-123'
    },
    memoryLimitMiB: 512,
  });
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_10(scope: Construct) {
  // Creating a task definition with plaintext environment variables using spread operator
  const baseEnv = {
    'LOG_LEVEL': 'info',
    'APP_ENV': 'production'
  };
  
  const secretEnv = {
    'GITHUB_TOKEN': 'github-personal-access-token',
    'NPM_TOKEN': 'npm-publish-token'
  };
  
  const taskDefinition = new ecs.FargateTaskDefinition(scope, 'CicdTaskDef');
  
  // ruleid: typescript_cdk_ecs_task_definition_no_environment_variables
  taskDefinition.addContainer('CicdContainer', {
    image: ecs.ContainerImage.fromRegistry('cicd:latest'),
    environment: {
      ...baseEnv,
      ...secretEnv
    },
    memoryLimitMiB: 1024,
  });
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_11(scope: Construct) {
  // Creating a task definition with plaintext environment variables conditionally
  const isProd = process.env.NODE_ENV === 'production';
  const taskDefinition = new ecs.FargateTaskDefinition(scope, 'ConditionalTaskDef');
  
  // ruleid: typescript_cdk_ecs_task_definition_no_environment_variables
  taskDefinition.addContainer('ConditionalContainer', {
    image: ecs.ContainerImage.fromRegistry('app:latest'),
    environment: isProd ? {
      'API_URL': 'https://api.production.com',
      'API_KEY': 'prod-api-key-secret'
    } : {
      'API_URL': 'https://api.staging.com',
      'API_KEY': 'staging-api-key'
    },
    memoryLimitMiB: 512,
  });
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_12(scope: Construct) {
  // Creating a task definition with plaintext environment variables from function
  function getEnvironmentVariables() {
    return {
      'PAYMENT_API_KEY': 'payment-gateway-secret-key',
      'PAYMENT_API_SECRET': 'payment-gateway-secret-value'
    };
  }
  
  const taskDefinition = new ecs.FargateTaskDefinition(scope, 'PaymentTaskDef');
  
  // ruleid: typescript_cdk_ecs_task_definition_no_environment_variables
  taskDefinition.addContainer('PaymentContainer', {
    image: ecs.ContainerImage.fromRegistry('payment-service:v1'),
    environment: getEnvironmentVariables(),
    memoryLimitMiB: 512,
  });
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_13(scope: Construct) {
  // Creating a task definition with plaintext environment variables with dynamic key names
  const keyPrefix = 'APP_';
  const taskDefinition = new ecs.FargateTaskDefinition(scope, 'DynamicKeyTaskDef');
  
  // ruleid: typescript_cdk_ecs_task_definition_no_environment_variables
  taskDefinition.addContainer('DynamicKeyContainer', {
    image: ecs.ContainerImage.fromRegistry('app:latest'),
    environment: {
      [`${keyPrefix}SECRET`]: 'dynamic-secret-value',
      [`${keyPrefix}API_KEY`]: 'dynamic-api-key-value',
      'STATIC_SECRET': 'static-secret-value'
    },
    memoryLimitMiB: 512,
  });
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_14(scope: Construct) {
  // Creating a task definition with plaintext environment variables in a sidecar pattern
  const taskDefinition = new ecs.FargateTaskDefinition(scope, 'SidecarTaskDef');
  
  // Main application container
  // ruleid: typescript_cdk_ecs_task_definition_no_environment_variables
  taskDefinition.addContainer('MainAppContainer', {
    image: ecs.ContainerImage.fromRegistry('main-app:latest'),
    environment: {
      'DATABASE_URL': 'postgres://user:password@db:5432/app',
      'REDIS_URL': 'redis://cache:6379'
    },
    memoryLimitMiB: 512,
  });
  
  // Sidecar container
  // ruleid: typescript_cdk_ecs_task_definition_no_environment_variables
  taskDefinition.addContainer('LoggingSidecar', {
    image: ecs.ContainerImage.fromRegistry('logging-agent:latest'),
    environment: {
      'LOG_AGGREGATOR_API_KEY': 'logging-service-api-key',
      'LOG_LEVEL': 'info'
    },
    memoryLimitMiB: 256,
  });
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_15(scope: Construct) {
  // Creating a task definition with plaintext environment variables using object merging
  const commonEnv = { 'APP_VERSION': '1.0.0', 'LOG_LEVEL': 'info' };
  const secretEnv = { 'AUTH_TOKEN': 'secret-auth-token-123' };
  
  const taskDefinition = new ecs.FargateTaskDefinition(scope, 'MergedEnvTaskDef');
  
  const mergedEnv = Object.assign({}, commonEnv, secretEnv);
  
  // ruleid: typescript_cdk_ecs_task_definition_no_environment_variables
  taskDefinition.addContainer('MergedEnvContainer', {
    image: ecs.ContainerImage.fromRegistry('app:latest'),
    environment: mergedEnv,
    memoryLimitMiB: 512,
  });
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_1(scope: Construct) {
  // Using AWS Secrets Manager for sensitive environment variables
  const secret = new secretsmanager.Secret(scope, 'ApiSecret', {
    secretName: 'api-secret',
    generateSecretString: {
      secretStringTemplate: JSON.stringify({ username: 'api-user' }),
      generateStringKey: 'password'
    }
  });
  
  const taskDefinition = new ecs.FargateTaskDefinition(scope, 'SecureTaskDef');
  
  // ok: typescript_cdk_ecs_task_definition_no_environment_variables
  taskDefinition.addContainer('SecureContainer', {
    image: ecs.ContainerImage.fromRegistry('app:latest'),
    secrets: {
      'API_KEY': ecs.Secret.fromSecretsManager(secret, 'password')
    },
    memoryLimitMiB: 512,
  });
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_2(scope: Construct) {
  // Using AWS Systems Manager Parameter Store for environment variables
  const dbUrlParam = new ssm.StringParameter(scope, 'DbUrlParam', {
    parameterName: '/app/database/url',
    stringValue: 'postgres://user:password@hostname:5432/dbname',
    type: ssm.ParameterType.SECURE_STRING
  });
  
  const taskDefinition = new ecs.FargateTaskDefinition(scope, 'SsmTaskDef');
  
  // ok: typescript_cdk_ecs_task_definition_no_environment_variables
  taskDefinition.addContainer('SsmContainer', {
    image: ecs.ContainerImage.fromRegistry('app:latest'),
    secrets: {
      'DATABASE_URL': ecs.Secret.fromSsmParameter(dbUrlParam)
    },
    memoryLimitMiB: 512,
  });
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_3(scope: Construct) {
  // Using AWS Secrets Manager with JSON field extraction
  const dbSecret = new secretsmanager.Secret(scope, 'DbCredentials', {
    secretName: 'db-credentials',
    generateSecretString: {
      secretStringTemplate: JSON.stringify({
        username: 'admin',
        host: 'mydb.cluster-123.us-east-1.rds.amazonaws.com',
        port: 5432,
        dbname: 'mydb'
      }),
      generateStringKey: 'password'
    }
  });
  
  const taskDefinition = new ecs.FargateTaskDefinition(scope, 'JsonSecretTaskDef');
  
  // ok: typescript_cdk_ecs_task_definition_no_environment_variables
  taskDefinition.addContainer('DbContainer', {
    image: ecs.ContainerImage.fromRegistry('db-app:latest'),
    secrets: {
      'DB_USERNAME': ecs.Secret.fromSecretsManager(dbSecret, 'username'),
      'DB_PASSWORD': ecs.Secret.fromSecretsManager(dbSecret, 'password'),
      'DB_HOST': ecs.Secret.fromSecretsManager(dbSecret, 'host'),
      'DB_PORT': ecs.Secret.fromSecretsManager(dbSecret, 'port'),
      'DB_NAME': ecs.Secret.fromSecretsManager(dbSecret, 'dbname')
    },
    memoryLimitMiB: 512,
  });
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_4(scope: Construct) {
  // Using existing AWS Secrets Manager secret by ARN
  const existingSecret = secretsmanager.Secret.fromSecretNameV2(scope, 'ExistingSecret', 'my-existing-secret');
  
  const taskDefinition = new ecs.FargateTaskDefinition(scope, 'ExistingSecretTaskDef');
  
  // ok: typescript_cdk_ecs_task_definition_no_environment_variables
  taskDefinition.addContainer('ApiContainer', {
    image: ecs.ContainerImage.fromRegistry('api:latest'),
    secrets: {
      'API_KEY': ecs.Secret.fromSecretsManager(existingSecret, 'api-key'),
      'API_SECRET': ecs.Secret.fromSecretsManager(existingSecret, 'api-secret')
    },
    memoryLimitMiB: 512,
  });
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_5(scope: Construct) {
  // Using existing AWS Systems Manager Parameter Store parameter by name
  const apiKeyParam = ssm.StringParameter.fromStringParameterName(
    scope,
    'ApiKeyParam',
    '/app/api/key'
  );
  
  const taskDefinition = new ecs.FargateTaskDefinition(scope, 'ExistingSsmTaskDef');
  
  // ok: typescript_cdk_ecs_task_definition_no_environment_variables
  taskDefinition.addContainer('AppContainer', {
    image: ecs.ContainerImage.fromRegistry('app:latest'),
    secrets: {
      'API_KEY': ecs.Secret.fromSsmParameter(apiKeyParam)
    },
    memoryLimitMiB: 512,
  });
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_6(scope: Construct) {
  // Using a mix of non-sensitive environment variables and secrets
  const secretToken = new secretsmanager.Secret(scope, 'SecretToken', {
    secretName: 'app-secret-token'
  });
  
  const taskDefinition = new ecs.FargateTaskDefinition(scope, 'MixedEnvTaskDef');
  
  // ok: typescript_cdk_ecs_task_definition_no_environment_variables
  taskDefinition.addContainer('MixedContainer', {
    image: ecs.ContainerImage.fromRegistry('app:latest'),
    environment: {
      'LOG_LEVEL': 'info',
      'APP_PORT': '8080',
      'DEBUG': 'false'
    },
    secrets: {
      'AUTH_TOKEN': ecs.Secret.fromSecretsManager(secretToken)
    },
    memoryLimitMiB: 512,
  });
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_7(scope: Construct) {
  // Using AWS Secrets Manager for multiple containers in a task definition
  const frontendSecret = new secretsmanager.Secret(scope, 'FrontendSecret', {
    secretName: 'frontend-secret'
  });
  
  const backendSecret = new secretsmanager.Secret(scope, 'BackendSecret', {
    secretName: 'backend-secret'
  });
  
  const taskDefinition = new ecs.FargateTaskDefinition(scope, 'MultiContainerSecureTaskDef');
  
  // ok: typescript_cdk_ecs_task_definition_no_environment_variables
  taskDefinition.addContainer('FrontendContainer', {
    image: ecs.ContainerImage.fromRegistry('frontend:latest'),
    secrets: {
      'API_KEY': ecs.Secret.fromSecretsManager(frontendSecret, 'api-key')
    },
    memoryLimitMiB: 256,
  });
  
  // ok: typescript_cdk_ecs_task_definition_no_environment_variables
  taskDefinition.addContainer('BackendContainer', {
    image: ecs.ContainerImage.fromRegistry('backend:latest'),
    secrets: {
      'DATABASE_PASSWORD': ecs.Secret.fromSecretsManager(backendSecret, 'db-password'),
      'CACHE_SECRET': ecs.Secret.fromSecretsManager(backendSecret, 'cache-secret')
    },
    memoryLimitMiB: 512,
  });
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_8(scope: Construct) {
  // Using AWS Secrets Manager with version stage
  const apiSecret = secretsmanager.Secret.fromSecretNameV2(
    scope,
    'VersionedSecret',
    'api-secret'
  );
  
  const taskDefinition = new ecs.FargateTaskDefinition(scope, 'VersionedSecretTaskDef');
  
  // ok: typescript_cdk_ecs_task_definition_no_environment_variables
  taskDefinition.addContainer('ApiContainer', {
    image: ecs.ContainerImage.fromRegistry('api:latest'),
    secrets: {
      'API_KEY': ecs.Secret.fromSecretsManagerVersion(apiSecret, {versionStage: 'AWSCURRENT'})
    },
    memoryLimitMiB: 512,
  });
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_9(scope: Construct) {
  // Using AWS Systems Manager Parameter Store with secure string
  const dbPasswordParam = new ssm.StringParameter(scope, 'DbPasswordParam', {
    parameterName: '/app/database/password',
    stringValue: 'initial-password',
    type: ssm.ParameterType.SECURE_STRING
  });
  
  const taskDefinition = new ecs.FargateTaskDefinition(scope, 'SecureStringTaskDef');
  
  // ok: typescript_cdk_ecs_task_definition_no_environment_variables
  taskDefinition.addContainer('DbContainer', {
    image: ecs.ContainerImage.fromRegistry('db-app:latest'),
    secrets: {
      'DB_PASSWORD': ecs.Secret.fromSsmParameter(dbPasswordParam)
    },
    memoryLimitMiB: 512,
  });
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_10(scope: Construct) {
  // Using AWS Secrets Manager with specific secret version
  const versionedSecret = secretsmanager.Secret.fromSecretCompleteArn(
    scope,
    'SpecificVersionSecret',
    'arn:aws:secretsmanager:us-west-2:123456789012:secret:my-secret-123abc'
  );
  
  const taskDefinition = new ecs.FargateTaskDefinition(scope, 'SpecificVersionTaskDef');
  
  // ok: typescript_cdk_ecs_task_definition_no_environment_variables
  taskDefinition.addContainer('AppContainer', {
    image: ecs.ContainerImage.fromRegistry('app:latest'),
    secrets: {
      'APP_SECRET': ecs.Secret.fromSecretsManagerVersion(versionedSecret, {versionId: 'abcdef-12345'})
    },
    memoryLimitMiB: 512,
  });
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_11(scope: Construct) {
  // Using AWS Secrets Manager for connection strings
  const connectionSecret = new secretsmanager.Secret(scope, 'ConnectionSecret', {
    secretName: 'connection-strings'
  });
  
  const taskDefinition = new ecs.FargateTaskDefinition(scope, 'ConnectionTaskDef');
  
  // ok: typescript_cdk_ecs_task_definition_no_environment_variables
  taskDefinition.addContainer('AppContainer', {
    image: ecs.ContainerImage.fromRegistry('app:latest'),
    secrets: {
      'DATABASE_URL': ecs.Secret.fromSecretsManager(connectionSecret, 'database-url'),
      'REDIS_URL': ecs.Secret.fromSecretsManager(connectionSecret, 'redis-url')
    },
    memoryLimitMiB: 512,
  });
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_12(scope: Construct) {
  // Using AWS Systems Manager Parameter Store with parameter path
  const paramPath = '/app/config/';
  
  const taskDefinition = new ecs.FargateTaskDefinition(scope, 'ParamPathTaskDef');
  
  // ok: typescript_cdk_ecs_task_definition_no_environment_variables
  taskDefinition.addContainer('AppContainer', {
    image: ecs.ContainerImage.fromRegistry('app:latest'),
    secrets: {
      'API_KEY': ecs.Secret.fromSsmParameter(
        ssm.StringParameter.fromSecureStringParameterAttributes(scope, 'ApiKeyParam', {
          parameterName: `${paramPath}api-key`,
          version: 1
        })
      ),
      'API_SECRET': ecs.Secret.fromSsmParameter(
        ssm.StringParameter.fromSecureStringParameterAttributes(scope, 'ApiSecretParam', {
          parameterName: `${paramPath}api-secret`,
          version: 1
        })
      )
    },
    memoryLimitMiB: 512,
  });
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_13(scope: Construct) {
  // Using AWS Secrets Manager with dynamic secret names
  const environment = 'prod';
  const secretName = `${environment}-api-credentials`;
  
  const apiSecret = new secretsmanager.Secret(scope, 'DynamicSecret', {
    secretName: secretName
  });
  
  const taskDefinition = new ecs.FargateTaskDefinition(scope, 'DynamicSecretTaskDef');
  
  // ok: typescript_cdk_ecs_task_definition_no_environment_variables
  taskDefinition.addContainer('ApiContainer', {
    image: ecs.ContainerImage.fromRegistry('api:latest'),
    secrets: {
      'API_KEY': ecs.Secret.fromSecretsManager(apiSecret, 'key'),
      'API_SECRET': ecs.Secret.fromSecretsManager(apiSecret, 'secret')
    },
    memoryLimitMiB: 512,
  });
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_14(scope: Construct) {
  // Using AWS Secrets Manager for OAuth credentials
  const oauthSecret = new secretsmanager.Secret(scope, 'OAuthSecret', {
    secretName: 'oauth-credentials',
    generateSecretString: {
      secretStringTemplate: JSON.stringify({
        client_id: 'example-client-id'
      }),
      generateStringKey: 'client_secret'
    }
  });
  
  const taskDefinition = new ecs.FargateTaskDefinition(scope, 'OAuthTaskDef');
  
  // ok: typescript_cdk_ecs_task_definition_no_environment_variables
  taskDefinition.addContainer('AuthContainer', {
    image: ecs.ContainerImage.fromRegistry('auth-service:latest'),
    secrets: {
      'OAUTH_CLIENT_ID': ecs.Secret.fromSecretsManager(oauthSecret, 'client_id'),
      'OAUTH_CLIENT_SECRET': ecs.Secret.fromSecretsManager(oauthSecret, 'client_secret')
    },
    memoryLimitMiB: 512,
  });
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_15(scope: Construct) {
  // Using AWS Secrets Manager with no environment variables at all
  const taskDefinition = new ecs.FargateTaskDefinition(scope, 'NoEnvTaskDef');
  
  // ok: typescript_cdk_ecs_task_definition_no_environment_variables
  taskDefinition.addContainer('AppContainer', {
    image: ecs.ContainerImage.fromRegistry('app:latest'),
    memoryLimitMiB: 512,
    logging: new ecs.AwsLogDriver({
      streamPrefix: 'app-container'
    })
  });
}
// {/fact}