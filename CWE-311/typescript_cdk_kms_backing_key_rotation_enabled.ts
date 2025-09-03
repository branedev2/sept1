import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import * as rds from 'aws-cdk-lib/aws-rds';
import * as lambda from 'aws-cdk-lib/aws-lambda';

// True Positives (Vulnerable Code)

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_1(scope: Construct) {
  // Creating a KMS key without enabling rotation
  // ruleid: typescript_cdk_kms_backing_key_rotation_enabled
  const key = new kms.Key(scope, 'MyKey1', {
    description: 'KMS key for encrypting important data',
    enabled: true,
  });
  
  return key;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_2(scope: Construct) {
  // Creating a KMS key with rotation explicitly disabled
  // ruleid: typescript_cdk_kms_backing_key_rotation_enabled
  const key = new kms.Key(scope, 'MyKey2', {
    description: 'KMS key for encrypting important data',
    enabled: true,
    enableKeyRotation: false
  });
  
  return key;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_3(scope: Construct) {
  // Creating a KMS key with default settings (rotation not enabled)
  // ruleid: typescript_cdk_kms_backing_key_rotation_enabled
  const key = new kms.Key(scope, 'MyKey3', {});
  
  return key;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_4(scope: Construct) {
  // Using KMS key without rotation for S3 bucket encryption
  // ruleid: typescript_cdk_kms_backing_key_rotation_enabled
  const encryptionKey = new kms.Key(scope, 'BucketKey', {
    description: 'Key for S3 bucket encryption',
  });
  
  const bucket = new s3.Bucket(scope, 'EncryptedBucket', {
    encryption: s3.BucketEncryption.KMS,
    encryptionKey: encryptionKey,
  });
  
  return { bucket, encryptionKey };
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_5(scope: Construct) {
  // Using KMS key without rotation for Secrets Manager
  // ruleid: typescript_cdk_kms_backing_key_rotation_enabled
  const encryptionKey = new kms.Key(scope, 'SecretKey', {
    description: 'Key for Secrets Manager encryption',
  });
  
  const secret = new secretsmanager.Secret(scope, 'MySecret', {
    encryptionKey: encryptionKey,
  });
  
  return { secret, encryptionKey };
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_6(scope: Construct) {
  // Creating a KMS key with complex configuration but no rotation
  // ruleid: typescript_cdk_kms_backing_key_rotation_enabled
  const key = new kms.Key(scope, 'ComplexKey', {
    description: 'Complex KMS key configuration',
    enabled: true,
    enableKeyRotation: false,
    alias: 'alias/complex-key',
    removalPolicy: cdk.RemovalPolicy.DESTROY,
  });
  
  return key;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_7(scope: Construct) {
  // Using KMS key without rotation for RDS database
  // ruleid: typescript_cdk_kms_backing_key_rotation_enabled
  const databaseKey = new kms.Key(scope, 'DatabaseKey', {
    description: 'Key for RDS database encryption',
  });
  
  const instance = new rds.DatabaseInstance(scope, 'Database', {
    engine: rds.DatabaseInstanceEngine.mysql({
      version: rds.MysqlEngineVersion.VER_8_0_26
    }),
    instanceType: cdk.aws_ec2.InstanceType.of(
      cdk.aws_ec2.InstanceClass.BURSTABLE3,
      cdk.aws_ec2.InstanceSize.SMALL
    ),
    storageEncryptionKey: databaseKey,
    vpc: new cdk.aws_ec2.Vpc(scope, 'VPC'),
  });
  
  return { instance, databaseKey };
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_8(scope: Construct) {
  // Creating multiple KMS keys without rotation
  // ruleid: typescript_cdk_kms_backing_key_rotation_enabled
  const key1 = new kms.Key(scope, 'Key1', {
    description: 'First key without rotation',
  });
  
  // ruleid: typescript_cdk_kms_backing_key_rotation_enabled
  const key2 = new kms.Key(scope, 'Key2', {
    description: 'Second key without rotation',
  });
  
  return { key1, key2 };
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_9(scope: Construct) {
  // Using KMS key without rotation in a conditional block
  const isProduction = process.env.ENVIRONMENT === 'production';
  
  if (isProduction) {
    // ruleid: typescript_cdk_kms_backing_key_rotation_enabled
    const key = new kms.Key(scope, 'ProdKey', {
      description: 'Production encryption key',
      enabled: true,
    });
    return key;
  } else {
    // ruleid: typescript_cdk_kms_backing_key_rotation_enabled
    const key = new kms.Key(scope, 'DevKey', {
      description: 'Development encryption key',
    });
    return key;
  }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_10(scope: Construct) {
  // Using KMS key without rotation for Lambda environment variables
  // ruleid: typescript_cdk_kms_backing_key_rotation_enabled
  const lambdaKey = new kms.Key(scope, 'LambdaKey', {
    description: 'Key for Lambda environment variables',
  });
  
  const fn = new lambda.Function(scope, 'MyFunction', {
    runtime: lambda.Runtime.NODEJS_14_X,
    handler: 'index.handler',
    code: lambda.Code.fromInline('exports.handler = async () => { return { statusCode: 200 }; }'),
    environment: {
      SECRET_VALUE: 'sensitive-data'
    },
    environmentEncryption: lambdaKey
  });
  
  return { fn, lambdaKey };
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_11(scope: Construct) {
  // Creating a KMS key with rotation disabled using variable
  const enableRotation = false;
  
  // ruleid: typescript_cdk_kms_backing_key_rotation_enabled
  const key = new kms.Key(scope, 'ConfigurableKey', {
    description: 'Key with configurable rotation',
    enableKeyRotation: enableRotation
  });
  
  return key;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_12(scope: Construct) {
  // Creating a KMS key with alias but no rotation
  // ruleid: typescript_cdk_kms_backing_key_rotation_enabled
  const key = new kms.Key(scope, 'AliasedKey', {
    description: 'Key with alias but no rotation',
  });
  
  // Adding alias separately
  const alias = new kms.Alias(scope, 'KeyAlias', {
    aliasName: 'alias/my-important-key',
    targetKey: key
  });
  
  return { key, alias };
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_13(scope: Construct) {
  // Creating a KMS key with pending window but no rotation
  // ruleid: typescript_cdk_kms_backing_key_rotation_enabled
  const key = new kms.Key(scope, 'PendingWindowKey', {
    description: 'Key with pending window but no rotation',
    pendingWindow: cdk.Duration.days(14),
  });
  
  return key;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_14(scope: Construct) {
  // Creating a KMS key with policy but no rotation
  const adminRole = new cdk.aws_iam.Role(scope, 'AdminRole', {
    assumedBy: new cdk.aws_iam.AccountRootPrincipal(),
  });
  
  // ruleid: typescript_cdk_kms_backing_key_rotation_enabled
  const key = new kms.Key(scope, 'PolicyKey', {
    description: 'Key with policy but no rotation',
    admins: [adminRole],
  });
  
  return key;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_15(scope: Construct) {
  // Creating a KMS key with custom tags but no rotation
  // ruleid: typescript_cdk_kms_backing_key_rotation_enabled
  const key = new kms.Key(scope, 'TaggedKey', {
    description: 'Key with tags but no rotation',
  });
  
  cdk.Tags.of(key).add('Environment', 'Production');
  cdk.Tags.of(key).add('CostCenter', '12345');
  
  return key;
}
// {/fact}

// True Negatives (Secure Code)

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_1(scope: Construct) {
  // Creating a KMS key with rotation enabled
  // ok: typescript_cdk_kms_backing_key_rotation_enabled
  const key = new kms.Key(scope, 'MySecureKey1', {
    description: 'KMS key with rotation enabled',
    enabled: true,
    enableKeyRotation: true
  });
  
  return key;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_2(scope: Construct) {
  // Using KMS key with rotation for S3 bucket encryption
  // ok: typescript_cdk_kms_backing_key_rotation_enabled
  const encryptionKey = new kms.Key(scope, 'SecureBucketKey', {
    description: 'Key for S3 bucket encryption',
    enableKeyRotation: true
  });
  
  const bucket = new s3.Bucket(scope, 'SecureEncryptedBucket', {
    encryption: s3.BucketEncryption.KMS,
    encryptionKey: encryptionKey,
  });
  
  return { bucket, encryptionKey };
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_3(scope: Construct) {
  // Using KMS key with rotation for Secrets Manager
  // ok: typescript_cdk_kms_backing_key_rotation_enabled
  const encryptionKey = new kms.Key(scope, 'SecureSecretKey', {
    description: 'Key for Secrets Manager encryption',
    enableKeyRotation: true
  });
  
  const secret = new secretsmanager.Secret(scope, 'MySecureSecret', {
    encryptionKey: encryptionKey,
  });
  
  return { secret, encryptionKey };
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_4(scope: Construct) {
  // Creating a KMS key with complex configuration and rotation enabled
  // ok: typescript_cdk_kms_backing_key_rotation_enabled
  const key = new kms.Key(scope, 'SecureComplexKey', {
    description: 'Complex KMS key configuration with rotation',
    enabled: true,
    enableKeyRotation: true,
    alias: 'alias/secure-complex-key',
    removalPolicy: cdk.RemovalPolicy.DESTROY,
  });
  
  return key;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_5(scope: Construct) {
  // Using KMS key with rotation for RDS database
  // ok: typescript_cdk_kms_backing_key_rotation_enabled
  const databaseKey = new kms.Key(scope, 'SecureDatabaseKey', {
    description: 'Key for RDS database encryption',
    enableKeyRotation: true
  });
  
  const instance = new rds.DatabaseInstance(scope, 'SecureDatabase', {
    engine: rds.DatabaseInstanceEngine.mysql({
      version: rds.MysqlEngineVersion.VER_8_0_26
    }),
    instanceType: cdk.aws_ec2.InstanceType.of(
      cdk.aws_ec2.InstanceClass.BURSTABLE3,
      cdk.aws_ec2.InstanceSize.SMALL
    ),
    storageEncryptionKey: databaseKey,
    vpc: new cdk.aws_ec2.Vpc(scope, 'SecureVPC'),
  });
  
  return { instance, databaseKey };
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_6(scope: Construct) {
  // Creating multiple KMS keys with rotation enabled
  // ok: typescript_cdk_kms_backing_key_rotation_enabled
  const key1 = new kms.Key(scope, 'SecureKey1', {
    description: 'First key with rotation',
    enableKeyRotation: true
  });
  
  // ok: typescript_cdk_kms_backing_key_rotation_enabled
  const key2 = new kms.Key(scope, 'SecureKey2', {
    description: 'Second key with rotation',
    enableKeyRotation: true
  });
  
  return { key1, key2 };
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_7(scope: Construct) {
  // Using KMS key with rotation in a conditional block
  const isProduction = process.env.ENVIRONMENT === 'production';
  
  if (isProduction) {
    // ok: typescript_cdk_kms_backing_key_rotation_enabled
    const key = new kms.Key(scope, 'SecureProdKey', {
      description: 'Production encryption key with rotation',
      enabled: true,
      enableKeyRotation: true
    });
    return key;
  } else {
    // ok: typescript_cdk_kms_backing_key_rotation_enabled
    const key = new kms.Key(scope, 'SecureDevKey', {
      description: 'Development encryption key with rotation',
      enableKeyRotation: true
    });
    return key;
  }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_8(scope: Construct) {
  // Using KMS key with rotation for Lambda environment variables
  // ok: typescript_cdk_kms_backing_key_rotation_enabled
  const lambdaKey = new kms.Key(scope, 'SecureLambdaKey', {
    description: 'Key for Lambda environment variables',
    enableKeyRotation: true
  });
  
  const fn = new lambda.Function(scope, 'MySecureFunction', {
    runtime: lambda.Runtime.NODEJS_14_X,
    handler: 'index.handler',
    code: lambda.Code.fromInline('exports.handler = async () => { return { statusCode: 200 }; }'),
    environment: {
      SECRET_VALUE: 'sensitive-data'
    },
    environmentEncryption: lambdaKey
  });
  
  return { fn, lambdaKey };
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_9(scope: Construct) {
  // Creating a KMS key with rotation enabled using variable
  const enableRotation = true;
  
  // ok: typescript_cdk_kms_backing_key_rotation_enabled
  const key = new kms.Key(scope, 'SecureConfigurableKey', {
    description: 'Key with configurable rotation',
    enableKeyRotation: enableRotation
  });
  
  return key;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_10(scope: Construct) {
  // Creating a KMS key with alias and rotation
  // ok: typescript_cdk_kms_backing_key_rotation_enabled
  const key = new kms.Key(scope, 'SecureAliasedKey', {
    description: 'Key with alias and rotation',
    enableKeyRotation: true
  });
  
  // Adding alias separately
  const alias = new kms.Alias(scope, 'SecureKeyAlias', {
    aliasName: 'alias/my-secure-important-key',
    targetKey: key
  });
  
  return { key, alias };
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_11(scope: Construct) {
  // Creating a KMS key with pending window and rotation
  // ok: typescript_cdk_kms_backing_key_rotation_enabled
  const key = new kms.Key(scope, 'SecurePendingWindowKey', {
    description: 'Key with pending window and rotation',
    pendingWindow: cdk.Duration.days(14),
    enableKeyRotation: true
  });
  
  return key;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_12(scope: Construct) {
  // Creating a KMS key with policy and rotation
  const adminRole = new cdk.aws_iam.Role(scope, 'SecureAdminRole', {
    assumedBy: new cdk.aws_iam.AccountRootPrincipal(),
  });
  
  // ok: typescript_cdk_kms_backing_key_rotation_enabled
  const key = new kms.Key(scope, 'SecurePolicyKey', {
    description: 'Key with policy and rotation',
    admins: [adminRole],
    enableKeyRotation: true
  });
  
  return key;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_13(scope: Construct) {
  // Creating a KMS key with custom tags and rotation
  // ok: typescript_cdk_kms_backing_key_rotation_enabled
  const key = new kms.Key(scope, 'SecureTaggedKey', {
    description: 'Key with tags and rotation',
    enableKeyRotation: true
  });
  
  cdk.Tags.of(key).add('Environment', 'Production');
  cdk.Tags.of(key).add('CostCenter', '12345');
  
  return key;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_14(scope: Construct) {
  // Using AWS managed key (which has rotation managed by AWS)
  const bucket = new s3.Bucket(scope, 'ManagedKeyBucket', {
    encryption: s3.BucketEncryption.KMS_MANAGED,
  });
  
  return bucket;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_15(scope: Construct) {
  // Using imported key with rotation enabled
  const importedKeyId = 'arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab';
  const importedKey = kms.Key.fromKeyArn(scope, 'ImportedKey', importedKeyId);
  
  // Using the imported key (which we assume has rotation enabled)
  const secret = new secretsmanager.Secret(scope, 'ImportedKeySecret', {
    encryptionKey: importedKey,
  });
  
  return secret;
}
// {/fact}