import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as kms from 'aws-cdk-lib/aws-kms';

// True Positive Examples (Vulnerable Code)

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_1(scope: Construct) {
  // Creating an S3 bucket without specifying encryption
  // ruleid: typescript_cdk_s3_partial_encrypt
  const bucket = new s3.Bucket(scope, 'MyUnencryptedBucket', {
    versioned: true,
    publicReadAccess: false,
    blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_2(scope: Construct) {
  // Creating an S3 bucket with encryption explicitly set to UNENCRYPTED
  // ruleid: typescript_cdk_s3_partial_encrypt
  const bucket = new s3.Bucket(scope, 'ExplicitlyUnencryptedBucket', {
    encryption: s3.BucketEncryption.UNENCRYPTED,
    versioned: true,
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_3(scope: Construct) {
  // Creating multiple buckets with one being unencrypted
  const encryptedBucket = new s3.Bucket(scope, 'EncryptedBucket', {
    encryption: s3.BucketEncryption.S3_MANAGED,
  });
  
  // ruleid: typescript_cdk_s3_partial_encrypt
  const unencryptedBucket = new s3.Bucket(scope, 'UnencryptedBucket', {
    versioned: true,
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_4(scope: Construct) {
  // Creating a bucket with conditional encryption that might be unencrypted
  const shouldEncrypt = Math.random() > 0.5;
  
  // ruleid: typescript_cdk_s3_partial_encrypt
  const bucket = new s3.Bucket(scope, 'ConditionallyEncryptedBucket', {
    encryption: shouldEncrypt ? s3.BucketEncryption.S3_MANAGED : s3.BucketEncryption.UNENCRYPTED,
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_5(scope: Construct) {
  // Creating a bucket with minimal configuration
  // ruleid: typescript_cdk_s3_partial_encrypt
  const bucket = new s3.Bucket(scope, 'MinimalBucket', {});
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_6(scope: Construct) {
  // Creating a bucket with many properties but no encryption
  // ruleid: typescript_cdk_s3_partial_encrypt
  const bucket = new s3.Bucket(scope, 'FeatureRichUnencryptedBucket', {
    versioned: true,
    publicReadAccess: false,
    blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
    cors: [
      {
        allowedMethods: [s3.HttpMethods.GET],
        allowedOrigins: ['https://example.com'],
        allowedHeaders: ['*'],
      },
    ],
    lifecycleRules: [
      {
        expiration: cdk.Duration.days(365),
      },
    ],
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_7(scope: Construct) {
  const bucketProps = {
    versioned: true,
    publicReadAccess: false,
  };
  
  // ruleid: typescript_cdk_s3_partial_encrypt
  const bucket = new s3.Bucket(scope, 'PropsBucket', bucketProps);
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_8(scope: Construct, encryptionType: string) {
  let encryption;
  
  if (encryptionType === 'none') {
    encryption = s3.BucketEncryption.UNENCRYPTED;
  } else if (encryptionType === 's3') {
    encryption = s3.BucketEncryption.S3_MANAGED;
  }
  
  // ruleid: typescript_cdk_s3_partial_encrypt
  const bucket = new s3.Bucket(scope, 'DynamicEncryptionBucket', {
    encryption: encryption,
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_9(scope: Construct) {
  const configs = [
    { id: 'Bucket1', encrypt: true },
    { id: 'Bucket2', encrypt: false },
  ];
  
  configs.forEach(config => {
    if (config.encrypt) {
      const bucket = new s3.Bucket(scope, config.id, {
        encryption: s3.BucketEncryption.S3_MANAGED,
      });
    } else {
      // ruleid: typescript_cdk_s3_partial_encrypt
      const bucket = new s3.Bucket(scope, config.id, {});
    }
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_10(scope: Construct) {
  class CustomBucketStack extends cdk.Stack {
    constructor(scope: Construct, id: string, props?: cdk.StackProps) {
      super(scope, id, props);
      
      // ruleid: typescript_cdk_s3_partial_encrypt
      const bucket = new s3.Bucket(this, 'CustomBucket', {
        versioned: true,
      });
    }
  }
  
  new CustomBucketStack(scope, 'CustomBucketStack');
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_11(scope: Construct) {
  // Using a factory function that doesn't set encryption
  function createBucket(scope: Construct, id: string) {
    // ruleid: typescript_cdk_s3_partial_encrypt
    return new s3.Bucket(scope, id, {
      versioned: true,
      publicReadAccess: false,
    });
  }
  
  const bucket = createBucket(scope, 'FactoryBucket');
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_12(scope: Construct) {
  // Creating a bucket with encryption set to undefined
  // ruleid: typescript_cdk_s3_partial_encrypt
  const bucket = new s3.Bucket(scope, 'UndefinedEncryptionBucket', {
    encryption: undefined,
    versioned: true,
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_13(scope: Construct) {
  // Creating a bucket using object spread
  const baseProps = {
    versioned: true,
    publicReadAccess: false,
  };
  
  // ruleid: typescript_cdk_s3_partial_encrypt
  const bucket = new s3.Bucket(scope, 'SpreadBucket', {
    ...baseProps,
    removalPolicy: cdk.RemovalPolicy.DESTROY,
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_14(scope: Construct) {
  // Creating a bucket with encryption type from a variable that might be null
  const encryptionType = null;
  let encryption;
  
  if (encryptionType) {
    encryption = s3.BucketEncryption.S3_MANAGED;
  }
  
  // ruleid: typescript_cdk_s3_partial_encrypt
  const bucket = new s3.Bucket(scope, 'NullableEncryptionBucket', {
    encryption: encryption,
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_15(scope: Construct) {
  // Creating a bucket in a loop without encryption
  for (let i = 0; i < 3; i++) {
    // ruleid: typescript_cdk_s3_partial_encrypt
    const bucket = new s3.Bucket(scope, `LoopBucket${i}`, {
      versioned: i % 2 === 0,
    });
  }
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_1(scope: Construct) {
  // Creating an S3 bucket with S3_MANAGED encryption
  // ok: typescript_cdk_s3_partial_encrypt
  const bucket = new s3.Bucket(scope, 'S3ManagedBucket', {
    encryption: s3.BucketEncryption.S3_MANAGED,
    versioned: true,
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_2(scope: Construct) {
  // Creating an S3 bucket with KMS_MANAGED encryption
  // ok: typescript_cdk_s3_partial_encrypt
  const bucket = new s3.Bucket(scope, 'KmsManagedBucket', {
    encryption: s3.BucketEncryption.KMS_MANAGED,
    versioned: true,
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_3(scope: Construct) {
  // Creating an S3 bucket with custom KMS key
  const key = new kms.Key(scope, 'MyKey');
  
  // ok: typescript_cdk_s3_partial_encrypt
  const bucket = new s3.Bucket(scope, 'CustomKmsBucket', {
    encryption: s3.BucketEncryption.KMS,
    encryptionKey: key,
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_4(scope: Construct) {
  // Creating multiple buckets all with encryption
  // ok: typescript_cdk_s3_partial_encrypt
  const bucket1 = new s3.Bucket(scope, 'Bucket1', {
    encryption: s3.BucketEncryption.S3_MANAGED,
  });
  
  // ok: typescript_cdk_s3_partial_encrypt
  const bucket2 = new s3.Bucket(scope, 'Bucket2', {
    encryption: s3.BucketEncryption.KMS_MANAGED,
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_5(scope: Construct) {
  // Creating a bucket with conditional encryption that's always secure
  const useKms = Math.random() > 0.5;
  
  // ok: typescript_cdk_s3_partial_encrypt
  const bucket = new s3.Bucket(scope, 'ConditionallyEncryptedBucket', {
    encryption: useKms ? s3.BucketEncryption.KMS_MANAGED : s3.BucketEncryption.S3_MANAGED,
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_6(scope: Construct) {
  // Creating a bucket with many properties including encryption
  // ok: typescript_cdk_s3_partial_encrypt
  const bucket = new s3.Bucket(scope, 'FeatureRichEncryptedBucket', {
    encryption: s3.BucketEncryption.S3_MANAGED,
    versioned: true,
    publicReadAccess: false,
    blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
    cors: [
      {
        allowedMethods: [s3.HttpMethods.GET],
        allowedOrigins: ['https://example.com'],
        allowedHeaders: ['*'],
      },
    ],
    lifecycleRules: [
      {
        expiration: cdk.Duration.days(365),
      },
    ],
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_7(scope: Construct) {
  const bucketProps = {
    versioned: true,
    publicReadAccess: false,
    encryption: s3.BucketEncryption.S3_MANAGED,
  };
  
  // ok: typescript_cdk_s3_partial_encrypt
  const bucket = new s3.Bucket(scope, 'PropsBucket', bucketProps);
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_8(scope: Construct, useKms: boolean) {
  // ok: typescript_cdk_s3_partial_encrypt
  const bucket = new s3.Bucket(scope, 'DynamicEncryptionBucket', {
    encryption: useKms ? s3.BucketEncryption.KMS_MANAGED : s3.BucketEncryption.S3_MANAGED,
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_9(scope: Construct) {
  const configs = [
    { id: 'Bucket1', kms: true },
    { id: 'Bucket2', kms: false },
  ];
  
  configs.forEach(config => {
    // ok: typescript_cdk_s3_partial_encrypt
    const bucket = new s3.Bucket(scope, config.id, {
      encryption: config.kms ? s3.BucketEncryption.KMS_MANAGED : s3.BucketEncryption.S3_MANAGED,
    });
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_10(scope: Construct) {
  class CustomBucketStack extends cdk.Stack {
    constructor(scope: Construct, id: string, props?: cdk.StackProps) {
      super(scope, id, props);
      
      // ok: typescript_cdk_s3_partial_encrypt
      const bucket = new s3.Bucket(this, 'CustomBucket', {
        encryption: s3.BucketEncryption.S3_MANAGED,
        versioned: true,
      });
    }
  }
  
  new CustomBucketStack(scope, 'CustomBucketStack');
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_11(scope: Construct) {
  // Using a factory function that sets encryption
  function createBucket(scope: Construct, id: string) {
    // ok: typescript_cdk_s3_partial_encrypt
    return new s3.Bucket(scope, id, {
      encryption: s3.BucketEncryption.S3_MANAGED,
      versioned: true,
      publicReadAccess: false,
    });
  }
  
  const bucket = createBucket(scope, 'FactoryBucket');
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_12(scope: Construct) {
  // Creating a bucket with explicitly set encryption
  // ok: typescript_cdk_s3_partial_encrypt
  const bucket = new s3.Bucket(scope, 'ExplicitEncryptionBucket', {
    encryption: s3.BucketEncryption.KMS_MANAGED,
    versioned: true,
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_13(scope: Construct) {
  // Creating a bucket using object spread with encryption
  const baseProps = {
    versioned: true,
    publicReadAccess: false,
  };
  
  // ok: typescript_cdk_s3_partial_encrypt
  const bucket = new s3.Bucket(scope, 'SpreadBucket', {
    ...baseProps,
    encryption: s3.BucketEncryption.S3_MANAGED,
    removalPolicy: cdk.RemovalPolicy.DESTROY,
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_14(scope: Construct) {
  // Creating a bucket with imported KMS key
  const importedKey = kms.Key.fromKeyArn(scope, 'ImportedKey', 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012');
  
  // ok: typescript_cdk_s3_partial_encrypt
  const bucket = new s3.Bucket(scope, 'ImportedKeyBucket', {
    encryption: s3.BucketEncryption.KMS,
    encryptionKey: importedKey,
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_15(scope: Construct) {
  // Creating buckets in a loop with encryption
  for (let i = 0; i < 3; i++) {
    // ok: typescript_cdk_s3_partial_encrypt
    const bucket = new s3.Bucket(scope, `LoopBucket${i}`, {
      encryption: s3.BucketEncryption.S3_MANAGED,
      versioned: i % 2 === 0,
    });
  }
}
// {/fact}