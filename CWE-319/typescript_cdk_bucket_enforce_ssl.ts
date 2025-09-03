import { Stack, App, StackProps } from 'aws-cdk-lib';
import { Bucket, BucketEncryption, BlockPublicAccess } from 'aws-cdk-lib/aws-s3';
import { PolicyStatement, Effect, AnyPrincipal } from 'aws-cdk-lib/aws-iam';

// True Positives (Vulnerable Cases)

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_1() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  // ruleid: typescript_cdk_bucket_enforce_ssl
  const bucket = new Bucket(stack, 'MyBucket', {
    encryption: BucketEncryption.S3_MANAGED,
    blockPublicAccess: BlockPublicAccess.BLOCK_ALL,
    // Missing enforceSSL property
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_2() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  // ruleid: typescript_cdk_bucket_enforce_ssl
  const bucket = new Bucket(stack, 'LogBucket', {
    versioned: true,
    // No SSL enforcement configured
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_3() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  // ruleid: typescript_cdk_bucket_enforce_ssl
  const bucket = new Bucket(stack, 'DataBucket', {
    encryption: BucketEncryption.KMS,
    enforceSSL: false // Explicitly disabled SSL enforcement
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_4() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  const bucketProps = {
    versioned: true,
    encryption: BucketEncryption.S3_MANAGED,
    // Missing enforceSSL
  };
  
  // ruleid: typescript_cdk_bucket_enforce_ssl
  const bucket = new Bucket(stack, 'ConfigBucket', bucketProps);
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_5() {
  class StorageStack extends Stack {
    constructor(scope: App, id: string, props?: StackProps) {
      super(scope, id, props);
      
      // ruleid: typescript_cdk_bucket_enforce_ssl
      const bucket = new Bucket(this, 'AssetBucket', {
        removalPolicy: RemovalPolicy.DESTROY,
        autoDeleteObjects: true,
        // Missing enforceSSL
      });
    }
  }
  
  const app = new App();
  new StorageStack(app, 'StorageStack');
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_6() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  // ruleid: typescript_cdk_bucket_enforce_ssl
  const bucket = new Bucket(stack, 'AnalyticsBucket', {});
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_7() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  const bucketConfig = {
    versioned: true,
    encryption: BucketEncryption.KMS_MANAGED,
    enforceSSL: false // Explicitly set to false
  };
  
  // ruleid: typescript_cdk_bucket_enforce_ssl
  const bucket = new Bucket(stack, 'ReportsBucket', bucketConfig);
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_8() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  // ruleid: typescript_cdk_bucket_enforce_ssl
  const bucket1 = new Bucket(stack, 'PrimaryBucket', {
    versioned: true
  });
  
  // ruleid: typescript_cdk_bucket_enforce_ssl
  const bucket2 = new Bucket(stack, 'SecondaryBucket', {
    versioned: false
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_9() {
  class DataStack extends Stack {
    constructor(scope: App, id: string) {
      super(scope, id);
      
      const config = {
        encryption: BucketEncryption.S3_MANAGED,
        blockPublicAccess: BlockPublicAccess.BLOCK_ALL,
        // Missing enforceSSL
      };
      
      // ruleid: typescript_cdk_bucket_enforce_ssl
      new Bucket(this, 'DataLakeBucket', config);
    }
  }
  
  const app = new App();
  new DataStack(app, 'DataStack');
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_10() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  function createBucket(id: string) {
    // ruleid: typescript_cdk_bucket_enforce_ssl
    return new Bucket(stack, id, {
      versioned: true,
      encryption: BucketEncryption.KMS,
      // Missing enforceSSL
    });
  }
  
  const bucket = createBucket('DynamicBucket');
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_11() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  const enforceSSL = false; // This is insecure
  
  // ruleid: typescript_cdk_bucket_enforce_ssl
  const bucket = new Bucket(stack, 'InsecureBucket', {
    enforceSSL: enforceSSL
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_12() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  // ruleid: typescript_cdk_bucket_enforce_ssl
  const bucket = new Bucket(stack, 'WebsiteHostingBucket', {
    websiteIndexDocument: 'index.html',
    websiteErrorDocument: 'error.html',
    // Missing enforceSSL
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_13() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  const shouldEnforceSSL = () => {
    // Some complex logic that returns false
    return false;
  };
  
  // ruleid: typescript_cdk_bucket_enforce_ssl
  const bucket = new Bucket(stack, 'DynamicConfigBucket', {
    enforceSSL: shouldEnforceSSL()
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_14() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  const bucketProps = {};
  
  // ruleid: typescript_cdk_bucket_enforce_ssl
  const bucket = new Bucket(stack, 'MinimalBucket', bucketProps);
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_15() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  // ruleid: typescript_cdk_bucket_enforce_ssl
  const bucket = new Bucket(stack, 'BackupBucket', {
    encryption: BucketEncryption.S3_MANAGED,
    versioned: true,
    lifecycleRules: [
      {
        expiration: Duration.days(365),
      }
    ],
    // Missing enforceSSL
  });
}
// {/fact}

// True Negatives (Secure Cases)

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_1() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  // ok: typescript_cdk_bucket_enforce_ssl
  const bucket = new Bucket(stack, 'SecureBucket', {
    encryption: BucketEncryption.S3_MANAGED,
    blockPublicAccess: BlockPublicAccess.BLOCK_ALL,
    enforceSSL: true
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_2() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  const bucketProps = {
    versioned: true,
    encryption: BucketEncryption.S3_MANAGED,
    enforceSSL: true
  };
  
  // ok: typescript_cdk_bucket_enforce_ssl
  const bucket = new Bucket(stack, 'SecureConfigBucket', bucketProps);
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_3() {
  class SecureStorageStack extends Stack {
    constructor(scope: App, id: string, props?: StackProps) {
      super(scope, id, props);
      
      // ok: typescript_cdk_bucket_enforce_ssl
      const bucket = new Bucket(this, 'SecureAssetBucket', {
        removalPolicy: RemovalPolicy.DESTROY,
        autoDeleteObjects: true,
        enforceSSL: true
      });
    }
  }
  
  const app = new App();
  new SecureStorageStack(app, 'SecureStorageStack');
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_4() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  // ok: typescript_cdk_bucket_enforce_ssl
  const bucket = new Bucket(stack, 'MinimalSecureBucket', {
    enforceSSL: true
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_5() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  const enforceSSL = true;
  
  // ok: typescript_cdk_bucket_enforce_ssl
  const bucket = new Bucket(stack, 'DynamicSecureBucket', {
    enforceSSL: enforceSSL
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_6() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  function createSecureBucket(id: string) {
    // ok: typescript_cdk_bucket_enforce_ssl
    return new Bucket(stack, id, {
      versioned: true,
      encryption: BucketEncryption.KMS,
      enforceSSL: true
    });
  }
  
  const bucket = createSecureBucket('DynamicSecureBucket');
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_7() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  // ok: typescript_cdk_bucket_enforce_ssl
  const bucket = new Bucket(stack, 'SecureWebsiteBucket', {
    websiteIndexDocument: 'index.html',
    websiteErrorDocument: 'error.html',
    enforceSSL: true
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_8() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  const shouldEnforceSSL = () => {
    // Some complex logic that returns true
    return true;
  };
  
  // ok: typescript_cdk_bucket_enforce_ssl
  const bucket = new Bucket(stack, 'DynamicSecureConfigBucket', {
    enforceSSL: shouldEnforceSSL()
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_9() {
  class DataStack extends Stack {
    constructor(scope: App, id: string) {
      super(scope, id);
      
      const config = {
        encryption: BucketEncryption.S3_MANAGED,
        blockPublicAccess: BlockPublicAccess.BLOCK_ALL,
        enforceSSL: true
      };
      
      // ok: typescript_cdk_bucket_enforce_ssl
      new Bucket(this, 'SecureDataLakeBucket', config);
    }
  }
  
  const app = new App();
  new DataStack(app, 'SecureDataStack');
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_10() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  // ok: typescript_cdk_bucket_enforce_ssl
  const bucket = new Bucket(stack, 'SecureBackupBucket', {
    encryption: BucketEncryption.S3_MANAGED,
    versioned: true,
    lifecycleRules: [
      {
        expiration: Duration.days(365),
      }
    ],
    enforceSSL: true
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_11() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  // Alternative approach: using bucket policy to enforce SSL
  const bucket = new Bucket(stack, 'PolicySecuredBucket');
  
  // ok: typescript_cdk_bucket_enforce_ssl
  bucket.addToResourcePolicy(
    new PolicyStatement({
      effect: Effect.DENY,
      principals: [new AnyPrincipal()],
      actions: ['s3:*'],
      resources: [bucket.bucketArn, `${bucket.bucketArn}/*`],
      conditions: {
        'Bool': {
          'aws:SecureTransport': 'false'
        }
      }
    })
  );
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_12() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  // ok: typescript_cdk_bucket_enforce_ssl
  const bucket1 = new Bucket(stack, 'PrimarySecureBucket', {
    versioned: true,
    enforceSSL: true
  });
  
  // ok: typescript_cdk_bucket_enforce_ssl
  const bucket2 = new Bucket(stack, 'SecondarySecureBucket', {
    versioned: false,
    enforceSSL: true
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_13() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  const getSecureBucketConfig = () => {
    return {
      encryption: BucketEncryption.KMS_MANAGED,
      enforceSSL: true
    };
  };
  
  // ok: typescript_cdk_bucket_enforce_ssl
  const bucket = new Bucket(stack, 'FunctionConfigBucket', getSecureBucketConfig());
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_14() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  const isProduction = true;
  
  // ok: typescript_cdk_bucket_enforce_ssl
  const bucket = new Bucket(stack, 'EnvironmentAwareBucket', {
    enforceSSL: isProduction ? true : true, // Always true regardless of environment
    encryption: isProduction ? BucketEncryption.KMS : BucketEncryption.S3_MANAGED
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_15() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  class SecureBucketFactory {
    static create(stack: Stack, id: string) {
      // ok: typescript_cdk_bucket_enforce_ssl
      return new Bucket(stack, id, {
        enforceSSL: true,
        encryption: BucketEncryption.S3_MANAGED
      });
    }
  }
  
  const bucket = SecureBucketFactory.create(stack, 'FactoryBucket');
}
// {/fact}