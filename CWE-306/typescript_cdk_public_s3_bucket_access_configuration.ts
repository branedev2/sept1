import { Stack, StackProps } from 'aws-cdk-lib';
import { Construct } from 'constructs';
import { Bucket, BlockPublicAccess, BucketAccessControl } from 'aws-cdk-lib/aws-s3';

// True Positives (Vulnerable Code)

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_1() {
  const stack = new Stack();
  // ruleid: typescript_cdk_public_s3_bucket_access_configuration
  new Bucket(stack, 'MyBucket', {
    publicReadAccess: true,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_2() {
  const stack = new Stack();
  // ruleid: typescript_cdk_public_s3_bucket_access_configuration
  new Bucket(stack, 'MyBucket', {
    blockPublicAccess: BlockPublicAccess.BLOCK_ACLS,
    accessControl: BucketAccessControl.PUBLIC_READ,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_3() {
  const stack = new Stack();
  // ruleid: typescript_cdk_public_s3_bucket_access_configuration
  new Bucket(stack, 'MyBucket', {
    blockPublicAccess: new BlockPublicAccess({
      blockPublicAcls: false,
      blockPublicPolicy: false,
      ignorePublicAcls: false,
      restrictPublicBuckets: false,
    }),
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_4() {
  const stack = new Stack();
  const isPublic = true;
  // ruleid: typescript_cdk_public_s3_bucket_access_configuration
  new Bucket(stack, 'MyBucket', {
    publicReadAccess: isPublic,
    blockPublicAccess: BlockPublicAccess.BLOCK_ACLS,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_5() {
  const stack = new Stack();
  // ruleid: typescript_cdk_public_s3_bucket_access_configuration
  const bucket = new Bucket(stack, 'MyBucket');
  bucket.grantPublicAccess();
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_6() {
  const stack = new Stack();
  // ruleid: typescript_cdk_public_s3_bucket_access_configuration
  const bucket = new Bucket(stack, 'MyBucket', {
    accessControl: BucketAccessControl.PUBLIC_READ_WRITE,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_7() {
  const stack = new Stack();
  // ruleid: typescript_cdk_public_s3_bucket_access_configuration
  const bucket = new Bucket(stack, 'MyBucket', {
    blockPublicAccess: BlockPublicAccess.BLOCK_ACLS,
  });
  bucket.grantPublicAccess('*', 's3:GetObject');
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_8() {
  const stack = new Stack();
  const config = {
    publicReadAccess: true,
    versioned: true,
  };
  // ruleid: typescript_cdk_public_s3_bucket_access_configuration
  new Bucket(stack, 'MyBucket', config);
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_9() {
  class WebsiteStack extends Stack {
    constructor(scope: Construct, id: string, props?: StackProps) {
      super(scope, id, props);
      
      // ruleid: typescript_cdk_public_s3_bucket_access_configuration
      new Bucket(this, 'WebsiteBucket', {
        websiteIndexDocument: 'index.html',
        websiteErrorDocument: 'error.html',
        publicReadAccess: true,
      });
    }
  }
  
  const app = new Construct(null, 'App');
  new WebsiteStack(app, 'WebsiteStack');
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_10() {
  const stack = new Stack();
  // ruleid: typescript_cdk_public_s3_bucket_access_configuration
  const bucket = new Bucket(stack, 'MyBucket', {
    blockPublicAccess: {
      blockPublicAcls: false,
      blockPublicPolicy: false,
      ignorePublicAcls: true,
      restrictPublicBuckets: false,
    },
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_11() {
  const stack = new Stack();
  const blockSetting = false;
  // ruleid: typescript_cdk_public_s3_bucket_access_configuration
  const bucket = new Bucket(stack, 'MyBucket', {
    blockPublicAccess: {
      blockPublicAcls: blockSetting,
      blockPublicPolicy: blockSetting,
      ignorePublicAcls: blockSetting,
      restrictPublicBuckets: blockSetting,
    },
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_12() {
  const stack = new Stack();
  // ruleid: typescript_cdk_public_s3_bucket_access_configuration
  const bucket = new Bucket(stack, 'MyBucket', {});
  bucket.addToResourcePolicy({
    effect: 'Allow',
    principal: { AWS: '*' },
    actions: ['s3:GetObject'],
    resources: [bucket.arnForObjects('*')],
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_13() {
  const stack = new Stack();
  const accessControl = BucketAccessControl.PUBLIC_READ;
  // ruleid: typescript_cdk_public_s3_bucket_access_configuration
  new Bucket(stack, 'MyBucket', {
    accessControl: accessControl,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_14() {
  const stack = new Stack();
  function createBucket(isPublic: boolean) {
    // ruleid: typescript_cdk_public_s3_bucket_access_configuration
    return new Bucket(stack, 'MyBucket', {
      publicReadAccess: isPublic,
    });
  }
  createBucket(true);
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_15() {
  const stack = new Stack();
  const bucketProps = {
    versioned: true,
    blockPublicAccess: BlockPublicAccess.BLOCK_ACLS,
    accessControl: BucketAccessControl.PUBLIC_READ,
  };
  // ruleid: typescript_cdk_public_s3_bucket_access_configuration
  new Bucket(stack, 'MyBucket', bucketProps);
}
// {/fact}

// True Negatives (Secure Code)

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_1() {
  const stack = new Stack();
  // ok: typescript_cdk_public_s3_bucket_access_configuration
  new Bucket(stack, 'MyBucket', {
    blockPublicAccess: BlockPublicAccess.BLOCK_ALL,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_2() {
  const stack = new Stack();
  // ok: typescript_cdk_public_s3_bucket_access_configuration
  new Bucket(stack, 'MyBucket', {
    publicReadAccess: false,
    blockPublicAccess: BlockPublicAccess.BLOCK_ALL,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_3() {
  const stack = new Stack();
  // ok: typescript_cdk_public_s3_bucket_access_configuration
  new Bucket(stack, 'MyBucket', {
    blockPublicAccess: new BlockPublicAccess({
      blockPublicAcls: true,
      blockPublicPolicy: true,
      ignorePublicAcls: true,
      restrictPublicBuckets: true,
    }),
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_4() {
  const stack = new Stack();
  // ok: typescript_cdk_public_s3_bucket_access_configuration
  new Bucket(stack, 'MyBucket', {
    accessControl: BucketAccessControl.PRIVATE,
    blockPublicAccess: BlockPublicAccess.BLOCK_ALL,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_5() {
  const stack = new Stack();
  // ok: typescript_cdk_public_s3_bucket_access_configuration
  const bucket = new Bucket(stack, 'MyBucket', {
    blockPublicAccess: BlockPublicAccess.BLOCK_ALL,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_6() {
  class SecureWebsiteStack extends Stack {
    constructor(scope: Construct, id: string, props?: StackProps) {
      super(scope, id, props);
      
      // ok: typescript_cdk_public_s3_bucket_access_configuration
      const bucket = new Bucket(this, 'WebsiteBucket', {
        blockPublicAccess: BlockPublicAccess.BLOCK_ALL,
      });
      
      // Use CloudFront distribution instead of public access
      // const distribution = new CloudFront.Distribution(...);
    }
  }
  
  const app = new Construct(null, 'App');
  new SecureWebsiteStack(app, 'SecureWebsiteStack');
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_7() {
  const stack = new Stack();
  const isPublic = false;
  // ok: typescript_cdk_public_s3_bucket_access_configuration
  new Bucket(stack, 'MyBucket', {
    publicReadAccess: isPublic,
    blockPublicAccess: BlockPublicAccess.BLOCK_ALL,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_8() {
  const stack = new Stack();
  // ok: typescript_cdk_public_s3_bucket_access_configuration
  const bucket = new Bucket(stack, 'MyBucket', {
    blockPublicAccess: {
      blockPublicAcls: true,
      blockPublicPolicy: true,
      ignorePublicAcls: true,
      restrictPublicBuckets: true,
    },
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_9() {
  const stack = new Stack();
  const blockSetting = true;
  // ok: typescript_cdk_public_s3_bucket_access_configuration
  const bucket = new Bucket(stack, 'MyBucket', {
    blockPublicAccess: {
      blockPublicAcls: blockSetting,
      blockPublicPolicy: blockSetting,
      ignorePublicAcls: blockSetting,
      restrictPublicBuckets: blockSetting,
    },
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_10() {
  const stack = new Stack();
  const config = {
    publicReadAccess: false,
    versioned: true,
    blockPublicAccess: BlockPublicAccess.BLOCK_ALL,
  };
  // ok: typescript_cdk_public_s3_bucket_access_configuration
  new Bucket(stack, 'MyBucket', config);
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_11() {
  const stack = new Stack();
  // ok: typescript_cdk_public_s3_bucket_access_configuration
  const bucket = new Bucket(stack, 'MyBucket', {
    blockPublicAccess: BlockPublicAccess.BLOCK_ALL,
  });
  
  // Grant access to specific IAM role instead of public access
  // const role = new iam.Role(...);
  // bucket.grantRead(role);
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_12() {
  const stack = new Stack();
  function createSecureBucket(name: string) {
    // ok: typescript_cdk_public_s3_bucket_access_configuration
    return new Bucket(stack, name, {
      blockPublicAccess: BlockPublicAccess.BLOCK_ALL,
      accessControl: BucketAccessControl.PRIVATE,
    });
  }
  createSecureBucket('SecureBucket');
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_13() {
  const stack = new Stack();
  const accessControl = BucketAccessControl.PRIVATE;
  // ok: typescript_cdk_public_s3_bucket_access_configuration
  new Bucket(stack, 'MyBucket', {
    accessControl: accessControl,
    blockPublicAccess: BlockPublicAccess.BLOCK_ALL,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_14() {
  const stack = new Stack();
  const bucketProps = {
    versioned: true,
    blockPublicAccess: BlockPublicAccess.BLOCK_ALL,
    accessControl: BucketAccessControl.PRIVATE,
  };
  // ok: typescript_cdk_public_s3_bucket_access_configuration
  new Bucket(stack, 'MyBucket', bucketProps);
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_15() {
  const stack = new Stack();
  // Default configuration with no explicit parameters is now secure in newer CDK versions
  // ok: typescript_cdk_public_s3_bucket_access_configuration
  const bucket = new Bucket(stack, 'MyBucket');
  // In newer CDK versions, BlockPublicAccess.BLOCK_ALL is the default
}
// {/fact}