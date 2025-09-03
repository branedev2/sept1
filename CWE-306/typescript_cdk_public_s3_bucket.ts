import { Stack, App } from 'aws-cdk-lib';
import { Construct } from 'constructs';
import { Bucket, BlockPublicAccess, BucketAccessControl, ObjectOwnership } from 'aws-cdk-lib/aws-s3';
import { Effect, PolicyStatement, AnyPrincipal } from 'aws-cdk-lib/aws-iam';

// True Positives (Vulnerable Code)

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_1() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  // ruleid: typescript_cdk_public_s3_bucket
  const bucket = new Bucket(stack, 'MyPublicBucket', {
    publicReadAccess: true,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_2() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  const bucket = new Bucket(stack, 'MyBucket');
  
  // ruleid: typescript_cdk_public_s3_bucket
  bucket.grantPublicAccess();
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_3() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  const bucket = new Bucket(stack, 'MyBucket');
  
  // ruleid: typescript_cdk_public_s3_bucket
  bucket.grantPublicAccess('*', 's3:GetObject');
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_4() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  // ruleid: typescript_cdk_public_s3_bucket
  const bucket = new Bucket(stack, 'MyBucket', {
    accessControl: BucketAccessControl.PUBLIC_READ,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_5() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  // ruleid: typescript_cdk_public_s3_bucket
  const bucket = new Bucket(stack, 'MyBucket', {
    blockPublicAccess: BlockPublicAccess.BLOCK_ACLS,  // Only blocks ACLs, not policies
    publicReadAccess: true,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_6() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  const bucket = new Bucket(stack, 'MyBucket');
  
  // ruleid: typescript_cdk_public_s3_bucket
  bucket.addToResourcePolicy(new PolicyStatement({
    effect: Effect.ALLOW,
    principals: [new AnyPrincipal()],
    actions: ['s3:GetObject'],
    resources: [bucket.arnForObjects('*')],
  }));
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_7() {
  class MyBucketStack extends Stack {
    constructor(scope: Construct, id: string) {
      super(scope, id);
      
      // ruleid: typescript_cdk_public_s3_bucket
      const bucket = new Bucket(this, 'MyBucket', {
        publicReadAccess: true,
        blockPublicAccess: BlockPublicAccess.BLOCK_ACLS,
      });
    }
  }
  
  const app = new App();
  new MyBucketStack(app, 'MyBucketStack');
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_8() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  const isPublic = true;
  
  // ruleid: typescript_cdk_public_s3_bucket
  const bucket = new Bucket(stack, 'MyBucket', {
    publicReadAccess: isPublic,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_9() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  const bucket = new Bucket(stack, 'MyBucket');
  
  // ruleid: typescript_cdk_public_s3_bucket
  bucket.addToResourcePolicy(new PolicyStatement({
    effect: Effect.ALLOW,
    principals: [new AnyPrincipal()],
    actions: ['s3:*'],
    resources: [`${bucket.bucketArn}/*`],
  }));
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_10() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  // ruleid: typescript_cdk_public_s3_bucket
  const bucket = new Bucket(stack, 'MyBucket', {
    accessControl: BucketAccessControl.PUBLIC_READ_WRITE,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_11() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  const bucket = new Bucket(stack, 'MyBucket');
  
  // ruleid: typescript_cdk_public_s3_bucket
  bucket.grantPublicAccess('index.html', 's3:GetObject');
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_12() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  // ruleid: typescript_cdk_public_s3_bucket
  const bucket = new Bucket(stack, 'WebsiteBucket', {
    websiteIndexDocument: 'index.html',
    publicReadAccess: true,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_13() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  const bucketProps = {
    publicReadAccess: true,
  };
  
  // ruleid: typescript_cdk_public_s3_bucket
  const bucket = new Bucket(stack, 'MyBucket', bucketProps);
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_14() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  const bucket = new Bucket(stack, 'MyBucket');
  
  const statement = new PolicyStatement({
    effect: Effect.ALLOW,
    principals: [new AnyPrincipal()],
    actions: ['s3:GetObject'],
    resources: [bucket.arnForObjects('*')],
  });
  
  // ruleid: typescript_cdk_public_s3_bucket
  bucket.addToResourcePolicy(statement);
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_15() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  // ruleid: typescript_cdk_public_s3_bucket
  const bucket = new Bucket(stack, 'MyBucket', {
    blockPublicAccess: new BlockPublicAccess({
      blockPublicAcls: true,
      blockPublicPolicy: false,
      ignorePublicAcls: true,
      restrictPublicBuckets: false,
    }),
    publicReadAccess: true,
  });
}
// {/fact}

// True Negatives (Secure Code)

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_1() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  // ok: typescript_cdk_public_s3_bucket
  const bucket = new Bucket(stack, 'MyPrivateBucket', {
    publicReadAccess: false,
    blockPublicAccess: BlockPublicAccess.BLOCK_ALL,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_2() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  // ok: typescript_cdk_public_s3_bucket
  const bucket = new Bucket(stack, 'MyBucket');  // Default is private
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_3() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  // ok: typescript_cdk_public_s3_bucket
  const bucket = new Bucket(stack, 'MyBucket', {
    blockPublicAccess: BlockPublicAccess.BLOCK_ALL,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_4() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  const bucket = new Bucket(stack, 'MyBucket');
  
  // ok: typescript_cdk_public_s3_bucket
  bucket.addToResourcePolicy(new PolicyStatement({
    effect: Effect.ALLOW,
    principals: [{ accountId: '123456789012' }],  // Specific account, not public
    actions: ['s3:GetObject'],
    resources: [bucket.arnForObjects('*')],
  }));
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_5() {
  class MySecureBucketStack extends Stack {
    constructor(scope: Construct, id: string) {
      super(scope, id);
      
      // ok: typescript_cdk_public_s3_bucket
      const bucket = new Bucket(this, 'MyBucket', {
        blockPublicAccess: BlockPublicAccess.BLOCK_ALL,
        encryption: BucketEncryption.S3_MANAGED,
      });
    }
  }
  
  const app = new App();
  new MySecureBucketStack(app, 'MySecureBucketStack');
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_6() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  // ok: typescript_cdk_public_s3_bucket
  const bucket = new Bucket(stack, 'MyBucket', {
    objectOwnership: ObjectOwnership.BUCKET_OWNER_ENFORCED,  // Disables ACLs
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_7() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  const isPublic = false;
  
  // ok: typescript_cdk_public_s3_bucket
  const bucket = new Bucket(stack, 'MyBucket', {
    publicReadAccess: isPublic,
    blockPublicAccess: BlockPublicAccess.BLOCK_ALL,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_8() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  // ok: typescript_cdk_public_s3_bucket
  const bucket = new Bucket(stack, 'MyBucket', {
    accessControl: BucketAccessControl.PRIVATE,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_9() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  const bucket = new Bucket(stack, 'MyBucket');
  
  // Using a specific IAM role instead of public access
  // ok: typescript_cdk_public_s3_bucket
  const role = new Role(stack, 'MyRole', {
    assumedBy: new ServicePrincipal('lambda.amazonaws.com'),
  });
  
  bucket.grantRead(role);
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_10() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  // ok: typescript_cdk_public_s3_bucket
  const bucket = new Bucket(stack, 'MyBucket', {
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
function good_case_11() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  const bucketProps = {
    blockPublicAccess: BlockPublicAccess.BLOCK_ALL,
    publicReadAccess: false,
  };
  
  // ok: typescript_cdk_public_s3_bucket
  const bucket = new Bucket(stack, 'MyBucket', bucketProps);
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_12() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  // Using CloudFront to serve content instead of making bucket public
  // ok: typescript_cdk_public_s3_bucket
  const bucket = new Bucket(stack, 'WebsiteBucket', {
    blockPublicAccess: BlockPublicAccess.BLOCK_ALL,
  });
  
  const distribution = new CloudFrontWebDistribution(stack, 'Distribution', {
    originConfigs: [
      {
        s3OriginSource: {
          s3BucketSource: bucket,
        },
        behaviors: [{ isDefaultBehavior: true }],
      },
    ],
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_13() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  // ok: typescript_cdk_public_s3_bucket
  const bucket = new Bucket(stack, 'MyBucket', {
    versioned: true,
    blockPublicAccess: BlockPublicAccess.BLOCK_ALL,
    enforceSSL: true,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_14() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  // ok: typescript_cdk_public_s3_bucket
  const logBucket = new Bucket(stack, 'LogBucket', {
    blockPublicAccess: BlockPublicAccess.BLOCK_ALL,
  });
  
  const dataBucket = new Bucket(stack, 'DataBucket', {
    blockPublicAccess: BlockPublicAccess.BLOCK_ALL,
    serverAccessLogsBucket: logBucket,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_15() {
  const app = new App();
  const stack = new Stack(app, 'MyStack');
  
  // ok: typescript_cdk_public_s3_bucket
  const bucket = new Bucket(stack, 'MyBucket', {
    removalPolicy: RemovalPolicy.RETAIN,
    autoDeleteObjects: false,
    blockPublicAccess: BlockPublicAccess.BLOCK_ALL,
  });
}
// {/fact}