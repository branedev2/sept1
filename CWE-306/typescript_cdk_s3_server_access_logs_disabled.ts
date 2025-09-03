import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as logs from 'aws-cdk-lib/aws-logs';

class TestStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);
  }
}

// True Positive Cases (Vulnerable Code)

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_1() {
  const app = new cdk.App();
  const stack = new TestStack(app, 'TestStack');
  
  // ruleid: typescript_cdk_s3_server_access_logs_disabled
  new s3.Bucket(stack, 'MyBucket1', {
    versioned: true,
    encryption: s3.BucketEncryption.S3_MANAGED,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_2() {
  const app = new cdk.App();
  const stack = new TestStack(app, 'TestStack');
  
  // ruleid: typescript_cdk_s3_server_access_logs_disabled
  const bucket = new s3.Bucket(stack, 'MyBucket2', {
    removalPolicy: cdk.RemovalPolicy.DESTROY,
    autoDeleteObjects: true,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_3() {
  const app = new cdk.App();
  const stack = new TestStack(app, 'TestStack');
  
  // ruleid: typescript_cdk_s3_server_access_logs_disabled
  const bucket = new s3.Bucket(stack, 'MyBucket3', {
    publicReadAccess: false,
    blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
    encryption: s3.BucketEncryption.KMS,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_4() {
  const app = new cdk.App();
  const stack = new TestStack(app, 'TestStack');
  
  const bucketProps: s3.BucketProps = {
    versioned: true,
    encryption: s3.BucketEncryption.KMS_MANAGED,
  };
  
  // ruleid: typescript_cdk_s3_server_access_logs_disabled
  new s3.Bucket(stack, 'MyBucket4', bucketProps);
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_5() {
  const app = new cdk.App();
  const stack = new TestStack(app, 'TestStack');
  
  // ruleid: typescript_cdk_s3_server_access_logs_disabled
  const bucket = new s3.Bucket(stack, 'MyBucket5');
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_6() {
  const app = new cdk.App();
  const stack = new TestStack(app, 'TestStack');
  
  // ruleid: typescript_cdk_s3_server_access_logs_disabled
  const bucket = new s3.Bucket(stack, 'MyBucket6', {
    websiteIndexDocument: 'index.html',
    websiteErrorDocument: 'error.html',
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_7() {
  const app = new cdk.App();
  const stack = new TestStack(app, 'TestStack');
  
  const props = {};
  
  // ruleid: typescript_cdk_s3_server_access_logs_disabled
  const bucket = new s3.Bucket(stack, 'MyBucket7', props as s3.BucketProps);
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_8() {
  const app = new cdk.App();
  const stack = new TestStack(app, 'TestStack');
  
  // Creating multiple buckets without logging
  // ruleid: typescript_cdk_s3_server_access_logs_disabled
  const bucket1 = new s3.Bucket(stack, 'MyBucket8a');
  
  // ruleid: typescript_cdk_s3_server_access_logs_disabled
  const bucket2 = new s3.Bucket(stack, 'MyBucket8b', {
    versioned: true,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_9() {
  const app = new cdk.App();
  const stack = new TestStack(app, 'TestStack');
  
  const createBucket = () => {
    // ruleid: typescript_cdk_s3_server_access_logs_disabled
    return new s3.Bucket(stack, 'MyBucket9', {
      encryption: s3.BucketEncryption.KMS,
    });
  };
  
  const bucket = createBucket();
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_10() {
  class CustomStack extends cdk.Stack {
    constructor(scope: Construct, id: string) {
      super(scope, id);
      
      // ruleid: typescript_cdk_s3_server_access_logs_disabled
      new s3.Bucket(this, 'MyBucket10', {
        versioned: true,
      });
    }
  }
  
  const app = new cdk.App();
  new CustomStack(app, 'CustomStack');
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_11() {
  const app = new cdk.App();
  const stack = new TestStack(app, 'TestStack');
  
  // Setting serverAccessLogsPrefix but no destination bucket
  // ruleid: typescript_cdk_s3_server_access_logs_disabled
  const bucket = new s3.Bucket(stack, 'MyBucket11', {
    serverAccessLogsPrefix: 'logs/',
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_12() {
  const app = new cdk.App();
  const stack = new TestStack(app, 'TestStack');
  
  // Empty serverAccessLogsBucket property
  // ruleid: typescript_cdk_s3_server_access_logs_disabled
  const bucket = new s3.Bucket(stack, 'MyBucket12', {
    serverAccessLogsBucket: undefined,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_13() {
  const app = new cdk.App();
  const stack = new TestStack(app, 'TestStack');
  
  // Setting other security features but not access logs
  // ruleid: typescript_cdk_s3_server_access_logs_disabled
  const bucket = new s3.Bucket(stack, 'MyBucket13', {
    encryption: s3.BucketEncryption.KMS,
    blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
    versioned: true,
    enforceSSL: true,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_14() {
  const app = new cdk.App();
  const stack = new TestStack(app, 'TestStack');
  
  const bucketProps = {};
  Object.assign(bucketProps, {
    versioned: true,
    encryption: s3.BucketEncryption.S3_MANAGED,
  });
  
  // ruleid: typescript_cdk_s3_server_access_logs_disabled
  new s3.Bucket(stack, 'MyBucket14', bucketProps as s3.BucketProps);
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_15() {
  const app = new cdk.App();
  const stack = new TestStack(app, 'TestStack');
  
  const config = {
    enableVersioning: true,
    enableEncryption: true,
    enableLogging: false,
  };
  
  // ruleid: typescript_cdk_s3_server_access_logs_disabled
  const bucket = new s3.Bucket(stack, 'MyBucket15', {
    versioned: config.enableVersioning,
    encryption: config.enableEncryption ? s3.BucketEncryption.S3_MANAGED : undefined,
  });
}
// {/fact}

// True Negative Cases (Secure Code)

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_1() {
  const app = new cdk.App();
  const stack = new TestStack(app, 'TestStack');
  
  const logBucket = new s3.Bucket(stack, 'LogBucket1');
  
  // ok: typescript_cdk_s3_server_access_logs_disabled
  new s3.Bucket(stack, 'MyBucket1', {
    versioned: true,
    encryption: s3.BucketEncryption.S3_MANAGED,
    serverAccessLogsBucket: logBucket,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_2() {
  const app = new cdk.App();
  const stack = new TestStack(app, 'TestStack');
  
  const logBucket = new s3.Bucket(stack, 'LogBucket2');
  
  // ok: typescript_cdk_s3_server_access_logs_disabled
  const bucket = new s3.Bucket(stack, 'MyBucket2', {
    removalPolicy: cdk.RemovalPolicy.DESTROY,
    autoDeleteObjects: true,
    serverAccessLogsBucket: logBucket,
    serverAccessLogsPrefix: 'logs/',
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_3() {
  const app = new cdk.App();
  const stack = new TestStack(app, 'TestStack');
  
  const logBucket = new s3.Bucket(stack, 'LogBucket3');
  
  // ok: typescript_cdk_s3_server_access_logs_disabled
  const bucket = new s3.Bucket(stack, 'MyBucket3', {
    publicReadAccess: false,
    blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
    encryption: s3.BucketEncryption.KMS,
    serverAccessLogsBucket: logBucket,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_4() {
  const app = new cdk.App();
  const stack = new TestStack(app, 'TestStack');
  
  const logBucket = new s3.Bucket(stack, 'LogBucket4');
  
  const bucketProps: s3.BucketProps = {
    versioned: true,
    encryption: s3.BucketEncryption.KMS_MANAGED,
    serverAccessLogsBucket: logBucket,
  };
  
  // ok: typescript_cdk_s3_server_access_logs_disabled
  new s3.Bucket(stack, 'MyBucket4', bucketProps);
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_5() {
  const app = new cdk.App();
  const stack = new TestStack(app, 'TestStack');
  
  // Self-logging bucket
  // ok: typescript_cdk_s3_server_access_logs_disabled
  const bucket = new s3.Bucket(stack, 'MyBucket5');
  bucket.addToResourcePolicy(new cdk.aws_iam.PolicyStatement({
    actions: ['s3:PutObject'],
    resources: [bucket.arnForObjects('logs/*')],
    principals: [new cdk.aws_iam.ServicePrincipal('logging.s3.amazonaws.com')],
  }));
  
  bucket.node.addDependency(new cdk.CfnResource(stack, 'BucketLoggingConfig', {
    type: 'AWS::S3::BucketLogging',
    properties: {
      BucketName: bucket.bucketName,
      LoggingConfiguration: {
        DestinationBucketName: bucket.bucketName,
        LogFilePrefix: 'logs/',
      },
    },
  }));
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_6() {
  const app = new cdk.App();
  const stack = new TestStack(app, 'TestStack');
  
  const logBucket = new s3.Bucket(stack, 'LogBucket6');
  
  // ok: typescript_cdk_s3_server_access_logs_disabled
  const bucket = new s3.Bucket(stack, 'MyBucket6', {
    websiteIndexDocument: 'index.html',
    websiteErrorDocument: 'error.html',
    serverAccessLogsBucket: logBucket,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_7() {
  const app = new cdk.App();
  const stack = new TestStack(app, 'TestStack');
  
  const logBucket = new s3.Bucket(stack, 'LogBucket7');
  
  const props = {
    serverAccessLogsBucket: logBucket,
  };
  
  // ok: typescript_cdk_s3_server_access_logs_disabled
  const bucket = new s3.Bucket(stack, 'MyBucket7', props as s3.BucketProps);
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_8() {
  const app = new cdk.App();
  const stack = new TestStack(app, 'TestStack');
  
  const logBucket = new s3.Bucket(stack, 'LogBucket8');
  
  // Creating multiple buckets with logging
  // ok: typescript_cdk_s3_server_access_logs_disabled
  const bucket1 = new s3.Bucket(stack, 'MyBucket8a', {
    serverAccessLogsBucket: logBucket,
  });
  
  // ok: typescript_cdk_s3_server_access_logs_disabled
  const bucket2 = new s3.Bucket(stack, 'MyBucket8b', {
    versioned: true,
    serverAccessLogsBucket: logBucket,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_9() {
  const app = new cdk.App();
  const stack = new TestStack(app, 'TestStack');
  
  const logBucket = new s3.Bucket(stack, 'LogBucket9');
  
  const createBucket = () => {
    // ok: typescript_cdk_s3_server_access_logs_disabled
    return new s3.Bucket(stack, 'MyBucket9', {
      encryption: s3.BucketEncryption.KMS,
      serverAccessLogsBucket: logBucket,
    });
  };
  
  const bucket = createBucket();
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_10() {
  class CustomStack extends cdk.Stack {
    constructor(scope: Construct, id: string) {
      super(scope, id);
      
      const logBucket = new s3.Bucket(this, 'LogBucket10');
      
      // ok: typescript_cdk_s3_server_access_logs_disabled
      new s3.Bucket(this, 'MyBucket10', {
        versioned: true,
        serverAccessLogsBucket: logBucket,
      });
    }
  }
  
  const app = new cdk.App();
  new CustomStack(app, 'CustomStack');
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_11() {
  const app = new cdk.App();
  const stack = new TestStack(app, 'TestStack');
  
  // Using both serverAccessLogsBucket and serverAccessLogsPrefix
  const logBucket = new s3.Bucket(stack, 'LogBucket11');
  
  // ok: typescript_cdk_s3_server_access_logs_disabled
  const bucket = new s3.Bucket(stack, 'MyBucket11', {
    serverAccessLogsBucket: logBucket,
    serverAccessLogsPrefix: 'logs/',
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_12() {
  const app = new cdk.App();
  const stack = new TestStack(app, 'TestStack');
  
  // Using a variable to conditionally set logging
  const logBucket = new s3.Bucket(stack, 'LogBucket12');
  const enableLogging = true;
  
  // ok: typescript_cdk_s3_server_access_logs_disabled
  const bucket = new s3.Bucket(stack, 'MyBucket12', {
    serverAccessLogsBucket: enableLogging ? logBucket : undefined,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_13() {
  const app = new cdk.App();
  const stack = new TestStack(app, 'TestStack');
  
  // Setting all security features including access logs
  const logBucket = new s3.Bucket(stack, 'LogBucket13');
  
  // ok: typescript_cdk_s3_server_access_logs_disabled
  const bucket = new s3.Bucket(stack, 'MyBucket13', {
    encryption: s3.BucketEncryption.KMS,
    blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
    versioned: true,
    enforceSSL: true,
    serverAccessLogsBucket: logBucket,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_14() {
  const app = new cdk.App();
  const stack = new TestStack(app, 'TestStack');
  
  const logBucket = new s3.Bucket(stack, 'LogBucket14');
  
  const bucketProps = {};
  Object.assign(bucketProps, {
    versioned: true,
    encryption: s3.BucketEncryption.S3_MANAGED,
    serverAccessLogsBucket: logBucket,
  });
  
  // ok: typescript_cdk_s3_server_access_logs_disabled
  new s3.Bucket(stack, 'MyBucket14', bucketProps as s3.BucketProps);
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_15() {
  const app = new cdk.App();
  const stack = new TestStack(app, 'TestStack');
  
  const config = {
    enableVersioning: true,
    enableEncryption: true,
    enableLogging: true,
  };
  
  const logBucket = new s3.Bucket(stack, 'LogBucket15');
  
  // ok: typescript_cdk_s3_server_access_logs_disabled
  const bucket = new s3.Bucket(stack, 'MyBucket15', {
    versioned: config.enableVersioning,
    encryption: config.enableEncryption ? s3.BucketEncryption.S3_MANAGED : undefined,
    serverAccessLogsBucket: config.enableLogging ? logBucket : undefined,
  });
}
// {/fact}