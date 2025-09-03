import { Stack, StackProps } from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as cloudfront from 'aws-cdk-lib/aws-cloudfront';
import * as origins from 'aws-cdk-lib/aws-cloudfront-origins';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as iam from 'aws-cdk-lib/aws-iam';

// True Positives (Vulnerable Cases)

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_1(scope: Construct) {
  // Creating an S3 bucket
  const bucket = new s3.Bucket(scope, 'MyBucket');
  
  // Creating a CloudFront distribution without origin access identity
  // ruleid: typescript_cdk_usage_of_origin_access_identity_for_cloudfront_distribution
  new cloudfront.Distribution(scope, 'MyDistribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket, {
        originAccessIdentity: undefined
      }),
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_2(scope: Construct) {
  // Creating an S3 bucket
  const bucket = new s3.Bucket(scope, 'WebsiteBucket', {
    websiteIndexDocument: 'index.html',
    publicReadAccess: true,
  });
  
  // Creating a CloudFront distribution with S3 website as origin (no OAI)
  // ruleid: typescript_cdk_usage_of_origin_access_identity_for_cloudfront_distribution
  new cloudfront.Distribution(scope, 'WebsiteDistribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket),
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_3(scope: Construct) {
  const bucket = new s3.Bucket(scope, 'AssetsBucket');
  
  // Explicitly setting originAccessIdentity to null
  // ruleid: typescript_cdk_usage_of_origin_access_identity_for_cloudfront_distribution
  const distribution = new cloudfront.Distribution(scope, 'AssetsDistribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket, {
        originAccessIdentity: null as any,
      }),
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_4(scope: Construct) {
  const bucket = new s3.Bucket(scope, 'MediaBucket');
  
  // Using HTTP origin instead of S3Origin for an S3 bucket
  // ruleid: typescript_cdk_usage_of_origin_access_identity_for_cloudfront_distribution
  new cloudfront.Distribution(scope, 'MediaDistribution', {
    defaultBehavior: {
      origin: new origins.HttpOrigin(`${bucket.bucketName}.s3.amazonaws.com`),
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_5(scope: Construct) {
  const bucket = new s3.Bucket(scope, 'StaticContentBucket');
  
  // Creating a custom origin with S3 website endpoint
  // ruleid: typescript_cdk_usage_of_origin_access_identity_for_cloudfront_distribution
  new cloudfront.Distribution(scope, 'StaticContentDistribution', {
    defaultBehavior: {
      origin: new origins.HttpOrigin(`${bucket.bucketName}.s3-website-us-east-1.amazonaws.com`),
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_6(scope: Construct) {
  const bucket = new s3.Bucket(scope, 'ImagesBucket');
  
  // Using custom S3 origin configuration without OAI
  // ruleid: typescript_cdk_usage_of_origin_access_identity_for_cloudfront_distribution
  new cloudfront.Distribution(scope, 'ImagesDistribution', {
    defaultBehavior: {
      origin: new cloudfront.Origin(bucket.bucketWebsiteUrl, {
        originId: 'imagesBucketOrigin',
        customOriginConfig: {
          originProtocolPolicy: cloudfront.OriginProtocolPolicy.HTTP_ONLY,
        },
      }),
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_7(scope: Construct) {
  const bucket = new s3.Bucket(scope, 'DocumentsBucket');
  
  // Multiple origins with one S3 origin missing OAI
  const httpOrigin = new origins.HttpOrigin('example.com');
  // ruleid: typescript_cdk_usage_of_origin_access_identity_for_cloudfront_distribution
  const s3Origin = new origins.S3Origin(bucket, { originAccessIdentity: undefined });
  
  new cloudfront.Distribution(scope, 'MultiOriginDistribution', {
    defaultBehavior: { origin: httpOrigin },
    additionalBehaviors: {
      'documents/*': { origin: s3Origin },
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_8(scope: Construct) {
  const bucket = new s3.Bucket(scope, 'DownloadsBucket');
  
  // Using S3BucketOrigin (deprecated) without OAI
  // ruleid: typescript_cdk_usage_of_origin_access_identity_for_cloudfront_distribution
  const origin = new cloudfront.S3BucketOrigin(bucket);
  
  new cloudfront.CloudFrontWebDistribution(scope, 'DownloadsDistribution', {
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

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_9(scope: Construct) {
  const bucket = new s3.Bucket(scope, 'ConfigBucket');
  
  // Using CloudFrontWebDistribution with S3 origin but no OAI
  // ruleid: typescript_cdk_usage_of_origin_access_identity_for_cloudfront_distribution
  new cloudfront.CloudFrontWebDistribution(scope, 'ConfigDistribution', {
    originConfigs: [
      {
        s3OriginSource: {
          s3BucketSource: bucket,
          originAccessIdentity: undefined,
        },
        behaviors: [{ isDefaultBehavior: true }],
      },
    ],
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_10(scope: Construct) {
  const bucket = new s3.Bucket(scope, 'ArchiveBucket');
  
  // Creating distribution with factory method but no OAI
  // ruleid: typescript_cdk_usage_of_origin_access_identity_for_cloudfront_distribution
  cloudfront.Distribution.fromDistributionAttributes(scope, 'ImportedDistribution', {
    distributionId: 'EDFDVBD632BHDS5',
    domainName: 'distribution.cloudfront.net',
  });
  
  new cloudfront.Distribution(scope, 'ArchiveDistribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket, { originAccessIdentity: undefined }),
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_11(scope: Construct) {
  const bucket = new s3.Bucket(scope, 'VideoBucket');
  
  // Using a variable to store origin configuration without OAI
  const originConfig = {
    origin: new origins.S3Origin(bucket),
  };
  
  // ruleid: typescript_cdk_usage_of_origin_access_identity_for_cloudfront_distribution
  new cloudfront.Distribution(scope, 'VideoDistribution', {
    defaultBehavior: originConfig,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_12(scope: Construct) {
  const bucket = new s3.Bucket(scope, 'BackupBucket');
  
  // Using conditional logic but still missing OAI
  const useOAI = false;
  const originConfig = useOAI 
    ? { origin: new origins.S3Origin(bucket, { originAccessIdentity: new cloudfront.OriginAccessIdentity(scope, 'OAI') }) }
    // ruleid: typescript_cdk_usage_of_origin_access_identity_for_cloudfront_distribution
    : { origin: new origins.S3Origin(bucket) };
  
  new cloudfront.Distribution(scope, 'BackupDistribution', {
    defaultBehavior: originConfig,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_13(scope: Construct) {
  const bucket = new s3.Bucket(scope, 'LogsBucket');
  
  // Creating distribution with factory method
  // ruleid: typescript_cdk_usage_of_origin_access_identity_for_cloudfront_distribution
  const distribution = new cloudfront.Distribution(scope, 'LogsDistribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket, {
        originAccessIdentity: undefined,
      }),
    },
  });
  
  // Adding additional behavior also without OAI
  distribution.addBehavior('logs/*', new origins.S3Origin(bucket));
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_14(scope: Construct) {
  const bucket = new s3.Bucket(scope, 'ReportsBucket');
  
  // Using a function to create the origin without OAI
  function createOrigin() {
    // ruleid: typescript_cdk_usage_of_origin_access_identity_for_cloudfront_distribution
    return new origins.S3Origin(bucket);
  }
  
  new cloudfront.Distribution(scope, 'ReportsDistribution', {
    defaultBehavior: {
      origin: createOrigin(),
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_15(scope: Construct) {
  const bucket = new s3.Bucket(scope, 'TemplatesBucket');
  
  // Using S3 bucket website configuration without OAI
  bucket.addToResourcePolicy(new iam.PolicyStatement({
    actions: ['s3:GetObject'],
    resources: [bucket.arnForObjects('*')],
    principals: [new iam.AnyPrincipal()],
  }));
  
  // ruleid: typescript_cdk_usage_of_origin_access_identity_for_cloudfront_distribution
  new cloudfront.Distribution(scope, 'TemplatesDistribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket),
    },
  });
}
// {/fact}

// True Negatives (Secure Cases)

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_1(scope: Construct) {
  // Creating an S3 bucket
  const bucket = new s3.Bucket(scope, 'MySecureBucket');
  
  // Creating a CloudFront distribution with origin access identity
  const oai = new cloudfront.OriginAccessIdentity(scope, 'MyOAI');
  
  // ok: typescript_cdk_usage_of_origin_access_identity_for_cloudfront_distribution
  new cloudfront.Distribution(scope, 'MySecureDistribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket, {
        originAccessIdentity: oai,
      }),
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_2(scope: Construct) {
  // Creating an S3 bucket
  const bucket = new s3.Bucket(scope, 'WebsiteSecureBucket');
  
  // Creating a CloudFront distribution with origin access identity
  const oai = new cloudfront.OriginAccessIdentity(scope, 'WebsiteOAI');
  
  // ok: typescript_cdk_usage_of_origin_access_identity_for_cloudfront_distribution
  new cloudfront.Distribution(scope, 'WebsiteSecureDistribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket, {
        originAccessIdentity: oai,
      }),
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_3(scope: Construct) {
  // Creating an S3 bucket
  const bucket = new s3.Bucket(scope, 'AssetsSecureBucket');
  
  // Creating a CloudFront distribution with origin access identity
  // ok: typescript_cdk_usage_of_origin_access_identity_for_cloudfront_distribution
  new cloudfront.Distribution(scope, 'AssetsSecureDistribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket), // Default includes OAI
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_4(scope: Construct) {
  // Creating an S3 bucket
  const bucket = new s3.Bucket(scope, 'MediaSecureBucket');
  
  // Using non-S3 origin (HTTP origin for a different service)
  // ok: typescript_cdk_usage_of_origin_access_identity_for_cloudfront_distribution
  new cloudfront.Distribution(scope, 'MediaSecureDistribution', {
    defaultBehavior: {
      origin: new origins.HttpOrigin('api.example.com'),
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_5(scope: Construct) {
  // Creating an S3 bucket
  const bucket = new s3.Bucket(scope, 'StaticContentSecureBucket');
  
  // Creating a CloudFront distribution with explicit OAI
  const oai = new cloudfront.OriginAccessIdentity(scope, 'StaticContentOAI', {
    comment: 'Access to static content bucket',
  });
  
  // ok: typescript_cdk_usage_of_origin_access_identity_for_cloudfront_distribution
  new cloudfront.Distribution(scope, 'StaticContentSecureDistribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket, {
        originAccessIdentity: oai,
      }),
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_6(scope: Construct) {
  // Creating an S3 bucket
  const bucket = new s3.Bucket(scope, 'ImagesSecureBucket');
  
  // Creating a CloudFront distribution with OAI
  const oai = new cloudfront.OriginAccessIdentity(scope, 'ImagesOAI');
  
  // ok: typescript_cdk_usage_of_origin_access_identity_for_cloudfront_distribution
  new cloudfront.Distribution(scope, 'ImagesSecureDistribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket, {
        originAccessIdentity: oai,
      }),
    },
    additionalBehaviors: {
      'images/*': {
        origin: new origins.S3Origin(bucket, {
          originAccessIdentity: oai,
        }),
      },
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_7(scope: Construct) {
  // Creating multiple origins with OAI for S3
  const bucket = new s3.Bucket(scope, 'DocumentsSecureBucket');
  const oai = new cloudfront.OriginAccessIdentity(scope, 'DocumentsOAI');
  
  const httpOrigin = new origins.HttpOrigin('example.com');
  // ok: typescript_cdk_usage_of_origin_access_identity_for_cloudfront_distribution
  const s3Origin = new origins.S3Origin(bucket, { originAccessIdentity: oai });
  
  new cloudfront.Distribution(scope, 'MultiOriginSecureDistribution', {
    defaultBehavior: { origin: httpOrigin },
    additionalBehaviors: {
      'documents/*': { origin: s3Origin },
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_8(scope: Construct) {
  const bucket = new s3.Bucket(scope, 'DownloadsSecureBucket');
  const oai = new cloudfront.OriginAccessIdentity(scope, 'DownloadsOAI');
  
  // Using CloudFrontWebDistribution with OAI
  // ok: typescript_cdk_usage_of_origin_access_identity_for_cloudfront_distribution
  new cloudfront.CloudFrontWebDistribution(scope, 'DownloadsSecureDistribution', {
    originConfigs: [
      {
        s3OriginSource: {
          s3BucketSource: bucket,
          originAccessIdentity: oai,
        },
        behaviors: [{ isDefaultBehavior: true }],
      },
    ],
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_9(scope: Construct) {
  // Using Lambda@Edge origin instead of S3
  // ok: typescript_cdk_usage_of_origin_access_identity_for_cloudfront_distribution
  new cloudfront.Distribution(scope, 'ApiDistribution', {
    defaultBehavior: {
      origin: new origins.HttpOrigin('api.example.com'),
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_10(scope: Construct) {
  const bucket = new s3.Bucket(scope, 'ArchiveSecureBucket');
  const oai = new cloudfront.OriginAccessIdentity(scope, 'ArchiveOAI');
  
  // Creating distribution with factory method and proper OAI
  // ok: typescript_cdk_usage_of_origin_access_identity_for_cloudfront_distribution
  new cloudfront.Distribution(scope, 'ArchiveSecureDistribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket, { originAccessIdentity: oai }),
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_11(scope: Construct) {
  const bucket = new s3.Bucket(scope, 'VideoSecureBucket');
  const oai = new cloudfront.OriginAccessIdentity(scope, 'VideoOAI');
  
  // Using a variable to store origin configuration with OAI
  // ok: typescript_cdk_usage_of_origin_access_identity_for_cloudfront_distribution
  const originConfig = {
    origin: new origins.S3Origin(bucket, { originAccessIdentity: oai }),
  };
  
  new cloudfront.Distribution(scope, 'VideoSecureDistribution', {
    defaultBehavior: originConfig,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_12(scope: Construct) {
  const bucket = new s3.Bucket(scope, 'BackupSecureBucket');
  const oai = new cloudfront.OriginAccessIdentity(scope, 'BackupOAI');
  
  // Using conditional logic with OAI in both branches
  const useCustomOAI = false;
  // ok: typescript_cdk_usage_of_origin_access_identity_for_cloudfront_distribution
  const originConfig = useCustomOAI 
    ? { origin: new origins.S3Origin(bucket, { originAccessIdentity: new cloudfront.OriginAccessIdentity(scope, 'CustomOAI') }) }
    : { origin: new origins.S3Origin(bucket, { originAccessIdentity: oai }) };
  
  new cloudfront.Distribution(scope, 'BackupSecureDistribution', {
    defaultBehavior: originConfig,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_13(scope: Construct) {
  const bucket = new s3.Bucket(scope, 'LogsSecureBucket');
  const oai = new cloudfront.OriginAccessIdentity(scope, 'LogsOAI');
  
  // Creating distribution with factory method
  // ok: typescript_cdk_usage_of_origin_access_identity_for_cloudfront_distribution
  const distribution = new cloudfront.Distribution(scope, 'LogsSecureDistribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket, {
        originAccessIdentity: oai,
      }),
    },
  });
  
  // Adding additional behavior also with OAI
  distribution.addBehavior('logs/*', new origins.S3Origin(bucket, { originAccessIdentity: oai }));
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_14(scope: Construct) {
  const bucket = new s3.Bucket(scope, 'ReportsSecureBucket');
  const oai = new cloudfront.OriginAccessIdentity(scope, 'ReportsOAI');
  
  // Using a function to create the origin with OAI
  function createSecureOrigin() {
    // ok: typescript_cdk_usage_of_origin_access_identity_for_cloudfront_distribution
    return new origins.S3Origin(bucket, { originAccessIdentity: oai });
  }
  
  new cloudfront.Distribution(scope, 'ReportsSecureDistribution', {
    defaultBehavior: {
      origin: createSecureOrigin(),
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_15(scope: Construct) {
  // Using OAI with Origin Access Control (OAC) - newer approach
  const bucket = new s3.Bucket(scope, 'TemplatesSecureBucket');
  const oai = new cloudfront.OriginAccessIdentity(scope, 'TemplatesOAI');
  
  // ok: typescript_cdk_usage_of_origin_access_identity_for_cloudfront_distribution
  new cloudfront.Distribution(scope, 'TemplatesSecureDistribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket, {
        originAccessIdentity: oai,
      }),
    },
  });
}
// {/fact}