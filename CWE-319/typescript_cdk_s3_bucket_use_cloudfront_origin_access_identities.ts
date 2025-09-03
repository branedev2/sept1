import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as cloudfront from 'aws-cdk-lib/aws-cloudfront';
import * as origins from 'aws-cdk-lib/aws-cloudfront-origins';
import * as iam from 'aws-cdk-lib/aws-iam';

// TRUE POSITIVES (Vulnerable Cases)

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_1(scope: Construct) {
  // S3 bucket configured for website hosting without OAI
  const bucket = new s3.Bucket(scope, 'WebsiteBucket', {
    websiteIndexDocument: 'index.html',
    websiteErrorDocument: 'error.html',
    publicReadAccess: true, // Making bucket publicly accessible
  });

  // ruleid: typescript_cdk_s3_bucket_use_cloudfront_origin_access_identities
  new cloudfront.Distribution(scope, 'Distribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket),
    },
    // No OAI configured
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_2(scope: Construct) {
  // S3 bucket with website configuration
  const bucket = new s3.Bucket(scope, 'WebsiteBucket', {
    websiteIndexDocument: 'index.html',
    blockPublicAccess: s3.BlockPublicAccess.BLOCK_ACLS,
  });
  
  // Allow public read access via bucket policy
  bucket.addToResourcePolicy(new iam.PolicyStatement({
    actions: ['s3:GetObject'],
    resources: [bucket.arnForObjects('*')],
    principals: [new iam.AnyPrincipal()],
  }));

  // ruleid: typescript_cdk_s3_bucket_use_cloudfront_origin_access_identities
  new cloudfront.Distribution(scope, 'Distribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket),
    },
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_3(scope: Construct) {
  // Create a bucket for hosting a static website
  const websiteBucket = new s3.Bucket(scope, 'WebsiteBucket', {
    websiteIndexDocument: 'index.html',
    websiteErrorDocument: 'error.html',
    removalPolicy: cdk.RemovalPolicy.DESTROY,
  });

  // Make the bucket contents publicly accessible
  websiteBucket.grantPublicAccess();

  // ruleid: typescript_cdk_s3_bucket_use_cloudfront_origin_access_identities
  const distribution = new cloudfront.Distribution(scope, 'Distribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(websiteBucket),
    },
    priceClass: cloudfront.PriceClass.PRICE_CLASS_100,
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_4(scope: Construct) {
  // Create bucket with website configuration
  const bucket = new s3.Bucket(scope, 'WebsiteBucket', {
    websiteIndexDocument: 'index.html',
    blockPublicAccess: new s3.BlockPublicAccess({
      blockPublicPolicy: false,
      blockPublicAcls: false,
      ignorePublicAcls: false,
      restrictPublicBuckets: false,
    }),
  });

  // ruleid: typescript_cdk_s3_bucket_use_cloudfront_origin_access_identities
  new cloudfront.Distribution(scope, 'MyDistribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket),
    },
    defaultRootObject: 'index.html',
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_5(scope: Construct) {
  // Create a bucket with website hosting enabled
  const siteBucket = new s3.Bucket(scope, 'SiteBucket', {
    websiteIndexDocument: 'index.html',
    websiteErrorDocument: 'error.html',
  });

  // Create CloudFront distribution without OAI
  // ruleid: typescript_cdk_s3_bucket_use_cloudfront_origin_access_identities
  const distribution = new cloudfront.Distribution(scope, 'SiteDistribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(siteBucket),
      viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
    },
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_6(scope: Construct) {
  const bucket = new s3.Bucket(scope, 'MyBucket', {
    websiteIndexDocument: 'index.html',
  });

  // Using HTTP origin instead of S3Origin with OAI
  // ruleid: typescript_cdk_s3_bucket_use_cloudfront_origin_access_identities
  new cloudfront.Distribution(scope, 'MyDist', {
    defaultBehavior: {
      origin: new origins.HttpOrigin(`${bucket.bucketWebsiteDomainName}`),
    },
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_7(scope: Construct) {
  // Create a bucket with website configuration
  const bucket = new s3.Bucket(scope, 'WebsiteBucket', {
    websiteIndexDocument: 'index.html',
    publicReadAccess: true,
  });

  // Create a CloudFront distribution using bucket website as origin
  // ruleid: typescript_cdk_s3_bucket_use_cloudfront_origin_access_identities
  const distribution = new cloudfront.Distribution(scope, 'Distribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket),
      allowedMethods: cloudfront.AllowedMethods.ALLOW_GET_HEAD,
      cachedMethods: cloudfront.CachedMethods.CACHE_GET_HEAD,
    },
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_8(scope: Construct) {
  // Create a bucket for static website hosting
  const bucket = new s3.Bucket(scope, 'StaticWebsiteBucket', {
    websiteIndexDocument: 'index.html',
    websiteErrorDocument: 'error.html',
  });

  // Allow public read access
  bucket.addToResourcePolicy(new iam.PolicyStatement({
    effect: iam.Effect.ALLOW,
    actions: ['s3:GetObject'],
    principals: [new iam.AnyPrincipal()],
    resources: [`${bucket.bucketArn}/*`],
  }));

  // ruleid: typescript_cdk_s3_bucket_use_cloudfront_origin_access_identities
  const distribution = new cloudfront.Distribution(scope, 'WebDistribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket),
      viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
    },
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_9(scope: Construct) {
  // Create a bucket for static website hosting
  const websiteBucket = new s3.Bucket(scope, 'WebsiteBucket', {
    websiteIndexDocument: 'index.html',
  });

  // Create a custom origin from the bucket website endpoint
  const origin = new origins.HttpOrigin(websiteBucket.bucketWebsiteDomainName);

  // ruleid: typescript_cdk_s3_bucket_use_cloudfront_origin_access_identities
  new cloudfront.Distribution(scope, 'Distribution', {
    defaultBehavior: {
      origin: origin,
    },
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_10(scope: Construct) {
  // Create a bucket with website hosting enabled
  const bucket = new s3.Bucket(scope, 'WebsiteBucket', {
    websiteIndexDocument: 'index.html',
    websiteErrorDocument: 'error.html',
    publicReadAccess: true,
  });

  // ruleid: typescript_cdk_s3_bucket_use_cloudfront_origin_access_identities
  const distribution = new cloudfront.Distribution(scope, 'Distribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket),
    },
    additionalBehaviors: {
      'images/*': {
        origin: new origins.S3Origin(bucket),
      },
    },
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_11(scope: Construct) {
  // Create a bucket for static website hosting
  const bucket = new s3.Bucket(scope, 'WebsiteBucket', {
    websiteIndexDocument: 'index.html',
    websiteErrorDocument: 'error.html',
  });

  // Make the bucket public
  const bucketPolicy = new s3.BucketPolicy(scope, 'BucketPolicy', {
    bucket: bucket,
  });
  
  bucketPolicy.document.addStatements(new iam.PolicyStatement({
    actions: ['s3:GetObject'],
    resources: [bucket.arnForObjects('*')],
    principals: [new iam.AnyPrincipal()],
  }));

  // ruleid: typescript_cdk_s3_bucket_use_cloudfront_origin_access_identities
  new cloudfront.Distribution(scope, 'Distribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket),
    },
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_12(scope: Construct) {
  // Create a bucket with website hosting enabled
  const bucket = new s3.Bucket(scope, 'WebsiteBucket', {
    websiteIndexDocument: 'index.html',
    websiteErrorDocument: 'error.html',
  });

  // Create a CloudFront distribution with S3 origin but no OAI
  // ruleid: typescript_cdk_s3_bucket_use_cloudfront_origin_access_identities
  const distribution = new cloudfront.Distribution(scope, 'WebDistribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket),
      viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
      cachePolicy: cloudfront.CachePolicy.CACHING_OPTIMIZED,
    },
    priceClass: cloudfront.PriceClass.PRICE_CLASS_100,
    enableLogging: true,
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_13(scope: Construct) {
  // Create a bucket with website hosting enabled
  const bucket = new s3.Bucket(scope, 'WebsiteBucket', {
    websiteIndexDocument: 'index.html',
    websiteErrorDocument: 'error.html',
  });

  // Create a CloudFront distribution with S3 origin but no OAI
  // ruleid: typescript_cdk_s3_bucket_use_cloudfront_origin_access_identities
  const distribution = new cloudfront.Distribution(scope, 'WebDistribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket),
      allowedMethods: cloudfront.AllowedMethods.ALLOW_GET_HEAD_OPTIONS,
      cachedMethods: cloudfront.CachedMethods.CACHE_GET_HEAD_OPTIONS,
    },
    domainNames: ['example.com', 'www.example.com'],
    defaultRootObject: 'index.html',
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_14(scope: Construct) {
  // Create a bucket with website hosting enabled
  const bucket = new s3.Bucket(scope, 'WebsiteBucket', {
    websiteIndexDocument: 'index.html',
  });

  // Create a CloudFront distribution with S3 origin but no OAI
  // ruleid: typescript_cdk_s3_bucket_use_cloudfront_origin_access_identities
  const distribution = new cloudfront.Distribution(scope, 'WebDistribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket),
    },
    errorResponses: [
      {
        httpStatus: 404,
        responseHttpStatus: 200,
        responsePagePath: '/index.html',
      },
    ],
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_15(scope: Construct) {
  // Create a bucket with website hosting enabled
  const bucket = new s3.Bucket(scope, 'WebsiteBucket', {
    websiteIndexDocument: 'index.html',
    websiteErrorDocument: 'error.html',
  });

  // Create a CloudFront distribution with S3 origin but no OAI
  // ruleid: typescript_cdk_s3_bucket_use_cloudfront_origin_access_identities
  const distribution = new cloudfront.Distribution(scope, 'WebDistribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket),
      viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.HTTPS_ONLY,
    },
    comment: 'Distribution for static website',
    enabled: true,
  });
}
// {/fact}

// TRUE NEGATIVES (Secure Cases)

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_1(scope: Construct) {
  // Create a bucket for static website content
  const bucket = new s3.Bucket(scope, 'WebsiteBucket', {
    blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
    removalPolicy: cdk.RemovalPolicy.DESTROY,
  });

  // Create an Origin Access Identity
  const oai = new cloudfront.OriginAccessIdentity(scope, 'OAI', {
    comment: 'Access to website bucket',
  });

  // Grant read access to the OAI
  bucket.grantRead(oai);

  // ok: typescript_cdk_s3_bucket_use_cloudfront_origin_access_identities
  new cloudfront.Distribution(scope, 'Distribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket, {
        originAccessIdentity: oai,
      }),
    },
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_2(scope: Construct) {
  // Create a bucket for static website content
  const bucket = new s3.Bucket(scope, 'WebsiteBucket', {
    blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
  });

  // Create an Origin Access Identity
  const oai = new cloudfront.OriginAccessIdentity(scope, 'OAI');

  // ok: typescript_cdk_s3_bucket_use_cloudfront_origin_access_identities
  const distribution = new cloudfront.Distribution(scope, 'Distribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket, {
        originAccessIdentity: oai,
      }),
      viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
    },
    defaultRootObject: 'index.html',
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_3(scope: Construct) {
  // Create a bucket for static website content
  const bucket = new s3.Bucket(scope, 'WebsiteBucket', {
    blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
    removalPolicy: cdk.RemovalPolicy.DESTROY,
  });

  // Create an Origin Access Identity
  const oai = new cloudfront.OriginAccessIdentity(scope, 'OAI', {
    comment: 'Access to website bucket',
  });

  // Grant the OAI read access to the bucket
  bucket.grantRead(oai);

  // ok: typescript_cdk_s3_bucket_use_cloudfront_origin_access_identities
  const distribution = new cloudfront.Distribution(scope, 'Distribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket, {
        originAccessIdentity: oai,
      }),
    },
    priceClass: cloudfront.PriceClass.PRICE_CLASS_100,
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_4(scope: Construct) {
  // Create a bucket for static website content
  const bucket = new s3.Bucket(scope, 'WebsiteBucket', {
    blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
  });

  // Create an Origin Access Identity
  const oai = new cloudfront.OriginAccessIdentity(scope, 'OAI');

  // Add a bucket policy that allows the OAI to read objects
  bucket.addToResourcePolicy(new iam.PolicyStatement({
    actions: ['s3:GetObject'],
    resources: [bucket.arnForObjects('*')],
    principals: [new iam.CanonicalUserPrincipal(oai.cloudFrontOriginAccessIdentityS3CanonicalUserId)],
  }));

  // ok: typescript_cdk_s3_bucket_use_cloudfront_origin_access_identities
  new cloudfront.Distribution(scope, 'Distribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket, {
        originAccessIdentity: oai,
      }),
    },
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_5(scope: Construct) {
  // Create a bucket for static website content
  const bucket = new s3.Bucket(scope, 'WebsiteBucket', {
    blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
  });

  // Create an Origin Access Identity
  const oai = new cloudfront.OriginAccessIdentity(scope, 'OAI');

  // ok: typescript_cdk_s3_bucket_use_cloudfront_origin_access_identities
  const distribution = new cloudfront.Distribution(scope, 'Distribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket, {
        originAccessIdentity: oai,
      }),
      allowedMethods: cloudfront.AllowedMethods.ALLOW_GET_HEAD,
      cachedMethods: cloudfront.CachedMethods.CACHE_GET_HEAD,
    },
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_6(scope: Construct) {
  // Create a bucket for static website content
  const bucket = new s3.Bucket(scope, 'WebsiteBucket', {
    blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
  });

  // Create an Origin Access Identity
  const oai = new cloudfront.OriginAccessIdentity(scope, 'OAI');

  // ok: typescript_cdk_s3_bucket_use_cloudfront_origin_access_identities
  const distribution = new cloudfront.Distribution(scope, 'Distribution', {
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

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_7(scope: Construct) {
  // Create a bucket for static website content
  const bucket = new s3.Bucket(scope, 'WebsiteBucket', {
    blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
  });

  // Create an Origin Access Identity
  const oai = new cloudfront.OriginAccessIdentity(scope, 'OAI', {
    comment: 'Access to website bucket',
  });

  // Grant read access to the OAI
  bucket.grantRead(oai);

  // ok: typescript_cdk_s3_bucket_use_cloudfront_origin_access_identities
  const distribution = new cloudfront.Distribution(scope, 'Distribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket, {
        originAccessIdentity: oai,
      }),
      viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
    },
    errorResponses: [
      {
        httpStatus: 404,
        responseHttpStatus: 200,
        responsePagePath: '/index.html',
      },
    ],
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_8(scope: Construct) {
  // Create a bucket for static website content
  const bucket = new s3.Bucket(scope, 'WebsiteBucket', {
    blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
  });

  // Create an Origin Access Identity
  const oai = new cloudfront.OriginAccessIdentity(scope, 'OAI');

  // ok: typescript_cdk_s3_bucket_use_cloudfront_origin_access_identities
  const distribution = new cloudfront.Distribution(scope, 'Distribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket, {
        originAccessIdentity: oai,
      }),
      cachePolicy: cloudfront.CachePolicy.CACHING_OPTIMIZED,
    },
    priceClass: cloudfront.PriceClass.PRICE_CLASS_100,
    enableLogging: true,
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_9(scope: Construct) {
  // Create a bucket for static website content
  const bucket = new s3.Bucket(scope, 'WebsiteBucket', {
    blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
  });

  // Create an Origin Access Identity
  const oai = new cloudfront.OriginAccessIdentity(scope, 'OAI');

  // ok: typescript_cdk_s3_bucket_use_cloudfront_origin_access_identities
  const distribution = new cloudfront.Distribution(scope, 'Distribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket, {
        originAccessIdentity: oai,
      }),
      allowedMethods: cloudfront.AllowedMethods.ALLOW_GET_HEAD_OPTIONS,
      cachedMethods: cloudfront.CachedMethods.CACHE_GET_HEAD_OPTIONS,
    },
    domainNames: ['example.com', 'www.example.com'],
    defaultRootObject: 'index.html',
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_10(scope: Construct) {
  // Create a bucket for static website content
  const bucket = new s3.Bucket(scope, 'WebsiteBucket', {
    blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
  });

  // Create an Origin Access Identity
  const oai = new cloudfront.OriginAccessIdentity(scope, 'OAI');

  // ok: typescript_cdk_s3_bucket_use_cloudfront_origin_access_identities
  const distribution = new cloudfront.Distribution(scope, 'Distribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket, {
        originAccessIdentity: oai,
      }),
      viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.HTTPS_ONLY,
    },
    comment: 'Distribution for static website',
    enabled: true,
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_11(scope: Construct) {
  // Using Origin Access Control (OAC) instead of OAI (newer approach)
  const bucket = new s3.Bucket(scope, 'WebsiteBucket', {
    blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
  });

  // ok: typescript_cdk_s3_bucket_use_cloudfront_origin_access_identities
  const distribution = new cloudfront.Distribution(scope, 'Distribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket, {
        originAccessControl: {
          controlType: 'origin-access-control',
          signRequests: true,
          signOriginAccessControl: true,
        },
      }),
    },
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_12(scope: Construct) {
  // Create a bucket for static website content
  const bucket = new s3.Bucket(scope, 'WebsiteBucket', {
    blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
  });

  // Create an Origin Access Identity
  const oai = new cloudfront.OriginAccessIdentity(scope, 'OAI');

  // ok: typescript_cdk_s3_bucket_use_cloudfront_origin_access_identities
  const distribution = new cloudfront.Distribution(scope, 'Distribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket, {
        originAccessIdentity: oai,
      }),
    },
    httpVersion: cloudfront.HttpVersion.HTTP2,
    defaultRootObject: 'index.html',
    enableIpv6: true,
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_13(scope: Construct) {
  // Create a bucket for static website content
  const bucket = new s3.Bucket(scope, 'WebsiteBucket', {
    blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
  });

  // Create an Origin Access Identity
  const oai = new cloudfront.OriginAccessIdentity(scope, 'OAI');

  // ok: typescript_cdk_s3_bucket_use_cloudfront_origin_access_identities
  const distribution = new cloudfront.Distribution(scope, 'Distribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket, {
        originAccessIdentity: oai,
      }),
      compress: true,
      viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
    },
    geoRestriction: cloudfront.GeoRestriction.allowlist('US', 'CA'),
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_14(scope: Construct) {
  // Create a bucket for static website content
  const bucket = new s3.Bucket(scope, 'WebsiteBucket', {
    blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
  });

  // Create an Origin Access Identity
  const oai = new cloudfront.OriginAccessIdentity(scope, 'OAI');

  // ok: typescript_cdk_s3_bucket_use_cloudfront_origin_access_identities
  const distribution = new cloudfront.Distribution(scope, 'Distribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket, {
        originAccessIdentity: oai,
      }),
      originRequestPolicy: cloudfront.OriginRequestPolicy.CORS_S3_ORIGIN,
    },
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_15(scope: Construct) {
  // Create a bucket for static website content
  const bucket = new s3.Bucket(scope, 'WebsiteBucket', {
    blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
  });

  // Create an Origin Access Identity
  const oai = new cloudfront.OriginAccessIdentity(scope, 'OAI');

  // Grant read access to the OAI
  bucket.grantRead(oai);

  // Create a CloudFront web distribution
  // ok: typescript_cdk_s3_bucket_use_cloudfront_origin_access_identities
  const distribution = new cloudfront.CloudFrontWebDistribution(scope, 'WebDistribution', {
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