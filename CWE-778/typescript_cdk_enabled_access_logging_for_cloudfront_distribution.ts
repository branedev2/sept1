import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as cloudfront from 'aws-cdk-lib/aws-cloudfront';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as origins from 'aws-cdk-lib/aws-cloudfront-origins';

// True Positive Examples (Vulnerable Code)

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_1(scope: Construct) {
  // Creating a CloudFront distribution without access logging
  // ruleid: typescript_cdk_enabled_access_logging_for_cloudfront_distribution
  const distribution = new cloudfront.Distribution(scope, 'Distribution', {
    defaultBehavior: {
      origin: new origins.HttpOrigin('www.example.com'),
    },
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_2(scope: Construct) {
  // Creating a CloudFront distribution with explicitly disabled access logging
  const bucket = new s3.Bucket(scope, 'LoggingBucket');
  
  // ruleid: typescript_cdk_enabled_access_logging_for_cloudfront_distribution
  const distribution = new cloudfront.Distribution(scope, 'Distribution', {
    defaultBehavior: {
      origin: new origins.HttpOrigin('www.example.com'),
    },
    logBucket: bucket,
    logFilePrefix: 'logs/',
    logIncludesCookies: false,
    enableLogging: false, // Explicitly disabled
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_3(scope: Construct) {
  // Creating a CloudFront distribution with default props
  const defaultProps = {
    defaultBehavior: {
      origin: new origins.HttpOrigin('www.example.com'),
    },
  };
  
  // ruleid: typescript_cdk_enabled_access_logging_for_cloudfront_distribution
  const distribution = new cloudfront.Distribution(scope, 'Distribution', defaultProps);
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_4(scope: Construct) {
  // Creating a CloudFront distribution with minimal configuration
  const originConfig = new origins.S3Origin(new s3.Bucket(scope, 'OriginBucket'));
  
  // ruleid: typescript_cdk_enabled_access_logging_for_cloudfront_distribution
  const distribution = new cloudfront.Distribution(scope, 'Distribution', {
    defaultBehavior: { origin: originConfig },
    priceClass: cloudfront.PriceClass.PRICE_CLASS_100,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_5(scope: Construct) {
  // Creating a CloudFront distribution with certificate but no logging
  // ruleid: typescript_cdk_enabled_access_logging_for_cloudfront_distribution
  const distribution = new cloudfront.Distribution(scope, 'Distribution', {
    defaultBehavior: {
      origin: new origins.HttpOrigin('www.example.com'),
      viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
    },
    domainNames: ['example.com'],
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_6(scope: Construct) {
  // Creating a CloudFront distribution with multiple behaviors but no logging
  // ruleid: typescript_cdk_enabled_access_logging_for_cloudfront_distribution
  const distribution = new cloudfront.Distribution(scope, 'Distribution', {
    defaultBehavior: {
      origin: new origins.HttpOrigin('www.example.com'),
    },
    additionalBehaviors: {
      '/api/*': {
        origin: new origins.HttpOrigin('api.example.com'),
      },
    },
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_7(scope: Construct) {
  // Creating a CloudFront distribution with geo restrictions but no logging
  // ruleid: typescript_cdk_enabled_access_logging_for_cloudfront_distribution
  const distribution = new cloudfront.Distribution(scope, 'Distribution', {
    defaultBehavior: {
      origin: new origins.HttpOrigin('www.example.com'),
    },
    geoRestriction: {
      restrictionType: cloudfront.GeoRestrictionType.WHITELIST,
      locations: ['US', 'CA', 'GB', 'DE'],
    },
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_8(scope: Construct) {
  // Creating a CloudFront distribution with WAF but no logging
  // ruleid: typescript_cdk_enabled_access_logging_for_cloudfront_distribution
  const distribution = new cloudfront.Distribution(scope, 'Distribution', {
    defaultBehavior: {
      origin: new origins.HttpOrigin('www.example.com'),
    },
    webAclId: 'arn:aws:wafv2:us-east-1:123456789012:global/webacl/ExampleWebACL/abcdef12-3456-7890-abcd-ef1234567890',
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_9(scope: Construct) {
  // Creating a CloudFront distribution with custom error responses but no logging
  // ruleid: typescript_cdk_enabled_access_logging_for_cloudfront_distribution
  const distribution = new cloudfront.Distribution(scope, 'Distribution', {
    defaultBehavior: {
      origin: new origins.HttpOrigin('www.example.com'),
    },
    errorResponses: [
      {
        httpStatus: 404,
        responseHttpStatus: 404,
        responsePagePath: '/404.html',
      },
    ],
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_10(scope: Construct) {
  // Creating a CloudFront distribution with HTTP version settings but no logging
  // ruleid: typescript_cdk_enabled_access_logging_for_cloudfront_distribution
  const distribution = new cloudfront.Distribution(scope, 'Distribution', {
    defaultBehavior: {
      origin: new origins.HttpOrigin('www.example.com'),
    },
    httpVersion: cloudfront.HttpVersion.HTTP2,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_11(scope: Construct) {
  // Creating a CloudFront distribution with enabled IPv6 but no logging
  // ruleid: typescript_cdk_enabled_access_logging_for_cloudfront_distribution
  const distribution = new cloudfront.Distribution(scope, 'Distribution', {
    defaultBehavior: {
      origin: new origins.HttpOrigin('www.example.com'),
    },
    enableIpv6: true,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_12(scope: Construct) {
  // Creating a CloudFront distribution with custom origin config but no logging
  // ruleid: typescript_cdk_enabled_access_logging_for_cloudfront_distribution
  const distribution = new cloudfront.Distribution(scope, 'Distribution', {
    defaultBehavior: {
      origin: new origins.HttpOrigin('www.example.com', {
        protocolPolicy: cloudfront.OriginProtocolPolicy.HTTPS_ONLY,
        readTimeout: cdk.Duration.seconds(30),
      }),
    },
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_13(scope: Construct) {
  // Creating a CloudFront distribution with caching settings but no logging
  // ruleid: typescript_cdk_enabled_access_logging_for_cloudfront_distribution
  const distribution = new cloudfront.Distribution(scope, 'Distribution', {
    defaultBehavior: {
      origin: new origins.HttpOrigin('www.example.com'),
      cachePolicy: cloudfront.CachePolicy.CACHING_OPTIMIZED,
    },
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_14(scope: Construct) {
  // Creating a CloudFront distribution with comment but no logging
  // ruleid: typescript_cdk_enabled_access_logging_for_cloudfront_distribution
  const distribution = new cloudfront.Distribution(scope, 'Distribution', {
    defaultBehavior: {
      origin: new origins.HttpOrigin('www.example.com'),
    },
    comment: 'Main website distribution',
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_15(scope: Construct) {
  // Creating a CloudFront distribution with enabled flag but no logging
  // ruleid: typescript_cdk_enabled_access_logging_for_cloudfront_distribution
  const distribution = new cloudfront.Distribution(scope, 'Distribution', {
    defaultBehavior: {
      origin: new origins.HttpOrigin('www.example.com'),
    },
    enabled: true,
  });
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_1(scope: Construct) {
  // Creating a CloudFront distribution with access logging enabled
  const bucket = new s3.Bucket(scope, 'LoggingBucket');
  
  // ok: typescript_cdk_enabled_access_logging_for_cloudfront_distribution
  const distribution = new cloudfront.Distribution(scope, 'Distribution', {
    defaultBehavior: {
      origin: new origins.HttpOrigin('www.example.com'),
    },
    logBucket: bucket,
    logFilePrefix: 'distribution-logs/',
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_2(scope: Construct) {
  // Creating a CloudFront distribution with access logging explicitly enabled
  const bucket = new s3.Bucket(scope, 'LoggingBucket');
  
  // ok: typescript_cdk_enabled_access_logging_for_cloudfront_distribution
  const distribution = new cloudfront.Distribution(scope, 'Distribution', {
    defaultBehavior: {
      origin: new origins.HttpOrigin('www.example.com'),
    },
    logBucket: bucket,
    logFilePrefix: 'logs/',
    enableLogging: true,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_3(scope: Construct) {
  // Creating a CloudFront distribution with access logging and cookie inclusion
  const bucket = new s3.Bucket(scope, 'LoggingBucket');
  
  // ok: typescript_cdk_enabled_access_logging_for_cloudfront_distribution
  const distribution = new cloudfront.Distribution(scope, 'Distribution', {
    defaultBehavior: {
      origin: new origins.HttpOrigin('www.example.com'),
    },
    logBucket: bucket,
    logFilePrefix: 'logs/',
    logIncludesCookies: true,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_4(scope: Construct) {
  // Creating a CloudFront distribution with access logging using variable
  const bucket = new s3.Bucket(scope, 'LoggingBucket');
  const logPrefix = 'cloudfront-logs/';
  
  // ok: typescript_cdk_enabled_access_logging_for_cloudfront_distribution
  const distribution = new cloudfront.Distribution(scope, 'Distribution', {
    defaultBehavior: {
      origin: new origins.HttpOrigin('www.example.com'),
    },
    logBucket: bucket,
    logFilePrefix: logPrefix,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_5(scope: Construct) {
  // Creating a CloudFront distribution with access logging and multiple behaviors
  const bucket = new s3.Bucket(scope, 'LoggingBucket');
  
  // ok: typescript_cdk_enabled_access_logging_for_cloudfront_distribution
  const distribution = new cloudfront.Distribution(scope, 'Distribution', {
    defaultBehavior: {
      origin: new origins.HttpOrigin('www.example.com'),
    },
    additionalBehaviors: {
      '/api/*': {
        origin: new origins.HttpOrigin('api.example.com'),
      },
    },
    logBucket: bucket,
    logFilePrefix: 'distribution-logs/',
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_6(scope: Construct) {
  // Creating a CloudFront distribution with access logging and certificate
  const bucket = new s3.Bucket(scope, 'LoggingBucket');
  
  // ok: typescript_cdk_enabled_access_logging_for_cloudfront_distribution
  const distribution = new cloudfront.Distribution(scope, 'Distribution', {
    defaultBehavior: {
      origin: new origins.HttpOrigin('www.example.com'),
      viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
    },
    domainNames: ['example.com'],
    logBucket: bucket,
    logFilePrefix: 'logs/',
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_7(scope: Construct) {
  // Creating a CloudFront distribution with access logging and geo restrictions
  const bucket = new s3.Bucket(scope, 'LoggingBucket');
  
  // ok: typescript_cdk_enabled_access_logging_for_cloudfront_distribution
  const distribution = new cloudfront.Distribution(scope, 'Distribution', {
    defaultBehavior: {
      origin: new origins.HttpOrigin('www.example.com'),
    },
    geoRestriction: {
      restrictionType: cloudfront.GeoRestrictionType.WHITELIST,
      locations: ['US', 'CA', 'GB', 'DE'],
    },
    logBucket: bucket,
    logFilePrefix: 'geo-restricted-logs/',
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_8(scope: Construct) {
  // Creating a CloudFront distribution with access logging and WAF
  const bucket = new s3.Bucket(scope, 'LoggingBucket');
  
  // ok: typescript_cdk_enabled_access_logging_for_cloudfront_distribution
  const distribution = new cloudfront.Distribution(scope, 'Distribution', {
    defaultBehavior: {
      origin: new origins.HttpOrigin('www.example.com'),
    },
    webAclId: 'arn:aws:wafv2:us-east-1:123456789012:global/webacl/ExampleWebACL/abcdef12-3456-7890-abcd-ef1234567890',
    logBucket: bucket,
    logFilePrefix: 'waf-protected-logs/',
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_9(scope: Construct) {
  // Creating a CloudFront distribution with access logging and custom error responses
  const bucket = new s3.Bucket(scope, 'LoggingBucket');
  
  // ok: typescript_cdk_enabled_access_logging_for_cloudfront_distribution
  const distribution = new cloudfront.Distribution(scope, 'Distribution', {
    defaultBehavior: {
      origin: new origins.HttpOrigin('www.example.com'),
    },
    errorResponses: [
      {
        httpStatus: 404,
        responseHttpStatus: 404,
        responsePagePath: '/404.html',
      },
    ],
    logBucket: bucket,
    logFilePrefix: 'error-logs/',
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_10(scope: Construct) {
  // Creating a CloudFront distribution with access logging and HTTP version settings
  const bucket = new s3.Bucket(scope, 'LoggingBucket');
  
  // ok: typescript_cdk_enabled_access_logging_for_cloudfront_distribution
  const distribution = new cloudfront.Distribution(scope, 'Distribution', {
    defaultBehavior: {
      origin: new origins.HttpOrigin('www.example.com'),
    },
    httpVersion: cloudfront.HttpVersion.HTTP2,
    logBucket: bucket,
    logFilePrefix: 'http2-logs/',
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_11(scope: Construct) {
  // Creating a CloudFront distribution with access logging and IPv6 enabled
  const bucket = new s3.Bucket(scope, 'LoggingBucket');
  
  // ok: typescript_cdk_enabled_access_logging_for_cloudfront_distribution
  const distribution = new cloudfront.Distribution(scope, 'Distribution', {
    defaultBehavior: {
      origin: new origins.HttpOrigin('www.example.com'),
    },
    enableIpv6: true,
    logBucket: bucket,
    logFilePrefix: 'ipv6-logs/',
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_12(scope: Construct) {
  // Creating a CloudFront distribution with access logging and S3 origin
  const contentBucket = new s3.Bucket(scope, 'ContentBucket');
  const logBucket = new s3.Bucket(scope, 'LoggingBucket');
  
  // ok: typescript_cdk_enabled_access_logging_for_cloudfront_distribution
  const distribution = new cloudfront.Distribution(scope, 'Distribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(contentBucket),
    },
    logBucket: logBucket,
    logFilePrefix: 's3-origin-logs/',
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_13(scope: Construct) {
  // Creating a CloudFront distribution with access logging and caching settings
  const bucket = new s3.Bucket(scope, 'LoggingBucket');
  
  // ok: typescript_cdk_enabled_access_logging_for_cloudfront_distribution
  const distribution = new cloudfront.Distribution(scope, 'Distribution', {
    defaultBehavior: {
      origin: new origins.HttpOrigin('www.example.com'),
      cachePolicy: cloudfront.CachePolicy.CACHING_OPTIMIZED,
    },
    logBucket: bucket,
    logFilePrefix: 'cached-content-logs/',
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_14(scope: Construct) {
  // Creating a CloudFront distribution with access logging using props object
  const bucket = new s3.Bucket(scope, 'LoggingBucket');
  
  const props = {
    defaultBehavior: {
      origin: new origins.HttpOrigin('www.example.com'),
    },
    logBucket: bucket,
    logFilePrefix: 'distribution-logs/',
  };
  
  // ok: typescript_cdk_enabled_access_logging_for_cloudfront_distribution
  const distribution = new cloudfront.Distribution(scope, 'Distribution', props);
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_15(scope: Construct) {
  // Creating a CloudFront distribution with access logging and price class
  const bucket = new s3.Bucket(scope, 'LoggingBucket');
  
  // ok: typescript_cdk_enabled_access_logging_for_cloudfront_distribution
  const distribution = new cloudfront.Distribution(scope, 'Distribution', {
    defaultBehavior: {
      origin: new origins.HttpOrigin('www.example.com'),
    },
    priceClass: cloudfront.PriceClass.PRICE_CLASS_100,
    logBucket: bucket,
    logFilePrefix: 'price-class-logs/',
  });
}
// {/fact}