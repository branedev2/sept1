import { Stack, StackProps } from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as cloudfront from 'aws-cdk-lib/aws-cloudfront';
import * as origins from 'aws-cdk-lib/aws-cloudfront-origins';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as acm from 'aws-cdk-lib/aws-certificatemanager';
import * as route53 from 'aws-cdk-lib/aws-route53';

// TRUE POSITIVES - Vulnerable configurations

// {fact rule=improperly-implemented-security-check@v1.0 defects=1}
function bad_case_1(scope: Construct) {
  // Using default CloudFront certificate without specifying minimum protocol version
  const bucket = new s3.Bucket(scope, 'MyBucket');
  
  // ruleid: typescript_cdk_allows_https_viewer_connections_cloudfront_distribution
  new cloudfront.Distribution(scope, 'MyDistribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket),
    },
    defaultRootObject: 'index.html',
  });
}
// {/fact}

// {fact rule=improperly-implemented-security-check@v1.0 defects=1}
function bad_case_2(scope: Construct) {
  // Using default CloudFront certificate with TLSv1 explicitly specified
  const bucket = new s3.Bucket(scope, 'MyBucket');
  
  // ruleid: typescript_cdk_allows_https_viewer_connections_cloudfront_distribution
  new cloudfront.Distribution(scope, 'MyDistribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket),
    },
    defaultRootObject: 'index.html',
    viewerCertificate: cloudfront.ViewerCertificate.fromCloudFrontDefaultCertificate('example.com', {
      minimumProtocolVersion: cloudfront.SecurityPolicyProtocol.TLS_V1,
    }),
  });
}
// {/fact}

// {fact rule=improperly-implemented-security-check@v1.0 defects=1}
function bad_case_3(scope: Construct) {
  // Using custom certificate but with TLSv1 protocol
  const bucket = new s3.Bucket(scope, 'MyBucket');
  const certificate = acm.Certificate.fromCertificateArn(scope, 'Certificate', 'arn:aws:acm:us-east-1:123456789012:certificate/my-cert-id');
  
  // ruleid: typescript_cdk_allows_https_viewer_connections_cloudfront_distribution
  new cloudfront.Distribution(scope, 'MyDistribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket),
    },
    domainNames: ['example.com'],
    certificate: certificate,
    minimumProtocolVersion: cloudfront.SecurityPolicyProtocol.TLS_V1,
  });
}
// {/fact}

// {fact rule=improperly-implemented-security-check@v1.0 defects=1}
function bad_case_4(scope: Construct) {
  // Using custom certificate with VIP SSL support method (which may default to TLSv1)
  const bucket = new s3.Bucket(scope, 'MyBucket');
  const certificate = acm.Certificate.fromCertificateArn(scope, 'Certificate', 'arn:aws:acm:us-east-1:123456789012:certificate/my-cert-id');
  
  // ruleid: typescript_cdk_allows_https_viewer_connections_cloudfront_distribution
  new cloudfront.Distribution(scope, 'MyDistribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket),
    },
    domainNames: ['example.com'],
    viewerCertificate: cloudfront.ViewerCertificate.fromAcmCertificate(certificate, {
      sslMethod: cloudfront.SSLMethod.VIP,
      securityPolicy: cloudfront.SecurityPolicyProtocol.TLS_V1_2_2019,
    }),
  });
}
// {/fact}

// {fact rule=improperly-implemented-security-check@v1.0 defects=1}
function bad_case_5(scope: Construct) {
  // Using IAM certificate with TLSv1
  const bucket = new s3.Bucket(scope, 'MyBucket');
  
  // ruleid: typescript_cdk_allows_https_viewer_connections_cloudfront_distribution
  new cloudfront.Distribution(scope, 'MyDistribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket),
    },
    viewerCertificate: cloudfront.ViewerCertificate.fromIamCertificate('certificate-id', {
      minimumProtocolVersion: cloudfront.SecurityPolicyProtocol.TLS_V1,
    }),
  });
}
// {/fact}

// {fact rule=improperly-implemented-security-check@v1.0 defects=1}
function bad_case_6(scope: Construct) {
  // Using CloudFront default certificate in a distribution with price class set
  const bucket = new s3.Bucket(scope, 'MyBucket');
  
  // ruleid: typescript_cdk_allows_https_viewer_connections_cloudfront_distribution
  new cloudfront.Distribution(scope, 'MyDistribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket),
    },
    priceClass: cloudfront.PriceClass.PRICE_CLASS_100,
    viewerCertificate: cloudfront.ViewerCertificate.fromCloudFrontDefaultCertificate(),
  });
}
// {/fact}

// {fact rule=improperly-implemented-security-check@v1.0 defects=1}
function bad_case_7(scope: Construct) {
  // Using ACM certificate but with TLSv1 protocol
  const bucket = new s3.Bucket(scope, 'MyBucket');
  const certificate = acm.Certificate.fromCertificateArn(scope, 'Certificate', 'arn:aws:acm:us-east-1:123456789012:certificate/my-cert-id');
  
  // ruleid: typescript_cdk_allows_https_viewer_connections_cloudfront_distribution
  new cloudfront.Distribution(scope, 'MyDistribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket),
    },
    viewerCertificate: cloudfront.ViewerCertificate.fromAcmCertificate(certificate, {
      securityPolicy: cloudfront.SecurityPolicyProtocol.TLS_V1,
    }),
  });
}
// {/fact}

// {fact rule=improperly-implemented-security-check@v1.0 defects=1}
function bad_case_8(scope: Construct) {
  // Using IAM certificate with VIP SSL method
  const bucket = new s3.Bucket(scope, 'MyBucket');
  
  // ruleid: typescript_cdk_allows_https_viewer_connections_cloudfront_distribution
  new cloudfront.Distribution(scope, 'MyDistribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket),
    },
    viewerCertificate: cloudfront.ViewerCertificate.fromIamCertificate('certificate-id', {
      sslMethod: cloudfront.SSLMethod.VIP,
    }),
  });
}
// {/fact}

// {fact rule=improperly-implemented-security-check@v1.0 defects=1}
function bad_case_9(scope: Construct) {
  // Using CloudFront default certificate with aliases
  const bucket = new s3.Bucket(scope, 'MyBucket');
  
  // ruleid: typescript_cdk_allows_https_viewer_connections_cloudfront_distribution
  new cloudfront.Distribution(scope, 'MyDistribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket),
    },
    domainNames: ['example.com', 'www.example.com'],
    certificate: cloudfront.ViewerCertificate.fromCloudFrontDefaultCertificate(),
  });
}
// {/fact}

// {fact rule=improperly-implemented-security-check@v1.0 defects=1}
function bad_case_10(scope: Construct) {
  // Using ACM certificate with TLSv1 protocol and SNI
  const bucket = new s3.Bucket(scope, 'MyBucket');
  const certificate = acm.Certificate.fromCertificateArn(scope, 'Certificate', 'arn:aws:acm:us-east-1:123456789012:certificate/my-cert-id');
  
  // ruleid: typescript_cdk_allows_https_viewer_connections_cloudfront_distribution
  new cloudfront.Distribution(scope, 'MyDistribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket),
    },
    viewerCertificate: cloudfront.ViewerCertificate.fromAcmCertificate(certificate, {
      securityPolicy: cloudfront.SecurityPolicyProtocol.TLS_V1,
      sslMethod: cloudfront.SSLMethod.SNI,
    }),
  });
}
// {/fact}

// {fact rule=improperly-implemented-security-check@v1.0 defects=1}
function bad_case_11(scope: Construct) {
  // Using IAM certificate with TLSv1 protocol explicitly
  const bucket = new s3.Bucket(scope, 'MyBucket');
  
  // ruleid: typescript_cdk_allows_https_viewer_connections_cloudfront_distribution
  new cloudfront.Distribution(scope, 'MyDistribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket),
    },
    viewerCertificate: cloudfront.ViewerCertificate.fromIamCertificate('certificate-id', {
      securityPolicy: cloudfront.SecurityPolicyProtocol.TLS_V1,
      sslMethod: cloudfront.SSLMethod.SNI,
    }),
  });
}
// {/fact}

// {fact rule=improperly-implemented-security-check@v1.0 defects=1}
function bad_case_12(scope: Construct) {
  // Using CloudFront default certificate with geo restrictions
  const bucket = new s3.Bucket(scope, 'MyBucket');
  
  // ruleid: typescript_cdk_allows_https_viewer_connections_cloudfront_distribution
  new cloudfront.Distribution(scope, 'MyDistribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket),
    },
    geoRestriction: cloudfront.GeoRestriction.allowlist('US', 'CA'),
    viewerCertificate: cloudfront.ViewerCertificate.fromCloudFrontDefaultCertificate(),
  });
}
// {/fact}

// {fact rule=improperly-implemented-security-check@v1.0 defects=1}
function bad_case_13(scope: Construct) {
  // Using ACM certificate with VIP SSL method
  const bucket = new s3.Bucket(scope, 'MyBucket');
  const certificate = acm.Certificate.fromCertificateArn(scope, 'Certificate', 'arn:aws:acm:us-east-1:123456789012:certificate/my-cert-id');
  
  // ruleid: typescript_cdk_allows_https_viewer_connections_cloudfront_distribution
  new cloudfront.Distribution(scope, 'MyDistribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket),
    },
    viewerCertificate: cloudfront.ViewerCertificate.fromAcmCertificate(certificate, {
      sslMethod: cloudfront.SSLMethod.VIP,
    }),
  });
}
// {/fact}

// {fact rule=improperly-implemented-security-check@v1.0 defects=1}
function bad_case_14(scope: Construct) {
  // Using IAM certificate with TLSv1_2016 (older policy)
  const bucket = new s3.Bucket(scope, 'MyBucket');
  
  // ruleid: typescript_cdk_allows_https_viewer_connections_cloudfront_distribution
  new cloudfront.Distribution(scope, 'MyDistribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket),
    },
    viewerCertificate: cloudfront.ViewerCertificate.fromIamCertificate('certificate-id', {
      securityPolicy: cloudfront.SecurityPolicyProtocol.TLS_V1_2016,
    }),
  });
}
// {/fact}

// {fact rule=improperly-implemented-security-check@v1.0 defects=1}
function bad_case_15(scope: Construct) {
  // Using CloudFront default certificate with HTTP to HTTPS redirection
  const bucket = new s3.Bucket(scope, 'MyBucket');
  
  // ruleid: typescript_cdk_allows_https_viewer_connections_cloudfront_distribution
  new cloudfront.Distribution(scope, 'MyDistribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket),
      viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
    },
    viewerCertificate: cloudfront.ViewerCertificate.fromCloudFrontDefaultCertificate(),
  });
}
// {/fact}

// TRUE NEGATIVES - Secure configurations

// {fact rule=improperly-implemented-security-check@v1.0 defects=0}
function good_case_1(scope: Construct) {
  // Using ACM certificate with TLSv1.2 protocol and SNI
  const bucket = new s3.Bucket(scope, 'MyBucket');
  const certificate = acm.Certificate.fromCertificateArn(scope, 'Certificate', 'arn:aws:acm:us-east-1:123456789012:certificate/my-cert-id');
  
  // ok: typescript_cdk_allows_https_viewer_connections_cloudfront_distribution
  new cloudfront.Distribution(scope, 'MyDistribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket),
    },
    viewerCertificate: cloudfront.ViewerCertificate.fromAcmCertificate(certificate, {
      securityPolicy: cloudfront.SecurityPolicyProtocol.TLS_V1_2_2019,
      sslMethod: cloudfront.SSLMethod.SNI,
    }),
  });
}
// {/fact}

// {fact rule=improperly-implemented-security-check@v1.0 defects=0}
function good_case_2(scope: Construct) {
  // Using IAM certificate with TLSv1.2 protocol and SNI
  const bucket = new s3.Bucket(scope, 'MyBucket');
  
  // ok: typescript_cdk_allows_https_viewer_connections_cloudfront_distribution
  new cloudfront.Distribution(scope, 'MyDistribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket),
    },
    viewerCertificate: cloudfront.ViewerCertificate.fromIamCertificate('certificate-id', {
      securityPolicy: cloudfront.SecurityPolicyProtocol.TLS_V1_2_2019,
      sslMethod: cloudfront.SSLMethod.SNI,
    }),
  });
}
// {/fact}

// {fact rule=improperly-implemented-security-check@v1.0 defects=0}
function good_case_3(scope: Construct) {
  // Using ACM certificate with TLSv1.2 protocol and SNI with domain names
  const bucket = new s3.Bucket(scope, 'MyBucket');
  const certificate = acm.Certificate.fromCertificateArn(scope, 'Certificate', 'arn:aws:acm:us-east-1:123456789012:certificate/my-cert-id');
  
  // ok: typescript_cdk_allows_https_viewer_connections_cloudfront_distribution
  new cloudfront.Distribution(scope, 'MyDistribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket),
    },
    domainNames: ['example.com', 'www.example.com'],
    viewerCertificate: cloudfront.ViewerCertificate.fromAcmCertificate(certificate, {
      securityPolicy: cloudfront.SecurityPolicyProtocol.TLS_V1_2_2019,
      sslMethod: cloudfront.SSLMethod.SNI,
    }),
  });
}
// {/fact}

// {fact rule=improperly-implemented-security-check@v1.0 defects=0}
function good_case_4(scope: Construct) {
  // Using ACM certificate with TLSv1.1 protocol (minimum acceptable)
  const bucket = new s3.Bucket(scope, 'MyBucket');
  const certificate = acm.Certificate.fromCertificateArn(scope, 'Certificate', 'arn:aws:acm:us-east-1:123456789012:certificate/my-cert-id');
  
  // ok: typescript_cdk_allows_https_viewer_connections_cloudfront_distribution
  new cloudfront.Distribution(scope, 'MyDistribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket),
    },
    viewerCertificate: cloudfront.ViewerCertificate.fromAcmCertificate(certificate, {
      securityPolicy: cloudfront.SecurityPolicyProtocol.TLS_V1_1_2016,
      sslMethod: cloudfront.SSLMethod.SNI,
    }),
  });
}
// {/fact}

// {fact rule=improperly-implemented-security-check@v1.0 defects=0}
function good_case_5(scope: Construct) {
  // Using IAM certificate with TLSv1.1 protocol (minimum acceptable)
  const bucket = new s3.Bucket(scope, 'MyBucket');
  
  // ok: typescript_cdk_allows_https_viewer_connections_cloudfront_distribution
  new cloudfront.Distribution(scope, 'MyDistribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket),
    },
    viewerCertificate: cloudfront.ViewerCertificate.fromIamCertificate('certificate-id', {
      securityPolicy: cloudfront.SecurityPolicyProtocol.TLS_V1_1_2016,
      sslMethod: cloudfront.SSLMethod.SNI,
    }),
  });
}
// {/fact}

// {fact rule=improperly-implemented-security-check@v1.0 defects=0}
function good_case_6(scope: Construct) {
  // Using ACM certificate with TLSv1.2_2018 protocol
  const bucket = new s3.Bucket(scope, 'MyBucket');
  const certificate = acm.Certificate.fromCertificateArn(scope, 'Certificate', 'arn:aws:acm:us-east-1:123456789012:certificate/my-cert-id');
  
  // ok: typescript_cdk_allows_https_viewer_connections_cloudfront_distribution
  new cloudfront.Distribution(scope, 'MyDistribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket),
    },
    viewerCertificate: cloudfront.ViewerCertificate.fromAcmCertificate(certificate, {
      securityPolicy: cloudfront.SecurityPolicyProtocol.TLS_V1_2_2018,
      sslMethod: cloudfront.SSLMethod.SNI,
    }),
  });
}
// {/fact}

// {fact rule=improperly-implemented-security-check@v1.0 defects=0}
function good_case_7(scope: Construct) {
  // Using IAM certificate with TLSv1.2_2018 protocol
  const bucket = new s3.Bucket(scope, 'MyBucket');
  
  // ok: typescript_cdk_allows_https_viewer_connections_cloudfront_distribution
  new cloudfront.Distribution(scope, 'MyDistribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket),
    },
    viewerCertificate: cloudfront.ViewerCertificate.fromIamCertificate('certificate-id', {
      securityPolicy: cloudfront.SecurityPolicyProtocol.TLS_V1_2_2018,
      sslMethod: cloudfront.SSLMethod.SNI,
    }),
  });
}
// {/fact}

// {fact rule=improperly-implemented-security-check@v1.0 defects=0}
function good_case_8(scope: Construct) {
  // Using ACM certificate with TLSv1.2_2021 protocol (most secure)
  const bucket = new s3.Bucket(scope, 'MyBucket');
  const certificate = acm.Certificate.fromCertificateArn(scope, 'Certificate', 'arn:aws:acm:us-east-1:123456789012:certificate/my-cert-id');
  
  // ok: typescript_cdk_allows_https_viewer_connections_cloudfront_distribution
  new cloudfront.Distribution(scope, 'MyDistribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket),
    },
    viewerCertificate: cloudfront.ViewerCertificate.fromAcmCertificate(certificate, {
      securityPolicy: cloudfront.SecurityPolicyProtocol.TLS_V1_2_2021,
      sslMethod: cloudfront.SSLMethod.SNI,
    }),
  });
}
// {/fact}

// {fact rule=improperly-implemented-security-check@v1.0 defects=0}
function good_case_9(scope: Construct) {
  // Using IAM certificate with TLSv1.2_2021 protocol (most secure)
  const bucket = new s3.Bucket(scope, 'MyBucket');
  
  // ok: typescript_cdk_allows_https_viewer_connections_cloudfront_distribution
  new cloudfront.Distribution(scope, 'MyDistribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket),
    },
    viewerCertificate: cloudfront.ViewerCertificate.fromIamCertificate('certificate-id', {
      securityPolicy: cloudfront.SecurityPolicyProtocol.TLS_V1_2_2021,
      sslMethod: cloudfront.SSLMethod.SNI,
    }),
  });
}
// {/fact}

// {fact rule=improperly-implemented-security-check@v1.0 defects=0}
function good_case_10(scope: Construct) {
  // Using ACM certificate with TLSv1.2 protocol and HTTP to HTTPS redirection
  const bucket = new s3.Bucket(scope, 'MyBucket');
  const certificate = acm.Certificate.fromCertificateArn(scope, 'Certificate', 'arn:aws:acm:us-east-1:123456789012:certificate/my-cert-id');
  
  // ok: typescript_cdk_allows_https_viewer_connections_cloudfront_distribution
  new cloudfront.Distribution(scope, 'MyDistribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket),
      viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
    },
    viewerCertificate: cloudfront.ViewerCertificate.fromAcmCertificate(certificate, {
      securityPolicy: cloudfront.SecurityPolicyProtocol.TLS_V1_2_2019,
      sslMethod: cloudfront.SSLMethod.SNI,
    }),
  });
}
// {/fact}

// {fact rule=improperly-implemented-security-check@v1.0 defects=0}
function good_case_11(scope: Construct) {
  // Using ACM certificate with TLSv1.2 protocol and HTTPS only
  const bucket = new s3.Bucket(scope, 'MyBucket');
  const certificate = acm.Certificate.fromCertificateArn(scope, 'Certificate', 'arn:aws:acm:us-east-1:123456789012:certificate/my-cert-id');
  
  // ok: typescript_cdk_allows_https_viewer_connections_cloudfront_distribution
  new cloudfront.Distribution(scope, 'MyDistribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket),
      viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.HTTPS_ONLY,
    },
    viewerCertificate: cloudfront.ViewerCertificate.fromAcmCertificate(certificate, {
      securityPolicy: cloudfront.SecurityPolicyProtocol.TLS_V1_2_2019,
      sslMethod: cloudfront.SSLMethod.SNI,
    }),
  });
}
// {/fact}

// {fact rule=improperly-implemented-security-check@v1.0 defects=0}
function good_case_12(scope: Construct) {
  // Using ACM certificate with TLSv1.2 protocol and geo restrictions
  const bucket = new s3.Bucket(scope, 'MyBucket');
  const certificate = acm.Certificate.fromCertificateArn(scope, 'Certificate', 'arn:aws:acm:us-east-1:123456789012:certificate/my-cert-id');
  
  // ok: typescript_cdk_allows_https_viewer_connections_cloudfront_distribution
  new cloudfront.Distribution(scope, 'MyDistribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket),
    },
    geoRestriction: cloudfront.GeoRestriction.allowlist('US', 'CA'),
    viewerCertificate: cloudfront.ViewerCertificate.fromAcmCertificate(certificate, {
      securityPolicy: cloudfront.SecurityPolicyProtocol.TLS_V1_2_2019,
      sslMethod: cloudfront.SSLMethod.SNI,
    }),
  });
}
// {/fact}

// {fact rule=improperly-implemented-security-check@v1.0 defects=0}
function good_case_13(scope: Construct) {
  // Using ACM certificate with TLSv1.2 protocol and price class set
  const bucket = new s3.Bucket(scope, 'MyBucket');
  const certificate = acm.Certificate.fromCertificateArn(scope, 'Certificate', 'arn:aws:acm:us-east-1:123456789012:certificate/my-cert-id');
  
  // ok: typescript_cdk_allows_https_viewer_connections_cloudfront_distribution
  new cloudfront.Distribution(scope, 'MyDistribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket),
    },
    priceClass: cloudfront.PriceClass.PRICE_CLASS_100,
    viewerCertificate: cloudfront.ViewerCertificate.fromAcmCertificate(certificate, {
      securityPolicy: cloudfront.SecurityPolicyProtocol.TLS_V1_2_2019,
      sslMethod: cloudfront.SSLMethod.SNI,
    }),
  });
}
// {/fact}

// {fact rule=improperly-implemented-security-check@v1.0 defects=0}
function good_case_14(scope: Construct) {
  // Using ACM certificate with TLSv1.2 protocol and custom error responses
  const bucket = new s3.Bucket(scope, 'MyBucket');
  const certificate = acm.Certificate.fromCertificateArn(scope, 'Certificate', 'arn:aws:acm:us-east-1:123456789012:certificate/my-cert-id');
  
  // ok: typescript_cdk_allows_https_viewer_connections_cloudfront_distribution
  new cloudfront.Distribution(scope, 'MyDistribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket),
    },
    errorResponses: [
      {
        httpStatus: 404,
        responseHttpStatus: 404,
        responsePagePath: '/error.html',
      },
    ],
    viewerCertificate: cloudfront.ViewerCertificate.fromAcmCertificate(certificate, {
      securityPolicy: cloudfront.SecurityPolicyProtocol.TLS_V1_2_2019,
      sslMethod: cloudfront.SSLMethod.SNI,
    }),
  });
}
// {/fact}

// {fact rule=improperly-implemented-security-check@v1.0 defects=0}
function good_case_15(scope: Construct) {
  // Using ACM certificate with TLSv1.2 protocol and multiple behaviors
  const bucket = new s3.Bucket(scope, 'MyBucket');
  const certificate = acm.Certificate.fromCertificateArn(scope, 'Certificate', 'arn:aws:acm:us-east-1:123456789012:certificate/my-cert-id');
  
  // ok: typescript_cdk_allows_https_viewer_connections_cloudfront_distribution
  new cloudfront.Distribution(scope, 'MyDistribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket),
    },
    additionalBehaviors: {
      '/api/*': {
        origin: new origins.S3Origin(bucket),
        allowedMethods: cloudfront.AllowedMethods.ALLOW_ALL,
      },
    },
    viewerCertificate: cloudfront.ViewerCertificate.fromAcmCertificate(certificate, {
      securityPolicy: cloudfront.SecurityPolicyProtocol.TLS_V1_2_2019,
      sslMethod: cloudfront.SSLMethod.SNI,
    }),
  });
}
// {/fact}