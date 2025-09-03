import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as cloudfront from 'aws-cdk-lib/aws-cloudfront';
import * as origins from 'aws-cdk-lib/aws-cloudfront-origins';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as iam from 'aws-cdk-lib/aws-iam';

// True Positive Examples (Vulnerable Code)

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_1() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const bucket = new s3.Bucket(stack, 'MyBucket');
  
  // ruleid: typescript-cdk-cloud-front-distribution-no-outdated-ssl
  new cloudfront.Distribution(stack, 'Distribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket),
      viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.HTTPS_ONLY,
    },
    minimumProtocolVersion: cloudfront.SecurityPolicyProtocol.SSL_V3,
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_2() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const bucket = new s3.Bucket(stack, 'MyBucket');
  
  // ruleid: typescript-cdk-cloud-front-distribution-no-outdated-ssl
  new cloudfront.Distribution(stack, 'Distribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket),
    },
    minimumProtocolVersion: cloudfront.SecurityPolicyProtocol.TLS_V1_0,
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_3() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const bucket = new s3.Bucket(stack, 'MyBucket');
  const distribution = new cloudfront.Distribution(stack, 'Distribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket),
    },
  });
  
  // ruleid: typescript-cdk-cloud-front-distribution-no-outdated-ssl
  const cfnDistribution = distribution.node.defaultChild as cloudfront.CfnDistribution;
  cfnDistribution.addPropertyOverride('DistributionConfig.ViewerCertificate.MinimumProtocolVersion', 'SSLv3');
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_4() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const bucket = new s3.Bucket(stack, 'MyBucket');
  
  const securityPolicy = cloudfront.SecurityPolicyProtocol.SSL_V3;
  
  // ruleid: typescript-cdk-cloud-front-distribution-no-outdated-ssl
  new cloudfront.Distribution(stack, 'Distribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket),
    },
    minimumProtocolVersion: securityPolicy,
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_5() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const bucket = new s3.Bucket(stack, 'MyBucket');
  
  const distributionProps: cloudfront.DistributionProps = {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket),
    },
    minimumProtocolVersion: cloudfront.SecurityPolicyProtocol.TLS_V1_0,
  };
  
  // ruleid: typescript-cdk-cloud-front-distribution-no-outdated-ssl
  new cloudfront.Distribution(stack, 'Distribution', distributionProps);
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_6() {
  class MyConstruct extends Construct {
    constructor(scope: Construct, id: string) {
      super(scope, id);
      
      const bucket = new s3.Bucket(this, 'MyBucket');
      
      // ruleid: typescript-cdk-cloud-front-distribution-no-outdated-ssl
      new cloudfront.Distribution(this, 'Distribution', {
        defaultBehavior: {
          origin: new origins.S3Origin(bucket),
        },
        minimumProtocolVersion: cloudfront.SecurityPolicyProtocol.SSL_V3,
      });
    }
  }
  
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  new MyConstruct(stack, 'MyConstruct');
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_7() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const bucket = new s3.Bucket(stack, 'MyBucket');
  
  const getSecurityPolicy = () => {
    return cloudfront.SecurityPolicyProtocol.TLS_V1_0;
  };
  
  // ruleid: typescript-cdk-cloud-front-distribution-no-outdated-ssl
  new cloudfront.Distribution(stack, 'Distribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket),
    },
    minimumProtocolVersion: getSecurityPolicy(),
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_8() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const bucket = new s3.Bucket(stack, 'MyBucket');
  const apiOrigin = new origins.HttpOrigin('api.example.com');
  
  // ruleid: typescript-cdk-cloud-front-distribution-no-outdated-ssl
  new cloudfront.Distribution(stack, 'Distribution', {
    defaultBehavior: {
      origin: apiOrigin,
    },
    additionalBehaviors: {
      '/api/*': {
        origin: new origins.S3Origin(bucket),
      },
    },
    minimumProtocolVersion: cloudfront.SecurityPolicyProtocol.TLS_V1_0,
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_9() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const bucket = new s3.Bucket(stack, 'MyBucket');
  
  const securityPolicies = [
    cloudfront.SecurityPolicyProtocol.TLS_V1_2,
    cloudfront.SecurityPolicyProtocol.TLS_V1_0,
    cloudfront.SecurityPolicyProtocol.TLS_V1_1,
  ];
  
  // ruleid: typescript-cdk-cloud-front-distribution-no-outdated-ssl
  new cloudfront.Distribution(stack, 'Distribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket),
    },
    minimumProtocolVersion: securityPolicies[1], // TLS_V1_0
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_10() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const bucket = new s3.Bucket(stack, 'MyBucket');
  
  const isProd = false;
  const securityPolicy = isProd 
    ? cloudfront.SecurityPolicyProtocol.TLS_V1_2 
    : cloudfront.SecurityPolicyProtocol.SSL_V3;
  
  // ruleid: typescript-cdk-cloud-front-distribution-no-outdated-ssl
  new cloudfront.Distribution(stack, 'Distribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket),
    },
    minimumProtocolVersion: securityPolicy,
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_11() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const bucket = new s3.Bucket(stack, 'MyBucket');
  
  // ruleid: typescript-cdk-cloud-front-distribution-no-outdated-ssl
  const distribution = new cloudfront.CloudFrontWebDistribution(stack, 'WebDistribution', {
    originConfigs: [
      {
        s3OriginSource: {
          s3BucketSource: bucket,
        },
        behaviors: [{ isDefaultBehavior: true }],
      },
    ],
    viewerCertificate: {
      cloudFrontDefaultCertificate: true,
      minimumProtocolVersion: 'TLSv1',
    },
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_12() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const bucket = new s3.Bucket(stack, 'MyBucket');
  
  // ruleid: typescript-cdk-cloud-front-distribution-no-outdated-ssl
  const distribution = new cloudfront.CloudFrontWebDistribution(stack, 'WebDistribution', {
    originConfigs: [
      {
        s3OriginSource: {
          s3BucketSource: bucket,
        },
        behaviors: [{ isDefaultBehavior: true }],
      },
    ],
    viewerCertificate: {
      acmCertificateArn: 'arn:aws:acm:us-east-1:123456789012:certificate/abcdef',
      sslSupportMethod: 'sni-only',
      minimumProtocolVersion: 'SSLv3',
    },
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_13() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const bucket = new s3.Bucket(stack, 'MyBucket');
  
  const viewerCertConfig = {
    cloudFrontDefaultCertificate: true,
    minimumProtocolVersion: 'TLSv1',
  };
  
  // ruleid: typescript-cdk-cloud-front-distribution-no-outdated-ssl
  const distribution = new cloudfront.CloudFrontWebDistribution(stack, 'WebDistribution', {
    originConfigs: [
      {
        s3OriginSource: {
          s3BucketSource: bucket,
        },
        behaviors: [{ isDefaultBehavior: true }],
      },
    ],
    viewerCertificate: viewerCertConfig,
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_14() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const bucket = new s3.Bucket(stack, 'MyBucket');
  
  // ruleid: typescript-cdk-cloud-front-distribution-no-outdated-ssl
  const cfnDistribution = new cloudfront.CfnDistribution(stack, 'CfnDistribution', {
    distributionConfig: {
      origins: [
        {
          id: 'S3Origin',
          domainName: bucket.bucketDomainName,
          s3OriginConfig: {
            originAccessIdentity: '',
          },
        },
      ],
      defaultCacheBehavior: {
        targetOriginId: 'S3Origin',
        viewerProtocolPolicy: 'redirect-to-https',
        allowedMethods: ['GET', 'HEAD'],
        cachedMethods: ['GET', 'HEAD'],
        forwardedValues: {
          queryString: false,
          cookies: { forward: 'none' },
        },
      },
      enabled: true,
      viewerCertificate: {
        cloudFrontDefaultCertificate: true,
        minimumProtocolVersion: 'TLSv1',
      },
    },
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_15() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const bucket = new s3.Bucket(stack, 'MyBucket');
  
  // ruleid: typescript-cdk-cloud-front-distribution-no-outdated-ssl
  const cfnDistribution = new cloudfront.CfnDistribution(stack, 'CfnDistribution', {
    distributionConfig: {
      origins: [
        {
          id: 'S3Origin',
          domainName: bucket.bucketDomainName,
          s3OriginConfig: {
            originAccessIdentity: '',
          },
        },
      ],
      defaultCacheBehavior: {
        targetOriginId: 'S3Origin',
        viewerProtocolPolicy: 'redirect-to-https',
        allowedMethods: ['GET', 'HEAD'],
        cachedMethods: ['GET', 'HEAD'],
        forwardedValues: {
          queryString: false,
          cookies: { forward: 'none' },
        },
      },
      enabled: true,
      viewerCertificate: {
        acmCertificateArn: 'arn:aws:acm:us-east-1:123456789012:certificate/abcdef',
        sslSupportMethod: 'sni-only',
        minimumProtocolVersion: 'SSLv3',
      },
    },
  });
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_1() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const bucket = new s3.Bucket(stack, 'MyBucket');
  
  // ok: typescript-cdk-cloud-front-distribution-no-outdated-ssl
  new cloudfront.Distribution(stack, 'Distribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket),
      viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.HTTPS_ONLY,
    },
    minimumProtocolVersion: cloudfront.SecurityPolicyProtocol.TLS_V1_2,
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_2() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const bucket = new s3.Bucket(stack, 'MyBucket');
  
  // ok: typescript-cdk-cloud-front-distribution-no-outdated-ssl
  new cloudfront.Distribution(stack, 'Distribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket),
    },
    minimumProtocolVersion: cloudfront.SecurityPolicyProtocol.TLS_V1_1,
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_3() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const bucket = new s3.Bucket(stack, 'MyBucket');
  const distribution = new cloudfront.Distribution(stack, 'Distribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket),
    },
  });
  
  // ok: typescript-cdk-cloud-front-distribution-no-outdated-ssl
  const cfnDistribution = distribution.node.defaultChild as cloudfront.CfnDistribution;
  cfnDistribution.addPropertyOverride('DistributionConfig.ViewerCertificate.MinimumProtocolVersion', 'TLSv1.2');
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_4() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const bucket = new s3.Bucket(stack, 'MyBucket');
  
  const securityPolicy = cloudfront.SecurityPolicyProtocol.TLS_V1_2_2019;
  
  // ok: typescript-cdk-cloud-front-distribution-no-outdated-ssl
  new cloudfront.Distribution(stack, 'Distribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket),
    },
    minimumProtocolVersion: securityPolicy,
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_5() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const bucket = new s3.Bucket(stack, 'MyBucket');
  
  const distributionProps: cloudfront.DistributionProps = {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket),
    },
    minimumProtocolVersion: cloudfront.SecurityPolicyProtocol.TLS_V1_2,
  };
  
  // ok: typescript-cdk-cloud-front-distribution-no-outdated-ssl
  new cloudfront.Distribution(stack, 'Distribution', distributionProps);
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_6() {
  class MyConstruct extends Construct {
    constructor(scope: Construct, id: string) {
      super(scope, id);
      
      const bucket = new s3.Bucket(this, 'MyBucket');
      
      // ok: typescript-cdk-cloud-front-distribution-no-outdated-ssl
      new cloudfront.Distribution(this, 'Distribution', {
        defaultBehavior: {
          origin: new origins.S3Origin(bucket),
        },
        minimumProtocolVersion: cloudfront.SecurityPolicyProtocol.TLS_V1_2,
      });
    }
  }
  
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  new MyConstruct(stack, 'MyConstruct');
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_7() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const bucket = new s3.Bucket(stack, 'MyBucket');
  
  const getSecurityPolicy = () => {
    return cloudfront.SecurityPolicyProtocol.TLS_V1_2;
  };
  
  // ok: typescript-cdk-cloud-front-distribution-no-outdated-ssl
  new cloudfront.Distribution(stack, 'Distribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket),
    },
    minimumProtocolVersion: getSecurityPolicy(),
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_8() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const bucket = new s3.Bucket(stack, 'MyBucket');
  const apiOrigin = new origins.HttpOrigin('api.example.com');
  
  // ok: typescript-cdk-cloud-front-distribution-no-outdated-ssl
  new cloudfront.Distribution(stack, 'Distribution', {
    defaultBehavior: {
      origin: apiOrigin,
    },
    additionalBehaviors: {
      '/api/*': {
        origin: new origins.S3Origin(bucket),
      },
    },
    minimumProtocolVersion: cloudfront.SecurityPolicyProtocol.TLS_V1_2_2021,
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_9() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const bucket = new s3.Bucket(stack, 'MyBucket');
  
  const securityPolicies = [
    cloudfront.SecurityPolicyProtocol.TLS_V1_2,
    cloudfront.SecurityPolicyProtocol.TLS_V1_2_2018,
    cloudfront.SecurityPolicyProtocol.TLS_V1_2_2019,
  ];
  
  // ok: typescript-cdk-cloud-front-distribution-no-outdated-ssl
  new cloudfront.Distribution(stack, 'Distribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket),
    },
    minimumProtocolVersion: securityPolicies[0], // TLS_V1_2
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_10() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const bucket = new s3.Bucket(stack, 'MyBucket');
  
  const isProd = true;
  const securityPolicy = isProd 
    ? cloudfront.SecurityPolicyProtocol.TLS_V1_2 
    : cloudfront.SecurityPolicyProtocol.TLS_V1_1;
  
  // ok: typescript-cdk-cloud-front-distribution-no-outdated-ssl
  new cloudfront.Distribution(stack, 'Distribution', {
    defaultBehavior: {
      origin: new origins.S3Origin(bucket),
    },
    minimumProtocolVersion: securityPolicy,
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_11() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const bucket = new s3.Bucket(stack, 'MyBucket');
  
  // ok: typescript-cdk-cloud-front-distribution-no-outdated-ssl
  const distribution = new cloudfront.CloudFrontWebDistribution(stack, 'WebDistribution', {
    originConfigs: [
      {
        s3OriginSource: {
          s3BucketSource: bucket,
        },
        behaviors: [{ isDefaultBehavior: true }],
      },
    ],
    viewerCertificate: {
      cloudFrontDefaultCertificate: true,
      minimumProtocolVersion: 'TLSv1.2',
    },
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_12() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const bucket = new s3.Bucket(stack, 'MyBucket');
  
  // ok: typescript-cdk-cloud-front-distribution-no-outdated-ssl
  const distribution = new cloudfront.CloudFrontWebDistribution(stack, 'WebDistribution', {
    originConfigs: [
      {
        s3OriginSource: {
          s3BucketSource: bucket,
        },
        behaviors: [{ isDefaultBehavior: true }],
      },
    ],
    viewerCertificate: {
      acmCertificateArn: 'arn:aws:acm:us-east-1:123456789012:certificate/abcdef',
      sslSupportMethod: 'sni-only',
      minimumProtocolVersion: 'TLSv1.1_2016',
    },
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_13() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const bucket = new s3.Bucket(stack, 'MyBucket');
  
  const viewerCertConfig = {
    cloudFrontDefaultCertificate: true,
    minimumProtocolVersion: 'TLSv1.2_2018',
  };
  
  // ok: typescript-cdk-cloud-front-distribution-no-outdated-ssl
  const distribution = new cloudfront.CloudFrontWebDistribution(stack, 'WebDistribution', {
    originConfigs: [
      {
        s3OriginSource: {
          s3BucketSource: bucket,
        },
        behaviors: [{ isDefaultBehavior: true }],
      },
    ],
    viewerCertificate: viewerCertConfig,
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_14() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const bucket = new s3.Bucket(stack, 'MyBucket');
  
  // ok: typescript-cdk-cloud-front-distribution-no-outdated-ssl
  const cfnDistribution = new cloudfront.CfnDistribution(stack, 'CfnDistribution', {
    distributionConfig: {
      origins: [
        {
          id: 'S3Origin',
          domainName: bucket.bucketDomainName,
          s3OriginConfig: {
            originAccessIdentity: '',
          },
        },
      ],
      defaultCacheBehavior: {
        targetOriginId: 'S3Origin',
        viewerProtocolPolicy: 'redirect-to-https',
        allowedMethods: ['GET', 'HEAD'],
        cachedMethods: ['GET', 'HEAD'],
        forwardedValues: {
          queryString: false,
          cookies: { forward: 'none' },
        },
      },
      enabled: true,
      viewerCertificate: {
        cloudFrontDefaultCertificate: true,
        minimumProtocolVersion: 'TLSv1.2_2019',
      },
    },
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_15() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const bucket = new s3.Bucket(stack, 'MyBucket');
  
  // ok: typescript-cdk-cloud-front-distribution-no-outdated-ssl
  const cfnDistribution = new cloudfront.CfnDistribution(stack, 'CfnDistribution', {
    distributionConfig: {
      origins: [
        {
          id: 'S3Origin',
          domainName: bucket.bucketDomainName,
          s3OriginConfig: {
            originAccessIdentity: '',
          },
        },
      ],
      defaultCacheBehavior: {
        targetOriginId: 'S3Origin',
        viewerProtocolPolicy: 'redirect-to-https',
        allowedMethods: ['GET', 'HEAD'],
        cachedMethods: ['GET', 'HEAD'],
        forwardedValues: {
          queryString: false,
          cookies: { forward: 'none' },
        },
      },
      enabled: true,
      viewerCertificate: {
        acmCertificateArn: 'arn:aws:acm:us-east-1:123456789012:certificate/abcdef',
        sslSupportMethod: 'sni-only',
        minimumProtocolVersion: 'TLSv1.2_2021',
      },
    },
  });
}
// {/fact}