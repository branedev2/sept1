import { Stack, App, StackProps } from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as cloudfront from 'aws-cdk-lib/aws-cloudfront';
import * as route53 from 'aws-cdk-lib/aws-route53';
import * as acm from 'aws-cdk-lib/aws-acm';
import * as cognito from 'aws-cdk-lib/aws-cognito';

// True Positives (Bad Cases) - Global resources without region in name/ID

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_1(scope: Construct) {
  // Creating an IAM role without region in name
  // ruleid: aws-cdk-no-region-in-global-resources-check-rule
  const adminRole = new iam.Role(scope, 'AdminRole', {
    assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
    roleName: 'AdminAccessRole',
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_2(scope: Construct) {
  // Creating an IAM policy without region in name
  // ruleid: aws-cdk-no-region-in-global-resources-check-rule
  const policy = new iam.Policy(scope, 'S3AccessPolicy', {
    policyName: 'S3BucketAccessPolicy',
    statements: [
      new iam.PolicyStatement({
        actions: ['s3:GetObject'],
        resources: ['*'],
      }),
    ],
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_3(scope: Construct) {
  // Creating a CloudFront distribution without region in ID
  // ruleid: aws-cdk-no-region-in-global-resources-check-rule
  const distribution = new cloudfront.Distribution(scope, 'WebDistribution', {
    defaultBehavior: {
      origin: new cloudfront.origins.HttpOrigin('example.com'),
    },
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_4(scope: Construct) {
  // Creating a Route53 hosted zone without region in ID
  // ruleid: aws-cdk-no-region-in-global-resources-check-rule
  const hostedZone = new route53.HostedZone(scope, 'MyHostedZone', {
    zoneName: 'example.com',
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_5(scope: Construct) {
  // Creating an ACM certificate without region in ID
  // ruleid: aws-cdk-no-region-in-global-resources-check-rule
  const certificate = new acm.Certificate(scope, 'SiteCertificate', {
    domainName: 'example.com',
    validation: acm.CertificateValidation.fromDns(),
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_6(scope: Construct) {
  // Creating a Cognito user pool without region in name
  // ruleid: aws-cdk-no-region-in-global-resources-check-rule
  const userPool = new cognito.UserPool(scope, 'UserPool', {
    userPoolName: 'ApplicationUserPool',
    selfSignUpEnabled: true,
    autoVerify: { email: true },
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_7(scope: Construct) {
  // Creating an IAM group without region in name
  // ruleid: aws-cdk-no-region-in-global-resources-check-rule
  const group = new iam.Group(scope, 'DevelopersGroup', {
    groupName: 'Developers',
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_8(scope: Construct) {
  // Creating an IAM user without region in name
  // ruleid: aws-cdk-no-region-in-global-resources-check-rule
  const user = new iam.User(scope, 'ServiceUser', {
    userName: 'service-account',
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_9(scope: Construct) {
  // Creating a CloudFront origin access identity without region in ID
  // ruleid: aws-cdk-no-region-in-global-resources-check-rule
  const oai = new cloudfront.OriginAccessIdentity(scope, 'WebsiteOAI', {
    comment: 'Access S3 bucket content only through CloudFront',
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_10(scope: Construct) {
  // Creating a Route53 record without region in ID
  // ruleid: aws-cdk-no-region-in-global-resources-check-rule
  const zone = route53.HostedZone.fromHostedZoneAttributes(scope, 'ImportedZone', {
    hostedZoneId: 'Z23ABC4XYZL05B',
    zoneName: 'example.com',
  });
  
  const record = new route53.ARecord(scope, 'ApiRecord', {
    zone,
    recordName: 'api.example.com',
    target: route53.RecordTarget.fromIpAddresses('192.0.2.1'),
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_11(scope: Construct) {
  // Creating an IAM role with a custom trust policy without region in name
  // ruleid: aws-cdk-no-region-in-global-resources-check-rule
  const customTrustPolicy = new iam.PolicyDocument({
    statements: [
      new iam.PolicyStatement({
        actions: ['sts:AssumeRole'],
        principals: [new iam.AccountPrincipal('123456789012')],
      }),
    ],
  });
  
  const role = new iam.Role(scope, 'CrossAccountRole', {
    assumedBy: new iam.CompositePrincipal(
      new iam.ServicePrincipal('lambda.amazonaws.com'),
      new iam.AccountPrincipal('123456789012')
    ),
    roleName: 'CrossAccountAccessRole',
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_12(scope: Construct) {
  // Creating a Cognito identity pool without region in name
  // ruleid: aws-cdk-no-region-in-global-resources-check-rule
  const userPool = new cognito.UserPool(scope, 'UserPoolNoRegion', {
    userPoolName: 'MainUserPool',
  });
  
  const identityPool = new cognito.CfnIdentityPool(scope, 'IdentityPool', {
    allowUnauthenticatedIdentities: false,
    cognitoIdentityProviders: [{
      clientId: userPool.userPoolClientIds[0],
      providerName: userPool.userPoolProviderName,
    }],
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_13(scope: Construct) {
  // Creating an IAM managed policy without region in name
  // ruleid: aws-cdk-no-region-in-global-resources-check-rule
  const managedPolicy = new iam.ManagedPolicy(scope, 'CustomManagedPolicy', {
    managedPolicyName: 'CustomS3AccessPolicy',
    statements: [
      new iam.PolicyStatement({
        actions: ['s3:GetObject', 's3:PutObject'],
        resources: ['arn:aws:s3:::example-bucket/*'],
      }),
    ],
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_14(scope: Construct, app: App) {
  // Creating a stack with global resources without region in ID
  // ruleid: aws-cdk-no-region-in-global-resources-check-rule
  class GlobalResourceStack extends Stack {
    constructor(scope: Construct, id: string, props?: StackProps) {
      super(scope, id, props);
      
      const role = new iam.Role(this, 'GlobalRole', {
        assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
        roleName: 'GlobalServiceRole',
      });
    }
  }
  
  new GlobalResourceStack(app, 'GlobalResourceStack');
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_15(scope: Construct) {
  // Creating multiple global resources without region in names
  // ruleid: aws-cdk-no-region-in-global-resources-check-rule
  const adminGroup = new iam.Group(scope, 'AdminGroup', {
    groupName: 'Administrators',
  });
  
  const developerGroup = new iam.Group(scope, 'DeveloperGroup', {
    groupName: 'Developers',
  });
  
  const adminPolicy = new iam.Policy(scope, 'AdminPolicy', {
    policyName: 'AdminAccess',
    statements: [
      new iam.PolicyStatement({
        actions: ['*'],
        resources: ['*'],
      }),
    ],
  });
}
// {/fact}

// True Negatives (Good Cases) - Global resources with region in name/ID

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_1(scope: Construct) {
  // Creating an IAM role with region in name
  // ok: aws-cdk-no-region-in-global-resources-check-rule
  const adminRole = new iam.Role(scope, 'AdminRole-useast1', {
    assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
    roleName: 'AdminAccessRole-us-east-1',
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_2(scope: Construct) {
  // Creating an IAM policy with region in name
  // ok: aws-cdk-no-region-in-global-resources-check-rule
  const policy = new iam.Policy(scope, 'S3AccessPolicy-uswest2', {
    policyName: 'S3BucketAccessPolicy-us-west-2',
    statements: [
      new iam.PolicyStatement({
        actions: ['s3:GetObject'],
        resources: ['*'],
      }),
    ],
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_3(scope: Construct) {
  // Creating a CloudFront distribution with region in ID
  // ok: aws-cdk-no-region-in-global-resources-check-rule
  const distribution = new cloudfront.Distribution(scope, 'WebDistribution-useast1', {
    defaultBehavior: {
      origin: new cloudfront.origins.HttpOrigin('example.com'),
    },
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_4(scope: Construct) {
  // Creating a Route53 hosted zone with region in ID
  // ok: aws-cdk-no-region-in-global-resources-check-rule
  const hostedZone = new route53.HostedZone(scope, 'MyHostedZone-useast1', {
    zoneName: 'example.com',
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_5(scope: Construct) {
  // Creating an ACM certificate with region in ID
  // ok: aws-cdk-no-region-in-global-resources-check-rule
  const certificate = new acm.Certificate(scope, 'SiteCertificate-useast1', {
    domainName: 'example.com',
    validation: acm.CertificateValidation.fromDns(),
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_6(scope: Construct) {
  // Creating a Cognito user pool with region in name
  // ok: aws-cdk-no-region-in-global-resources-check-rule
  const userPool = new cognito.UserPool(scope, 'UserPool-euwest1', {
    userPoolName: 'ApplicationUserPool-eu-west-1',
    selfSignUpEnabled: true,
    autoVerify: { email: true },
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_7(scope: Construct) {
  // Creating an IAM group with region in name
  // ok: aws-cdk-no-region-in-global-resources-check-rule
  const group = new iam.Group(scope, 'DevelopersGroup-useast2', {
    groupName: 'Developers-us-east-2',
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_8(scope: Construct) {
  // Creating an IAM user with region in name
  // ok: aws-cdk-no-region-in-global-resources-check-rule
  const user = new iam.User(scope, 'ServiceUser-uswest1', {
    userName: 'service-account-us-west-1',
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_9(scope: Construct) {
  // Creating a CloudFront origin access identity with region in ID
  // ok: aws-cdk-no-region-in-global-resources-check-rule
  const oai = new cloudfront.OriginAccessIdentity(scope, 'WebsiteOAI-useast1', {
    comment: 'Access S3 bucket content only through CloudFront',
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_10(scope: Construct) {
  // Creating a Route53 record with region in ID
  // ok: aws-cdk-no-region-in-global-resources-check-rule
  const zone = route53.HostedZone.fromHostedZoneAttributes(scope, 'ImportedZone-useast1', {
    hostedZoneId: 'Z23ABC4XYZL05B',
    zoneName: 'example.com',
  });
  
  const record = new route53.ARecord(scope, 'ApiRecord-useast1', {
    zone,
    recordName: 'api.example.com',
    target: route53.RecordTarget.fromIpAddresses('192.0.2.1'),
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_11(scope: Construct) {
  // Creating an IAM role with a custom trust policy with region in name
  // ok: aws-cdk-no-region-in-global-resources-check-rule
  const customTrustPolicy = new iam.PolicyDocument({
    statements: [
      new iam.PolicyStatement({
        actions: ['sts:AssumeRole'],
        principals: [new iam.AccountPrincipal('123456789012')],
      }),
    ],
  });
  
  const role = new iam.Role(scope, 'CrossAccountRole-euwest2', {
    assumedBy: new iam.CompositePrincipal(
      new iam.ServicePrincipal('lambda.amazonaws.com'),
      new iam.AccountPrincipal('123456789012')
    ),
    roleName: 'CrossAccountAccessRole-eu-west-2',
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_12(scope: Construct) {
  // Creating a Cognito identity pool with region in name
  // ok: aws-cdk-no-region-in-global-resources-check-rule
  const userPool = new cognito.UserPool(scope, 'UserPool-apnortheast1', {
    userPoolName: 'MainUserPool-ap-northeast-1',
  });
  
  const identityPool = new cognito.CfnIdentityPool(scope, 'IdentityPool-apnortheast1', {
    allowUnauthenticatedIdentities: false,
    cognitoIdentityProviders: [{
      clientId: userPool.userPoolClientIds[0],
      providerName: userPool.userPoolProviderName,
    }],
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_13(scope: Construct) {
  // Creating an IAM managed policy with region in name
  // ok: aws-cdk-no-region-in-global-resources-check-rule
  const managedPolicy = new iam.ManagedPolicy(scope, 'CustomManagedPolicy-saeast1', {
    managedPolicyName: 'CustomS3AccessPolicy-sa-east-1',
    statements: [
      new iam.PolicyStatement({
        actions: ['s3:GetObject', 's3:PutObject'],
        resources: ['arn:aws:s3:::example-bucket/*'],
      }),
    ],
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_14(scope: Construct, app: App) {
  // Creating a stack with global resources with region in ID
  // ok: aws-cdk-no-region-in-global-resources-check-rule
  class RegionalResourceStack extends Stack {
    constructor(scope: Construct, id: string, props?: StackProps) {
      super(scope, id, props);
      
      const role = new iam.Role(this, 'GlobalRole-useast1', {
        assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
        roleName: 'GlobalServiceRole-us-east-1',
      });
    }
  }
  
  new RegionalResourceStack(app, 'RegionalResourceStack-useast1');
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_15(scope: Construct) {
  // Creating multiple global resources with region in names
  // ok: aws-cdk-no-region-in-global-resources-check-rule
  const adminGroup = new iam.Group(scope, 'AdminGroup-useast1', {
    groupName: 'Administrators-us-east-1',
  });
  
  const developerGroup = new iam.Group(scope, 'DeveloperGroup-useast1', {
    groupName: 'Developers-us-east-1',
  });
  
  const adminPolicy = new iam.Policy(scope, 'AdminPolicy-useast1', {
    policyName: 'AdminAccess-us-east-1',
    statements: [
      new iam.PolicyStatement({
        actions: ['*'],
        resources: ['*'],
      }),
    ],
  });
}
// {/fact}