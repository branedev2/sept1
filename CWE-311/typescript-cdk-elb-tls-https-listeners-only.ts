import * as cdk from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as elasticloadbalancing from 'aws-cdk-lib/aws-elasticloadbalancing';
import { Construct } from 'constructs';

// True Positives (Vulnerable Code)

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_1(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // Creating a load balancer with HTTP listener (insecure)
  // ruleid: typescript-cdk-elb-tls-https-listeners-only
  const lb = new elasticloadbalancing.LoadBalancer(scope, 'LB', {
    vpc,
    internetFacing: true,
    healthCheck: {
      port: 80,
      path: '/health',
    },
    listeners: [
      {
        port: 80,
        externalPort: 80,
        protocol: elasticloadbalancing.LoadBalancingProtocol.HTTP,
      },
    ],
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_2(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // Creating a load balancer with TCP listener (insecure)
  // ruleid: typescript-cdk-elb-tls-https-listeners-only
  const lb = new elasticloadbalancing.LoadBalancer(scope, 'LB', {
    vpc,
    internetFacing: true,
    listeners: [
      {
        port: 3306,
        externalPort: 3306,
        protocol: elasticloadbalancing.LoadBalancingProtocol.TCP,
      },
    ],
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_3(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // Creating a load balancer with multiple listeners including HTTP (insecure)
  // ruleid: typescript-cdk-elb-tls-https-listeners-only
  const lb = new elasticloadbalancing.LoadBalancer(scope, 'LB', {
    vpc,
    internetFacing: true,
    listeners: [
      {
        port: 80,
        externalPort: 80,
        protocol: elasticloadbalancing.LoadBalancingProtocol.HTTP,
      },
      {
        port: 443,
        externalPort: 443,
        protocol: elasticloadbalancing.LoadBalancingProtocol.HTTPS,
        certificateId: 'arn:aws:acm:region:account:certificate/certificate-id',
      },
    ],
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_4(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // Creating a load balancer with HTTP listener using addListener method
  const lb = new elasticloadbalancing.LoadBalancer(scope, 'LB', {
    vpc,
    internetFacing: true,
  });
  
  // ruleid: typescript-cdk-elb-tls-https-listeners-only
  lb.addListener({
    externalPort: 80,
    internalPort: 80,
    protocol: elasticloadbalancing.LoadBalancingProtocol.HTTP,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_5(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // Creating a load balancer with TCP listener using addListener method
  const lb = new elasticloadbalancing.LoadBalancer(scope, 'LB', {
    vpc,
    internetFacing: true,
  });
  
  // ruleid: typescript-cdk-elb-tls-https-listeners-only
  lb.addListener({
    externalPort: 5432,
    internalPort: 5432,
    protocol: elasticloadbalancing.LoadBalancingProtocol.TCP,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_6(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // Creating a load balancer with multiple listeners using addListener method
  const lb = new elasticloadbalancing.LoadBalancer(scope, 'LB', {
    vpc,
    internetFacing: true,
  });
  
  // ruleid: typescript-cdk-elb-tls-https-listeners-only
  lb.addListener({
    externalPort: 80,
    internalPort: 8080,
    protocol: elasticloadbalancing.LoadBalancingProtocol.HTTP,
  });
  
  lb.addListener({
    externalPort: 443,
    internalPort: 8443,
    protocol: elasticloadbalancing.LoadBalancingProtocol.HTTPS,
    certificateId: 'arn:aws:acm:region:account:certificate/certificate-id',
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_7(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // Creating a load balancer with HTTP listener and setting protocol directly
  // ruleid: typescript-cdk-elb-tls-https-listeners-only
  const lb = new elasticloadbalancing.LoadBalancer(scope, 'LB', {
    vpc,
    internetFacing: true,
  });
  
  const listener = {
    externalPort: 80,
    internalPort: 80,
    protocol: elasticloadbalancing.LoadBalancingProtocol.HTTP,
  };
  
  lb.addListener(listener);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_8(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // Creating a load balancer with HTTP listener using variable for protocol
  const httpProtocol = elasticloadbalancing.LoadBalancingProtocol.HTTP;
  
  // ruleid: typescript-cdk-elb-tls-https-listeners-only
  const lb = new elasticloadbalancing.LoadBalancer(scope, 'LB', {
    vpc,
    internetFacing: true,
    listeners: [
      {
        port: 80,
        externalPort: 80,
        protocol: httpProtocol,
      },
    ],
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_9(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // Creating a load balancer with TCP listener for a custom application
  // ruleid: typescript-cdk-elb-tls-https-listeners-only
  const lb = new elasticloadbalancing.LoadBalancer(scope, 'LB', {
    vpc,
    internetFacing: true,
    listeners: [
      {
        port: 8080,
        externalPort: 8080,
        protocol: elasticloadbalancing.LoadBalancingProtocol.TCP,
      },
    ],
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_10(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // Creating a load balancer with HTTP listener for internal traffic
  // ruleid: typescript-cdk-elb-tls-https-listeners-only
  const lb = new elasticloadbalancing.LoadBalancer(scope, 'LB', {
    vpc,
    internetFacing: false, // Even internal LBs should use HTTPS
    listeners: [
      {
        port: 80,
        externalPort: 80,
        protocol: elasticloadbalancing.LoadBalancingProtocol.HTTP,
      },
    ],
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_11(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // Creating a load balancer with conditional HTTP listener
  const useSecureProtocol = false;
  const protocol = useSecureProtocol 
    ? elasticloadbalancing.LoadBalancingProtocol.HTTPS 
    : elasticloadbalancing.LoadBalancingProtocol.HTTP;
  
  // ruleid: typescript-cdk-elb-tls-https-listeners-only
  const lb = new elasticloadbalancing.LoadBalancer(scope, 'LB', {
    vpc,
    internetFacing: true,
    listeners: [
      {
        port: useSecureProtocol ? 443 : 80,
        externalPort: useSecureProtocol ? 443 : 80,
        protocol: protocol,
        certificateId: useSecureProtocol ? 'arn:aws:acm:region:account:certificate/certificate-id' : undefined,
      },
    ],
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_12(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // Creating a load balancer with HTTP listener for a development environment
  const isProduction = false;
  
  // ruleid: typescript-cdk-elb-tls-https-listeners-only
  const lb = new elasticloadbalancing.LoadBalancer(scope, 'LB', {
    vpc,
    internetFacing: true,
    listeners: [
      {
        port: 80,
        externalPort: 80,
        protocol: elasticloadbalancing.LoadBalancingProtocol.HTTP, // Insecure even in dev
      },
    ],
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_13(scope: Construct, stackProps: cdk.StackProps) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // Creating a load balancer with HTTP listener in a specific environment
  const env = stackProps.env?.region === 'us-west-2' ? 'prod' : 'dev';
  
  // ruleid: typescript-cdk-elb-tls-https-listeners-only
  const lb = new elasticloadbalancing.LoadBalancer(scope, 'LB', {
    vpc,
    internetFacing: true,
    listeners: [
      {
        port: 80,
        externalPort: 80,
        protocol: elasticloadbalancing.LoadBalancingProtocol.HTTP,
      },
    ],
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_14(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // Creating a load balancer with TCP listener for a custom application port
  const customPort = 9000;
  
  // ruleid: typescript-cdk-elb-tls-https-listeners-only
  const lb = new elasticloadbalancing.LoadBalancer(scope, 'LB', {
    vpc,
    internetFacing: true,
    listeners: [
      {
        port: customPort,
        externalPort: customPort,
        protocol: elasticloadbalancing.LoadBalancingProtocol.TCP,
      },
    ],
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_15(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // Creating a load balancer with HTTP listener for a health check endpoint
  // ruleid: typescript-cdk-elb-tls-https-listeners-only
  const lb = new elasticloadbalancing.LoadBalancer(scope, 'LB', {
    vpc,
    internetFacing: true,
    healthCheck: {
      port: 80,
      path: '/health',
      protocol: elasticloadbalancing.LoadBalancingProtocol.HTTP,
    },
    listeners: [
      {
        port: 80,
        externalPort: 80,
        protocol: elasticloadbalancing.LoadBalancingProtocol.HTTP,
      },
    ],
  });
}
// {/fact}

// True Negatives (Secure Code)

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_1(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // Creating a load balancer with HTTPS listener (secure)
  // ok: typescript-cdk-elb-tls-https-listeners-only
  const lb = new elasticloadbalancing.LoadBalancer(scope, 'LB', {
    vpc,
    internetFacing: true,
    healthCheck: {
      port: 443,
      path: '/health',
      protocol: elasticloadbalancing.LoadBalancingProtocol.HTTPS,
    },
    listeners: [
      {
        port: 443,
        externalPort: 443,
        protocol: elasticloadbalancing.LoadBalancingProtocol.HTTPS,
        certificateId: 'arn:aws:acm:region:account:certificate/certificate-id',
      },
    ],
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_2(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // Creating a load balancer with SSL listener (secure)
  // ok: typescript-cdk-elb-tls-https-listeners-only
  const lb = new elasticloadbalancing.LoadBalancer(scope, 'LB', {
    vpc,
    internetFacing: true,
    listeners: [
      {
        port: 443,
        externalPort: 443,
        protocol: elasticloadbalancing.LoadBalancingProtocol.SSL,
        certificateId: 'arn:aws:acm:region:account:certificate/certificate-id',
      },
    ],
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_3(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // Creating a load balancer with multiple secure listeners
  // ok: typescript-cdk-elb-tls-https-listeners-only
  const lb = new elasticloadbalancing.LoadBalancer(scope, 'LB', {
    vpc,
    internetFacing: true,
    listeners: [
      {
        port: 443,
        externalPort: 443,
        protocol: elasticloadbalancing.LoadBalancingProtocol.HTTPS,
        certificateId: 'arn:aws:acm:region:account:certificate/certificate-id',
      },
      {
        port: 8443,
        externalPort: 8443,
        protocol: elasticloadbalancing.LoadBalancingProtocol.SSL,
        certificateId: 'arn:aws:acm:region:account:certificate/certificate-id',
      },
    ],
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_4(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // Creating a load balancer with HTTPS listener using addListener method
  const lb = new elasticloadbalancing.LoadBalancer(scope, 'LB', {
    vpc,
    internetFacing: true,
  });
  
  // ok: typescript-cdk-elb-tls-https-listeners-only
  lb.addListener({
    externalPort: 443,
    internalPort: 443,
    protocol: elasticloadbalancing.LoadBalancingProtocol.HTTPS,
    certificateId: 'arn:aws:acm:region:account:certificate/certificate-id',
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_5(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // Creating a load balancer with SSL listener using addListener method
  const lb = new elasticloadbalancing.LoadBalancer(scope, 'LB', {
    vpc,
    internetFacing: true,
  });
  
  // ok: typescript-cdk-elb-tls-https-listeners-only
  lb.addListener({
    externalPort: 443,
    internalPort: 443,
    protocol: elasticloadbalancing.LoadBalancingProtocol.SSL,
    certificateId: 'arn:aws:acm:region:account:certificate/certificate-id',
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_6(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // Creating a load balancer with multiple secure listeners using addListener method
  const lb = new elasticloadbalancing.LoadBalancer(scope, 'LB', {
    vpc,
    internetFacing: true,
  });
  
  // ok: typescript-cdk-elb-tls-https-listeners-only
  lb.addListener({
    externalPort: 443,
    internalPort: 8443,
    protocol: elasticloadbalancing.LoadBalancingProtocol.HTTPS,
    certificateId: 'arn:aws:acm:region:account:certificate/certificate-id',
  });
  
  lb.addListener({
    externalPort: 8443,
    internalPort: 9443,
    protocol: elasticloadbalancing.LoadBalancingProtocol.SSL,
    certificateId: 'arn:aws:acm:region:account:certificate/certificate-id',
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_7(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // Creating a load balancer with HTTPS listener and setting protocol directly
  // ok: typescript-cdk-elb-tls-https-listeners-only
  const lb = new elasticloadbalancing.LoadBalancer(scope, 'LB', {
    vpc,
    internetFacing: true,
  });
  
  const listener = {
    externalPort: 443,
    internalPort: 443,
    protocol: elasticloadbalancing.LoadBalancingProtocol.HTTPS,
    certificateId: 'arn:aws:acm:region:account:certificate/certificate-id',
  };
  
  lb.addListener(listener);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_8(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // Creating a load balancer with HTTPS listener using variable for protocol
  const httpsProtocol = elasticloadbalancing.LoadBalancingProtocol.HTTPS;
  
  // ok: typescript-cdk-elb-tls-https-listeners-only
  const lb = new elasticloadbalancing.LoadBalancer(scope, 'LB', {
    vpc,
    internetFacing: true,
    listeners: [
      {
        port: 443,
        externalPort: 443,
        protocol: httpsProtocol,
        certificateId: 'arn:aws:acm:region:account:certificate/certificate-id',
      },
    ],
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_9(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // Creating a load balancer with SSL listener for a custom application
  // ok: typescript-cdk-elb-tls-https-listeners-only
  const lb = new elasticloadbalancing.LoadBalancer(scope, 'LB', {
    vpc,
    internetFacing: true,
    listeners: [
      {
        port: 8443,
        externalPort: 8443,
        protocol: elasticloadbalancing.LoadBalancingProtocol.SSL,
        certificateId: 'arn:aws:acm:region:account:certificate/certificate-id',
      },
    ],
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_10(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // Creating a load balancer with HTTPS listener for internal traffic
  // ok: typescript-cdk-elb-tls-https-listeners-only
  const lb = new elasticloadbalancing.LoadBalancer(scope, 'LB', {
    vpc,
    internetFacing: false,
    listeners: [
      {
        port: 443,
        externalPort: 443,
        protocol: elasticloadbalancing.LoadBalancingProtocol.HTTPS,
        certificateId: 'arn:aws:acm:region:account:certificate/certificate-id',
      },
    ],
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_11(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // Creating a load balancer with conditional HTTPS listener
  const useSecureProtocol = true;
  const protocol = useSecureProtocol 
    ? elasticloadbalancing.LoadBalancingProtocol.HTTPS 
    : elasticloadbalancing.LoadBalancingProtocol.HTTP;
  
  // ok: typescript-cdk-elb-tls-https-listeners-only
  const lb = new elasticloadbalancing.LoadBalancer(scope, 'LB', {
    vpc,
    internetFacing: true,
    listeners: [
      {
        port: useSecureProtocol ? 443 : 80,
        externalPort: useSecureProtocol ? 443 : 80,
        protocol: protocol,
        certificateId: useSecureProtocol ? 'arn:aws:acm:region:account:certificate/certificate-id' : undefined,
      },
    ],
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_12(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // Creating a load balancer with HTTPS listener for a development environment
  const isProduction = false; // Even in dev, we use HTTPS
  
  // ok: typescript-cdk-elb-tls-https-listeners-only
  const lb = new elasticloadbalancing.LoadBalancer(scope, 'LB', {
    vpc,
    internetFacing: true,
    listeners: [
      {
        port: 443,
        externalPort: 443,
        protocol: elasticloadbalancing.LoadBalancingProtocol.HTTPS,
        certificateId: 'arn:aws:acm:region:account:certificate/certificate-id',
      },
    ],
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_13(scope: Construct, stackProps: cdk.StackProps) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // Creating a load balancer with HTTPS listener in a specific environment
  const env = stackProps.env?.region === 'us-west-2' ? 'prod' : 'dev';
  
  // ok: typescript-cdk-elb-tls-https-listeners-only
  const lb = new elasticloadbalancing.LoadBalancer(scope, 'LB', {
    vpc,
    internetFacing: true,
    listeners: [
      {
        port: 443,
        externalPort: 443,
        protocol: elasticloadbalancing.LoadBalancingProtocol.HTTPS,
        certificateId: 'arn:aws:acm:region:account:certificate/certificate-id',
      },
    ],
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_14(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // Creating a load balancer with SSL listener for a custom application port
  const customPort = 9000;
  
  // ok: typescript-cdk-elb-tls-https-listeners-only
  const lb = new elasticloadbalancing.LoadBalancer(scope, 'LB', {
    vpc,
    internetFacing: true,
    listeners: [
      {
        port: customPort,
        externalPort: customPort,
        protocol: elasticloadbalancing.LoadBalancingProtocol.SSL,
        certificateId: 'arn:aws:acm:region:account:certificate/certificate-id',
      },
    ],
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_15(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // Creating a load balancer with HTTPS listener for a health check endpoint
  // ok: typescript-cdk-elb-tls-https-listeners-only
  const lb = new elasticloadbalancing.LoadBalancer(scope, 'LB', {
    vpc,
    internetFacing: true,
    healthCheck: {
      port: 443,
      path: '/health',
      protocol: elasticloadbalancing.LoadBalancingProtocol.HTTPS,
    },
    listeners: [
      {
        port: 443,
        externalPort: 443,
        protocol: elasticloadbalancing.LoadBalancingProtocol.HTTPS,
        certificateId: 'arn:aws:acm:region:account:certificate/certificate-id',
      },
    ],
  });
}
// {/fact}