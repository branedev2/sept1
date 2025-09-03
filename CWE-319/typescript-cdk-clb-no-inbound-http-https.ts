import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as elasticloadbalancing from 'aws-cdk-lib/aws-elasticloadbalancing';
import * as elasticloadbalancingv2 from 'aws-cdk-lib/aws-elasticloadbalancingv2';
import * as elbv2 from 'aws-cdk-lib/aws-elasticloadbalancingv2';

class LoadBalancerStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // Common setup for examples
    const vpc = new ec2.Vpc(this, 'VPC');
  }
}

// True Positive Examples (Vulnerable Code)

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_1(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript-cdk-clb-no-inbound-http-https
  const lb = new elasticloadbalancing.LoadBalancer(scope, 'LB', {
    vpc,
    internetFacing: true,
    healthCheck: {
      port: 80
    },
    listeners: [
      {
        externalPort: 80,
        internalPort: 8080
      }
    ]
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_2(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript-cdk-clb-no-inbound-http-https
  const lb = new elasticloadbalancing.LoadBalancer(scope, 'LB', {
    vpc,
    internetFacing: true,
    listeners: [
      {
        externalPort: 443,
        internalPort: 8443,
        sslCertificateId: 'arn:aws:acm:region:account:certificate/certificate-id'
      }
    ]
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_3(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript-cdk-clb-no-inbound-http-https
  const lb = new elasticloadbalancing.LoadBalancer(scope, 'LB', {
    vpc,
    listeners: [
      {
        externalPort: 80,
        internalPort: 80
      },
      {
        externalPort: 8080,
        internalPort: 8080
      }
    ]
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_4(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  const httpPort = 80;
  
  // ruleid: typescript-cdk-clb-no-inbound-http-https
  const lb = new elasticloadbalancing.LoadBalancer(scope, 'LB', {
    vpc,
    listeners: [
      {
        externalPort: httpPort,
        internalPort: 8080
      }
    ]
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_5(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  const httpsPort = 443;
  
  // ruleid: typescript-cdk-clb-no-inbound-http-https
  const lb = new elasticloadbalancing.LoadBalancer(scope, 'LB', {
    vpc,
    listeners: [
      {
        externalPort: httpsPort,
        internalPort: 8443
      }
    ]
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_6(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  const config = {
    externalPort: 80,
    internalPort: 8080
  };
  
  // ruleid: typescript-cdk-clb-no-inbound-http-https
  const lb = new elasticloadbalancing.LoadBalancer(scope, 'LB', {
    vpc,
    listeners: [config]
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_7(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript-cdk-clb-no-inbound-http-https
  const lb = new elasticloadbalancing.LoadBalancer(scope, 'LB', {
    vpc,
    listeners: [
      {
        externalPort: 443,
        internalPort: 8443
      },
      {
        externalPort: 8080,
        internalPort: 8080
      }
    ]
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_8(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  const listeners = [];
  listeners.push({
    externalPort: 80,
    internalPort: 8080
  });
  
  // ruleid: typescript-cdk-clb-no-inbound-http-https
  const lb = new elasticloadbalancing.LoadBalancer(scope, 'LB', {
    vpc,
    listeners
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_9(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript-cdk-clb-no-inbound-http-https
  const lb = new elasticloadbalancing.LoadBalancer(scope, 'LB', {
    vpc
  });
  
  lb.addListener({
    externalPort: 80,
    internalPort: 8080
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_10(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript-cdk-clb-no-inbound-http-https
  const lb = new elasticloadbalancing.LoadBalancer(scope, 'LB', {
    vpc
  });
  
  lb.addListener({
    externalPort: 443,
    internalPort: 8443
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_11(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  const ports = [80, 8080, 9090];
  
  // ruleid: typescript-cdk-clb-no-inbound-http-https
  const lb = new elasticloadbalancing.LoadBalancer(scope, 'LB', {
    vpc,
    listeners: ports.map(port => ({
      externalPort: port,
      internalPort: 8080
    }))
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_12(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  function createListener(external: number, internal: number) {
    return {
      externalPort: external,
      internalPort: internal
    };
  }
  
  // ruleid: typescript-cdk-clb-no-inbound-http-https
  const lb = new elasticloadbalancing.LoadBalancer(scope, 'LB', {
    vpc,
    listeners: [createListener(80, 8080)]
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_13(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  const DEFAULT_HTTP_PORT = 80;
  const DEFAULT_HTTPS_PORT = 443;
  
  // ruleid: typescript-cdk-clb-no-inbound-http-https
  const lb = new elasticloadbalancing.LoadBalancer(scope, 'LB', {
    vpc,
    listeners: [
      {
        externalPort: DEFAULT_HTTP_PORT,
        internalPort: 8080
      },
      {
        externalPort: DEFAULT_HTTPS_PORT,
        internalPort: 8443
      }
    ]
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_14(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  const getPort = () => 80;
  
  // ruleid: typescript-cdk-clb-no-inbound-http-https
  const lb = new elasticloadbalancing.LoadBalancer(scope, 'LB', {
    vpc,
    listeners: [
      {
        externalPort: getPort(),
        internalPort: 8080
      }
    ]
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_15(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  const externalPorts = {
    http: 80,
    https: 443
  };
  
  // ruleid: typescript-cdk-clb-no-inbound-http-https
  const lb = new elasticloadbalancing.LoadBalancer(scope, 'LB', {
    vpc,
    listeners: [
      {
        externalPort: externalPorts.https,
        internalPort: 8443
      }
    ]
  });
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_1(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript-cdk-clb-no-inbound-http-https
  const lb = new elasticloadbalancing.LoadBalancer(scope, 'LB', {
    vpc,
    listeners: [
      {
        externalPort: 8080,
        internalPort: 8080
      }
    ]
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_2(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript-cdk-clb-no-inbound-http-https
  const lb = new elasticloadbalancing.LoadBalancer(scope, 'LB', {
    vpc,
    listeners: [
      {
        externalPort: 8443,
        internalPort: 8443,
        sslCertificateId: 'arn:aws:acm:region:account:certificate/certificate-id'
      }
    ]
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_3(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript-cdk-clb-no-inbound-http-https
  const lb = new elasticloadbalancing.LoadBalancer(scope, 'LB', {
    vpc,
    listeners: [
      {
        externalPort: 8080,
        internalPort: 80
      },
      {
        externalPort: 8443,
        internalPort: 443
      }
    ]
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_4(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  const customPort = 8080;
  
  // ok: typescript-cdk-clb-no-inbound-http-https
  const lb = new elasticloadbalancing.LoadBalancer(scope, 'LB', {
    vpc,
    listeners: [
      {
        externalPort: customPort,
        internalPort: 80
      }
    ]
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_5(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  const securePort = 8443;
  
  // ok: typescript-cdk-clb-no-inbound-http-https
  const lb = new elasticloadbalancing.LoadBalancer(scope, 'LB', {
    vpc,
    listeners: [
      {
        externalPort: securePort,
        internalPort: 443
      }
    ]
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_6(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  const config = {
    externalPort: 8080,
    internalPort: 80
  };
  
  // ok: typescript-cdk-clb-no-inbound-http-https
  const lb = new elasticloadbalancing.LoadBalancer(scope, 'LB', {
    vpc,
    listeners: [config]
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_7(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript-cdk-clb-no-inbound-http-https
  const lb = new elasticloadbalancing.LoadBalancer(scope, 'LB', {
    vpc,
    listeners: [
      {
        externalPort: 8443,
        internalPort: 443
      },
      {
        externalPort: 9090,
        internalPort: 9090
      }
    ]
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_8(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  const listeners = [];
  listeners.push({
    externalPort: 8080,
    internalPort: 80
  });
  
  // ok: typescript-cdk-clb-no-inbound-http-https
  const lb = new elasticloadbalancing.LoadBalancer(scope, 'LB', {
    vpc,
    listeners
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_9(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript-cdk-clb-no-inbound-http-https
  const lb = new elasticloadbalancing.LoadBalancer(scope, 'LB', {
    vpc
  });
  
  lb.addListener({
    externalPort: 8080,
    internalPort: 80
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_10(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript-cdk-clb-no-inbound-http-https
  const lb = new elasticloadbalancing.LoadBalancer(scope, 'LB', {
    vpc
  });
  
  lb.addListener({
    externalPort: 8443,
    internalPort: 443
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_11(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  const ports = [8080, 8443, 9090];
  
  // ok: typescript-cdk-clb-no-inbound-http-https
  const lb = new elasticloadbalancing.LoadBalancer(scope, 'LB', {
    vpc,
    listeners: ports.map(port => ({
      externalPort: port,
      internalPort: 8080
    }))
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_12(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // Using Application Load Balancer with HTTPS listener on port 443
  // but redirecting HTTP to HTTPS
  // ok: typescript-cdk-clb-no-inbound-http-https
  const alb = new elasticloadbalancingv2.ApplicationLoadBalancer(scope, 'ALB', {
    vpc,
    internetFacing: true
  });
  
  const httpsListener = alb.addListener('HttpsListener', {
    port: 8443,
    certificates: [elbv2.ListenerCertificate.fromArn('arn:aws:acm:region:account:certificate/certificate-id')]
  });
  
  alb.addRedirect({
    sourcePort: 8080,
    targetPort: 8443,
    open: true
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_13(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  const CUSTOM_HTTP_PORT = 8080;
  const CUSTOM_HTTPS_PORT = 8443;
  
  // ok: typescript-cdk-clb-no-inbound-http-https
  const lb = new elasticloadbalancing.LoadBalancer(scope, 'LB', {
    vpc,
    listeners: [
      {
        externalPort: CUSTOM_HTTP_PORT,
        internalPort: 80
      },
      {
        externalPort: CUSTOM_HTTPS_PORT,
        internalPort: 443
      }
    ]
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_14(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  const getSecurePort = () => 8443;
  
  // ok: typescript-cdk-clb-no-inbound-http-https
  const lb = new elasticloadbalancing.LoadBalancer(scope, 'LB', {
    vpc,
    listeners: [
      {
        externalPort: getSecurePort(),
        internalPort: 443
      }
    ]
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_15(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // Using Network Load Balancer with custom ports
  // ok: typescript-cdk-clb-no-inbound-http-https
  const nlb = new elasticloadbalancingv2.NetworkLoadBalancer(scope, 'NLB', {
    vpc,
    internetFacing: true
  });
  
  const listener = nlb.addListener('Listener', {
    port: 8443
  });
  
  listener.addTargets('Target', {
    port: 8443,
    targets: []
  });
}
// {/fact}