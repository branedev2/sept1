import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as elb from 'aws-cdk-lib/aws-elasticloadbalancing';
import * as elbv2 from 'aws-cdk-lib/aws-elasticloadbalancingv2';

// True Positives (Vulnerable Code Examples)

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_1(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript-cdk-elb-cross-zone-load-balancing-enabled
  new elb.LoadBalancer(scope, 'LB', {
    vpc,
    internetFacing: true,
    crossZone: false,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_2(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript-cdk-elb-cross-zone-load-balancing-enabled
  const lb = new elb.LoadBalancer(scope, 'LB', {
    vpc,
    crossZone: false,
    healthCheck: {
      port: 80,
      path: '/health',
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_3(scope: Construct, subnets: ec2.ISubnet[]) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript-cdk-elb-cross-zone-load-balancing-enabled
  const loadBalancer = new elb.LoadBalancer(scope, 'LoadBalancer', {
    vpc,
    internetFacing: true,
    listeners: [
      { externalPort: 80, internalPort: 8080 }
    ],
    crossZone: false,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_4(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  const securityGroup = new ec2.SecurityGroup(scope, 'SecurityGroup', { vpc });
  
  // ruleid: typescript-cdk-elb-cross-zone-load-balancing-enabled
  new elb.LoadBalancer(scope, 'LoadBalancer', {
    vpc,
    securityGroups: [securityGroup],
    crossZone: false,
    listeners: [
      { externalPort: 443, internalPort: 8443 }
    ],
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_5(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  const options = {
    crossZone: false,
    healthCheck: {
      port: 80,
      protocol: elb.LoadBalancingProtocol.HTTP,
      path: '/health',
    }
  };
  
  // ruleid: typescript-cdk-elb-cross-zone-load-balancing-enabled
  new elb.LoadBalancer(scope, 'LoadBalancer', {
    vpc,
    ...options
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_6(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  const crossZoneEnabled = false;
  
  // ruleid: typescript-cdk-elb-cross-zone-load-balancing-enabled
  new elb.LoadBalancer(scope, 'LoadBalancer', {
    vpc,
    crossZone: crossZoneEnabled,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_7(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  const config = {
    internetFacing: true,
    crossZone: false,
  };
  
  // ruleid: typescript-cdk-elb-cross-zone-load-balancing-enabled
  new elb.LoadBalancer(scope, 'LoadBalancer', {
    vpc,
    ...config,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_8(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  function createLoadBalancer() {
    // ruleid: typescript-cdk-elb-cross-zone-load-balancing-enabled
    return new elb.LoadBalancer(scope, 'LoadBalancer', {
      vpc,
      crossZone: false,
      listeners: [
        { externalPort: 80, internalPort: 8080 }
      ],
    });
  }
  
  const lb = createLoadBalancer();
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_9(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  const lbProps = {
    vpc,
    crossZone: false,
    healthCheck: {
      port: 80,
      path: '/health',
    },
  };
  
  // ruleid: typescript-cdk-elb-cross-zone-load-balancing-enabled
  new elb.LoadBalancer(scope, 'LoadBalancer', lbProps);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_10(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript-cdk-elb-cross-zone-load-balancing-enabled
  const lb = new elb.LoadBalancer(scope, 'LoadBalancer', {
    vpc,
    crossZone: false,
  });
  
  // Adding listeners after creation doesn't fix the cross-zone issue
  lb.addListener({
    externalPort: 80,
    internalPort: 8080,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_11(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  const isProduction = true;
  
  // ruleid: typescript-cdk-elb-cross-zone-load-balancing-enabled
  new elb.LoadBalancer(scope, 'LoadBalancer', {
    vpc,
    crossZone: isProduction ? false : true, // Still false in production
    healthCheck: {
      port: 80,
      path: '/health',
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_12(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  for (let i = 0; i < 3; i++) {
    // ruleid: typescript-cdk-elb-cross-zone-load-balancing-enabled
    new elb.LoadBalancer(scope, `LoadBalancer-${i}`, {
      vpc,
      crossZone: false,
      listeners: [
        { externalPort: 80 + i, internalPort: 8080 + i }
      ],
    });
  }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_13(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  const environments = ['dev', 'staging', 'prod'];
  
  environments.forEach(env => {
    // ruleid: typescript-cdk-elb-cross-zone-load-balancing-enabled
    new elb.LoadBalancer(scope, `LoadBalancer-${env}`, {
      vpc,
      crossZone: false,
      healthCheck: {
        port: 80,
        path: '/health',
      },
    });
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_14(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  const crossZoneConfig = { enabled: false };
  
  // ruleid: typescript-cdk-elb-cross-zone-load-balancing-enabled
  new elb.LoadBalancer(scope, 'LoadBalancer', {
    vpc,
    crossZone: crossZoneConfig.enabled,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_15(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  class LoadBalancerFactory {
    createLoadBalancer() {
      // ruleid: typescript-cdk-elb-cross-zone-load-balancing-enabled
      return new elb.LoadBalancer(scope, 'LoadBalancer', {
        vpc,
        crossZone: false,
        listeners: [
          { externalPort: 80, internalPort: 8080 }
        ],
      });
    }
  }
  
  const factory = new LoadBalancerFactory();
  const lb = factory.createLoadBalancer();
}
// {/fact}

// True Negatives (Secure Code Examples)

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_1(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript-cdk-elb-cross-zone-load-balancing-enabled
  new elb.LoadBalancer(scope, 'LB', {
    vpc,
    internetFacing: true,
    crossZone: true,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_2(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript-cdk-elb-cross-zone-load-balancing-enabled
  const lb = new elb.LoadBalancer(scope, 'LB', {
    vpc,
    crossZone: true,
    healthCheck: {
      port: 80,
      path: '/health',
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_3(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // Default value for crossZone is true, so not specifying it is also secure
  // ok: typescript-cdk-elb-cross-zone-load-balancing-enabled
  new elb.LoadBalancer(scope, 'LoadBalancer', {
    vpc,
    internetFacing: true,
    listeners: [
      { externalPort: 80, internalPort: 8080 }
    ],
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_4(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  const securityGroup = new ec2.SecurityGroup(scope, 'SecurityGroup', { vpc });
  
  // ok: typescript-cdk-elb-cross-zone-load-balancing-enabled
  new elb.LoadBalancer(scope, 'LoadBalancer', {
    vpc,
    securityGroups: [securityGroup],
    crossZone: true,
    listeners: [
      { externalPort: 443, internalPort: 8443 }
    ],
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_5(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  const options = {
    crossZone: true,
    healthCheck: {
      port: 80,
      protocol: elb.LoadBalancingProtocol.HTTP,
      path: '/health',
    }
  };
  
  // ok: typescript-cdk-elb-cross-zone-load-balancing-enabled
  new elb.LoadBalancer(scope, 'LoadBalancer', {
    vpc,
    ...options
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_6(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  const crossZoneEnabled = true;
  
  // ok: typescript-cdk-elb-cross-zone-load-balancing-enabled
  new elb.LoadBalancer(scope, 'LoadBalancer', {
    vpc,
    crossZone: crossZoneEnabled,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_7(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  const config = {
    internetFacing: true,
    crossZone: true,
  };
  
  // ok: typescript-cdk-elb-cross-zone-load-balancing-enabled
  new elb.LoadBalancer(scope, 'LoadBalancer', {
    vpc,
    ...config,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_8(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  function createLoadBalancer() {
    // ok: typescript-cdk-elb-cross-zone-load-balancing-enabled
    return new elb.LoadBalancer(scope, 'LoadBalancer', {
      vpc,
      crossZone: true,
      listeners: [
        { externalPort: 80, internalPort: 8080 }
      ],
    });
  }
  
  const lb = createLoadBalancer();
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_9(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // Using Application Load Balancer (ALBv2) which has cross-zone load balancing enabled by default
  // ok: typescript-cdk-elb-cross-zone-load-balancing-enabled
  new elbv2.ApplicationLoadBalancer(scope, 'ALB', {
    vpc,
    internetFacing: true,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_10(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // Using Network Load Balancer with cross-zone load balancing enabled
  // ok: typescript-cdk-elb-cross-zone-load-balancing-enabled
  new elbv2.NetworkLoadBalancer(scope, 'NLB', {
    vpc,
    crossZoneEnabled: true,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_11(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  const isProduction = true;
  
  // ok: typescript-cdk-elb-cross-zone-load-balancing-enabled
  new elb.LoadBalancer(scope, 'LoadBalancer', {
    vpc,
    crossZone: isProduction ? true : false, // True in production
    healthCheck: {
      port: 80,
      path: '/health',
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_12(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  for (let i = 0; i < 3; i++) {
    // ok: typescript-cdk-elb-cross-zone-load-balancing-enabled
    new elb.LoadBalancer(scope, `LoadBalancer-${i}`, {
      vpc,
      crossZone: true,
      listeners: [
        { externalPort: 80 + i, internalPort: 8080 + i }
      ],
    });
  }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_13(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  const environments = ['dev', 'staging', 'prod'];
  
  environments.forEach(env => {
    // ok: typescript-cdk-elb-cross-zone-load-balancing-enabled
    new elb.LoadBalancer(scope, `LoadBalancer-${env}`, {
      vpc,
      crossZone: true,
      healthCheck: {
        port: 80,
        path: '/health',
      },
    });
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_14(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  const crossZoneConfig = { enabled: true };
  
  // ok: typescript-cdk-elb-cross-zone-load-balancing-enabled
  new elb.LoadBalancer(scope, 'LoadBalancer', {
    vpc,
    crossZone: crossZoneConfig.enabled,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_15(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  class LoadBalancerFactory {
    createLoadBalancer() {
      // ok: typescript-cdk-elb-cross-zone-load-balancing-enabled
      return new elb.LoadBalancer(scope, 'LoadBalancer', {
        vpc,
        crossZone: true,
        listeners: [
          { externalPort: 80, internalPort: 8080 }
        ],
      });
    }
  }
  
  const factory = new LoadBalancerFactory();
  const lb = factory.createLoadBalancer();
}
// {/fact}