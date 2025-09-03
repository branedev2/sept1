import * as cdk from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as elb from 'aws-cdk-lib/aws-elasticloadbalancing';
import { Construct } from 'constructs';

// True Positives (Vulnerable Code - Connection Draining Not Enabled)

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_1() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'TestStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ruleid: typescript-cdk-clb-connection-draining
  new elb.LoadBalancer(stack, 'LB', {
    vpc,
    internetFacing: true,
    healthCheck: {
      port: 80,
      path: '/health',
    },
    // Connection draining not enabled (missing property)
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_2() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'TestStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ruleid: typescript-cdk-clb-connection-draining
  const lb = new elb.LoadBalancer(stack, 'LB', {
    vpc,
    internetFacing: true,
  });
  
  // No connection draining configured after creation
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_3() {
  class MyStack extends cdk.Stack {
    constructor(scope: Construct, id: string, props?: cdk.StackProps) {
      super(scope, id, props);
      
      const vpc = new ec2.Vpc(this, 'VPC');
      
      // ruleid: typescript-cdk-clb-connection-draining
      new elb.LoadBalancer(this, 'LoadBalancer', {
        vpc,
        internetFacing: false,
        listeners: [
          {
            port: 80,
            externalPort: 80,
          }
        ],
        // Missing connection draining configuration
      });
    }
  }
  
  const app = new cdk.App();
  new MyStack(app, 'MyStack');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_4() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'TestStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ruleid: typescript-cdk-clb-connection-draining
  new elb.LoadBalancer(stack, 'LB', {
    vpc,
    internetFacing: true,
    connectionDraining: false, // Explicitly disabled
    connectionDrainingTimeout: cdk.Duration.seconds(300),
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_5() {
  class InfraStack extends cdk.Stack {
    constructor(scope: Construct, id: string, props?: cdk.StackProps) {
      super(scope, id, props);
      
      const vpc = new ec2.Vpc(this, 'VPC');
      
      // ruleid: typescript-cdk-clb-connection-draining
      const lb = new elb.LoadBalancer(this, 'WebLoadBalancer', {
        vpc,
        internetFacing: true,
        healthCheck: {
          port: 80,
          protocol: elb.LoadBalancingProtocol.HTTP,
          path: '/health',
          interval: cdk.Duration.seconds(30),
        },
        // Connection draining not enabled
      });
    }
  }
  
  const app = new cdk.App();
  new InfraStack(app, 'InfraStack');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_6() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'TestStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ruleid: typescript-cdk-clb-connection-draining
  const lb = new elb.LoadBalancer(stack, 'LB', {
    vpc,
    internetFacing: true,
    connectionDraining: false, // Explicitly disabled
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_7() {
  class WebStack extends cdk.Stack {
    constructor(scope: Construct, id: string, props?: cdk.StackProps) {
      super(scope, id, props);
      
      const vpc = new ec2.Vpc(this, 'VPC');
      
      // ruleid: typescript-cdk-clb-connection-draining
      const loadBalancer = new elb.LoadBalancer(this, 'WebLB', {
        vpc,
        internetFacing: true,
        listeners: [
          {
            port: 80,
            externalPort: 80,
          },
          {
            port: 443,
            externalPort: 443,
          }
        ],
        // Connection draining not configured
      });
    }
  }
  
  const app = new cdk.App();
  new WebStack(app, 'WebStack');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_8() {
  const createLoadBalancer = (stack: cdk.Stack, vpc: ec2.Vpc) => {
    // ruleid: typescript-cdk-clb-connection-draining
    return new elb.LoadBalancer(stack, 'AppLB', {
      vpc,
      internetFacing: false,
      healthCheck: {
        port: 8080,
        protocol: elb.LoadBalancingProtocol.HTTP,
        path: '/status',
      },
      // No connection draining configuration
    });
  };
  
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'TestStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  createLoadBalancer(stack, vpc);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_9() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'TestStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const lbProps = {
    vpc,
    internetFacing: true,
    // No connection draining
  };
  
  // ruleid: typescript-cdk-clb-connection-draining
  new elb.LoadBalancer(stack, 'LB', lbProps);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_10() {
  class MultiTierStack extends cdk.Stack {
    constructor(scope: Construct, id: string, props?: cdk.StackProps) {
      super(scope, id, props);
      
      const vpc = new ec2.Vpc(this, 'VPC');
      
      // ruleid: typescript-cdk-clb-connection-draining
      const frontendLB = new elb.LoadBalancer(this, 'FrontendLB', {
        vpc,
        internetFacing: true,
        // No connection draining
      });
      
      // ruleid: typescript-cdk-clb-connection-draining
      const backendLB = new elb.LoadBalancer(this, 'BackendLB', {
        vpc,
        internetFacing: false,
        // No connection draining
      });
    }
  }
  
  const app = new cdk.App();
  new MultiTierStack(app, 'MultiTierStack');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_11() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'TestStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ruleid: typescript-cdk-clb-connection-draining
  const lb = new elb.LoadBalancer(stack, 'LB', {
    vpc,
    internetFacing: true,
    connectionDrainingTimeout: cdk.Duration.seconds(60), // Timeout specified but draining not enabled
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_12() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'TestStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const configureLoadBalancer = () => {
    // ruleid: typescript-cdk-clb-connection-draining
    return new elb.LoadBalancer(stack, 'ServiceLB', {
      vpc,
      internetFacing: false,
      crossZone: true,
      // Connection draining not enabled
    });
  };
  
  configureLoadBalancer();
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_13() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'TestStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const createInternalLB = (id: string) => {
    // ruleid: typescript-cdk-clb-connection-draining
    return new elb.LoadBalancer(stack, id, {
      vpc,
      internetFacing: false,
      // No connection draining
    });
  };
  
  createInternalLB('InternalLB1');
  createInternalLB('InternalLB2');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_14() {
  class LoadBalancerFactory {
    static createPublicLB(stack: cdk.Stack, vpc: ec2.Vpc, id: string) {
      // ruleid: typescript-cdk-clb-connection-draining
      return new elb.LoadBalancer(stack, id, {
        vpc,
        internetFacing: true,
        // Missing connection draining
      });
    }
  }
  
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'TestStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  LoadBalancerFactory.createPublicLB(stack, vpc, 'PublicLB');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_15() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'TestStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const enabledFeatures = {
    crossZone: true,
    securityGroups: [],
    // Connection draining not included
  };
  
  // ruleid: typescript-cdk-clb-connection-draining
  new elb.LoadBalancer(stack, 'LB', {
    vpc,
    internetFacing: true,
    ...enabledFeatures,
  });
}
// {/fact}

// True Negatives (Secure Code - Connection Draining Enabled)

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_1() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'TestStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ok: typescript-cdk-clb-connection-draining
  new elb.LoadBalancer(stack, 'LB', {
    vpc,
    internetFacing: true,
    connectionDraining: true,
    connectionDrainingTimeout: cdk.Duration.seconds(300),
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_2() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'TestStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ok: typescript-cdk-clb-connection-draining
  new elb.LoadBalancer(stack, 'LB', {
    vpc,
    internetFacing: false,
    connectionDraining: true,
    connectionDrainingTimeout: cdk.Duration.seconds(60),
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_3() {
  class MyStack extends cdk.Stack {
    constructor(scope: Construct, id: string, props?: cdk.StackProps) {
      super(scope, id, props);
      
      const vpc = new ec2.Vpc(this, 'VPC');
      
      // ok: typescript-cdk-clb-connection-draining
      new elb.LoadBalancer(this, 'LoadBalancer', {
        vpc,
        internetFacing: true,
        listeners: [
          {
            port: 80,
            externalPort: 80,
          }
        ],
        connectionDraining: true,
        connectionDrainingTimeout: cdk.Duration.seconds(120),
      });
    }
  }
  
  const app = new cdk.App();
  new MyStack(app, 'MyStack');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_4() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'TestStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const timeout = 300; // 5 minutes
  
  // ok: typescript-cdk-clb-connection-draining
  new elb.LoadBalancer(stack, 'LB', {
    vpc,
    internetFacing: true,
    connectionDraining: true,
    connectionDrainingTimeout: cdk.Duration.seconds(timeout),
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_5() {
  class InfraStack extends cdk.Stack {
    constructor(scope: Construct, id: string, props?: cdk.StackProps) {
      super(scope, id, props);
      
      const vpc = new ec2.Vpc(this, 'VPC');
      
      // ok: typescript-cdk-clb-connection-draining
      const lb = new elb.LoadBalancer(this, 'WebLoadBalancer', {
        vpc,
        internetFacing: true,
        healthCheck: {
          port: 80,
          protocol: elb.LoadBalancingProtocol.HTTP,
          path: '/health',
          interval: cdk.Duration.seconds(30),
        },
        connectionDraining: true,
        connectionDrainingTimeout: cdk.Duration.seconds(60),
      });
    }
  }
  
  const app = new cdk.App();
  new InfraStack(app, 'InfraStack');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_6() {
  const createSecureLoadBalancer = (stack: cdk.Stack, vpc: ec2.Vpc) => {
    // ok: typescript-cdk-clb-connection-draining
    return new elb.LoadBalancer(stack, 'SecureLB', {
      vpc,
      internetFacing: false,
      connectionDraining: true,
      connectionDrainingTimeout: cdk.Duration.seconds(300),
    });
  };
  
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'TestStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  createSecureLoadBalancer(stack, vpc);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_7() {
  class WebStack extends cdk.Stack {
    constructor(scope: Construct, id: string, props?: cdk.StackProps) {
      super(scope, id, props);
      
      const vpc = new ec2.Vpc(this, 'VPC');
      
      // ok: typescript-cdk-clb-connection-draining
      const loadBalancer = new elb.LoadBalancer(this, 'WebLB', {
        vpc,
        internetFacing: true,
        listeners: [
          {
            port: 80,
            externalPort: 80,
          },
          {
            port: 443,
            externalPort: 443,
          }
        ],
        connectionDraining: true,
        connectionDrainingTimeout: cdk.Duration.seconds(120),
      });
    }
  }
  
  const app = new cdk.App();
  new WebStack(app, 'WebStack');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_8() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'TestStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const lbProps = {
    vpc,
    internetFacing: true,
    connectionDraining: true,
    connectionDrainingTimeout: cdk.Duration.seconds(180),
  };
  
  // ok: typescript-cdk-clb-connection-draining
  new elb.LoadBalancer(stack, 'LB', lbProps);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_9() {
  class MultiTierStack extends cdk.Stack {
    constructor(scope: Construct, id: string, props?: cdk.StackProps) {
      super(scope, id, props);
      
      const vpc = new ec2.Vpc(this, 'VPC');
      
      // ok: typescript-cdk-clb-connection-draining
      const frontendLB = new elb.LoadBalancer(this, 'FrontendLB', {
        vpc,
        internetFacing: true,
        connectionDraining: true,
        connectionDrainingTimeout: cdk.Duration.seconds(60),
      });
      
      // ok: typescript-cdk-clb-connection-draining
      const backendLB = new elb.LoadBalancer(this, 'BackendLB', {
        vpc,
        internetFacing: false,
        connectionDraining: true,
        connectionDrainingTimeout: cdk.Duration.seconds(120),
      });
    }
  }
  
  const app = new cdk.App();
  new MultiTierStack(app, 'MultiTierStack');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_10() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'TestStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const drainingTimeout = cdk.Duration.seconds(300);
  
  // ok: typescript-cdk-clb-connection-draining
  const lb = new elb.LoadBalancer(stack, 'LB', {
    vpc,
    internetFacing: true,
    connectionDraining: true,
    connectionDrainingTimeout: drainingTimeout,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_11() {
  class LoadBalancerFactory {
    static createSecureLB(stack: cdk.Stack, vpc: ec2.Vpc, id: string) {
      // ok: typescript-cdk-clb-connection-draining
      return new elb.LoadBalancer(stack, id, {
        vpc,
        internetFacing: true,
        connectionDraining: true,
        connectionDrainingTimeout: cdk.Duration.seconds(240),
      });
    }
  }
  
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'TestStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  LoadBalancerFactory.createSecureLB(stack, vpc, 'SecureLB');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_12() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'TestStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const enabledFeatures = {
    crossZone: true,
    securityGroups: [],
    connectionDraining: true,
    connectionDrainingTimeout: cdk.Duration.seconds(60),
  };
  
  // ok: typescript-cdk-clb-connection-draining
  new elb.LoadBalancer(stack, 'LB', {
    vpc,
    internetFacing: true,
    ...enabledFeatures,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_13() {
  const createLoadBalancerWithDraining = (stack: cdk.Stack, vpc: ec2.Vpc, timeout: number) => {
    // ok: typescript-cdk-clb-connection-draining
    return new elb.LoadBalancer(stack, 'AppLB', {
      vpc,
      internetFacing: false,
      healthCheck: {
        port: 8080,
        protocol: elb.LoadBalancingProtocol.HTTP,
        path: '/status',
      },
      connectionDraining: true,
      connectionDrainingTimeout: cdk.Duration.seconds(timeout),
    });
  };
  
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'TestStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  createLoadBalancerWithDraining(stack, vpc, 120);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_14() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'TestStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const createInternalLB = (id: string) => {
    // ok: typescript-cdk-clb-connection-draining
    return new elb.LoadBalancer(stack, id, {
      vpc,
      internetFacing: false,
      connectionDraining: true,
      connectionDrainingTimeout: cdk.Duration.seconds(180),
    });
  };
  
  createInternalLB('InternalLB1');
  createInternalLB('InternalLB2');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_15() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'TestStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const getConnectionDrainingConfig = () => {
    return {
      connectionDraining: true,
      connectionDrainingTimeout: cdk.Duration.seconds(300),
    };
  };
  
  // ok: typescript-cdk-clb-connection-draining
  new elb.LoadBalancer(stack, 'LB', {
    vpc,
    internetFacing: true,
    ...getConnectionDrainingConfig(),
  });
}
// {/fact}