import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as neptune from 'aws-cdk-lib/aws-neptune';
import * as ec2 from 'aws-cdk-lib/aws-ec2';

// True Positive Examples (Vulnerable Code)

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_1() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'NeptuneStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ruleid: typescript_cdk_neptunedb_database_authentication_disabled
  new neptune.DatabaseCluster(stack, 'NeptuneCluster', {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_2() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'NeptuneStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ruleid: typescript_cdk_neptunedb_database_authentication_disabled
  new neptune.DatabaseCluster(stack, 'NeptuneCluster', {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
    iamAuthentication: false,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_3() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'NeptuneStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const clusterParams = {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
    iamAuthentication: false,
  };
  
  // ruleid: typescript_cdk_neptunedb_database_authentication_disabled
  new neptune.DatabaseCluster(stack, 'NeptuneCluster', clusterParams);
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_4() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'NeptuneStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const enableIam = false;
  
  // ruleid: typescript_cdk_neptunedb_database_authentication_disabled
  new neptune.DatabaseCluster(stack, 'NeptuneCluster', {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
    iamAuthentication: enableIam,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_5() {
  class NeptuneStack extends cdk.Stack {
    constructor(scope: Construct, id: string, props?: cdk.StackProps) {
      super(scope, id, props);
      
      const vpc = new ec2.Vpc(this, 'VPC');
      
      // ruleid: typescript_cdk_neptunedb_database_authentication_disabled
      new neptune.DatabaseCluster(this, 'NeptuneCluster', {
        vpc,
        instanceType: neptune.InstanceType.R5_LARGE,
      });
    }
  }
  
  const app = new cdk.App();
  new NeptuneStack(app, 'NeptuneStack');
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_6() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'NeptuneStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  function createNeptuneCluster() {
    // ruleid: typescript_cdk_neptunedb_database_authentication_disabled
    return new neptune.DatabaseCluster(stack, 'NeptuneCluster', {
      vpc,
      instanceType: neptune.InstanceType.R5_LARGE,
      iamAuthentication: false,
    });
  }
  
  createNeptuneCluster();
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_7() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'NeptuneStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const config = {
    enableIamAuth: false,
    instanceSize: neptune.InstanceType.R5_LARGE,
  };
  
  // ruleid: typescript_cdk_neptunedb_database_authentication_disabled
  new neptune.DatabaseCluster(stack, 'NeptuneCluster', {
    vpc,
    instanceType: config.instanceSize,
    iamAuthentication: config.enableIamAuth,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_8() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'NeptuneStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const isProduction = true;
  
  // ruleid: typescript_cdk_neptunedb_database_authentication_disabled
  new neptune.DatabaseCluster(stack, 'NeptuneCluster', {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
    iamAuthentication: isProduction ? false : false, // Always false regardless of environment
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_9() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'NeptuneStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ruleid: typescript_cdk_neptunedb_database_authentication_disabled
  const cluster = new neptune.DatabaseCluster(stack, 'NeptuneCluster', {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
    iamAuthentication: false,
    removalPolicy: cdk.RemovalPolicy.DESTROY,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_10() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'NeptuneStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const securityGroups = [
    new ec2.SecurityGroup(stack, 'SecurityGroup', { vpc })
  ];
  
  // ruleid: typescript_cdk_neptunedb_database_authentication_disabled
  new neptune.DatabaseCluster(stack, 'NeptuneCluster', {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
    securityGroups,
    iamAuthentication: false,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_11() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'NeptuneStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ruleid: typescript_cdk_neptunedb_database_authentication_disabled
  const cluster = new neptune.DatabaseCluster(stack, 'NeptuneCluster', {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
    deletionProtection: true, // Good security practice but IAM auth still disabled
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_12() {
  class DatabaseStack extends cdk.Stack {
    constructor(scope: Construct, id: string, props?: cdk.StackProps) {
      super(scope, id, props);
      
      const vpc = new ec2.Vpc(this, 'VPC');
      
      // ruleid: typescript_cdk_neptunedb_database_authentication_disabled
      const cluster = new neptune.DatabaseCluster(this, 'NeptuneCluster', {
        vpc,
        instanceType: neptune.InstanceType.R5_LARGE,
        iamAuthentication: false,
        port: 8182,
      });
    }
  }
  
  const app = new cdk.App();
  new DatabaseStack(app, 'DatabaseStack');
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_13() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'NeptuneStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const subnetGroup = new neptune.SubnetGroup(stack, 'NeptuneSubnetGroup', {
    vpc,
    description: 'Neptune subnet group',
  });
  
  // ruleid: typescript_cdk_neptunedb_database_authentication_disabled
  new neptune.DatabaseCluster(stack, 'NeptuneCluster', {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
    subnetGroup,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_14() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'NeptuneStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const parameterGroup = new neptune.ParameterGroup(stack, 'NeptuneParameterGroup', {
    description: 'Neptune parameter group',
    parameters: {
      'neptune_enable_audit_log': '1',
    },
  });
  
  // ruleid: typescript_cdk_neptunedb_database_authentication_disabled
  new neptune.DatabaseCluster(stack, 'NeptuneCluster', {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
    parameterGroup,
    iamAuthentication: false,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_15() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'NeptuneStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const clusterProps = {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
    engineVersion: '1.1.0.0',
    preferredMaintenanceWindow: 'sun:22:00-mon:00:00',
  };
  
  // ruleid: typescript_cdk_neptunedb_database_authentication_disabled
  new neptune.DatabaseCluster(stack, 'NeptuneCluster', clusterProps);
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_1() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'NeptuneStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ok: typescript_cdk_neptunedb_database_authentication_disabled
  new neptune.DatabaseCluster(stack, 'NeptuneCluster', {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
    iamAuthentication: true,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_2() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'NeptuneStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const enableIam = true;
  
  // ok: typescript_cdk_neptunedb_database_authentication_disabled
  new neptune.DatabaseCluster(stack, 'NeptuneCluster', {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
    iamAuthentication: enableIam,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_3() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'NeptuneStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const clusterParams = {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
    iamAuthentication: true,
  };
  
  // ok: typescript_cdk_neptunedb_database_authentication_disabled
  new neptune.DatabaseCluster(stack, 'NeptuneCluster', clusterParams);
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_4() {
  class NeptuneStack extends cdk.Stack {
    constructor(scope: Construct, id: string, props?: cdk.StackProps) {
      super(scope, id, props);
      
      const vpc = new ec2.Vpc(this, 'VPC');
      
      // ok: typescript_cdk_neptunedb_database_authentication_disabled
      new neptune.DatabaseCluster(this, 'NeptuneCluster', {
        vpc,
        instanceType: neptune.InstanceType.R5_LARGE,
        iamAuthentication: true,
      });
    }
  }
  
  const app = new cdk.App();
  new NeptuneStack(app, 'NeptuneStack');
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_5() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'NeptuneStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  function createNeptuneCluster() {
    // ok: typescript_cdk_neptunedb_database_authentication_disabled
    return new neptune.DatabaseCluster(stack, 'NeptuneCluster', {
      vpc,
      instanceType: neptune.InstanceType.R5_LARGE,
      iamAuthentication: true,
    });
  }
  
  createNeptuneCluster();
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_6() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'NeptuneStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const config = {
    enableIamAuth: true,
    instanceSize: neptune.InstanceType.R5_LARGE,
  };
  
  // ok: typescript_cdk_neptunedb_database_authentication_disabled
  new neptune.DatabaseCluster(stack, 'NeptuneCluster', {
    vpc,
    instanceType: config.instanceSize,
    iamAuthentication: config.enableIamAuth,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_7() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'NeptuneStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const isProduction = true;
  
  // ok: typescript_cdk_neptunedb_database_authentication_disabled
  new neptune.DatabaseCluster(stack, 'NeptuneCluster', {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
    iamAuthentication: isProduction ? true : false, // Enable IAM auth in production
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_8() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'NeptuneStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ok: typescript_cdk_neptunedb_database_authentication_disabled
  const cluster = new neptune.DatabaseCluster(stack, 'NeptuneCluster', {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
    iamAuthentication: true,
    removalPolicy: cdk.RemovalPolicy.RETAIN,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_9() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'NeptuneStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const securityGroups = [
    new ec2.SecurityGroup(stack, 'SecurityGroup', { vpc })
  ];
  
  // ok: typescript_cdk_neptunedb_database_authentication_disabled
  new neptune.DatabaseCluster(stack, 'NeptuneCluster', {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
    securityGroups,
    iamAuthentication: true,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_10() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'NeptuneStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ok: typescript_cdk_neptunedb_database_authentication_disabled
  const cluster = new neptune.DatabaseCluster(stack, 'NeptuneCluster', {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
    deletionProtection: true,
    iamAuthentication: true,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_11() {
  class DatabaseStack extends cdk.Stack {
    constructor(scope: Construct, id: string, props?: cdk.StackProps) {
      super(scope, id, props);
      
      const vpc = new ec2.Vpc(this, 'VPC');
      
      // ok: typescript_cdk_neptunedb_database_authentication_disabled
      const cluster = new neptune.DatabaseCluster(this, 'NeptuneCluster', {
        vpc,
        instanceType: neptune.InstanceType.R5_LARGE,
        iamAuthentication: true,
        port: 8182,
      });
    }
  }
  
  const app = new cdk.App();
  new DatabaseStack(app, 'DatabaseStack');
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_12() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'NeptuneStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const subnetGroup = new neptune.SubnetGroup(stack, 'NeptuneSubnetGroup', {
    vpc,
    description: 'Neptune subnet group',
  });
  
  // ok: typescript_cdk_neptunedb_database_authentication_disabled
  new neptune.DatabaseCluster(stack, 'NeptuneCluster', {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
    subnetGroup,
    iamAuthentication: true,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_13() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'NeptuneStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const parameterGroup = new neptune.ParameterGroup(stack, 'NeptuneParameterGroup', {
    description: 'Neptune parameter group',
    parameters: {
      'neptune_enable_audit_log': '1',
    },
  });
  
  // ok: typescript_cdk_neptunedb_database_authentication_disabled
  new neptune.DatabaseCluster(stack, 'NeptuneCluster', {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
    parameterGroup,
    iamAuthentication: true,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_14() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'NeptuneStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const clusterProps = {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
    engineVersion: '1.1.0.0',
    preferredMaintenanceWindow: 'sun:22:00-mon:00:00',
    iamAuthentication: true,
  };
  
  // ok: typescript_cdk_neptunedb_database_authentication_disabled
  new neptune.DatabaseCluster(stack, 'NeptuneCluster', clusterProps);
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_15() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'NeptuneStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const getIamAuthSetting = () => {
    return true; // Return true to enable IAM authentication
  };
  
  // ok: typescript_cdk_neptunedb_database_authentication_disabled
  new neptune.DatabaseCluster(stack, 'NeptuneCluster', {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
    iamAuthentication: getIamAuthSetting(),
  });
}
// {/fact}