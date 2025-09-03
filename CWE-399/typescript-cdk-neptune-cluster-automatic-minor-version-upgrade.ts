import { Stack, App } from 'aws-cdk-lib';
import * as neptune from 'aws-cdk-lib/aws-neptune';
import * as ec2 from 'aws-cdk-lib/aws-ec2';

// True Positive Examples (Vulnerable Code)

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_1() {
  const app = new App();
  const stack = new Stack(app, 'NeptuneStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ruleid: typescript-cdk-neptune-cluster-automatic-minor-version-upgrade
  new neptune.CfnDBInstance(stack, 'NeptuneInstance', {
    dbInstanceClass: 'db.r5.large',
    autoMinorVersionUpgrade: false,
    dbClusterIdentifier: 'my-cluster',
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_2() {
  const app = new App();
  const stack = new Stack(app, 'NeptuneStack');
  
  // ruleid: typescript-cdk-neptune-cluster-automatic-minor-version-upgrade
  const neptuneInstance = new neptune.CfnDBInstance(stack, 'NeptuneInstance', {
    dbInstanceClass: 'db.r5.large',
    autoMinorVersionUpgrade: false,
    availabilityZone: 'us-east-1a',
    dbClusterIdentifier: 'my-cluster',
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_3() {
  const app = new App();
  const stack = new Stack(app, 'NeptuneStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const autoUpgrade = false;
  
  // ruleid: typescript-cdk-neptune-cluster-automatic-minor-version-upgrade
  new neptune.CfnDBInstance(stack, 'NeptuneInstance', {
    dbInstanceClass: 'db.r5.large',
    autoMinorVersionUpgrade: autoUpgrade,
    dbClusterIdentifier: 'my-cluster',
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_4() {
  const app = new App();
  const stack = new Stack(app, 'NeptuneStack');
  
  const instanceProps = {
    dbInstanceClass: 'db.r5.large',
    autoMinorVersionUpgrade: false,
    dbClusterIdentifier: 'my-cluster',
  };
  
  // ruleid: typescript-cdk-neptune-cluster-automatic-minor-version-upgrade
  new neptune.CfnDBInstance(stack, 'NeptuneInstance', instanceProps);
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_5() {
  const app = new App();
  const stack = new Stack(app, 'NeptuneStack');
  
  // ruleid: typescript-cdk-neptune-cluster-automatic-minor-version-upgrade
  const instance = new neptune.CfnDBInstance(stack, 'NeptuneInstance', {
    dbInstanceClass: 'db.r5.large',
    autoMinorVersionUpgrade: false,
    dbClusterIdentifier: 'my-cluster',
  });
  
  // Additional configuration doesn't fix the issue
  instance.applyRemovalPolicy(RemovalPolicy.DESTROY);
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_6() {
  const app = new App();
  const stack = new Stack(app, 'NeptuneStack');
  
  const config = getConfig();
  
  // ruleid: typescript-cdk-neptune-cluster-automatic-minor-version-upgrade
  new neptune.CfnDBInstance(stack, 'NeptuneInstance', {
    dbInstanceClass: 'db.r5.large',
    autoMinorVersionUpgrade: config.disableAutoUpgrade, // disableAutoUpgrade is true
    dbClusterIdentifier: 'my-cluster',
  });
  
  function getConfig() {
    return {
      disableAutoUpgrade: false
    };
  }
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_7() {
  const app = new App();
  const stack = new Stack(app, 'NeptuneStack');
  
  for (let i = 0; i < 3; i++) {
    // ruleid: typescript-cdk-neptune-cluster-automatic-minor-version-upgrade
    new neptune.CfnDBInstance(stack, `NeptuneInstance-${i}`, {
      dbInstanceClass: 'db.r5.large',
      autoMinorVersionUpgrade: false,
      dbClusterIdentifier: `my-cluster-${i}`,
    });
  }
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_8() {
  const app = new App();
  const stack = new Stack(app, 'NeptuneStack');
  
  const shouldAutoUpgrade = () => false;
  
  // ruleid: typescript-cdk-neptune-cluster-automatic-minor-version-upgrade
  new neptune.CfnDBInstance(stack, 'NeptuneInstance', {
    dbInstanceClass: 'db.r5.large',
    autoMinorVersionUpgrade: shouldAutoUpgrade(),
    dbClusterIdentifier: 'my-cluster',
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_9() {
  const app = new App();
  const stack = new Stack(app, 'NeptuneStack');
  
  const instanceProps: neptune.CfnDBInstanceProps = {
    dbInstanceClass: 'db.r5.large',
    autoMinorVersionUpgrade: false,
    dbClusterIdentifier: 'my-cluster',
  };
  
  // ruleid: typescript-cdk-neptune-cluster-automatic-minor-version-upgrade
  new neptune.CfnDBInstance(stack, 'NeptuneInstance', instanceProps);
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_10() {
  const app = new App();
  const stack = new Stack(app, 'NeptuneStack');
  
  const autoUpgradeSettings = {
    dev: false,
    prod: true
  };
  
  // ruleid: typescript-cdk-neptune-cluster-automatic-minor-version-upgrade
  new neptune.CfnDBInstance(stack, 'NeptuneInstance', {
    dbInstanceClass: 'db.r5.large',
    autoMinorVersionUpgrade: autoUpgradeSettings.dev, // Using dev setting which is false
    dbClusterIdentifier: 'my-cluster',
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_11() {
  const app = new App();
  const stack = new Stack(app, 'NeptuneStack');
  
  const createNeptuneInstance = (autoUpgrade: boolean) => {
    // ruleid: typescript-cdk-neptune-cluster-automatic-minor-version-upgrade
    return new neptune.CfnDBInstance(stack, 'NeptuneInstance', {
      dbInstanceClass: 'db.r5.large',
      autoMinorVersionUpgrade: autoUpgrade,
      dbClusterIdentifier: 'my-cluster',
    });
  };
  
  createNeptuneInstance(false);
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_12() {
  const app = new App();
  const stack = new Stack(app, 'NeptuneStack');
  
  const instanceSettings = {
    class: 'db.r5.large',
    upgrade: false,
    cluster: 'my-cluster'
  };
  
  // ruleid: typescript-cdk-neptune-cluster-automatic-minor-version-upgrade
  new neptune.CfnDBInstance(stack, 'NeptuneInstance', {
    dbInstanceClass: instanceSettings.class,
    autoMinorVersionUpgrade: instanceSettings.upgrade,
    dbClusterIdentifier: instanceSettings.cluster,
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_13() {
  const app = new App();
  const stack = new Stack(app, 'NeptuneStack');
  
  let autoUpgrade = true;
  if (process.env.NODE_ENV === 'development') {
    autoUpgrade = false;
  }
  
  // ruleid: typescript-cdk-neptune-cluster-automatic-minor-version-upgrade
  new neptune.CfnDBInstance(stack, 'NeptuneInstance', {
    dbInstanceClass: 'db.r5.large',
    autoMinorVersionUpgrade: autoUpgrade, // Could be false based on condition
    dbClusterIdentifier: 'my-cluster',
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_14() {
  const app = new App();
  const stack = new Stack(app, 'NeptuneStack');
  
  // ruleid: typescript-cdk-neptune-cluster-automatic-minor-version-upgrade
  const neptuneProps = {
    dbInstanceClass: 'db.r5.large',
    autoMinorVersionUpgrade: false,
    dbClusterIdentifier: 'my-cluster',
  };
  
  const instance = new neptune.CfnDBInstance(stack, 'NeptuneInstance', neptuneProps);
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_15() {
  const app = new App();
  const stack = new Stack(app, 'NeptuneStack');
  
  const options = { autoUpgrade: false };
  
  // ruleid: typescript-cdk-neptune-cluster-automatic-minor-version-upgrade
  new neptune.CfnDBInstance(stack, 'NeptuneInstance', {
    dbInstanceClass: 'db.r5.large',
    autoMinorVersionUpgrade: options.autoUpgrade,
    dbClusterIdentifier: 'my-cluster',
  });
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=object-presence@v1.0 defects=0}
function good_case_1() {
  const app = new App();
  const stack = new Stack(app, 'NeptuneStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ok: typescript-cdk-neptune-cluster-automatic-minor-version-upgrade
  new neptune.CfnDBInstance(stack, 'NeptuneInstance', {
    dbInstanceClass: 'db.r5.large',
    autoMinorVersionUpgrade: true,
    dbClusterIdentifier: 'my-cluster',
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_2() {
  const app = new App();
  const stack = new Stack(app, 'NeptuneStack');
  
  // ok: typescript-cdk-neptune-cluster-automatic-minor-version-upgrade
  const neptuneInstance = new neptune.CfnDBInstance(stack, 'NeptuneInstance', {
    dbInstanceClass: 'db.r5.large',
    autoMinorVersionUpgrade: true,
    availabilityZone: 'us-east-1a',
    dbClusterIdentifier: 'my-cluster',
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_3() {
  const app = new App();
  const stack = new Stack(app, 'NeptuneStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const autoUpgrade = true;
  
  // ok: typescript-cdk-neptune-cluster-automatic-minor-version-upgrade
  new neptune.CfnDBInstance(stack, 'NeptuneInstance', {
    dbInstanceClass: 'db.r5.large',
    autoMinorVersionUpgrade: autoUpgrade,
    dbClusterIdentifier: 'my-cluster',
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_4() {
  const app = new App();
  const stack = new Stack(app, 'NeptuneStack');
  
  const instanceProps = {
    dbInstanceClass: 'db.r5.large',
    autoMinorVersionUpgrade: true,
    dbClusterIdentifier: 'my-cluster',
  };
  
  // ok: typescript-cdk-neptune-cluster-automatic-minor-version-upgrade
  new neptune.CfnDBInstance(stack, 'NeptuneInstance', instanceProps);
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_5() {
  const app = new App();
  const stack = new Stack(app, 'NeptuneStack');
  
  // Default behavior is to enable auto minor version upgrade
  // ok: typescript-cdk-neptune-cluster-automatic-minor-version-upgrade
  const instance = new neptune.CfnDBInstance(stack, 'NeptuneInstance', {
    dbInstanceClass: 'db.r5.large',
    dbClusterIdentifier: 'my-cluster',
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_6() {
  const app = new App();
  const stack = new Stack(app, 'NeptuneStack');
  
  const config = getConfig();
  
  // ok: typescript-cdk-neptune-cluster-automatic-minor-version-upgrade
  new neptune.CfnDBInstance(stack, 'NeptuneInstance', {
    dbInstanceClass: 'db.r5.large',
    autoMinorVersionUpgrade: config.enableAutoUpgrade, // enableAutoUpgrade is true
    dbClusterIdentifier: 'my-cluster',
  });
  
  function getConfig() {
    return {
      enableAutoUpgrade: true
    };
  }
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_7() {
  const app = new App();
  const stack = new Stack(app, 'NeptuneStack');
  
  for (let i = 0; i < 3; i++) {
    // ok: typescript-cdk-neptune-cluster-automatic-minor-version-upgrade
    new neptune.CfnDBInstance(stack, `NeptuneInstance-${i}`, {
      dbInstanceClass: 'db.r5.large',
      autoMinorVersionUpgrade: true,
      dbClusterIdentifier: `my-cluster-${i}`,
    });
  }
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_8() {
  const app = new App();
  const stack = new Stack(app, 'NeptuneStack');
  
  const shouldAutoUpgrade = () => true;
  
  // ok: typescript-cdk-neptune-cluster-automatic-minor-version-upgrade
  new neptune.CfnDBInstance(stack, 'NeptuneInstance', {
    dbInstanceClass: 'db.r5.large',
    autoMinorVersionUpgrade: shouldAutoUpgrade(),
    dbClusterIdentifier: 'my-cluster',
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_9() {
  const app = new App();
  const stack = new Stack(app, 'NeptuneStack');
  
  const instanceProps: neptune.CfnDBInstanceProps = {
    dbInstanceClass: 'db.r5.large',
    autoMinorVersionUpgrade: true,
    dbClusterIdentifier: 'my-cluster',
  };
  
  // ok: typescript-cdk-neptune-cluster-automatic-minor-version-upgrade
  new neptune.CfnDBInstance(stack, 'NeptuneInstance', instanceProps);
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_10() {
  const app = new App();
  const stack = new Stack(app, 'NeptuneStack');
  
  const autoUpgradeSettings = {
    dev: true,
    prod: true
  };
  
  // ok: typescript-cdk-neptune-cluster-automatic-minor-version-upgrade
  new neptune.CfnDBInstance(stack, 'NeptuneInstance', {
    dbInstanceClass: 'db.r5.large',
    autoMinorVersionUpgrade: autoUpgradeSettings.prod, // Using prod setting which is true
    dbClusterIdentifier: 'my-cluster',
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_11() {
  const app = new App();
  const stack = new Stack(app, 'NeptuneStack');
  
  const createNeptuneInstance = (autoUpgrade: boolean) => {
    // ok: typescript-cdk-neptune-cluster-automatic-minor-version-upgrade
    return new neptune.CfnDBInstance(stack, 'NeptuneInstance', {
      dbInstanceClass: 'db.r5.large',
      autoMinorVersionUpgrade: autoUpgrade,
      dbClusterIdentifier: 'my-cluster',
    });
  };
  
  createNeptuneInstance(true);
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_12() {
  const app = new App();
  const stack = new Stack(app, 'NeptuneStack');
  
  const instanceSettings = {
    class: 'db.r5.large',
    upgrade: true,
    cluster: 'my-cluster'
  };
  
  // ok: typescript-cdk-neptune-cluster-automatic-minor-version-upgrade
  new neptune.CfnDBInstance(stack, 'NeptuneInstance', {
    dbInstanceClass: instanceSettings.class,
    autoMinorVersionUpgrade: instanceSettings.upgrade,
    dbClusterIdentifier: instanceSettings.cluster,
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_13() {
  const app = new App();
  const stack = new Stack(app, 'NeptuneStack');
  
  // Using environment variable to determine auto upgrade setting
  const autoUpgrade = process.env.DISABLE_AUTO_UPGRADE !== 'true';
  
  // ok: typescript-cdk-neptune-cluster-automatic-minor-version-upgrade
  new neptune.CfnDBInstance(stack, 'NeptuneInstance', {
    dbInstanceClass: 'db.r5.large',
    autoMinorVersionUpgrade: autoUpgrade,
    dbClusterIdentifier: 'my-cluster',
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_14() {
  const app = new App();
  const stack = new Stack(app, 'NeptuneStack');
  
  // ok: typescript-cdk-neptune-cluster-automatic-minor-version-upgrade
  const neptuneProps = {
    dbInstanceClass: 'db.r5.large',
    autoMinorVersionUpgrade: true,
    dbClusterIdentifier: 'my-cluster',
  };
  
  const instance = new neptune.CfnDBInstance(stack, 'NeptuneInstance', neptuneProps);
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_15() {
  const app = new App();
  const stack = new Stack(app, 'NeptuneStack');
  
  // Using a higher level construct that sets autoMinorVersionUpgrade to true by default
  // ok: typescript-cdk-neptune-cluster-automatic-minor-version-upgrade
  const cluster = new neptune.DatabaseCluster(stack, 'Database', {
    vpc: new ec2.Vpc(stack, 'VPC'),
    instanceType: neptune.InstanceType.R5_LARGE,
  });
}
// {/fact}