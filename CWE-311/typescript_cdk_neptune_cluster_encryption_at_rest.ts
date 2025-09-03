import { Stack, App } from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as neptune from 'aws-cdk-lib/aws-neptune';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as kms from 'aws-cdk-lib/aws-kms';

// TRUE POSITIVES (Vulnerable Code Examples)

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_1() {
  const app = new App();
  const stack = new Stack(app, 'NeptuneStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ruleid: typescript_cdk_neptune_cluster_encryption_at_rest
  const cluster = new neptune.DatabaseCluster(stack, 'Database', {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_2() {
  const app = new App();
  const stack = new Stack(app, 'NeptuneStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ruleid: typescript_cdk_neptune_cluster_encryption_at_rest
  const cluster = new neptune.DatabaseCluster(stack, 'Database', {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
    storageEncrypted: false,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_3() {
  const app = new App();
  const stack = new Stack(app, 'NeptuneStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const params = {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
  };
  
  // ruleid: typescript_cdk_neptune_cluster_encryption_at_rest
  const cluster = new neptune.DatabaseCluster(stack, 'Database', params);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_4() {
  const app = new App();
  const stack = new Stack(app, 'NeptuneStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const isEncrypted = false;
  
  // ruleid: typescript_cdk_neptune_cluster_encryption_at_rest
  const cluster = new neptune.DatabaseCluster(stack, 'Database', {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
    storageEncrypted: isEncrypted,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_5() {
  const app = new App();
  const stack = new Stack(app, 'NeptuneStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const config = getConfig();
  
  // ruleid: typescript_cdk_neptune_cluster_encryption_at_rest
  const cluster = new neptune.DatabaseCluster(stack, 'Database', {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
    ...config,
  });
  
  function getConfig() {
    return {
      storageEncrypted: false,
    };
  }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_6() {
  class NeptuneStack extends Stack {
    constructor(scope: Construct, id: string) {
      super(scope, id);
      
      const vpc = new ec2.Vpc(this, 'VPC');
      
      // ruleid: typescript_cdk_neptune_cluster_encryption_at_rest
      new neptune.DatabaseCluster(this, 'Database', {
        vpc,
        instanceType: neptune.InstanceType.R5_LARGE,
      });
    }
  }
  
  const app = new App();
  new NeptuneStack(app, 'NeptuneStack');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_7() {
  const app = new App();
  const stack = new Stack(app, 'NeptuneStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const clusterProps = {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
  };
  
  // ruleid: typescript_cdk_neptune_cluster_encryption_at_rest
  createNeptuneCluster(stack, clusterProps);
  
  function createNeptuneCluster(scope: Construct, props: any) {
    return new neptune.DatabaseCluster(scope, 'Database', props);
  }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_8() {
  const app = new App();
  const stack = new Stack(app, 'NeptuneStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const encryptionConfig = {
    storageEncrypted: undefined,
  };
  
  // ruleid: typescript_cdk_neptune_cluster_encryption_at_rest
  const cluster = new neptune.DatabaseCluster(stack, 'Database', {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
    ...encryptionConfig,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_9() {
  const app = new App();
  const stack = new Stack(app, 'NeptuneStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const isProd = false;
  
  // ruleid: typescript_cdk_neptune_cluster_encryption_at_rest
  const cluster = new neptune.DatabaseCluster(stack, 'Database', {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
    storageEncrypted: isProd ? true : false,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_10() {
  const app = new App();
  const stack = new Stack(app, 'NeptuneStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const options = { enableEncryption: false };
  
  // ruleid: typescript_cdk_neptune_cluster_encryption_at_rest
  const cluster = new neptune.DatabaseCluster(stack, 'Database', {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
    storageEncrypted: options.enableEncryption,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_11() {
  const app = new App();
  const stack = new Stack(app, 'NeptuneStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const configMap = new Map<string, any>();
  configMap.set('vpc', vpc);
  configMap.set('instanceType', neptune.InstanceType.R5_LARGE);
  
  // ruleid: typescript_cdk_neptune_cluster_encryption_at_rest
  const cluster = new neptune.DatabaseCluster(stack, 'Database', Object.fromEntries(configMap));
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_12() {
  const app = new App();
  const stack = new Stack(app, 'NeptuneStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  function getNeptuneConfig() {
    if (process.env.NODE_ENV === 'production') {
      return {
        storageEncrypted: true,
      };
    }
    return {};
  }
  
  // ruleid: typescript_cdk_neptune_cluster_encryption_at_rest
  const cluster = new neptune.DatabaseCluster(stack, 'Database', {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
    ...getNeptuneConfig(),
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_13() {
  const app = new App();
  const stack = new Stack(app, 'NeptuneStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ruleid: typescript_cdk_neptune_cluster_encryption_at_rest
  const cluster = new neptune.DatabaseCluster(stack, 'Database', {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
    storageEncrypted: process.env.ENCRYPT_STORAGE === 'true',
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_14() {
  class DatabaseStack extends Stack {
    constructor(scope: Construct, id: string, props?: any) {
      super(scope, id, props);
      
      const vpc = new ec2.Vpc(this, 'VPC');
      
      // ruleid: typescript_cdk_neptune_cluster_encryption_at_rest
      this.createNeptuneCluster(vpc);
    }
    
    private createNeptuneCluster(vpc: ec2.Vpc) {
      return new neptune.DatabaseCluster(this, 'Database', {
        vpc,
        instanceType: neptune.InstanceType.R5_LARGE,
      });
    }
  }
  
  const app = new App();
  new DatabaseStack(app, 'DatabaseStack');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_15() {
  const app = new App();
  const stack = new Stack(app, 'NeptuneStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const baseConfig = {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
  };
  
  const devConfig = {
    ...baseConfig,
    removalPolicy: 'destroy',
  };
  
  // ruleid: typescript_cdk_neptune_cluster_encryption_at_rest
  const cluster = new neptune.DatabaseCluster(stack, 'Database', devConfig);
}
// {/fact}

// TRUE NEGATIVES (Secure Code Examples)

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_1() {
  const app = new App();
  const stack = new Stack(app, 'NeptuneStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ok: typescript_cdk_neptune_cluster_encryption_at_rest
  const cluster = new neptune.DatabaseCluster(stack, 'Database', {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
    storageEncrypted: true,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_2() {
  const app = new App();
  const stack = new Stack(app, 'NeptuneStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  const key = new kms.Key(stack, 'NeptuneKey');
  
  // ok: typescript_cdk_neptune_cluster_encryption_at_rest
  const cluster = new neptune.DatabaseCluster(stack, 'Database', {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
    storageEncrypted: true,
    kmsKey: key,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_3() {
  const app = new App();
  const stack = new Stack(app, 'NeptuneStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const params = {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
    storageEncrypted: true,
  };
  
  // ok: typescript_cdk_neptune_cluster_encryption_at_rest
  const cluster = new neptune.DatabaseCluster(stack, 'Database', params);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_4() {
  const app = new App();
  const stack = new Stack(app, 'NeptuneStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const isEncrypted = true;
  
  // ok: typescript_cdk_neptune_cluster_encryption_at_rest
  const cluster = new neptune.DatabaseCluster(stack, 'Database', {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
    storageEncrypted: isEncrypted,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_5() {
  const app = new App();
  const stack = new Stack(app, 'NeptuneStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const config = getConfig();
  
  // ok: typescript_cdk_neptune_cluster_encryption_at_rest
  const cluster = new neptune.DatabaseCluster(stack, 'Database', {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
    ...config,
  });
  
  function getConfig() {
    return {
      storageEncrypted: true,
    };
  }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_6() {
  class NeptuneStack extends Stack {
    constructor(scope: Construct, id: string) {
      super(scope, id);
      
      const vpc = new ec2.Vpc(this, 'VPC');
      
      // ok: typescript_cdk_neptune_cluster_encryption_at_rest
      new neptune.DatabaseCluster(this, 'Database', {
        vpc,
        instanceType: neptune.InstanceType.R5_LARGE,
        storageEncrypted: true,
      });
    }
  }
  
  const app = new App();
  new NeptuneStack(app, 'NeptuneStack');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_7() {
  const app = new App();
  const stack = new Stack(app, 'NeptuneStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const clusterProps = {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
    storageEncrypted: true,
  };
  
  // ok: typescript_cdk_neptune_cluster_encryption_at_rest
  createNeptuneCluster(stack, clusterProps);
  
  function createNeptuneCluster(scope: Construct, props: any) {
    return new neptune.DatabaseCluster(scope, 'Database', props);
  }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_8() {
  const app = new App();
  const stack = new Stack(app, 'NeptuneStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const encryptionConfig = {
    storageEncrypted: true,
  };
  
  // ok: typescript_cdk_neptune_cluster_encryption_at_rest
  const cluster = new neptune.DatabaseCluster(stack, 'Database', {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
    ...encryptionConfig,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_9() {
  const app = new App();
  const stack = new Stack(app, 'NeptuneStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const isProd = true;
  
  // ok: typescript_cdk_neptune_cluster_encryption_at_rest
  const cluster = new neptune.DatabaseCluster(stack, 'Database', {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
    storageEncrypted: isProd ? true : true, // Always true regardless of environment
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_10() {
  const app = new App();
  const stack = new Stack(app, 'NeptuneStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const key = kms.Key.fromKeyArn(stack, 'ImportedKey', 'arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab');
  
  // ok: typescript_cdk_neptune_cluster_encryption_at_rest
  const cluster = new neptune.DatabaseCluster(stack, 'Database', {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
    storageEncrypted: true,
    kmsKey: key,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_11() {
  const app = new App();
  const stack = new Stack(app, 'NeptuneStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const configMap = new Map<string, any>();
  configMap.set('vpc', vpc);
  configMap.set('instanceType', neptune.InstanceType.R5_LARGE);
  configMap.set('storageEncrypted', true);
  
  // ok: typescript_cdk_neptune_cluster_encryption_at_rest
  const cluster = new neptune.DatabaseCluster(stack, 'Database', Object.fromEntries(configMap));
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_12() {
  const app = new App();
  const stack = new Stack(app, 'NeptuneStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  function getNeptuneConfig() {
    return {
      storageEncrypted: true,
    };
  }
  
  // ok: typescript_cdk_neptune_cluster_encryption_at_rest
  const cluster = new neptune.DatabaseCluster(stack, 'Database', {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
    ...getNeptuneConfig(),
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_13() {
  const app = new App();
  const stack = new Stack(app, 'NeptuneStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ok: typescript_cdk_neptune_cluster_encryption_at_rest
  const cluster = new neptune.DatabaseCluster(stack, 'Database', {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
    storageEncrypted: true,
    deletionProtection: true,
    removalPolicy: 'retain',
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_14() {
  class DatabaseStack extends Stack {
    constructor(scope: Construct, id: string, props?: any) {
      super(scope, id, props);
      
      const vpc = new ec2.Vpc(this, 'VPC');
      
      // ok: typescript_cdk_neptune_cluster_encryption_at_rest
      this.createNeptuneCluster(vpc);
    }
    
    private createNeptuneCluster(vpc: ec2.Vpc) {
      return new neptune.DatabaseCluster(this, 'Database', {
        vpc,
        instanceType: neptune.InstanceType.R5_LARGE,
        storageEncrypted: true,
      });
    }
  }
  
  const app = new App();
  new DatabaseStack(app, 'DatabaseStack');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_15() {
  const app = new App();
  const stack = new Stack(app, 'NeptuneStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const baseConfig = {
    vpc,
    instanceType: neptune.InstanceType.R5_LARGE,
    storageEncrypted: true,
  };
  
  const devConfig = {
    ...baseConfig,
    removalPolicy: 'destroy',
  };
  
  // ok: typescript_cdk_neptune_cluster_encryption_at_rest
  const cluster = new neptune.DatabaseCluster(stack, 'Database', devConfig);
}
// {/fact}