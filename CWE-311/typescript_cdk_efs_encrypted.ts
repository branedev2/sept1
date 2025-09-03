import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as efs from 'aws-cdk-lib/aws-efs';
import * as iam from 'aws-cdk-lib/aws-iam';

// True Positive Examples (Vulnerable Code)

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_1() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'EfsStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ruleid: typescript_cdk_efs_encrypted
  const fileSystem = new efs.FileSystem(stack, 'MyEfsFileSystem', {
    vpc,
    encrypted: false, // Explicitly disabling encryption
    performanceMode: efs.PerformanceMode.GENERAL_PURPOSE,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_2() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'EfsStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ruleid: typescript_cdk_efs_encrypted
  const fileSystem = new efs.FileSystem(stack, 'MyEfsFileSystem', {
    vpc,
    // No encrypted property specified, defaults to false
    performanceMode: efs.PerformanceMode.GENERAL_PURPOSE,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_3() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'EfsStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const encryptionSetting = false;
  
  // ruleid: typescript_cdk_efs_encrypted
  const fileSystem = new efs.FileSystem(stack, 'MyEfsFileSystem', {
    vpc,
    encrypted: encryptionSetting, // Variable set to false
    performanceMode: efs.PerformanceMode.MAX_IO,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_4() {
  class EfsConstruct extends Construct {
    constructor(scope: Construct, id: string) {
      super(scope, id);
      
      const vpc = new ec2.Vpc(this, 'VPC');
      
      // ruleid: typescript_cdk_efs_encrypted
      const fileSystem = new efs.FileSystem(this, 'FileSystem', {
        vpc,
        encrypted: false,
        lifecyclePolicy: efs.LifecyclePolicy.AFTER_14_DAYS,
      });
    }
  }
  
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'EfsStack');
  new EfsConstruct(stack, 'EfsConstruct');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_5() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'EfsStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const config = {
    encrypted: false,
    performanceMode: efs.PerformanceMode.GENERAL_PURPOSE,
  };
  
  // ruleid: typescript_cdk_efs_encrypted
  const fileSystem = new efs.FileSystem(stack, 'MyEfsFileSystem', {
    vpc,
    ...config, // Spreading config with encrypted: false
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_6() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'EfsStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  function createFileSystem(enableEncryption: boolean) {
    // ruleid: typescript_cdk_efs_encrypted
    return new efs.FileSystem(stack, 'MyEfsFileSystem', {
      vpc,
      encrypted: enableEncryption,
      performanceMode: efs.PerformanceMode.GENERAL_PURPOSE,
    });
  }
  
  const fileSystem = createFileSystem(false); // Passing false for encryption
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_7() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'EfsStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const isProduction = false;
  
  // ruleid: typescript_cdk_efs_encrypted
  const fileSystem = new efs.FileSystem(stack, 'MyEfsFileSystem', {
    vpc,
    encrypted: isProduction, // Using a variable that's false
    performanceMode: efs.PerformanceMode.GENERAL_PURPOSE,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_8() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'EfsStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ruleid: typescript_cdk_efs_encrypted
  const fileSystem = new efs.FileSystem(stack, 'MyEfsFileSystem', {
    vpc,
    encrypted: false,
    removalPolicy: cdk.RemovalPolicy.DESTROY,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_9() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'EfsStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const shouldEncrypt = () => false;
  
  // ruleid: typescript_cdk_efs_encrypted
  const fileSystem = new efs.FileSystem(stack, 'MyEfsFileSystem', {
    vpc,
    encrypted: shouldEncrypt(), // Function returning false
    performanceMode: efs.PerformanceMode.GENERAL_PURPOSE,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_10() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'EfsStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const environmentConfig = {
    dev: { encrypted: false },
    prod: { encrypted: true }
  };
  
  const env = 'dev';
  
  // ruleid: typescript_cdk_efs_encrypted
  const fileSystem = new efs.FileSystem(stack, 'MyEfsFileSystem', {
    vpc,
    encrypted: environmentConfig[env].encrypted, // Using dev config which is false
    performanceMode: efs.PerformanceMode.GENERAL_PURPOSE,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_11() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'EfsStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ruleid: typescript_cdk_efs_encrypted
  const fileSystem = new efs.CfnFileSystem(stack, 'MyCfnFileSystem', {
    encrypted: false,
    performanceMode: 'generalPurpose',
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_12() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'EfsStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const options = { encrypted: false };
  
  // ruleid: typescript_cdk_efs_encrypted
  const fileSystem = new efs.FileSystem(stack, 'MyEfsFileSystem', {
    vpc,
    encrypted: options.encrypted,
    performanceMode: efs.PerformanceMode.GENERAL_PURPOSE,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_13() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'EfsStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const encryptionSettings = [true, false, true];
  
  // ruleid: typescript_cdk_efs_encrypted
  const fileSystem = new efs.FileSystem(stack, 'MyEfsFileSystem', {
    vpc,
    encrypted: encryptionSettings[1], // Using false from array
    performanceMode: efs.PerformanceMode.GENERAL_PURPOSE,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_14() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'EfsStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const encryptionMap = new Map<string, boolean>();
  encryptionMap.set('dev', false);
  encryptionMap.set('prod', true);
  
  // ruleid: typescript_cdk_efs_encrypted
  const fileSystem = new efs.FileSystem(stack, 'MyEfsFileSystem', {
    vpc,
    encrypted: encryptionMap.get('dev'), // Getting false from map
    performanceMode: efs.PerformanceMode.GENERAL_PURPOSE,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_15() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'EfsStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const getEncryptionSetting = (env: string) => {
    if (env === 'prod') return true;
    return false;
  };
  
  // ruleid: typescript_cdk_efs_encrypted
  const fileSystem = new efs.FileSystem(stack, 'MyEfsFileSystem', {
    vpc,
    encrypted: getEncryptionSetting('dev'), // Function returns false for 'dev'
    performanceMode: efs.PerformanceMode.GENERAL_PURPOSE,
  });
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_1() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'EfsStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ok: typescript_cdk_efs_encrypted
  const fileSystem = new efs.FileSystem(stack, 'MyEfsFileSystem', {
    vpc,
    encrypted: true, // Explicitly enabling encryption
    performanceMode: efs.PerformanceMode.GENERAL_PURPOSE,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_2() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'EfsStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const encryptionSetting = true;
  
  // ok: typescript_cdk_efs_encrypted
  const fileSystem = new efs.FileSystem(stack, 'MyEfsFileSystem', {
    vpc,
    encrypted: encryptionSetting, // Variable set to true
    performanceMode: efs.PerformanceMode.MAX_IO,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_3() {
  class SecureEfsConstruct extends Construct {
    constructor(scope: Construct, id: string) {
      super(scope, id);
      
      const vpc = new ec2.Vpc(this, 'VPC');
      
      // ok: typescript_cdk_efs_encrypted
      const fileSystem = new efs.FileSystem(this, 'FileSystem', {
        vpc,
        encrypted: true,
        lifecyclePolicy: efs.LifecyclePolicy.AFTER_14_DAYS,
      });
    }
  }
  
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'EfsStack');
  new SecureEfsConstruct(stack, 'SecureEfsConstruct');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_4() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'EfsStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const config = {
    encrypted: true,
    performanceMode: efs.PerformanceMode.GENERAL_PURPOSE,
  };
  
  // ok: typescript_cdk_efs_encrypted
  const fileSystem = new efs.FileSystem(stack, 'MyEfsFileSystem', {
    vpc,
    ...config, // Spreading config with encrypted: true
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_5() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'EfsStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  function createFileSystem(enableEncryption: boolean) {
    // ok: typescript_cdk_efs_encrypted
    return new efs.FileSystem(stack, 'MyEfsFileSystem', {
      vpc,
      encrypted: enableEncryption,
      performanceMode: efs.PerformanceMode.GENERAL_PURPOSE,
    });
  }
  
  const fileSystem = createFileSystem(true); // Passing true for encryption
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_6() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'EfsStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const isProduction = true;
  
  // ok: typescript_cdk_efs_encrypted
  const fileSystem = new efs.FileSystem(stack, 'MyEfsFileSystem', {
    vpc,
    encrypted: isProduction, // Using a variable that's true
    performanceMode: efs.PerformanceMode.GENERAL_PURPOSE,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_7() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'EfsStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ok: typescript_cdk_efs_encrypted
  const fileSystem = new efs.FileSystem(stack, 'MyEfsFileSystem', {
    vpc,
    encrypted: true,
    removalPolicy: cdk.RemovalPolicy.DESTROY,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_8() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'EfsStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const shouldEncrypt = () => true;
  
  // ok: typescript_cdk_efs_encrypted
  const fileSystem = new efs.FileSystem(stack, 'MyEfsFileSystem', {
    vpc,
    encrypted: shouldEncrypt(), // Function returning true
    performanceMode: efs.PerformanceMode.GENERAL_PURPOSE,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_9() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'EfsStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const environmentConfig = {
    dev: { encrypted: true },
    prod: { encrypted: true }
  };
  
  const env = 'dev';
  
  // ok: typescript_cdk_efs_encrypted
  const fileSystem = new efs.FileSystem(stack, 'MyEfsFileSystem', {
    vpc,
    encrypted: environmentConfig[env].encrypted, // Using dev config which is true
    performanceMode: efs.PerformanceMode.GENERAL_PURPOSE,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_10() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'EfsStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ok: typescript_cdk_efs_encrypted
  const fileSystem = new efs.CfnFileSystem(stack, 'MyCfnFileSystem', {
    encrypted: true,
    performanceMode: 'generalPurpose',
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_11() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'EfsStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const options = { encrypted: true };
  
  // ok: typescript_cdk_efs_encrypted
  const fileSystem = new efs.FileSystem(stack, 'MyEfsFileSystem', {
    vpc,
    encrypted: options.encrypted,
    performanceMode: efs.PerformanceMode.GENERAL_PURPOSE,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_12() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'EfsStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const encryptionSettings = [true, false, true];
  
  // ok: typescript_cdk_efs_encrypted
  const fileSystem = new efs.FileSystem(stack, 'MyEfsFileSystem', {
    vpc,
    encrypted: encryptionSettings[0], // Using true from array
    performanceMode: efs.PerformanceMode.GENERAL_PURPOSE,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_13() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'EfsStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const encryptionMap = new Map<string, boolean>();
  encryptionMap.set('dev', true);
  encryptionMap.set('prod', true);
  
  // ok: typescript_cdk_efs_encrypted
  const fileSystem = new efs.FileSystem(stack, 'MyEfsFileSystem', {
    vpc,
    encrypted: encryptionMap.get('dev'), // Getting true from map
    performanceMode: efs.PerformanceMode.GENERAL_PURPOSE,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_14() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'EfsStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const getEncryptionSetting = (env: string) => {
    return true; // Always return true regardless of environment
  };
  
  // ok: typescript_cdk_efs_encrypted
  const fileSystem = new efs.FileSystem(stack, 'MyEfsFileSystem', {
    vpc,
    encrypted: getEncryptionSetting('dev'), // Function always returns true
    performanceMode: efs.PerformanceMode.GENERAL_PURPOSE,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_15() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'EfsStack');
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // Using KMS key for encryption automatically implies encrypted=true
  const key = new cdk.aws_kms.Key(stack, 'EfsKey');
  
  // ok: typescript_cdk_efs_encrypted
  const fileSystem = new efs.FileSystem(stack, 'MyEfsFileSystem', {
    vpc,
    encrypted: true,
    kmsKey: key,
    performanceMode: efs.PerformanceMode.GENERAL_PURPOSE,
  });
}
// {/fact}