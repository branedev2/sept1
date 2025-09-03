import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as sagemaker from 'aws-cdk-lib/aws-sagemaker';
import * as kms from 'aws-cdk-lib/aws-kms';

// True positive examples (vulnerable code)

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_1() {
  const stack = new cdk.Stack();
  
  // ruleid: typescript_cdk_sagemaker_notebook_missing_encryption
  new sagemaker.CfnNotebookInstance(stack, 'MyNotebook1', {
    instanceType: 'ml.t2.medium',
    roleArn: 'arn:aws:iam::123456789012:role/service-role/AmazonSageMaker-ExecutionRole',
    notebookInstanceName: 'my-notebook-instance'
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_2() {
  const stack = new cdk.Stack();
  
  // ruleid: typescript_cdk_sagemaker_notebook_missing_encryption
  const notebook = new sagemaker.CfnNotebookInstance(stack, 'MyNotebook2', {
    instanceType: 'ml.t3.large',
    roleArn: 'arn:aws:iam::123456789012:role/service-role/AmazonSageMaker-ExecutionRole',
    notebookInstanceName: 'data-science-notebook'
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_3() {
  const stack = new cdk.Stack();
  const props = {
    instanceType: 'ml.m5.xlarge',
    roleArn: 'arn:aws:iam::123456789012:role/service-role/AmazonSageMaker-ExecutionRole',
    notebookInstanceName: 'ml-notebook'
  };
  
  // ruleid: typescript_cdk_sagemaker_notebook_missing_encryption
  new sagemaker.CfnNotebookInstance(stack, 'MyNotebook3', props);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_4() {
  class MachineLearningStack extends cdk.Stack {
    constructor(scope: Construct, id: string, props?: cdk.StackProps) {
      super(scope, id, props);
      
      // ruleid: typescript_cdk_sagemaker_notebook_missing_encryption
      new sagemaker.CfnNotebookInstance(this, 'MyNotebook4', {
        instanceType: 'ml.t2.medium',
        roleArn: 'arn:aws:iam::123456789012:role/service-role/AmazonSageMaker-ExecutionRole',
        notebookInstanceName: 'ml-training-notebook',
        directInternetAccess: 'Enabled'
      });
    }
  }
  
  const app = new cdk.App();
  new MachineLearningStack(app, 'MachineLearningStack');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_5() {
  const stack = new cdk.Stack();
  
  // ruleid: typescript_cdk_sagemaker_notebook_missing_encryption
  new sagemaker.CfnNotebookInstance(stack, 'MyNotebook5', {
    instanceType: 'ml.m5.large',
    roleArn: 'arn:aws:iam::123456789012:role/service-role/AmazonSageMaker-ExecutionRole',
    notebookInstanceName: 'production-notebook',
    volumeSizeInGb: 50
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_6() {
  const stack = new cdk.Stack();
  const notebookProps = {
    instanceType: 'ml.c5.xlarge',
    roleArn: 'arn:aws:iam::123456789012:role/service-role/AmazonSageMaker-ExecutionRole',
    notebookInstanceName: 'high-performance-notebook',
    lifecycleConfigName: 'setup-script'
  };
  
  // ruleid: typescript_cdk_sagemaker_notebook_missing_encryption
  const notebook = new sagemaker.CfnNotebookInstance(stack, 'MyNotebook6', notebookProps);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_7() {
  class DataScienceStack extends cdk.Stack {
    constructor(scope: Construct, id: string, props?: cdk.StackProps) {
      super(scope, id, props);
      
      for (let i = 1; i <= 3; i++) {
        // ruleid: typescript_cdk_sagemaker_notebook_missing_encryption
        new sagemaker.CfnNotebookInstance(this, `DataScienceNotebook${i}`, {
          instanceType: 'ml.t2.medium',
          roleArn: 'arn:aws:iam::123456789012:role/service-role/AmazonSageMaker-ExecutionRole',
          notebookInstanceName: `data-science-notebook-${i}`
        });
      }
    }
  }
  
  const app = new cdk.App();
  new DataScienceStack(app, 'DataScienceStack');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_8() {
  const stack = new cdk.Stack();
  
  const createNotebook = (id: string, name: string) => {
    // ruleid: typescript_cdk_sagemaker_notebook_missing_encryption
    return new sagemaker.CfnNotebookInstance(stack, id, {
      instanceType: 'ml.t2.medium',
      roleArn: 'arn:aws:iam::123456789012:role/service-role/AmazonSageMaker-ExecutionRole',
      notebookInstanceName: name
    });
  };
  
  createNotebook('MyNotebook8', 'functional-notebook');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_9() {
  const stack = new cdk.Stack();
  
  // ruleid: typescript_cdk_sagemaker_notebook_missing_encryption
  new sagemaker.CfnNotebookInstance(stack, 'MyNotebook9', {
    instanceType: 'ml.t2.medium',
    roleArn: 'arn:aws:iam::123456789012:role/service-role/AmazonSageMaker-ExecutionRole',
    notebookInstanceName: 'my-notebook-instance',
    defaultCodeRepository: 'https://github.com/example/ml-models'
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_10() {
  const stack = new cdk.Stack();
  
  const instanceType = process.env.INSTANCE_TYPE || 'ml.t2.medium';
  
  // ruleid: typescript_cdk_sagemaker_notebook_missing_encryption
  new sagemaker.CfnNotebookInstance(stack, 'MyNotebook10', {
    instanceType: instanceType,
    roleArn: 'arn:aws:iam::123456789012:role/service-role/AmazonSageMaker-ExecutionRole',
    notebookInstanceName: 'dynamic-notebook'
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_11() {
  const stack = new cdk.Stack();
  
  // Setting KmsKeyId to empty string is still insecure
  // ruleid: typescript_cdk_sagemaker_notebook_missing_encryption
  new sagemaker.CfnNotebookInstance(stack, 'MyNotebook11', {
    instanceType: 'ml.t2.medium',
    roleArn: 'arn:aws:iam::123456789012:role/service-role/AmazonSageMaker-ExecutionRole',
    notebookInstanceName: 'empty-key-notebook',
    kmsKeyId: ''
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_12() {
  const stack = new cdk.Stack();
  
  // Setting KmsKeyId to undefined is still insecure
  // ruleid: typescript_cdk_sagemaker_notebook_missing_encryption
  new sagemaker.CfnNotebookInstance(stack, 'MyNotebook12', {
    instanceType: 'ml.t2.medium',
    roleArn: 'arn:aws:iam::123456789012:role/service-role/AmazonSageMaker-ExecutionRole',
    notebookInstanceName: 'undefined-key-notebook',
    kmsKeyId: undefined
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_13() {
  class MLOpsStack extends cdk.Stack {
    constructor(scope: Construct, id: string, props?: cdk.StackProps) {
      super(scope, id, props);
      
      const config = {
        instanceType: 'ml.m5.large',
        roleArn: 'arn:aws:iam::123456789012:role/service-role/AmazonSageMaker-ExecutionRole',
        notebookInstanceName: 'mlops-notebook'
      };
      
      // ruleid: typescript_cdk_sagemaker_notebook_missing_encryption
      new sagemaker.CfnNotebookInstance(this, 'MyNotebook13', config);
    }
  }
  
  const app = new cdk.App();
  new MLOpsStack(app, 'MLOpsStack');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_14() {
  const stack = new cdk.Stack();
  
  const notebookProps: sagemaker.CfnNotebookInstanceProps = {
    instanceType: 'ml.t2.medium',
    roleArn: 'arn:aws:iam::123456789012:role/service-role/AmazonSageMaker-ExecutionRole',
    notebookInstanceName: 'typed-notebook'
  };
  
  // ruleid: typescript_cdk_sagemaker_notebook_missing_encryption
  new sagemaker.CfnNotebookInstance(stack, 'MyNotebook14', notebookProps);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_15() {
  const stack = new cdk.Stack();
  
  const createNotebookWithTags = () => {
    // ruleid: typescript_cdk_sagemaker_notebook_missing_encryption
    return new sagemaker.CfnNotebookInstance(stack, 'MyNotebook15', {
      instanceType: 'ml.t2.medium',
      roleArn: 'arn:aws:iam::123456789012:role/service-role/AmazonSageMaker-ExecutionRole',
      notebookInstanceName: 'tagged-notebook',
      tags: [
        { key: 'Environment', value: 'Development' },
        { key: 'Owner', value: 'DataScience' }
      ]
    });
  };
  
  createNotebookWithTags();
}
// {/fact}

// True negative examples (secure code)

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_1() {
  const stack = new cdk.Stack();
  const key = new kms.Key(stack, 'NotebookEncryptionKey');
  
  // ok: typescript_cdk_sagemaker_notebook_missing_encryption
  new sagemaker.CfnNotebookInstance(stack, 'MySecureNotebook1', {
    instanceType: 'ml.t2.medium',
    roleArn: 'arn:aws:iam::123456789012:role/service-role/AmazonSageMaker-ExecutionRole',
    notebookInstanceName: 'secure-notebook-1',
    kmsKeyId: key.keyId
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_2() {
  const stack = new cdk.Stack();
  
  // ok: typescript_cdk_sagemaker_notebook_missing_encryption
  new sagemaker.CfnNotebookInstance(stack, 'MySecureNotebook2', {
    instanceType: 'ml.t3.large',
    roleArn: 'arn:aws:iam::123456789012:role/service-role/AmazonSageMaker-ExecutionRole',
    notebookInstanceName: 'secure-notebook-2',
    kmsKeyId: 'arn:aws:kms:us-west-2:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab'
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_3() {
  const stack = new cdk.Stack();
  const key = new kms.Key(stack, 'NotebookEncryptionKey3');
  
  const props = {
    instanceType: 'ml.m5.xlarge',
    roleArn: 'arn:aws:iam::123456789012:role/service-role/AmazonSageMaker-ExecutionRole',
    notebookInstanceName: 'secure-notebook-3',
    kmsKeyId: key.keyId
  };
  
  // ok: typescript_cdk_sagemaker_notebook_missing_encryption
  new sagemaker.CfnNotebookInstance(stack, 'MySecureNotebook3', props);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_4() {
  class SecureMachineLearningStack extends cdk.Stack {
    constructor(scope: Construct, id: string, props?: cdk.StackProps) {
      super(scope, id, props);
      
      const key = new kms.Key(this, 'NotebookEncryptionKey4');
      
      // ok: typescript_cdk_sagemaker_notebook_missing_encryption
      new sagemaker.CfnNotebookInstance(this, 'MySecureNotebook4', {
        instanceType: 'ml.t2.medium',
        roleArn: 'arn:aws:iam::123456789012:role/service-role/AmazonSageMaker-ExecutionRole',
        notebookInstanceName: 'secure-notebook-4',
        kmsKeyId: key.keyId,
        directInternetAccess: 'Enabled'
      });
    }
  }
  
  const app = new cdk.App();
  new SecureMachineLearningStack(app, 'SecureMachineLearningStack');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_5() {
  const stack = new cdk.Stack();
  const keyId = 'arn:aws:kms:us-west-2:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab';
  
  // ok: typescript_cdk_sagemaker_notebook_missing_encryption
  new sagemaker.CfnNotebookInstance(stack, 'MySecureNotebook5', {
    instanceType: 'ml.m5.large',
    roleArn: 'arn:aws:iam::123456789012:role/service-role/AmazonSageMaker-ExecutionRole',
    notebookInstanceName: 'secure-notebook-5',
    volumeSizeInGb: 50,
    kmsKeyId: keyId
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_6() {
  const stack = new cdk.Stack();
  const key = new kms.Key(stack, 'NotebookEncryptionKey6');
  
  const notebookProps = {
    instanceType: 'ml.c5.xlarge',
    roleArn: 'arn:aws:iam::123456789012:role/service-role/AmazonSageMaker-ExecutionRole',
    notebookInstanceName: 'secure-notebook-6',
    lifecycleConfigName: 'setup-script',
    kmsKeyId: key.keyId
  };
  
  // ok: typescript_cdk_sagemaker_notebook_missing_encryption
  const notebook = new sagemaker.CfnNotebookInstance(stack, 'MySecureNotebook6', notebookProps);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_7() {
  class SecureDataScienceStack extends cdk.Stack {
    constructor(scope: Construct, id: string, props?: cdk.StackProps) {
      super(scope, id, props);
      
      const key = new kms.Key(this, 'NotebookEncryptionKey7');
      
      for (let i = 1; i <= 3; i++) {
        // ok: typescript_cdk_sagemaker_notebook_missing_encryption
        new sagemaker.CfnNotebookInstance(this, `SecureDataScienceNotebook${i}`, {
          instanceType: 'ml.t2.medium',
          roleArn: 'arn:aws:iam::123456789012:role/service-role/AmazonSageMaker-ExecutionRole',
          notebookInstanceName: `secure-data-science-notebook-${i}`,
          kmsKeyId: key.keyId
        });
      }
    }
  }
  
  const app = new cdk.App();
  new SecureDataScienceStack(app, 'SecureDataScienceStack');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_8() {
  const stack = new cdk.Stack();
  const key = new kms.Key(stack, 'NotebookEncryptionKey8');
  
  const createSecureNotebook = (id: string, name: string) => {
    // ok: typescript_cdk_sagemaker_notebook_missing_encryption
    return new sagemaker.CfnNotebookInstance(stack, id, {
      instanceType: 'ml.t2.medium',
      roleArn: 'arn:aws:iam::123456789012:role/service-role/AmazonSageMaker-ExecutionRole',
      notebookInstanceName: name,
      kmsKeyId: key.keyId
    });
  };
  
  createSecureNotebook('MySecureNotebook8', 'secure-functional-notebook');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_9() {
  const stack = new cdk.Stack();
  const key = new kms.Key(stack, 'NotebookEncryptionKey9');
  
  // ok: typescript_cdk_sagemaker_notebook_missing_encryption
  new sagemaker.CfnNotebookInstance(stack, 'MySecureNotebook9', {
    instanceType: 'ml.t2.medium',
    roleArn: 'arn:aws:iam::123456789012:role/service-role/AmazonSageMaker-ExecutionRole',
    notebookInstanceName: 'secure-notebook-9',
    defaultCodeRepository: 'https://github.com/example/ml-models',
    kmsKeyId: key.keyId
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_10() {
  const stack = new cdk.Stack();
  
  const instanceType = process.env.INSTANCE_TYPE || 'ml.t2.medium';
  const keyId = process.env.KMS_KEY_ID || 'arn:aws:kms:us-west-2:123456789012:key/default-key';
  
  // ok: typescript_cdk_sagemaker_notebook_missing_encryption
  new sagemaker.CfnNotebookInstance(stack, 'MySecureNotebook10', {
    instanceType: instanceType,
    roleArn: 'arn:aws:iam::123456789012:role/service-role/AmazonSageMaker-ExecutionRole',
    notebookInstanceName: 'secure-dynamic-notebook',
    kmsKeyId: keyId
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_11() {
  const stack = new cdk.Stack();
  const key = kms.Key.fromKeyArn(stack, 'ImportedKey', 
    'arn:aws:kms:us-west-2:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab');
  
  // ok: typescript_cdk_sagemaker_notebook_missing_encryption
  new sagemaker.CfnNotebookInstance(stack, 'MySecureNotebook11', {
    instanceType: 'ml.t2.medium',
    roleArn: 'arn:aws:iam::123456789012:role/service-role/AmazonSageMaker-ExecutionRole',
    notebookInstanceName: 'secure-imported-key-notebook',
    kmsKeyId: key.keyArn
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_12() {
  class SecureMLOpsStack extends cdk.Stack {
    constructor(scope: Construct, id: string, props?: cdk.StackProps) {
      super(scope, id, props);
      
      const key = new kms.Key(this, 'NotebookEncryptionKey12', {
        description: 'Key for SageMaker notebook encryption',
        enableKeyRotation: true
      });
      
      // ok: typescript_cdk_sagemaker_notebook_missing_encryption
      new sagemaker.CfnNotebookInstance(this, 'MySecureNotebook12', {
        instanceType: 'ml.t2.medium',
        roleArn: 'arn:aws:iam::123456789012:role/service-role/AmazonSageMaker-ExecutionRole',
        notebookInstanceName: 'secure-mlops-notebook',
        kmsKeyId: key.keyId
      });
    }
  }
  
  const app = new cdk.App();
  new SecureMLOpsStack(app, 'SecureMLOpsStack');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_13() {
  const stack = new cdk.Stack();
  
  const keyAlias = 'alias/sagemaker-notebook-key';
  
  // ok: typescript_cdk_sagemaker_notebook_missing_encryption
  new sagemaker.CfnNotebookInstance(stack, 'MySecureNotebook13', {
    instanceType: 'ml.t2.medium',
    roleArn: 'arn:aws:iam::123456789012:role/service-role/AmazonSageMaker-ExecutionRole',
    notebookInstanceName: 'secure-alias-key-notebook',
    kmsKeyId: keyAlias
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_14() {
  const stack = new cdk.Stack();
  const key = new kms.Key(stack, 'NotebookEncryptionKey14');
  
  const notebookProps: sagemaker.CfnNotebookInstanceProps = {
    instanceType: 'ml.t2.medium',
    roleArn: 'arn:aws:iam::123456789012:role/service-role/AmazonSageMaker-ExecutionRole',
    notebookInstanceName: 'secure-typed-notebook',
    kmsKeyId: key.keyId
  };
  
  // ok: typescript_cdk_sagemaker_notebook_missing_encryption
  new sagemaker.CfnNotebookInstance(stack, 'MySecureNotebook14', notebookProps);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_15() {
  const stack = new cdk.Stack();
  const key = new kms.Key(stack, 'NotebookEncryptionKey15');
  
  const createSecureNotebookWithTags = () => {
    // ok: typescript_cdk_sagemaker_notebook_missing_encryption
    return new sagemaker.CfnNotebookInstance(stack, 'MySecureNotebook15', {
      instanceType: 'ml.t2.medium',
      roleArn: 'arn:aws:iam::123456789012:role/service-role/AmazonSageMaker-ExecutionRole',
      notebookInstanceName: 'secure-tagged-notebook',
      kmsKeyId: key.keyId,
      tags: [
        { key: 'Environment', value: 'Production' },
        { key: 'Owner', value: 'DataScience' },
        { key: 'Security', value: 'Encrypted' }
      ]
    });
  };
  
  createSecureNotebookWithTags();
}
// {/fact}