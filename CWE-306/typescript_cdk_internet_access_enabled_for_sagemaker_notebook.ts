import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as sagemaker from 'aws-cdk-lib/aws-sagemaker';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as iam from 'aws-cdk-lib/aws-iam';

// True Positives (Vulnerable Code)

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_1(scope: Construct) {
  // Creating a SageMaker notebook instance with direct internet access explicitly enabled
  // ruleid: typescript_cdk_internet_access_enabled_for_sagemaker_notebook
  new sagemaker.CfnNotebookInstance(scope, 'VulnerableNotebook1', {
    instanceType: 'ml.t2.medium',
    roleArn: 'arn:aws:iam::123456789012:role/SageMakerRole',
    directInternetAccess: 'Enabled',
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_2(scope: Construct) {
  // Creating a SageMaker notebook with direct internet access enabled by default (not specifying is the same as Enabled)
  // ruleid: typescript_cdk_internet_access_enabled_for_sagemaker_notebook
  new sagemaker.CfnNotebookInstance(scope, 'VulnerableNotebook2', {
    instanceType: 'ml.t3.large',
    roleArn: 'arn:aws:iam::123456789012:role/SageMakerRole',
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_3(scope: Construct, vpc: ec2.Vpc) {
  // Creating a notebook with direct internet access enabled despite having a VPC
  // ruleid: typescript_cdk_internet_access_enabled_for_sagemaker_notebook
  new sagemaker.CfnNotebookInstance(scope, 'VulnerableNotebook3', {
    instanceType: 'ml.m5.xlarge',
    roleArn: 'arn:aws:iam::123456789012:role/SageMakerRole',
    directInternetAccess: 'Enabled',
    subnetId: vpc.privateSubnets[0].subnetId,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_4(scope: Construct) {
  // Creating a notebook with direct internet access enabled using a variable
  const internetAccess = 'Enabled';
  
  // ruleid: typescript_cdk_internet_access_enabled_for_sagemaker_notebook
  new sagemaker.CfnNotebookInstance(scope, 'VulnerableNotebook4', {
    instanceType: 'ml.c5.large',
    roleArn: 'arn:aws:iam::123456789012:role/SageMakerRole',
    directInternetAccess: internetAccess,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_5(scope: Construct) {
  // Creating a notebook with direct internet access enabled using props object
  const notebookProps = {
    instanceType: 'ml.p2.xlarge',
    roleArn: 'arn:aws:iam::123456789012:role/SageMakerRole',
    directInternetAccess: 'Enabled',
  };
  
  // ruleid: typescript_cdk_internet_access_enabled_for_sagemaker_notebook
  new sagemaker.CfnNotebookInstance(scope, 'VulnerableNotebook5', notebookProps);
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_6(scope: Construct) {
  // Creating multiple notebooks with direct internet access enabled
  const roleArn = 'arn:aws:iam::123456789012:role/SageMakerRole';
  
  // ruleid: typescript_cdk_internet_access_enabled_for_sagemaker_notebook
  new sagemaker.CfnNotebookInstance(scope, 'VulnerableNotebook6A', {
    instanceType: 'ml.t2.large',
    roleArn: roleArn,
    directInternetAccess: 'Enabled',
  });
  
  // ruleid: typescript_cdk_internet_access_enabled_for_sagemaker_notebook
  new sagemaker.CfnNotebookInstance(scope, 'VulnerableNotebook6B', {
    instanceType: 'ml.t2.xlarge',
    roleArn: roleArn,
    directInternetAccess: 'Enabled',
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_7(scope: Construct) {
  // Creating a notebook with direct internet access enabled and additional configuration
  // ruleid: typescript_cdk_internet_access_enabled_for_sagemaker_notebook
  new sagemaker.CfnNotebookInstance(scope, 'VulnerableNotebook7', {
    instanceType: 'ml.m5.2xlarge',
    roleArn: 'arn:aws:iam::123456789012:role/SageMakerRole',
    directInternetAccess: 'Enabled',
    volumeSizeInGb: 100,
    acceleratorTypes: ['ml.eia1.medium'],
    defaultCodeRepository: 'https://github.com/example/repository',
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_8(scope: Construct) {
  // Creating a notebook with direct internet access enabled using a function
  function getInternetAccessConfig() {
    return 'Enabled';
  }
  
  // ruleid: typescript_cdk_internet_access_enabled_for_sagemaker_notebook
  new sagemaker.CfnNotebookInstance(scope, 'VulnerableNotebook8', {
    instanceType: 'ml.c5.2xlarge',
    roleArn: 'arn:aws:iam::123456789012:role/SageMakerRole',
    directInternetAccess: getInternetAccessConfig(),
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_9(scope: Construct) {
  // Creating a notebook with direct internet access enabled using a conditional
  const isProduction = false;
  const internetAccess = isProduction ? 'Disabled' : 'Enabled';
  
  // ruleid: typescript_cdk_internet_access_enabled_for_sagemaker_notebook
  new sagemaker.CfnNotebookInstance(scope, 'VulnerableNotebook9', {
    instanceType: 'ml.m4.xlarge',
    roleArn: 'arn:aws:iam::123456789012:role/SageMakerRole',
    directInternetAccess: internetAccess,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_10(scope: Construct) {
  // Creating a notebook with direct internet access enabled and lifecycle configuration
  // ruleid: typescript_cdk_internet_access_enabled_for_sagemaker_notebook
  new sagemaker.CfnNotebookInstance(scope, 'VulnerableNotebook10', {
    instanceType: 'ml.t3.2xlarge',
    roleArn: 'arn:aws:iam::123456789012:role/SageMakerRole',
    directInternetAccess: 'Enabled',
    lifecycleConfigName: 'MyLifecycleConfig',
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_11(scope: Construct) {
  // Creating a notebook with direct internet access enabled and tags
  // ruleid: typescript_cdk_internet_access_enabled_for_sagemaker_notebook
  new sagemaker.CfnNotebookInstance(scope, 'VulnerableNotebook11', {
    instanceType: 'ml.c4.xlarge',
    roleArn: 'arn:aws:iam::123456789012:role/SageMakerRole',
    directInternetAccess: 'Enabled',
    tags: [
      { key: 'Environment', value: 'Development' },
      { key: 'Project', value: 'ML-Pipeline' }
    ],
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_12(scope: Construct) {
  // Creating a notebook with direct internet access enabled and KMS key
  // ruleid: typescript_cdk_internet_access_enabled_for_sagemaker_notebook
  new sagemaker.CfnNotebookInstance(scope, 'VulnerableNotebook12', {
    instanceType: 'ml.p3.2xlarge',
    roleArn: 'arn:aws:iam::123456789012:role/SageMakerRole',
    directInternetAccess: 'Enabled',
    kmsKeyId: 'arn:aws:kms:us-west-2:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab',
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_13(scope: Construct, vpc: ec2.Vpc) {
  // Creating a notebook with direct internet access enabled and security groups
  // ruleid: typescript_cdk_internet_access_enabled_for_sagemaker_notebook
  new sagemaker.CfnNotebookInstance(scope, 'VulnerableNotebook13', {
    instanceType: 'ml.g4dn.xlarge',
    roleArn: 'arn:aws:iam::123456789012:role/SageMakerRole',
    directInternetAccess: 'Enabled',
    subnetId: vpc.privateSubnets[0].subnetId,
    securityGroupIds: ['sg-12345678'],
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_14(scope: Construct) {
  // Creating a notebook with direct internet access enabled and root access
  // ruleid: typescript_cdk_internet_access_enabled_for_sagemaker_notebook
  new sagemaker.CfnNotebookInstance(scope, 'VulnerableNotebook14', {
    instanceType: 'ml.c5.4xlarge',
    roleArn: 'arn:aws:iam::123456789012:role/SageMakerRole',
    directInternetAccess: 'Enabled',
    rootAccess: 'Enabled',
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_15(scope: Construct) {
  // Creating a notebook with direct internet access enabled and platform identifier
  // ruleid: typescript_cdk_internet_access_enabled_for_sagemaker_notebook
  new sagemaker.CfnNotebookInstance(scope, 'VulnerableNotebook15', {
    instanceType: 'ml.m5.4xlarge',
    roleArn: 'arn:aws:iam::123456789012:role/SageMakerRole',
    directInternetAccess: 'Enabled',
    platformIdentifier: 'notebook-al2-v1',
  });
}
// {/fact}

// True Negatives (Secure Code)

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_1(scope: Construct) {
  // Creating a SageMaker notebook instance with direct internet access explicitly disabled
  // ok: typescript_cdk_internet_access_enabled_for_sagemaker_notebook
  new sagemaker.CfnNotebookInstance(scope, 'SecureNotebook1', {
    instanceType: 'ml.t2.medium',
    roleArn: 'arn:aws:iam::123456789012:role/SageMakerRole',
    directInternetAccess: 'Disabled',
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_2(scope: Construct, vpc: ec2.Vpc) {
  // Creating a SageMaker notebook with direct internet access disabled and VPC configuration
  // ok: typescript_cdk_internet_access_enabled_for_sagemaker_notebook
  new sagemaker.CfnNotebookInstance(scope, 'SecureNotebook2', {
    instanceType: 'ml.t3.large',
    roleArn: 'arn:aws:iam::123456789012:role/SageMakerRole',
    directInternetAccess: 'Disabled',
    subnetId: vpc.privateSubnets[0].subnetId,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_3(scope: Construct) {
  // Creating a notebook with direct internet access disabled using a variable
  const internetAccess = 'Disabled';
  
  // ok: typescript_cdk_internet_access_enabled_for_sagemaker_notebook
  new sagemaker.CfnNotebookInstance(scope, 'SecureNotebook3', {
    instanceType: 'ml.c5.large',
    roleArn: 'arn:aws:iam::123456789012:role/SageMakerRole',
    directInternetAccess: internetAccess,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_4(scope: Construct) {
  // Creating a notebook with direct internet access disabled using props object
  const notebookProps = {
    instanceType: 'ml.p2.xlarge',
    roleArn: 'arn:aws:iam::123456789012:role/SageMakerRole',
    directInternetAccess: 'Disabled',
  };
  
  // ok: typescript_cdk_internet_access_enabled_for_sagemaker_notebook
  new sagemaker.CfnNotebookInstance(scope, 'SecureNotebook4', notebookProps);
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_5(scope: Construct) {
  // Creating multiple notebooks with direct internet access disabled
  const roleArn = 'arn:aws:iam::123456789012:role/SageMakerRole';
  
  // ok: typescript_cdk_internet_access_enabled_for_sagemaker_notebook
  new sagemaker.CfnNotebookInstance(scope, 'SecureNotebook5A', {
    instanceType: 'ml.t2.large',
    roleArn: roleArn,
    directInternetAccess: 'Disabled',
  });
  
  // ok: typescript_cdk_internet_access_enabled_for_sagemaker_notebook
  new sagemaker.CfnNotebookInstance(scope, 'SecureNotebook5B', {
    instanceType: 'ml.t2.xlarge',
    roleArn: roleArn,
    directInternetAccess: 'Disabled',
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_6(scope: Construct) {
  // Creating a notebook with direct internet access disabled and additional configuration
  // ok: typescript_cdk_internet_access_enabled_for_sagemaker_notebook
  new sagemaker.CfnNotebookInstance(scope, 'SecureNotebook6', {
    instanceType: 'ml.m5.2xlarge',
    roleArn: 'arn:aws:iam::123456789012:role/SageMakerRole',
    directInternetAccess: 'Disabled',
    volumeSizeInGb: 100,
    acceleratorTypes: ['ml.eia1.medium'],
    defaultCodeRepository: 'https://github.com/example/repository',
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_7(scope: Construct) {
  // Creating a notebook with direct internet access disabled using a function
  function getInternetAccessConfig() {
    return 'Disabled';
  }
  
  // ok: typescript_cdk_internet_access_enabled_for_sagemaker_notebook
  new sagemaker.CfnNotebookInstance(scope, 'SecureNotebook7', {
    instanceType: 'ml.c5.2xlarge',
    roleArn: 'arn:aws:iam::123456789012:role/SageMakerRole',
    directInternetAccess: getInternetAccessConfig(),
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_8(scope: Construct) {
  // Creating a notebook with direct internet access disabled using a conditional
  const isProduction = true;
  const internetAccess = isProduction ? 'Disabled' : 'Enabled';
  
  // ok: typescript_cdk_internet_access_enabled_for_sagemaker_notebook
  new sagemaker.CfnNotebookInstance(scope, 'SecureNotebook8', {
    instanceType: 'ml.m4.xlarge',
    roleArn: 'arn:aws:iam::123456789012:role/SageMakerRole',
    directInternetAccess: internetAccess,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_9(scope: Construct) {
  // Creating a notebook with direct internet access disabled and lifecycle configuration
  // ok: typescript_cdk_internet_access_enabled_for_sagemaker_notebook
  new sagemaker.CfnNotebookInstance(scope, 'SecureNotebook9', {
    instanceType: 'ml.t3.2xlarge',
    roleArn: 'arn:aws:iam::123456789012:role/SageMakerRole',
    directInternetAccess: 'Disabled',
    lifecycleConfigName: 'MyLifecycleConfig',
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_10(scope: Construct) {
  // Creating a notebook with direct internet access disabled and tags
  // ok: typescript_cdk_internet_access_enabled_for_sagemaker_notebook
  new sagemaker.CfnNotebookInstance(scope, 'SecureNotebook10', {
    instanceType: 'ml.c4.xlarge',
    roleArn: 'arn:aws:iam::123456789012:role/SageMakerRole',
    directInternetAccess: 'Disabled',
    tags: [
      { key: 'Environment', value: 'Production' },
      { key: 'Project', value: 'ML-Pipeline' }
    ],
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_11(scope: Construct) {
  // Creating a notebook with direct internet access disabled and KMS key
  // ok: typescript_cdk_internet_access_enabled_for_sagemaker_notebook
  new sagemaker.CfnNotebookInstance(scope, 'SecureNotebook11', {
    instanceType: 'ml.p3.2xlarge',
    roleArn: 'arn:aws:iam::123456789012:role/SageMakerRole',
    directInternetAccess: 'Disabled',
    kmsKeyId: 'arn:aws:kms:us-west-2:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab',
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_12(scope: Construct, vpc: ec2.Vpc) {
  // Creating a notebook with direct internet access disabled and security groups
  // ok: typescript_cdk_internet_access_enabled_for_sagemaker_notebook
  new sagemaker.CfnNotebookInstance(scope, 'SecureNotebook12', {
    instanceType: 'ml.g4dn.xlarge',
    roleArn: 'arn:aws:iam::123456789012:role/SageMakerRole',
    directInternetAccess: 'Disabled',
    subnetId: vpc.privateSubnets[0].subnetId,
    securityGroupIds: ['sg-12345678'],
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_13(scope: Construct) {
  // Creating a notebook with direct internet access disabled and root access
  // ok: typescript_cdk_internet_access_enabled_for_sagemaker_notebook
  new sagemaker.CfnNotebookInstance(scope, 'SecureNotebook13', {
    instanceType: 'ml.c5.4xlarge',
    roleArn: 'arn:aws:iam::123456789012:role/SageMakerRole',
    directInternetAccess: 'Disabled',
    rootAccess: 'Enabled',
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_14(scope: Construct) {
  // Creating a notebook with direct internet access disabled and platform identifier
  // ok: typescript_cdk_internet_access_enabled_for_sagemaker_notebook
  new sagemaker.CfnNotebookInstance(scope, 'SecureNotebook14', {
    instanceType: 'ml.m5.4xlarge',
    roleArn: 'arn:aws:iam::123456789012:role/SageMakerRole',
    directInternetAccess: 'Disabled',
    platformIdentifier: 'notebook-al2-v1',
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_15(scope: Construct, vpc: ec2.Vpc) {
  // Using the higher-level CDK construct which configures secure defaults
  const role = new iam.Role(scope, 'NotebookRole', {
    assumedBy: new iam.ServicePrincipal('sagemaker.amazonaws.com'),
  });
  
  // ok: typescript_cdk_internet_access_enabled_for_sagemaker_notebook
  new sagemaker.NotebookInstance(scope, 'SecureNotebook15', {
    instanceType: new ec2.InstanceType('ml.t3.medium'),
    role: role,
    vpc: vpc,
    vpcSubnet: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
    directInternetAccess: false,
  });
}
// {/fact}