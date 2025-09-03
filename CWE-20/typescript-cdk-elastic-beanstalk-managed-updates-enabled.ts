import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as elasticbeanstalk from 'aws-cdk-lib/aws-elasticbeanstalk';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as s3deploy from 'aws-cdk-lib/aws-s3-deployment';

// True Positive Examples (Vulnerable Code)

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_1(scope: Construct) {
  // Missing managed updates configuration
  // ruleid: typescript-cdk-elastic-beanstalk-managed-updates-enabled
  new elasticbeanstalk.CfnEnvironment(scope, 'Environment', {
    applicationName: 'MyApp',
    environmentName: 'Production',
    solutionStackName: '64bit Amazon Linux 2 v5.4.9 running Node.js 14',
    optionSettings: [
      {
        namespace: 'aws:autoscaling:launchconfiguration',
        optionName: 'IamInstanceProfile',
        value: 'aws-elasticbeanstalk-ec2-role',
      },
    ],
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_2(scope: Construct) {
  // Empty option settings
  // ruleid: typescript-cdk-elastic-beanstalk-managed-updates-enabled
  new elasticbeanstalk.CfnEnvironment(scope, 'Environment', {
    applicationName: 'MyApp',
    environmentName: 'Staging',
    solutionStackName: '64bit Amazon Linux 2 v5.4.9 running Node.js 14',
    optionSettings: [],
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_3(scope: Construct) {
  // Wrong namespace for managed updates
  // ruleid: typescript-cdk-elastic-beanstalk-managed-updates-enabled
  new elasticbeanstalk.CfnEnvironment(scope, 'Environment', {
    applicationName: 'MyApp',
    environmentName: 'Dev',
    solutionStackName: '64bit Amazon Linux 2 v5.4.9 running Node.js 14',
    optionSettings: [
      {
        namespace: 'aws:autoscaling:launchconfiguration',
        optionName: 'UpdateLevel',
        value: 'minor',
      },
    ],
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_4(scope: Construct) {
  // Wrong option name for managed updates
  // ruleid: typescript-cdk-elastic-beanstalk-managed-updates-enabled
  new elasticbeanstalk.CfnEnvironment(scope, 'Environment', {
    applicationName: 'MyApp',
    environmentName: 'Test',
    solutionStackName: '64bit Amazon Linux 2 v5.4.9 running Node.js 14',
    optionSettings: [
      {
        namespace: 'aws:elasticbeanstalk:managedactions',
        optionName: 'ManagedUpdateLevel',
        value: 'minor',
      },
    ],
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_5(scope: Construct) {
  // Missing UpdateLevel option
  // ruleid: typescript-cdk-elastic-beanstalk-managed-updates-enabled
  new elasticbeanstalk.CfnEnvironment(scope, 'Environment', {
    applicationName: 'MyApp',
    environmentName: 'QA',
    solutionStackName: '64bit Amazon Linux 2 v5.4.9 running Node.js 14',
    optionSettings: [
      {
        namespace: 'aws:elasticbeanstalk:managedactions',
        optionName: 'ManagedActionsEnabled',
        value: 'true',
      },
    ],
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_6(scope: Construct) {
  // Has managed actions but disabled
  // ruleid: typescript-cdk-elastic-beanstalk-managed-updates-enabled
  new elasticbeanstalk.CfnEnvironment(scope, 'Environment', {
    applicationName: 'MyApp',
    environmentName: 'Prod',
    solutionStackName: '64bit Amazon Linux 2 v5.4.9 running Node.js 14',
    optionSettings: [
      {
        namespace: 'aws:elasticbeanstalk:managedactions',
        optionName: 'ManagedActionsEnabled',
        value: 'false',
      },
      {
        namespace: 'aws:elasticbeanstalk:managedactions',
        optionName: 'PreferredStartTime',
        value: 'Tue:09:00',
      },
    ],
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_7(scope: Construct) {
  // Has UpdateLevel but managed actions not enabled
  // ruleid: typescript-cdk-elastic-beanstalk-managed-updates-enabled
  new elasticbeanstalk.CfnEnvironment(scope, 'Environment', {
    applicationName: 'MyApp',
    environmentName: 'Beta',
    solutionStackName: '64bit Amazon Linux 2 v5.4.9 running Node.js 14',
    optionSettings: [
      {
        namespace: 'aws:elasticbeanstalk:managedactions',
        optionName: 'UpdateLevel',
        value: 'minor',
      },
    ],
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_8(scope: Construct) {
  // Using L2 construct but missing managed updates
  // ruleid: typescript-cdk-elastic-beanstalk-managed-updates-enabled
  const appVersionProps = {
    applicationName: 'MyApp',
    sourceBundle: {
      s3Bucket: 'my-bucket',
      s3Key: 'my-app.zip',
    },
  };
  
  const appVersion = new elasticbeanstalk.CfnApplicationVersion(scope, 'AppVersion', appVersionProps);
  
  new elasticbeanstalk.CfnEnvironment(scope, 'Environment', {
    applicationName: 'MyApp',
    versionLabel: appVersion.ref,
    environmentName: 'Alpha',
    solutionStackName: '64bit Amazon Linux 2 v5.4.9 running Node.js 14',
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_9(scope: Construct) {
  // Using variable for option settings but missing managed updates
  // ruleid: typescript-cdk-elastic-beanstalk-managed-updates-enabled
  const optionSettings = [
    {
      namespace: 'aws:autoscaling:launchconfiguration',
      optionName: 'InstanceType',
      value: 't3.micro',
    },
    {
      namespace: 'aws:elasticbeanstalk:environment',
      optionName: 'EnvironmentType',
      value: 'LoadBalanced',
    },
  ];
  
  new elasticbeanstalk.CfnEnvironment(scope, 'Environment', {
    applicationName: 'MyApp',
    environmentName: 'Demo',
    solutionStackName: '64bit Amazon Linux 2 v5.4.9 running Node.js 14',
    optionSettings,
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_10(scope: Construct) {
  // Using incorrect value for UpdateLevel
  // ruleid: typescript-cdk-elastic-beanstalk-managed-updates-enabled
  new elasticbeanstalk.CfnEnvironment(scope, 'Environment', {
    applicationName: 'MyApp',
    environmentName: 'Sandbox',
    solutionStackName: '64bit Amazon Linux 2 v5.4.9 running Node.js 14',
    optionSettings: [
      {
        namespace: 'aws:elasticbeanstalk:managedactions',
        optionName: 'ManagedActionsEnabled',
        value: 'true',
      },
      {
        namespace: 'aws:elasticbeanstalk:managedactions',
        optionName: 'UpdateLevel',
        value: 'none', // Incorrect value
      },
    ],
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_11(scope: Construct) {
  // Using properties object but missing managed updates
  // ruleid: typescript-cdk-elastic-beanstalk-managed-updates-enabled
  const envProps = {
    applicationName: 'MyApp',
    environmentName: 'Integration',
    solutionStackName: '64bit Amazon Linux 2 v5.4.9 running Node.js 14',
    optionSettings: [
      {
        namespace: 'aws:ec2:vpc',
        optionName: 'VPCId',
        value: 'vpc-12345',
      },
    ],
  };
  
  new elasticbeanstalk.CfnEnvironment(scope, 'Environment', envProps);
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_12(scope: Construct) {
  // Using conditional logic but missing managed updates in both branches
  // ruleid: typescript-cdk-elastic-beanstalk-managed-updates-enabled
  const isProd = process.env.ENV === 'prod';
  const optionSettings = isProd ? 
    [
      {
        namespace: 'aws:autoscaling:asg',
        optionName: 'MinSize',
        value: '2',
      },
    ] : 
    [
      {
        namespace: 'aws:autoscaling:asg',
        optionName: 'MinSize',
        value: '1',
      },
    ];
  
  new elasticbeanstalk.CfnEnvironment(scope, 'Environment', {
    applicationName: 'MyApp',
    environmentName: isProd ? 'Production' : 'Development',
    solutionStackName: '64bit Amazon Linux 2 v5.4.9 running Node.js 14',
    optionSettings,
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_13(scope: Construct) {
  // Using array spread but missing managed updates
  // ruleid: typescript-cdk-elastic-beanstalk-managed-updates-enabled
  const baseOptions = [
    {
      namespace: 'aws:autoscaling:launchconfiguration',
      optionName: 'IamInstanceProfile',
      value: 'aws-elasticbeanstalk-ec2-role',
    },
  ];
  
  const additionalOptions = [
    {
      namespace: 'aws:elasticbeanstalk:application:environment',
      optionName: 'NODE_ENV',
      value: 'production',
    },
  ];
  
  new elasticbeanstalk.CfnEnvironment(scope, 'Environment', {
    applicationName: 'MyApp',
    environmentName: 'Gamma',
    solutionStackName: '64bit Amazon Linux 2 v5.4.9 running Node.js 14',
    optionSettings: [...baseOptions, ...additionalOptions],
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_14(scope: Construct) {
  // Using function to generate options but missing managed updates
  // ruleid: typescript-cdk-elastic-beanstalk-managed-updates-enabled
  const getOptions = () => {
    return [
      {
        namespace: 'aws:autoscaling:launchconfiguration',
        optionName: 'InstanceType',
        value: 't3.small',
      },
      {
        namespace: 'aws:elasticbeanstalk:environment',
        optionName: 'ServiceRole',
        value: 'aws-elasticbeanstalk-service-role',
      },
    ];
  };
  
  new elasticbeanstalk.CfnEnvironment(scope, 'Environment', {
    applicationName: 'MyApp',
    environmentName: 'PreProd',
    solutionStackName: '64bit Amazon Linux 2 v5.4.9 running Node.js 14',
    optionSettings: getOptions(),
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_15(scope: Construct) {
  // Using object destructuring but missing managed updates
  // ruleid: typescript-cdk-elastic-beanstalk-managed-updates-enabled
  const config = {
    appName: 'MyApp',
    envName: 'UAT',
    stack: '64bit Amazon Linux 2 v5.4.9 running Node.js 14',
    options: [
      {
        namespace: 'aws:elasticbeanstalk:application:environment',
        optionName: 'API_URL',
        value: 'https://api.example.com',
      },
    ],
  };
  
  const { appName, envName, stack, options } = config;
  
  new elasticbeanstalk.CfnEnvironment(scope, 'Environment', {
    applicationName: appName,
    environmentName: envName,
    solutionStackName: stack,
    optionSettings: options,
  });
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_1(scope: Construct) {
  // Properly configured managed updates with minor level
  // ok: typescript-cdk-elastic-beanstalk-managed-updates-enabled
  new elasticbeanstalk.CfnEnvironment(scope, 'Environment', {
    applicationName: 'MyApp',
    environmentName: 'Production',
    solutionStackName: '64bit Amazon Linux 2 v5.4.9 running Node.js 14',
    optionSettings: [
      {
        namespace: 'aws:elasticbeanstalk:managedactions',
        optionName: 'ManagedActionsEnabled',
        value: 'true',
      },
      {
        namespace: 'aws:elasticbeanstalk:managedactions',
        optionName: 'UpdateLevel',
        value: 'minor',
      },
    ],
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_2(scope: Construct) {
  // Properly configured managed updates with patch level
  // ok: typescript-cdk-elastic-beanstalk-managed-updates-enabled
  new elasticbeanstalk.CfnEnvironment(scope, 'Environment', {
    applicationName: 'MyApp',
    environmentName: 'Staging',
    solutionStackName: '64bit Amazon Linux 2 v5.4.9 running Node.js 14',
    optionSettings: [
      {
        namespace: 'aws:elasticbeanstalk:managedactions',
        optionName: 'ManagedActionsEnabled',
        value: 'true',
      },
      {
        namespace: 'aws:elasticbeanstalk:managedactions',
        optionName: 'UpdateLevel',
        value: 'patch',
      },
    ],
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_3(scope: Construct) {
  // Properly configured managed updates with additional settings
  // ok: typescript-cdk-elastic-beanstalk-managed-updates-enabled
  new elasticbeanstalk.CfnEnvironment(scope, 'Environment', {
    applicationName: 'MyApp',
    environmentName: 'Dev',
    solutionStackName: '64bit Amazon Linux 2 v5.4.9 running Node.js 14',
    optionSettings: [
      {
        namespace: 'aws:elasticbeanstalk:managedactions',
        optionName: 'ManagedActionsEnabled',
        value: 'true',
      },
      {
        namespace: 'aws:elasticbeanstalk:managedactions',
        optionName: 'UpdateLevel',
        value: 'minor',
      },
      {
        namespace: 'aws:elasticbeanstalk:managedactions',
        optionName: 'PreferredStartTime',
        value: 'Sun:02:00',
      },
      {
        namespace: 'aws:autoscaling:launchconfiguration',
        optionName: 'IamInstanceProfile',
        value: 'aws-elasticbeanstalk-ec2-role',
      },
    ],
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_4(scope: Construct) {
  // Using variables but properly configuring managed updates
  // ok: typescript-cdk-elastic-beanstalk-managed-updates-enabled
  const optionSettings = [
    {
      namespace: 'aws:elasticbeanstalk:managedactions',
      optionName: 'ManagedActionsEnabled',
      value: 'true',
    },
    {
      namespace: 'aws:elasticbeanstalk:managedactions',
      optionName: 'UpdateLevel',
      value: 'minor',
    },
    {
      namespace: 'aws:autoscaling:launchconfiguration',
      optionName: 'InstanceType',
      value: 't3.micro',
    },
  ];
  
  new elasticbeanstalk.CfnEnvironment(scope, 'Environment', {
    applicationName: 'MyApp',
    environmentName: 'Test',
    solutionStackName: '64bit Amazon Linux 2 v5.4.9 running Node.js 14',
    optionSettings,
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_5(scope: Construct) {
  // Using L2 construct with properly configured managed updates
  // ok: typescript-cdk-elastic-beanstalk-managed-updates-enabled
  const appVersionProps = {
    applicationName: 'MyApp',
    sourceBundle: {
      s3Bucket: 'my-bucket',
      s3Key: 'my-app.zip',
    },
  };
  
  const appVersion = new elasticbeanstalk.CfnApplicationVersion(scope, 'AppVersion', appVersionProps);
  
  new elasticbeanstalk.CfnEnvironment(scope, 'Environment', {
    applicationName: 'MyApp',
    versionLabel: appVersion.ref,
    environmentName: 'QA',
    solutionStackName: '64bit Amazon Linux 2 v5.4.9 running Node.js 14',
    optionSettings: [
      {
        namespace: 'aws:elasticbeanstalk:managedactions',
        optionName: 'ManagedActionsEnabled',
        value: 'true',
      },
      {
        namespace: 'aws:elasticbeanstalk:managedactions',
        optionName: 'UpdateLevel',
        value: 'minor',
      },
    ],
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_6(scope: Construct) {
  // Using conditional logic with properly configured managed updates in both branches
  // ok: typescript-cdk-elastic-beanstalk-managed-updates-enabled
  const isProd = process.env.ENV === 'prod';
  const optionSettings = isProd ? 
    [
      {
        namespace: 'aws:elasticbeanstalk:managedactions',
        optionName: 'ManagedActionsEnabled',
        value: 'true',
      },
      {
        namespace: 'aws:elasticbeanstalk:managedactions',
        optionName: 'UpdateLevel',
        value: 'minor',
      },
      {
        namespace: 'aws:autoscaling:asg',
        optionName: 'MinSize',
        value: '2',
      },
    ] : 
    [
      {
        namespace: 'aws:elasticbeanstalk:managedactions',
        optionName: 'ManagedActionsEnabled',
        value: 'true',
      },
      {
        namespace: 'aws:elasticbeanstalk:managedactions',
        optionName: 'UpdateLevel',
        value: 'patch',
      },
      {
        namespace: 'aws:autoscaling:asg',
        optionName: 'MinSize',
        value: '1',
      },
    ];
  
  new elasticbeanstalk.CfnEnvironment(scope, 'Environment', {
    applicationName: 'MyApp',
    environmentName: isProd ? 'Production' : 'Development',
    solutionStackName: '64bit Amazon Linux 2 v5.4.9 running Node.js 14',
    optionSettings,
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_7(scope: Construct) {
  // Using array spread with properly configured managed updates
  // ok: typescript-cdk-elastic-beanstalk-managed-updates-enabled
  const baseOptions = [
    {
      namespace: 'aws:elasticbeanstalk:managedactions',
      optionName: 'ManagedActionsEnabled',
      value: 'true',
    },
    {
      namespace: 'aws:elasticbeanstalk:managedactions',
      optionName: 'UpdateLevel',
      value: 'minor',
    },
  ];
  
  const additionalOptions = [
    {
      namespace: 'aws:elasticbeanstalk:application:environment',
      optionName: 'NODE_ENV',
      value: 'production',
    },
  ];
  
  new elasticbeanstalk.CfnEnvironment(scope, 'Environment', {
    applicationName: 'MyApp',
    environmentName: 'Prod',
    solutionStackName: '64bit Amazon Linux 2 v5.4.9 running Node.js 14',
    optionSettings: [...baseOptions, ...additionalOptions],
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_8(scope: Construct) {
  // Using function to generate options with properly configured managed updates
  // ok: typescript-cdk-elastic-beanstalk-managed-updates-enabled
  const getOptions = () => {
    return [
      {
        namespace: 'aws:elasticbeanstalk:managedactions',
        optionName: 'ManagedActionsEnabled',
        value: 'true',
      },
      {
        namespace: 'aws:elasticbeanstalk:managedactions',
        optionName: 'UpdateLevel',
        value: 'minor',
      },
      {
        namespace: 'aws:autoscaling:launchconfiguration',
        optionName: 'InstanceType',
        value: 't3.small',
      },
    ];
  };
  
  new elasticbeanstalk.CfnEnvironment(scope, 'Environment', {
    applicationName: 'MyApp',
    environmentName: 'Beta',
    solutionStackName: '64bit Amazon Linux 2 v5.4.9 running Node.js 14',
    optionSettings: getOptions(),
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_9(scope: Construct) {
  // Using object destructuring with properly configured managed updates
  // ok: typescript-cdk-elastic-beanstalk-managed-updates-enabled
  const config = {
    appName: 'MyApp',
    envName: 'Alpha',
    stack: '64bit Amazon Linux 2 v5.4.9 running Node.js 14',
    options: [
      {
        namespace: 'aws:elasticbeanstalk:managedactions',
        optionName: 'ManagedActionsEnabled',
        value: 'true',
      },
      {
        namespace: 'aws:elasticbeanstalk:managedactions',
        optionName: 'UpdateLevel',
        value: 'minor',
      },
      {
        namespace: 'aws:elasticbeanstalk:application:environment',
        optionName: 'API_URL',
        value: 'https://api.example.com',
      },
    ],
  };
  
  const { appName, envName, stack, options } = config;
  
  new elasticbeanstalk.CfnEnvironment(scope, 'Environment', {
    applicationName: appName,
    environmentName: envName,
    solutionStackName: stack,
    optionSettings: options,
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_10(scope: Construct) {
  // Using managed updates with preferred start time
  // ok: typescript-cdk-elastic-beanstalk-managed-updates-enabled
  new elasticbeanstalk.CfnEnvironment(scope, 'Environment', {
    applicationName: 'MyApp',
    environmentName: 'Demo',
    solutionStackName: '64bit Amazon Linux 2 v5.4.9 running Node.js 14',
    optionSettings: [
      {
        namespace: 'aws:elasticbeanstalk:managedactions',
        optionName: 'ManagedActionsEnabled',
        value: 'true',
      },
      {
        namespace: 'aws:elasticbeanstalk:managedactions',
        optionName: 'PreferredStartTime',
        value: 'Mon:03:00',
      },
      {
        namespace: 'aws:elasticbeanstalk:managedactions',
        optionName: 'UpdateLevel',
        value: 'minor',
      },
    ],
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_11(scope: Construct) {
  // Using managed updates with instance refresh enabled
  // ok: typescript-cdk-elastic-beanstalk-managed-updates-enabled
  new elasticbeanstalk.CfnEnvironment(scope, 'Environment', {
    applicationName: 'MyApp',
    environmentName: 'Sandbox',
    solutionStackName: '64bit Amazon Linux 2 v5.4.9 running Node.js 14',
    optionSettings: [
      {
        namespace: 'aws:elasticbeanstalk:managedactions',
        optionName: 'ManagedActionsEnabled',
        value: 'true',
      },
      {
        namespace: 'aws:elasticbeanstalk:managedactions',
        optionName: 'UpdateLevel',
        value: 'minor',
      },
      {
        namespace: 'aws:elasticbeanstalk:managedactions:platformupdate',
        optionName: 'InstanceRefreshEnabled',
        value: 'true',
      },
    ],
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_12(scope: Construct) {
  // Using properties object with properly configured managed updates
  // ok: typescript-cdk-elastic-beanstalk-managed-updates-enabled
  const envProps = {
    applicationName: 'MyApp',
    environmentName: 'Integration',
    solutionStackName: '64bit Amazon Linux 2 v5.4.9 running Node.js 14',
    optionSettings: [
      {
        namespace: 'aws:elasticbeanstalk:managedactions',
        optionName: 'ManagedActionsEnabled',
        value: 'true',
      },
      {
        namespace: 'aws:elasticbeanstalk:managedactions',
        optionName: 'UpdateLevel',
        value: 'minor',
      },
      {
        namespace: 'aws:ec2:vpc',
        optionName: 'VPCId',
        value: 'vpc-12345',
      },
    ],
  };
  
  new elasticbeanstalk.CfnEnvironment(scope, 'Environment', envProps);
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_13(scope: Construct) {
  // Using managed updates with multiple environment settings
  // ok: typescript-cdk-elastic-beanstalk-managed-updates-enabled
  new elasticbeanstalk.CfnEnvironment(scope, 'Environment', {
    applicationName: 'MyApp',
    environmentName: 'PreProd',
    solutionStackName: '64bit Amazon Linux 2 v5.4.9 running Node.js 14',
    optionSettings: [
      {
        namespace: 'aws:elasticbeanstalk:managedactions',
        optionName: 'ManagedActionsEnabled',
        value: 'true',
      },
      {
        namespace: 'aws:elasticbeanstalk:managedactions',
        optionName: 'UpdateLevel',
        value: 'minor',
      },
      {
        namespace: 'aws:elasticbeanstalk:environment',
        optionName: 'EnvironmentType',
        value: 'LoadBalanced',
      },
      {
        namespace: 'aws:autoscaling:asg',
        optionName: 'MinSize',
        value: '2',
      },
      {
        namespace: 'aws:autoscaling:asg',
        optionName: 'MaxSize',
        value: '6',
      },
    ],
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_14(scope: Construct) {
  // Using managed updates with application version deployment
  // ok: typescript-cdk-elastic-beanstalk-managed-updates-enabled
  const bucket = new s3.Bucket(scope, 'DeploymentBucket');
  
  const deployment = new s3deploy.BucketDeployment(scope, 'DeployApp', {
    sources: [s3deploy.Source.asset('./app')],
    destinationBucket: bucket,
    destinationKeyPrefix: 'app-versions',
  });
  
  new elasticbeanstalk.CfnEnvironment(scope, 'Environment', {
    applicationName: 'MyApp',
    environmentName: 'UAT',
    solutionStackName: '64bit Amazon Linux 2 v5.4.9 running Node.js 14',
    versionLabel: 'v1.0.0',
    optionSettings: [
      {
        namespace: 'aws:elasticbeanstalk:managedactions',
        optionName: 'ManagedActionsEnabled',
        value: 'true',
      },
      {
        namespace: 'aws:elasticbeanstalk:managedactions',
        optionName: 'UpdateLevel',
        value: 'minor',
      },
    ],
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_15(scope: Construct) {
  // Using managed updates with dynamic configuration
  // ok: typescript-cdk-elastic-beanstalk-managed-updates-enabled
  const updateLevel = process.env.UPDATE_LEVEL || 'minor';
  const managedActionsEnabled = process.env.MANAGED_ACTIONS_ENABLED || 'true';
  
  new elasticbeanstalk.CfnEnvironment(scope, 'Environment', {
    applicationName: 'MyApp',
    environmentName: 'Gamma',
    solutionStackName: '64bit Amazon Linux 2 v5.4.9 running Node.js 14',
    optionSettings: [
      {
        namespace: 'aws:elasticbeanstalk:managedactions',
        optionName: 'ManagedActionsEnabled',
        value: managedActionsEnabled,
      },
      {
        namespace: 'aws:elasticbeanstalk:managedactions',
        optionName: 'UpdateLevel',
        value: updateLevel,
      },
    ],
  });
}
// {/fact}