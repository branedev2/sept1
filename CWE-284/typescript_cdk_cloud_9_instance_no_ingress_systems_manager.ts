import * as cdk from 'aws-cdk-lib';
import * as cloud9 from 'aws-cdk-lib/aws-cloud9';
import { Construct } from 'constructs';

// True Positive Examples (Vulnerable Code)

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_1(scope: Construct) {
  // Creating a Cloud9 environment without specifying connectionType
  // ruleid: typescript_cdk_cloud_9_instance_no_ingress_systems_manager
  new cloud9.CfnEnvironmentEC2(scope, 'Cloud9Env1', {
    instanceType: 't3.small',
    automaticStopTimeMinutes: 30,
    name: 'DevEnvironment',
  });
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_2(scope: Construct) {
  // Creating a Cloud9 environment with explicit SSH connection type
  // ruleid: typescript_cdk_cloud_9_instance_no_ingress_systems_manager
  new cloud9.CfnEnvironmentEC2(scope, 'Cloud9Env2', {
    instanceType: 't3.medium',
    automaticStopTimeMinutes: 60,
    name: 'TestEnvironment',
    connectionType: 'CONNECT_SSH',
  });
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_3(scope: Construct) {
  // Creating a Cloud9 environment with properties defined in a variable
  const envProps = {
    instanceType: 't2.micro',
    automaticStopTimeMinutes: 30,
    name: 'DevEnv',
  };
  
  // ruleid: typescript_cdk_cloud_9_instance_no_ingress_systems_manager
  new cloud9.CfnEnvironmentEC2(scope, 'Cloud9Env3', envProps);
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_4(scope: Construct) {
  // Creating a Cloud9 environment with properties spread from another object
  const baseProps = {
    instanceType: 't3.large',
    automaticStopTimeMinutes: 120,
  };
  
  // ruleid: typescript_cdk_cloud_9_instance_no_ingress_systems_manager
  new cloud9.CfnEnvironmentEC2(scope, 'Cloud9Env4', {
    ...baseProps,
    name: 'ProdEnvironment',
  });
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_5(scope: Construct) {
  // Creating a Cloud9 environment with conditional properties
  const isProduction = process.env.ENV === 'production';
  
  // ruleid: typescript_cdk_cloud_9_instance_no_ingress_systems_manager
  new cloud9.CfnEnvironmentEC2(scope, 'Cloud9Env5', {
    instanceType: isProduction ? 't3.large' : 't3.small',
    automaticStopTimeMinutes: isProduction ? 60 : 30,
    name: `${isProduction ? 'Prod' : 'Dev'}Environment`,
  });
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_6(scope: Construct) {
  // Creating multiple Cloud9 environments in a loop
  const environments = ['dev', 'test', 'staging'];
  
  environments.forEach((env, index) => {
    // ruleid: typescript_cdk_cloud_9_instance_no_ingress_systems_manager
    new cloud9.CfnEnvironmentEC2(scope, `Cloud9Env${index + 6}`, {
      instanceType: 't3.small',
      automaticStopTimeMinutes: 30,
      name: `${env.charAt(0).toUpperCase() + env.slice(1)}Environment`,
    });
  });
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_7(scope: Construct, props: any) {
  // Creating a Cloud9 environment with dynamic properties
  const instanceSize = props.size || 'small';
  const instanceMap: Record<string, string> = {
    small: 't3.small',
    medium: 't3.medium',
    large: 't3.large'
  };
  
  // ruleid: typescript_cdk_cloud_9_instance_no_ingress_systems_manager
  new cloud9.CfnEnvironmentEC2(scope, 'Cloud9Env7', {
    instanceType: instanceMap[instanceSize],
    automaticStopTimeMinutes: props.timeout || 30,
    name: props.name || 'DefaultEnvironment',
  });
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_8(scope: Construct) {
  // Creating a Cloud9 environment with a wrong connection type value
  // ruleid: typescript_cdk_cloud_9_instance_no_ingress_systems_manager
  new cloud9.CfnEnvironmentEC2(scope, 'Cloud9Env8', {
    instanceType: 't3.small',
    automaticStopTimeMinutes: 30,
    name: 'DevEnvironment',
    connectionType: 'SSH', // Incorrect value
  });
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_9(scope: Construct) {
  // Creating a Cloud9 environment with empty string connection type
  // ruleid: typescript_cdk_cloud_9_instance_no_ingress_systems_manager
  new cloud9.CfnEnvironmentEC2(scope, 'Cloud9Env9', {
    instanceType: 't3.small',
    automaticStopTimeMinutes: 30,
    name: 'DevEnvironment',
    connectionType: '',
  });
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_10(scope: Construct) {
  // Creating a Cloud9 environment with null connection type
  const connectionType = null;
  
  // ruleid: typescript_cdk_cloud_9_instance_no_ingress_systems_manager
  new cloud9.CfnEnvironmentEC2(scope, 'Cloud9Env10', {
    instanceType: 't3.small',
    automaticStopTimeMinutes: 30,
    name: 'DevEnvironment',
    connectionType,
  });
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_11(scope: Construct) {
  // Creating a Cloud9 environment with undefined connection type
  let connectionType: string | undefined;
  
  // ruleid: typescript_cdk_cloud_9_instance_no_ingress_systems_manager
  new cloud9.CfnEnvironmentEC2(scope, 'Cloud9Env11', {
    instanceType: 't3.small',
    automaticStopTimeMinutes: 30,
    name: 'DevEnvironment',
    connectionType,
  });
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_12(scope: Construct) {
  // Creating a Cloud9 environment with a function that returns non-SSM connection type
  const getConnectionType = () => {
    return 'CONNECT_SSH';
  };
  
  // ruleid: typescript_cdk_cloud_9_instance_no_ingress_systems_manager
  new cloud9.CfnEnvironmentEC2(scope, 'Cloud9Env12', {
    instanceType: 't3.small',
    automaticStopTimeMinutes: 30,
    name: 'DevEnvironment',
    connectionType: getConnectionType(),
  });
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_13(scope: Construct) {
  // Creating a Cloud9 environment with a ternary that could result in non-SSM connection
  const useSSM = false;
  
  // ruleid: typescript_cdk_cloud_9_instance_no_ingress_systems_manager
  new cloud9.CfnEnvironmentEC2(scope, 'Cloud9Env13', {
    instanceType: 't3.small',
    automaticStopTimeMinutes: 30,
    name: 'DevEnvironment',
    connectionType: useSSM ? 'CONNECT_SSM' : 'CONNECT_SSH',
  });
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_14(scope: Construct) {
  // Creating a Cloud9 environment with a variable that might be overridden
  let connectionType = 'CONNECT_SSM';
  
  // Simulating some logic that changes the connection type
  if (process.env.ALLOW_SSH === 'true') {
    connectionType = 'CONNECT_SSH';
  }
  
  // ruleid: typescript_cdk_cloud_9_instance_no_ingress_systems_manager
  new cloud9.CfnEnvironmentEC2(scope, 'Cloud9Env14', {
    instanceType: 't3.small',
    automaticStopTimeMinutes: 30,
    name: 'DevEnvironment',
    connectionType,
  });
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_15(scope: Construct) {
  // Creating a Cloud9 environment with properties from a function
  const getEnvironmentProps = () => {
    return {
      instanceType: 't3.small',
      automaticStopTimeMinutes: 30,
      name: 'FunctionGeneratedEnvironment',
      // No connectionType specified
    };
  };
  
  // ruleid: typescript_cdk_cloud_9_instance_no_ingress_systems_manager
  new cloud9.CfnEnvironmentEC2(scope, 'Cloud9Env15', getEnvironmentProps());
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_1(scope: Construct) {
  // Creating a Cloud9 environment with SSM connection type
  // ok: typescript_cdk_cloud_9_instance_no_ingress_systems_manager
  new cloud9.CfnEnvironmentEC2(scope, 'Cloud9Env16', {
    instanceType: 't3.small',
    automaticStopTimeMinutes: 30,
    name: 'DevEnvironment',
    connectionType: 'CONNECT_SSM',
  });
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_2(scope: Construct) {
  // Creating a Cloud9 environment with properties defined in a variable including SSM
  const envProps = {
    instanceType: 't2.micro',
    automaticStopTimeMinutes: 30,
    name: 'DevEnv',
    connectionType: 'CONNECT_SSM',
  };
  
  // ok: typescript_cdk_cloud_9_instance_no_ingress_systems_manager
  new cloud9.CfnEnvironmentEC2(scope, 'Cloud9Env17', envProps);
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_3(scope: Construct) {
  // Creating a Cloud9 environment with properties spread from another object
  const baseProps = {
    instanceType: 't3.large',
    automaticStopTimeMinutes: 120,
  };
  
  // ok: typescript_cdk_cloud_9_instance_no_ingress_systems_manager
  new cloud9.CfnEnvironmentEC2(scope, 'Cloud9Env18', {
    ...baseProps,
    name: 'ProdEnvironment',
    connectionType: 'CONNECT_SSM',
  });
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_4(scope: Construct) {
  // Creating a Cloud9 environment with conditional properties but always SSM
  const isProduction = process.env.ENV === 'production';
  
  // ok: typescript_cdk_cloud_9_instance_no_ingress_systems_manager
  new cloud9.CfnEnvironmentEC2(scope, 'Cloud9Env19', {
    instanceType: isProduction ? 't3.large' : 't3.small',
    automaticStopTimeMinutes: isProduction ? 60 : 30,
    name: `${isProduction ? 'Prod' : 'Dev'}Environment`,
    connectionType: 'CONNECT_SSM',
  });
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_5(scope: Construct) {
  // Creating multiple Cloud9 environments in a loop with SSM
  const environments = ['dev', 'test', 'staging'];
  
  environments.forEach((env, index) => {
    // ok: typescript_cdk_cloud_9_instance_no_ingress_systems_manager
    new cloud9.CfnEnvironmentEC2(scope, `Cloud9Env${index + 20}`, {
      instanceType: 't3.small',
      automaticStopTimeMinutes: 30,
      name: `${env.charAt(0).toUpperCase() + env.slice(1)}Environment`,
      connectionType: 'CONNECT_SSM',
    });
  });
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_6(scope: Construct, props: any) {
  // Creating a Cloud9 environment with dynamic properties but fixed SSM
  const instanceSize = props.size || 'small';
  const instanceMap: Record<string, string> = {
    small: 't3.small',
    medium: 't3.medium',
    large: 't3.large'
  };
  
  // ok: typescript_cdk_cloud_9_instance_no_ingress_systems_manager
  new cloud9.CfnEnvironmentEC2(scope, 'Cloud9Env21', {
    instanceType: instanceMap[instanceSize],
    automaticStopTimeMinutes: props.timeout || 30,
    name: props.name || 'DefaultEnvironment',
    connectionType: 'CONNECT_SSM',
  });
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_7(scope: Construct) {
  // Creating a Cloud9 environment with a constant for connection type
  const SSM_CONNECTION = 'CONNECT_SSM';
  
  // ok: typescript_cdk_cloud_9_instance_no_ingress_systems_manager
  new cloud9.CfnEnvironmentEC2(scope, 'Cloud9Env22', {
    instanceType: 't3.small',
    automaticStopTimeMinutes: 30,
    name: 'DevEnvironment',
    connectionType: SSM_CONNECTION,
  });
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_8(scope: Construct) {
  // Creating a Cloud9 environment with a function that always returns SSM
  const getSecureConnectionType = () => {
    return 'CONNECT_SSM';
  };
  
  // ok: typescript_cdk_cloud_9_instance_no_ingress_systems_manager
  new cloud9.CfnEnvironmentEC2(scope, 'Cloud9Env23', {
    instanceType: 't3.small',
    automaticStopTimeMinutes: 30,
    name: 'DevEnvironment',
    connectionType: getSecureConnectionType(),
  });
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_9(scope: Construct) {
  // Creating a Cloud9 environment with a ternary that always results in SSM
  const useStrictSecurity = true;
  
  // ok: typescript_cdk_cloud_9_instance_no_ingress_systems_manager
  new cloud9.CfnEnvironmentEC2(scope, 'Cloud9Env24', {
    instanceType: 't3.small',
    automaticStopTimeMinutes: 30,
    name: 'DevEnvironment',
    connectionType: useStrictSecurity ? 'CONNECT_SSM' : 'CONNECT_SSM',
  });
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_10(scope: Construct) {
  // Creating a Cloud9 environment with properties from a function that includes SSM
  const getSecureEnvironmentProps = () => {
    return {
      instanceType: 't3.small',
      automaticStopTimeMinutes: 30,
      name: 'FunctionGeneratedEnvironment',
      connectionType: 'CONNECT_SSM',
    };
  };
  
  // ok: typescript_cdk_cloud_9_instance_no_ingress_systems_manager
  new cloud9.CfnEnvironmentEC2(scope, 'Cloud9Env25', getSecureEnvironmentProps());
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_11(scope: Construct) {
  // Creating a Cloud9 environment with a variable that is guaranteed to be SSM
  let connectionType = 'CONNECT_SSM';
  
  // This won't change the connection type
  if (process.env.ALLOW_SSH === 'true') {
    console.log('SSH requested but using SSM for security');
  }
  
  // ok: typescript_cdk_cloud_9_instance_no_ingress_systems_manager
  new cloud9.CfnEnvironmentEC2(scope, 'Cloud9Env26', {
    instanceType: 't3.small',
    automaticStopTimeMinutes: 30,
    name: 'DevEnvironment',
    connectionType,
  });
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_12(scope: Construct) {
  // Creating a Cloud9 environment with connection type from environment variable with fallback to SSM
  const connectionType = process.env.CONNECTION_TYPE === 'CONNECT_SSM' 
    ? process.env.CONNECTION_TYPE 
    : 'CONNECT_SSM';
  
  // ok: typescript_cdk_cloud_9_instance_no_ingress_systems_manager
  new cloud9.CfnEnvironmentEC2(scope, 'Cloud9Env27', {
    instanceType: 't3.small',
    automaticStopTimeMinutes: 30,
    name: 'DevEnvironment',
    connectionType,
  });
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_13(scope: Construct) {
  // Creating a Cloud9 environment with SSM connection type and additional tags
  // ok: typescript_cdk_cloud_9_instance_no_ingress_systems_manager
  new cloud9.CfnEnvironmentEC2(scope, 'Cloud9Env28', {
    instanceType: 't3.small',
    automaticStopTimeMinutes: 30,
    name: 'DevEnvironment',
    connectionType: 'CONNECT_SSM',
    tags: [
      {
        key: 'Environment',
        value: 'Development'
      },
      {
        key: 'Owner',
        value: 'DevOps'
      }
    ]
  });
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_14(scope: Construct) {
  // Creating a Cloud9 environment with SSM connection type and subnet configuration
  // ok: typescript_cdk_cloud_9_instance_no_ingress_systems_manager
  new cloud9.CfnEnvironmentEC2(scope, 'Cloud9Env29', {
    instanceType: 't3.small',
    automaticStopTimeMinutes: 30,
    name: 'DevEnvironment',
    connectionType: 'CONNECT_SSM',
    subnetId: 'subnet-12345678',
  });
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_15(scope: Construct) {
  // Creating a Cloud9 environment with SSM connection type and owner ARN
  // ok: typescript_cdk_cloud_9_instance_no_ingress_systems_manager
  new cloud9.CfnEnvironmentEC2(scope, 'Cloud9Env30', {
    instanceType: 't3.small',
    automaticStopTimeMinutes: 30,
    name: 'DevEnvironment',
    connectionType: 'CONNECT_SSM',
    ownerArn: 'arn:aws:iam::123456789012:user/developer',
  });
}
// {/fact}