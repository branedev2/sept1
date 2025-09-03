import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as cognito from 'aws-cdk-lib/aws-cognito';

// True Positives (Vulnerable Code)

// {fact rule=secure-design-principles-violation@v1.0 defects=1}
function bad_case_1(scope: Construct) {
  // Basic case: Creating a user pool with advancedSecurityMode explicitly set to OFF
  // ruleid: typescript_cdk_cognito_user_pool_advanced_security_mode_enforced
  new cognito.CfnUserPool(scope, 'UserPool1', {
    userPoolName: 'my-user-pool',
    userPoolAddOns: {
      advancedSecurityMode: 'OFF'
    }
  });
}
// {/fact}

// {fact rule=secure-design-principles-violation@v1.0 defects=1}
function bad_case_2(scope: Construct) {
  // Using a variable to set the mode to OFF
  const securityMode = 'OFF';
  
  // ruleid: typescript_cdk_cognito_user_pool_advanced_security_mode_enforced
  new cognito.CfnUserPool(scope, 'UserPool2', {
    userPoolName: 'my-user-pool',
    userPoolAddOns: {
      advancedSecurityMode: securityMode
    }
  });
}
// {/fact}

// {fact rule=secure-design-principles-violation@v1.0 defects=1}
function bad_case_3(scope: Construct) {
  // Using an object to define the user pool properties
  const userPoolProps = {
    userPoolName: 'my-user-pool',
    userPoolAddOns: {
      advancedSecurityMode: 'OFF'
    }
  };
  
  // ruleid: typescript_cdk_cognito_user_pool_advanced_security_mode_enforced
  new cognito.CfnUserPool(scope, 'UserPool3', userPoolProps);
}
// {/fact}

// {fact rule=secure-design-principles-violation@v1.0 defects=1}
function bad_case_4(scope: Construct) {
  // Using a function that returns OFF
  const getSecurityMode = () => 'OFF';
  
  // ruleid: typescript_cdk_cognito_user_pool_advanced_security_mode_enforced
  new cognito.CfnUserPool(scope, 'UserPool4', {
    userPoolName: 'my-user-pool',
    userPoolAddOns: {
      advancedSecurityMode: getSecurityMode()
    }
  });
}
// {/fact}

// {fact rule=secure-design-principles-violation@v1.0 defects=1}
function bad_case_5(scope: Construct) {
  // Using a conditional expression that evaluates to OFF
  const isProduction = false;
  
  // ruleid: typescript_cdk_cognito_user_pool_advanced_security_mode_enforced
  new cognito.CfnUserPool(scope, 'UserPool5', {
    userPoolName: 'my-user-pool',
    userPoolAddOns: {
      advancedSecurityMode: isProduction ? 'ENFORCED' : 'OFF'
    }
  });
}
// {/fact}

// {fact rule=secure-design-principles-violation@v1.0 defects=1}
function bad_case_6(scope: Construct) {
  // Using string concatenation that results in OFF
  const securityMode = 'O' + 'F' + 'F';
  
  // ruleid: typescript_cdk_cognito_user_pool_advanced_security_mode_enforced
  new cognito.CfnUserPool(scope, 'UserPool6', {
    userPoolName: 'my-user-pool',
    userPoolAddOns: {
      advancedSecurityMode: securityMode
    }
  });
}
// {/fact}

// {fact rule=secure-design-principles-violation@v1.0 defects=1}
function bad_case_7(scope: Construct, config: any) {
  // Using a configuration object with a default value of OFF
  const securityMode = config?.securityMode || 'OFF';
  
  // ruleid: typescript_cdk_cognito_user_pool_advanced_security_mode_enforced
  new cognito.CfnUserPool(scope, 'UserPool7', {
    userPoolName: 'my-user-pool',
    userPoolAddOns: {
      advancedSecurityMode: securityMode
    }
  });
}
// {/fact}

// {fact rule=secure-design-principles-violation@v1.0 defects=1}
function bad_case_8(scope: Construct) {
  // Creating multiple user pools with one having advancedSecurityMode set to OFF
  new cognito.CfnUserPool(scope, 'SecureUserPool', {
    userPoolName: 'secure-user-pool',
    userPoolAddOns: {
      advancedSecurityMode: 'ENFORCED'
    }
  });
  
  // ruleid: typescript_cdk_cognito_user_pool_advanced_security_mode_enforced
  new cognito.CfnUserPool(scope, 'InsecureUserPool', {
    userPoolName: 'insecure-user-pool',
    userPoolAddOns: {
      advancedSecurityMode: 'OFF'
    }
  });
}
// {/fact}

// {fact rule=secure-design-principles-violation@v1.0 defects=1}
function bad_case_9(scope: Construct) {
  // Using an array of modes and selecting OFF
  const modes = ['ENFORCED', 'AUDIT', 'OFF'];
  
  // ruleid: typescript_cdk_cognito_user_pool_advanced_security_mode_enforced
  new cognito.CfnUserPool(scope, 'UserPool9', {
    userPoolName: 'my-user-pool',
    userPoolAddOns: {
      advancedSecurityMode: modes[2] // OFF
    }
  });
}
// {/fact}

// {fact rule=secure-design-principles-violation@v1.0 defects=1}
function bad_case_10(scope: Construct) {
  // Using a switch statement that results in OFF
  const environment = 'dev';
  let securityMode: string;
  
  switch (environment) {
    case 'prod':
      securityMode = 'ENFORCED';
      break;
    case 'staging':
      securityMode = 'AUDIT';
      break;
    default:
      securityMode = 'OFF';
      break;
  }
  
  // ruleid: typescript_cdk_cognito_user_pool_advanced_security_mode_enforced
  new cognito.CfnUserPool(scope, 'UserPool10', {
    userPoolName: 'my-user-pool',
    userPoolAddOns: {
      advancedSecurityMode: securityMode
    }
  });
}
// {/fact}

// {fact rule=secure-design-principles-violation@v1.0 defects=1}
function bad_case_11(scope: Construct) {
  // Using a map to get the security mode
  const securityModes = new Map<string, string>();
  securityModes.set('prod', 'ENFORCED');
  securityModes.set('dev', 'OFF');
  
  const environment = 'dev';
  
  // ruleid: typescript_cdk_cognito_user_pool_advanced_security_mode_enforced
  new cognito.CfnUserPool(scope, 'UserPool11', {
    userPoolName: 'my-user-pool',
    userPoolAddOns: {
      advancedSecurityMode: securityModes.get(environment)
    }
  });
}
// {/fact}

// {fact rule=secure-design-principles-violation@v1.0 defects=1}
function bad_case_12(scope: Construct) {
  // Using a helper function to create the user pool with OFF mode
  function createUserPool(name: string, mode: string) {
    return new cognito.CfnUserPool(scope, name, {
      userPoolName: name,
      userPoolAddOns: {
        advancedSecurityMode: mode
      }
    });
  }
  
  // ruleid: typescript_cdk_cognito_user_pool_advanced_security_mode_enforced
  createUserPool('UserPool12', 'OFF');
}
// {/fact}

// {fact rule=secure-design-principles-violation@v1.0 defects=1}
function bad_case_13(scope: Construct) {
  // Using destructuring to set properties
  const poolConfig = {
    name: 'my-user-pool',
    securityMode: 'OFF'
  };
  
  const { name, securityMode } = poolConfig;
  
  // ruleid: typescript_cdk_cognito_user_pool_advanced_security_mode_enforced
  new cognito.CfnUserPool(scope, 'UserPool13', {
    userPoolName: name,
    userPoolAddOns: {
      advancedSecurityMode: securityMode
    }
  });
}
// {/fact}

// {fact rule=secure-design-principles-violation@v1.0 defects=1}
function bad_case_14(scope: Construct) {
  // Using a class to create user pools
  class UserPoolCreator {
    private scope: Construct;
    
    constructor(scope: Construct) {
      this.scope = scope;
    }
    
    createPool(id: string, securityMode: string) {
      return new cognito.CfnUserPool(this.scope, id, {
        userPoolName: id,
        userPoolAddOns: {
          advancedSecurityMode: securityMode
        }
      });
    }
  }
  
  const creator = new UserPoolCreator(scope);
  // ruleid: typescript_cdk_cognito_user_pool_advanced_security_mode_enforced
  creator.createPool('UserPool14', 'OFF');
}
// {/fact}

// {fact rule=secure-design-principles-violation@v1.0 defects=1}
function bad_case_15(scope: Construct) {
  // Using spread operator with OFF mode
  const baseProps = {
    userPoolName: 'my-user-pool'
  };
  
  const addOns = {
    advancedSecurityMode: 'OFF'
  };
  
  // ruleid: typescript_cdk_cognito_user_pool_advanced_security_mode_enforced
  new cognito.CfnUserPool(scope, 'UserPool15', {
    ...baseProps,
    userPoolAddOns: {
      ...addOns
    }
  });
}
// {/fact}

// True Negatives (Secure Code)

// {fact rule=secure-design-principles-violation@v1.0 defects=0}
function good_case_1(scope: Construct) {
  // Basic case: Creating a user pool with advancedSecurityMode set to ENFORCED
  // ok: typescript_cdk_cognito_user_pool_advanced_security_mode_enforced
  new cognito.CfnUserPool(scope, 'UserPool1', {
    userPoolName: 'my-user-pool',
    userPoolAddOns: {
      advancedSecurityMode: 'ENFORCED'
    }
  });
}
// {/fact}

// {fact rule=secure-design-principles-violation@v1.0 defects=0}
function good_case_2(scope: Construct) {
  // Using a variable to set the mode to ENFORCED
  const securityMode = 'ENFORCED';
  
  // ok: typescript_cdk_cognito_user_pool_advanced_security_mode_enforced
  new cognito.CfnUserPool(scope, 'UserPool2', {
    userPoolName: 'my-user-pool',
    userPoolAddOns: {
      advancedSecurityMode: securityMode
    }
  });
}
// {/fact}

// {fact rule=secure-design-principles-violation@v1.0 defects=0}
function good_case_3(scope: Construct) {
  // Using AUDIT mode which is also acceptable
  // ok: typescript_cdk_cognito_user_pool_advanced_security_mode_enforced
  new cognito.CfnUserPool(scope, 'UserPool3', {
    userPoolName: 'my-user-pool',
    userPoolAddOns: {
      advancedSecurityMode: 'AUDIT'
    }
  });
}
// {/fact}

// {fact rule=secure-design-principles-violation@v1.0 defects=0}
function good_case_4(scope: Construct) {
  // Using a function that returns ENFORCED
  const getSecurityMode = () => 'ENFORCED';
  
  // ok: typescript_cdk_cognito_user_pool_advanced_security_mode_enforced
  new cognito.CfnUserPool(scope, 'UserPool4', {
    userPoolName: 'my-user-pool',
    userPoolAddOns: {
      advancedSecurityMode: getSecurityMode()
    }
  });
}
// {/fact}

// {fact rule=secure-design-principles-violation@v1.0 defects=0}
function good_case_5(scope: Construct) {
  // Using a conditional expression that evaluates to ENFORCED
  const isProduction = true;
  
  // ok: typescript_cdk_cognito_user_pool_advanced_security_mode_enforced
  new cognito.CfnUserPool(scope, 'UserPool5', {
    userPoolName: 'my-user-pool',
    userPoolAddOns: {
      advancedSecurityMode: isProduction ? 'ENFORCED' : 'AUDIT'
    }
  });
}
// {/fact}

// {fact rule=secure-design-principles-violation@v1.0 defects=0}
function good_case_6(scope: Construct) {
  // Using string concatenation that results in ENFORCED
  const securityMode = 'ENFOR' + 'CED';
  
  // ok: typescript_cdk_cognito_user_pool_advanced_security_mode_enforced
  new cognito.CfnUserPool(scope, 'UserPool6', {
    userPoolName: 'my-user-pool',
    userPoolAddOns: {
      advancedSecurityMode: securityMode
    }
  });
}
// {/fact}

// {fact rule=secure-design-principles-violation@v1.0 defects=0}
function good_case_7(scope: Construct, config: any) {
  // Using a configuration object with a default value of ENFORCED
  const securityMode = config?.securityMode || 'ENFORCED';
  
  // ok: typescript_cdk_cognito_user_pool_advanced_security_mode_enforced
  new cognito.CfnUserPool(scope, 'UserPool7', {
    userPoolName: 'my-user-pool',
    userPoolAddOns: {
      advancedSecurityMode: securityMode
    }
  });
}
// {/fact}

// {fact rule=secure-design-principles-violation@v1.0 defects=0}
function good_case_8(scope: Construct) {
  // Creating multiple user pools all with secure settings
  // ok: typescript_cdk_cognito_user_pool_advanced_security_mode_enforced
  new cognito.CfnUserPool(scope, 'UserPool8A', {
    userPoolName: 'user-pool-8a',
    userPoolAddOns: {
      advancedSecurityMode: 'ENFORCED'
    }
  });
  
  // ok: typescript_cdk_cognito_user_pool_advanced_security_mode_enforced
  new cognito.CfnUserPool(scope, 'UserPool8B', {
    userPoolName: 'user-pool-8b',
    userPoolAddOns: {
      advancedSecurityMode: 'AUDIT'
    }
  });
}
// {/fact}

// {fact rule=secure-design-principles-violation@v1.0 defects=0}
function good_case_9(scope: Construct) {
  // Using an array of modes and selecting ENFORCED
  const modes = ['ENFORCED', 'AUDIT', 'OFF'];
  
  // ok: typescript_cdk_cognito_user_pool_advanced_security_mode_enforced
  new cognito.CfnUserPool(scope, 'UserPool9', {
    userPoolName: 'my-user-pool',
    userPoolAddOns: {
      advancedSecurityMode: modes[0] // ENFORCED
    }
  });
}
// {/fact}

// {fact rule=secure-design-principles-violation@v1.0 defects=0}
function good_case_10(scope: Construct) {
  // Using a switch statement that results in ENFORCED
  const environment = 'prod';
  let securityMode: string;
  
  switch (environment) {
    case 'prod':
      securityMode = 'ENFORCED';
      break;
    case 'staging':
      securityMode = 'AUDIT';
      break;
    default:
      securityMode = 'AUDIT'; // Not using OFF as default
      break;
  }
  
  // ok: typescript_cdk_cognito_user_pool_advanced_security_mode_enforced
  new cognito.CfnUserPool(scope, 'UserPool10', {
    userPoolName: 'my-user-pool',
    userPoolAddOns: {
      advancedSecurityMode: securityMode
    }
  });
}
// {/fact}

// {fact rule=secure-design-principles-violation@v1.0 defects=0}
function good_case_11(scope: Construct) {
  // Using a map to get the security mode
  const securityModes = new Map<string, string>();
  securityModes.set('prod', 'ENFORCED');
  securityModes.set('dev', 'AUDIT');
  
  const environment = 'prod';
  
  // ok: typescript_cdk_cognito_user_pool_advanced_security_mode_enforced
  new cognito.CfnUserPool(scope, 'UserPool11', {
    userPoolName: 'my-user-pool',
    userPoolAddOns: {
      advancedSecurityMode: securityModes.get(environment)
    }
  });
}
// {/fact}

// {fact rule=secure-design-principles-violation@v1.0 defects=0}
function good_case_12(scope: Construct) {
  // Using a helper function to create the user pool with ENFORCED mode
  function createUserPool(name: string, mode: string) {
    return new cognito.CfnUserPool(scope, name, {
      userPoolName: name,
      userPoolAddOns: {
        advancedSecurityMode: mode
      }
    });
  }
  
  // ok: typescript_cdk_cognito_user_pool_advanced_security_mode_enforced
  createUserPool('UserPool12', 'ENFORCED');
}
// {/fact}

// {fact rule=secure-design-principles-violation@v1.0 defects=0}
function good_case_13(scope: Construct) {
  // Using destructuring to set properties
  const poolConfig = {
    name: 'my-user-pool',
    securityMode: 'ENFORCED'
  };
  
  const { name, securityMode } = poolConfig;
  
  // ok: typescript_cdk_cognito_user_pool_advanced_security_mode_enforced
  new cognito.CfnUserPool(scope, 'UserPool13', {
    userPoolName: name,
    userPoolAddOns: {
      advancedSecurityMode: securityMode
    }
  });
}
// {/fact}

// {fact rule=secure-design-principles-violation@v1.0 defects=0}
function good_case_14(scope: Construct) {
  // Using environment variables to set the security mode
  const getEnvVar = (name: string, defaultValue: string): string => {
    // In a real scenario, this would access process.env
    // For this example, we'll simulate it
    const envVars = {
      'COGNITO_SECURITY_MODE': 'ENFORCED'
    };
    return envVars[name] || defaultValue;
  };
  
  const securityMode = getEnvVar('COGNITO_SECURITY_MODE', 'ENFORCED');
  
  // ok: typescript_cdk_cognito_user_pool_advanced_security_mode_enforced
  new cognito.CfnUserPool(scope, 'UserPool14', {
    userPoolName: 'my-user-pool',
    userPoolAddOns: {
      advancedSecurityMode: securityMode
    }
  });
}
// {/fact}

// {fact rule=secure-design-principles-violation@v1.0 defects=0}
function good_case_15(scope: Construct) {
  // Using the L2 construct with secure defaults
  // ok: typescript_cdk_cognito_user_pool_advanced_security_mode_enforced
  new cognito.UserPool(scope, 'UserPool15', {
    userPoolName: 'my-user-pool',
    advancedSecurityMode: cognito.AdvancedSecurityMode.ENFORCED
  });
}
// {/fact}

// Main stack class for reference
class CognitoStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);
    
    // Examples would be called from here in a real application
    good_case_1(this);
  }
}