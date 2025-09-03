import { Stack, App } from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as cognito from 'aws-cdk-lib/aws-cognito';

// True Positives (Vulnerable Cases)

// {fact rule=incorrect-authentication-exploitation@v1.0 defects=1}
function bad_case_1() {
  const stack = new Stack();
  // ruleid: typescript-cdk-cognito-user-pool-strong-password-policy
  new cognito.UserPool(stack, 'UserPool1', {
    // No password policy specified, defaults to weak policy
  });
}
// {/fact}

// {fact rule=incorrect-authentication-exploitation@v1.0 defects=1}
function bad_case_2() {
  const stack = new Stack();
  // ruleid: typescript-cdk-cognito-user-pool-strong-password-policy
  new cognito.UserPool(stack, 'UserPool2', {
    passwordPolicy: {
      minLength: 6, // Too short
      requireUppercase: true,
      requireDigits: true,
      requireSymbols: true,
    }
  });
}
// {/fact}

// {fact rule=incorrect-authentication-exploitation@v1.0 defects=1}
function bad_case_3() {
  const stack = new Stack();
  // ruleid: typescript-cdk-cognito-user-pool-strong-password-policy
  new cognito.UserPool(stack, 'UserPool3', {
    passwordPolicy: {
      minLength: 8,
      requireUppercase: false, // Missing uppercase requirement
      requireDigits: true,
      requireSymbols: true,
    }
  });
}
// {/fact}

// {fact rule=incorrect-authentication-exploitation@v1.0 defects=1}
function bad_case_4() {
  const stack = new Stack();
  // ruleid: typescript-cdk-cognito-user-pool-strong-password-policy
  new cognito.UserPool(stack, 'UserPool4', {
    passwordPolicy: {
      minLength: 8,
      requireUppercase: true,
      requireDigits: false, // Missing digits requirement
      requireSymbols: true,
    }
  });
}
// {/fact}

// {fact rule=incorrect-authentication-exploitation@v1.0 defects=1}
function bad_case_5() {
  const stack = new Stack();
  // ruleid: typescript-cdk-cognito-user-pool-strong-password-policy
  new cognito.UserPool(stack, 'UserPool5', {
    passwordPolicy: {
      minLength: 8,
      requireUppercase: true,
      requireDigits: true,
      requireSymbols: false, // Missing symbols requirement
    }
  });
}
// {/fact}

// {fact rule=incorrect-authentication-exploitation@v1.0 defects=1}
function bad_case_6() {
  const stack = new Stack();
  // ruleid: typescript-cdk-cognito-user-pool-strong-password-policy
  const userPool = new cognito.UserPool(stack, 'UserPool6', {
    passwordPolicy: {
      minLength: 4, // Too short
      requireUppercase: false,
      requireDigits: false,
      requireSymbols: false,
    }
  });
}
// {/fact}

// {fact rule=incorrect-authentication-exploitation@v1.0 defects=1}
function bad_case_7() {
  const stack = new Stack();
  const props = { passwordPolicy: { minLength: 6 } }; // Incomplete policy
  // ruleid: typescript-cdk-cognito-user-pool-strong-password-policy
  new cognito.UserPool(stack, 'UserPool7', props);
}
// {/fact}

// {fact rule=incorrect-authentication-exploitation@v1.0 defects=1}
function bad_case_8() {
  class MyStack extends Stack {
    constructor(scope: Construct, id: string) {
      super(scope, id);
      
      // ruleid: typescript-cdk-cognito-user-pool-strong-password-policy
      new cognito.UserPool(this, 'UserPool8', {
        passwordPolicy: {
          minLength: 8,
          requireUppercase: false,
          requireDigits: false,
          requireSymbols: false,
        }
      });
    }
  }
  
  const app = new App();
  new MyStack(app, 'MyStack');
}
// {/fact}

// {fact rule=incorrect-authentication-exploitation@v1.0 defects=1}
function bad_case_9() {
  const stack = new Stack();
  const passwordPolicy = {
    minLength: 8,
    requireUppercase: true,
    requireDigits: false, // Missing digits requirement
    requireSymbols: false, // Missing symbols requirement
  };
  
  // ruleid: typescript-cdk-cognito-user-pool-strong-password-policy
  new cognito.UserPool(stack, 'UserPool9', {
    passwordPolicy: passwordPolicy
  });
}
// {/fact}

// {fact rule=incorrect-authentication-exploitation@v1.0 defects=1}
function bad_case_10() {
  const stack = new Stack();
  
  for (let i = 0; i < 3; i++) {
    // ruleid: typescript-cdk-cognito-user-pool-strong-password-policy
    new cognito.UserPool(stack, `UserPool10-${i}`, {
      passwordPolicy: {
        minLength: 7, // Too short
        requireUppercase: true,
        requireDigits: true,
        requireSymbols: true,
      }
    });
  }
}
// {/fact}

// {fact rule=incorrect-authentication-exploitation@v1.0 defects=1}
function bad_case_11() {
  const stack = new Stack();
  const minLength = process.env.MIN_LENGTH ? parseInt(process.env.MIN_LENGTH) : 6; // Default too short
  
  // ruleid: typescript-cdk-cognito-user-pool-strong-password-policy
  new cognito.UserPool(stack, 'UserPool11', {
    passwordPolicy: {
      minLength: minLength,
      requireUppercase: true,
      requireDigits: true,
      requireSymbols: true,
    }
  });
}
// {/fact}

// {fact rule=incorrect-authentication-exploitation@v1.0 defects=1}
function bad_case_12() {
  const stack = new Stack();
  const isProduction = process.env.ENV === 'production';
  
  // ruleid: typescript-cdk-cognito-user-pool-strong-password-policy
  new cognito.UserPool(stack, 'UserPool12', {
    passwordPolicy: {
      minLength: isProduction ? 8 : 6, // Non-production is too short
      requireUppercase: isProduction,
      requireDigits: isProduction,
      requireSymbols: isProduction,
    }
  });
}
// {/fact}

// {fact rule=incorrect-authentication-exploitation@v1.0 defects=1}
function bad_case_13() {
  const stack = new Stack();
  
  // ruleid: typescript-cdk-cognito-user-pool-strong-password-policy
  const userPool = new cognito.UserPool(stack, 'UserPool13', {});
  
  // Adding a client but not fixing the password policy
  new cognito.UserPoolClient(stack, 'UserPoolClient', {
    userPool: userPool,
    generateSecret: true,
  });
}
// {/fact}

// {fact rule=incorrect-authentication-exploitation@v1.0 defects=1}
function bad_case_14() {
  const stack = new Stack();
  const config = {
    passwordPolicy: {
      minLength: 8,
      requireUppercase: true,
      requireDigits: true,
      // Missing requireSymbols
    }
  };
  
  // ruleid: typescript-cdk-cognito-user-pool-strong-password-policy
  new cognito.UserPool(stack, 'UserPool14', config);
}
// {/fact}

// {fact rule=incorrect-authentication-exploitation@v1.0 defects=1}
function bad_case_15() {
  const stack = new Stack();
  let passwordPolicy;
  
  if (process.env.STRICT_MODE === 'true') {
    passwordPolicy = {
      minLength: 10,
      requireUppercase: true,
      requireDigits: true,
      requireSymbols: true,
    };
  } else {
    passwordPolicy = {
      minLength: 6, // Too short
      requireUppercase: false,
      requireDigits: true,
      requireSymbols: false,
    };
  }
  
  // ruleid: typescript-cdk-cognito-user-pool-strong-password-policy
  new cognito.UserPool(stack, 'UserPool15', {
    passwordPolicy: passwordPolicy
  });
}
// {/fact}

// True Negatives (Secure Cases)

// {fact rule=incorrect-authentication-exploitation@v1.0 defects=0}
function good_case_1() {
  const stack = new Stack();
  // ok: typescript-cdk-cognito-user-pool-strong-password-policy
  new cognito.UserPool(stack, 'UserPool1', {
    passwordPolicy: {
      minLength: 8,
      requireUppercase: true,
      requireDigits: true,
      requireSymbols: true,
    }
  });
}
// {/fact}

// {fact rule=incorrect-authentication-exploitation@v1.0 defects=0}
function good_case_2() {
  const stack = new Stack();
  // ok: typescript-cdk-cognito-user-pool-strong-password-policy
  new cognito.UserPool(stack, 'UserPool2', {
    passwordPolicy: {
      minLength: 12, // Stronger than minimum
      requireUppercase: true,
      requireDigits: true,
      requireSymbols: true,
    }
  });
}
// {/fact}

// {fact rule=incorrect-authentication-exploitation@v1.0 defects=0}
function good_case_3() {
  const stack = new Stack();
  const strongPolicy = {
    minLength: 10,
    requireUppercase: true,
    requireDigits: true,
    requireSymbols: true,
    tempPasswordValidity: cognito.Duration.days(3),
  };
  
  // ok: typescript-cdk-cognito-user-pool-strong-password-policy
  new cognito.UserPool(stack, 'UserPool3', {
    passwordPolicy: strongPolicy
  });
}
// {/fact}

// {fact rule=incorrect-authentication-exploitation@v1.0 defects=0}
function good_case_4() {
  class SecureStack extends Stack {
    constructor(scope: Construct, id: string) {
      super(scope, id);
      
      // ok: typescript-cdk-cognito-user-pool-strong-password-policy
      new cognito.UserPool(this, 'UserPool4', {
        passwordPolicy: {
          minLength: 8,
          requireUppercase: true,
          requireDigits: true,
          requireSymbols: true,
          tempPasswordValidity: cognito.Duration.days(1),
        }
      });
    }
  }
  
  const app = new App();
  new SecureStack(app, 'SecureStack');
}
// {/fact}

// {fact rule=incorrect-authentication-exploitation@v1.0 defects=0}
function good_case_5() {
  const stack = new Stack();
  const minPasswordLength = 16; // Stronger than required
  
  // ok: typescript-cdk-cognito-user-pool-strong-password-policy
  new cognito.UserPool(stack, 'UserPool5', {
    passwordPolicy: {
      minLength: minPasswordLength,
      requireUppercase: true,
      requireDigits: true,
      requireSymbols: true,
    }
  });
}
// {/fact}

// {fact rule=incorrect-authentication-exploitation@v1.0 defects=0}
function good_case_6() {
  const stack = new Stack();
  const isProduction = process.env.ENV === 'production';
  
  // ok: typescript-cdk-cognito-user-pool-strong-password-policy
  new cognito.UserPool(stack, 'UserPool6', {
    passwordPolicy: {
      minLength: isProduction ? 12 : 8, // Both values are sufficient
      requireUppercase: true,
      requireDigits: true,
      requireSymbols: true,
    }
  });
}
// {/fact}

// {fact rule=incorrect-authentication-exploitation@v1.0 defects=0}
function good_case_7() {
  const stack = new Stack();
  
  for (let i = 0; i < 3; i++) {
    // ok: typescript-cdk-cognito-user-pool-strong-password-policy
    new cognito.UserPool(stack, `UserPool7-${i}`, {
      passwordPolicy: {
        minLength: 8 + i, // All values are sufficient (8 or greater)
        requireUppercase: true,
        requireDigits: true,
        requireSymbols: true,
      }
    });
  }
}
// {/fact}

// {fact rule=incorrect-authentication-exploitation@v1.0 defects=0}
function good_case_8() {
  const stack = new Stack();
  const config = {
    userPoolName: 'MyUserPool',
    passwordPolicy: {
      minLength: 10,
      requireUppercase: true,
      requireDigits: true,
      requireSymbols: true,
    }
  };
  
  // ok: typescript-cdk-cognito-user-pool-strong-password-policy
  new cognito.UserPool(stack, 'UserPool8', config);
}
// {/fact}

// {fact rule=incorrect-authentication-exploitation@v1.0 defects=0}
function good_case_9() {
  const stack = new Stack();
  let passwordPolicy;
  
  if (process.env.STRICT_MODE === 'true') {
    passwordPolicy = {
      minLength: 14,
      requireUppercase: true,
      requireDigits: true,
      requireSymbols: true,
    };
  } else {
    passwordPolicy = {
      minLength: 8, // Still sufficient
      requireUppercase: true,
      requireDigits: true,
      requireSymbols: true,
    };
  }
  
  // ok: typescript-cdk-cognito-user-pool-strong-password-policy
  new cognito.UserPool(stack, 'UserPool9', {
    passwordPolicy: passwordPolicy
  });
}
// {/fact}

// {fact rule=incorrect-authentication-exploitation@v1.0 defects=0}
function good_case_10() {
  const stack = new Stack();
  
  // ok: typescript-cdk-cognito-user-pool-strong-password-policy
  const userPool = new cognito.UserPool(stack, 'UserPool10', {
    passwordPolicy: {
      minLength: 8,
      requireUppercase: true,
      requireDigits: true,
      requireSymbols: true,
    }
  });
  
  // Adding a client with the properly configured user pool
  new cognito.UserPoolClient(stack, 'UserPoolClient', {
    userPool: userPool,
    generateSecret: true,
  });
}
// {/fact}

// {fact rule=incorrect-authentication-exploitation@v1.0 defects=0}
function good_case_11() {
  const stack = new Stack();
  const minLength = Math.max(8, process.env.MIN_LENGTH ? parseInt(process.env.MIN_LENGTH) : 8);
  
  // ok: typescript-cdk-cognito-user-pool-strong-password-policy
  new cognito.UserPool(stack, 'UserPool11', {
    passwordPolicy: {
      minLength: minLength, // Guaranteed to be at least 8
      requireUppercase: true,
      requireDigits: true,
      requireSymbols: true,
    }
  });
}
// {/fact}

// {fact rule=incorrect-authentication-exploitation@v1.0 defects=0}
function good_case_12() {
  const stack = new Stack();
  
  // Define a function that creates a secure password policy
  const createSecurePasswordPolicy = () => {
    return {
      minLength: 10,
      requireUppercase: true,
      requireDigits: true,
      requireSymbols: true,
    };
  };
  
  // ok: typescript-cdk-cognito-user-pool-strong-password-policy
  new cognito.UserPool(stack, 'UserPool12', {
    passwordPolicy: createSecurePasswordPolicy()
  });
}
// {/fact}

// {fact rule=incorrect-authentication-exploitation@v1.0 defects=0}
function good_case_13() {
  const stack = new Stack();
  const securityLevel = process.env.SECURITY_LEVEL || 'high';
  
  const passwordPolicyConfig = {
    low: {
      minLength: 8,
      requireUppercase: true,
      requireDigits: true,
      requireSymbols: true,
    },
    medium: {
      minLength: 10,
      requireUppercase: true,
      requireDigits: true,
      requireSymbols: true,
    },
    high: {
      minLength: 12,
      requireUppercase: true,
      requireDigits: true,
      requireSymbols: true,
    }
  };
  
  // ok: typescript-cdk-cognito-user-pool-strong-password-policy
  new cognito.UserPool(stack, 'UserPool13', {
    passwordPolicy: passwordPolicyConfig[securityLevel as keyof typeof passwordPolicyConfig]
  });
}
// {/fact}

// {fact rule=incorrect-authentication-exploitation@v1.0 defects=0}
function good_case_14() {
  const stack = new Stack();
  
  // ok: typescript-cdk-cognito-user-pool-strong-password-policy
  new cognito.UserPool(stack, 'UserPool14', {
    selfSignUpEnabled: true,
    userVerification: {
      emailSubject: 'Verify your email',
      emailBody: 'Thanks for signing up! Your verification code is {####}',
      emailStyle: cognito.VerificationEmailStyle.CODE,
    },
    passwordPolicy: {
      minLength: 8,
      requireUppercase: true,
      requireDigits: true,
      requireSymbols: true,
      tempPasswordValidity: cognito.Duration.days(2),
    }
  });
}
// {/fact}

// {fact rule=incorrect-authentication-exploitation@v1.0 defects=0}
function good_case_15() {
  const stack = new Stack();
  
  // ok: typescript-cdk-cognito-user-pool-strong-password-policy
  const userPool = new cognito.UserPool(stack, 'UserPool15', {
    accountRecovery: cognito.AccountRecovery.EMAIL_ONLY,
    autoVerify: { email: true },
    passwordPolicy: {
      minLength: 8,
      requireLowercase: true, // Additional requirement
      requireUppercase: true,
      requireDigits: true,
      requireSymbols: true,
    }
  });
}
// {/fact}