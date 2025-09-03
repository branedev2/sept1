import { Stack, App } from 'aws-cdk-lib';
import * as cognito from 'aws-cdk-lib/aws-cognito';
import * as iam from 'aws-cdk-lib/aws-iam';
import { Construct } from 'constructs';

// True Positive Examples (Vulnerable Code)

// {fact rule=hardcoded-credentials@v1.0 defects=1}
function bad_case_1() {
  const app = new App();
  const stack = new Stack(app, 'TestStack');
  
  // ruleid: typescript_cdk_cognito_user_pool_no_unauthenticated_logins
  new cognito.CfnIdentityPool(stack, 'IdentityPool', {
    allowUnauthenticatedIdentities: true,
  });
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
function bad_case_2() {
  const app = new App();
  const stack = new Stack(app, 'TestStack');
  
  // ruleid: typescript_cdk_cognito_user_pool_no_unauthenticated_logins
  const identityPool = new cognito.CfnIdentityPool(stack, 'IdentityPool', {
    identityPoolName: 'myIdentityPool',
    allowUnauthenticatedIdentities: true,
    supportedLoginProviders: {
      'graph.facebook.com': '12345678',
      'accounts.google.com': '12345678',
    }
  });
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
function bad_case_3() {
  class MyConstruct extends Construct {
    constructor(scope: Construct, id: string) {
      super(scope, id);
      
      // ruleid: typescript_cdk_cognito_user_pool_no_unauthenticated_logins
      new cognito.CfnIdentityPool(this, 'IdentityPool', {
        allowUnauthenticatedIdentities: true,
        cognitoIdentityProviders: [{
          clientId: 'client-id',
          providerName: 'provider-name'
        }]
      });
    }
  }
  
  const app = new App();
  const stack = new Stack(app, 'TestStack');
  new MyConstruct(stack, 'MyConstruct');
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
function bad_case_4() {
  const app = new App();
  const stack = new Stack(app, 'TestStack');
  
  const allowUnauth = true;
  
  // ruleid: typescript_cdk_cognito_user_pool_no_unauthenticated_logins
  new cognito.CfnIdentityPool(stack, 'IdentityPool', {
    allowUnauthenticatedIdentities: allowUnauth,
  });
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
function bad_case_5() {
  const app = new App();
  const stack = new Stack(app, 'TestStack');
  
  const userPool = new cognito.UserPool(stack, 'UserPool', {
    selfSignUpEnabled: true,
    autoVerify: { email: true },
    standardAttributes: {
      email: { required: true, mutable: true }
    }
  });
  
  const userPoolClient = new cognito.UserPoolClient(stack, 'UserPoolClient', {
    userPool,
    generateSecret: false
  });
  
  // ruleid: typescript_cdk_cognito_user_pool_no_unauthenticated_logins
  new cognito.CfnIdentityPool(stack, 'IdentityPool', {
    allowUnauthenticatedIdentities: true,
    cognitoIdentityProviders: [{
      clientId: userPoolClient.userPoolClientId,
      providerName: userPool.userPoolProviderName
    }]
  });
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
function bad_case_6() {
  const createIdentityPool = (stack: Stack, allowUnauth: boolean) => {
    // ruleid: typescript_cdk_cognito_user_pool_no_unauthenticated_logins
    return new cognito.CfnIdentityPool(stack, 'IdentityPool', {
      allowUnauthenticatedIdentities: allowUnauth
    });
  };
  
  const app = new App();
  const stack = new Stack(app, 'TestStack');
  createIdentityPool(stack, true);
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
function bad_case_7() {
  const app = new App();
  const stack = new Stack(app, 'TestStack');
  
  const config = {
    allowUnauth: true,
    poolName: 'myPool'
  };
  
  // ruleid: typescript_cdk_cognito_user_pool_no_unauthenticated_logins
  new cognito.CfnIdentityPool(stack, 'IdentityPool', {
    identityPoolName: config.poolName,
    allowUnauthenticatedIdentities: config.allowUnauth
  });
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
function bad_case_8() {
  const app = new App();
  const stack = new Stack(app, 'TestStack');
  
  // ruleid: typescript_cdk_cognito_user_pool_no_unauthenticated_logins
  const identityPool = new cognito.CfnIdentityPool(stack, 'IdentityPool', {
    allowUnauthenticatedIdentities: true
  });
  
  const unauthRole = new iam.Role(stack, 'UnauthRole', {
    assumedBy: new iam.FederatedPrincipal('cognito-identity.amazonaws.com', {
      StringEquals: { 'cognito-identity.amazonaws.com:aud': identityPool.ref },
      'ForAnyValue:StringLike': { 'cognito-identity.amazonaws.com:amr': 'unauthenticated' }
    }, 'sts:AssumeRoleWithWebIdentity')
  });
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
function bad_case_9() {
  const app = new App();
  const stack = new Stack(app, 'TestStack');
  
  const props = {
    identityPoolName: 'myIdentityPool',
    allowUnauthenticatedIdentities: true
  };
  
  // ruleid: typescript_cdk_cognito_user_pool_no_unauthenticated_logins
  new cognito.CfnIdentityPool(stack, 'IdentityPool', props);
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
function bad_case_10() {
  const app = new App();
  const stack = new Stack(app, 'TestStack');
  
  function createIdentityPoolProps() {
    return {
      allowUnauthenticatedIdentities: true,
      identityPoolName: 'myIdentityPool'
    };
  }
  
  // ruleid: typescript_cdk_cognito_user_pool_no_unauthenticated_logins
  new cognito.CfnIdentityPool(stack, 'IdentityPool', createIdentityPoolProps());
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
function bad_case_11() {
  const app = new App();
  const stack = new Stack(app, 'TestStack');
  
  const isDevEnvironment = true;
  
  // ruleid: typescript_cdk_cognito_user_pool_no_unauthenticated_logins
  new cognito.CfnIdentityPool(stack, 'IdentityPool', {
    allowUnauthenticatedIdentities: isDevEnvironment ? true : false,
  });
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
function bad_case_12() {
  class AuthStack extends Stack {
    constructor(scope: Construct, id: string) {
      super(scope, id);
      
      // ruleid: typescript_cdk_cognito_user_pool_no_unauthenticated_logins
      const identityPool = new cognito.CfnIdentityPool(this, 'IdentityPool', {
        allowUnauthenticatedIdentities: true
      });
      
      // Set up roles for authenticated and unauthenticated users
      const unauthRole = new iam.Role(this, 'UnauthRole', {
        assumedBy: new iam.FederatedPrincipal('cognito-identity.amazonaws.com', {}, 'sts:AssumeRoleWithWebIdentity')
      });
      
      new cognito.CfnIdentityPoolRoleAttachment(this, 'IdentityPoolRoleAttachment', {
        identityPoolId: identityPool.ref,
        roles: {
          'unauthenticated': unauthRole.roleArn
        }
      });
    }
  }
  
  const app = new App();
  new AuthStack(app, 'AuthStack');
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
function bad_case_13() {
  const app = new App();
  const stack = new Stack(app, 'TestStack');
  
  const allowUnauthenticatedAccess = () => {
    // This is for a public content delivery app
    return true;
  };
  
  // ruleid: typescript_cdk_cognito_user_pool_no_unauthenticated_logins
  new cognito.CfnIdentityPool(stack, 'IdentityPool', {
    allowUnauthenticatedIdentities: allowUnauthenticatedAccess(),
    identityPoolName: 'PublicContentDeliveryPool'
  });
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
function bad_case_14() {
  const app = new App();
  const stack = new Stack(app, 'TestStack');
  
  const settings = {
    auth: {
      allowUnauthenticated: true
    }
  };
  
  // ruleid: typescript_cdk_cognito_user_pool_no_unauthenticated_logins
  new cognito.CfnIdentityPool(stack, 'IdentityPool', {
    allowUnauthenticatedIdentities: settings.auth.allowUnauthenticated
  });
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
function bad_case_15() {
  const app = new App();
  const stack = new Stack(app, 'TestStack');
  
  const poolProps = {
    allowUnauthenticatedIdentities: false
  };
  
  // Override for development environment
  if (process.env.NODE_ENV === 'development' || true) {
    poolProps.allowUnauthenticatedIdentities = true;
  }
  
  // ruleid: typescript_cdk_cognito_user_pool_no_unauthenticated_logins
  new cognito.CfnIdentityPool(stack, 'IdentityPool', poolProps);
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=hardcoded-credentials@v1.0 defects=0}
function good_case_1() {
  const app = new App();
  const stack = new Stack(app, 'TestStack');
  
  // ok: typescript_cdk_cognito_user_pool_no_unauthenticated_logins
  new cognito.CfnIdentityPool(stack, 'IdentityPool', {
    allowUnauthenticatedIdentities: false,
  });
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
function good_case_2() {
  const app = new App();
  const stack = new Stack(app, 'TestStack');
  
  // ok: typescript_cdk_cognito_user_pool_no_unauthenticated_logins
  const identityPool = new cognito.CfnIdentityPool(stack, 'IdentityPool', {
    identityPoolName: 'myIdentityPool',
    allowUnauthenticatedIdentities: false,
    supportedLoginProviders: {
      'graph.facebook.com': '12345678',
      'accounts.google.com': '12345678',
    }
  });
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
function good_case_3() {
  class MyConstruct extends Construct {
    constructor(scope: Construct, id: string) {
      super(scope, id);
      
      // ok: typescript_cdk_cognito_user_pool_no_unauthenticated_logins
      new cognito.CfnIdentityPool(this, 'IdentityPool', {
        allowUnauthenticatedIdentities: false,
        cognitoIdentityProviders: [{
          clientId: 'client-id',
          providerName: 'provider-name'
        }]
      });
    }
  }
  
  const app = new App();
  const stack = new Stack(app, 'TestStack');
  new MyConstruct(stack, 'MyConstruct');
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
function good_case_4() {
  const app = new App();
  const stack = new Stack(app, 'TestStack');
  
  const allowUnauth = false;
  
  // ok: typescript_cdk_cognito_user_pool_no_unauthenticated_logins
  new cognito.CfnIdentityPool(stack, 'IdentityPool', {
    allowUnauthenticatedIdentities: allowUnauth,
  });
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
function good_case_5() {
  const app = new App();
  const stack = new Stack(app, 'TestStack');
  
  const userPool = new cognito.UserPool(stack, 'UserPool', {
    selfSignUpEnabled: true,
    autoVerify: { email: true },
    standardAttributes: {
      email: { required: true, mutable: true }
    }
  });
  
  const userPoolClient = new cognito.UserPoolClient(stack, 'UserPoolClient', {
    userPool,
    generateSecret: false
  });
  
  // ok: typescript_cdk_cognito_user_pool_no_unauthenticated_logins
  new cognito.CfnIdentityPool(stack, 'IdentityPool', {
    allowUnauthenticatedIdentities: false,
    cognitoIdentityProviders: [{
      clientId: userPoolClient.userPoolClientId,
      providerName: userPool.userPoolProviderName
    }]
  });
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
function good_case_6() {
  const createIdentityPool = (stack: Stack, allowUnauth: boolean) => {
    // ok: typescript_cdk_cognito_user_pool_no_unauthenticated_logins
    return new cognito.CfnIdentityPool(stack, 'IdentityPool', {
      allowUnauthenticatedIdentities: allowUnauth
    });
  };
  
  const app = new App();
  const stack = new Stack(app, 'TestStack');
  createIdentityPool(stack, false);
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
function good_case_7() {
  const app = new App();
  const stack = new Stack(app, 'TestStack');
  
  const config = {
    allowUnauth: false,
    poolName: 'myPool'
  };
  
  // ok: typescript_cdk_cognito_user_pool_no_unauthenticated_logins
  new cognito.CfnIdentityPool(stack, 'IdentityPool', {
    identityPoolName: config.poolName,
    allowUnauthenticatedIdentities: config.allowUnauth
  });
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
function good_case_8() {
  const app = new App();
  const stack = new Stack(app, 'TestStack');
  
  // ok: typescript_cdk_cognito_user_pool_no_unauthenticated_logins
  const identityPool = new cognito.CfnIdentityPool(stack, 'IdentityPool', {
    allowUnauthenticatedIdentities: false
  });
  
  const authRole = new iam.Role(stack, 'AuthRole', {
    assumedBy: new iam.FederatedPrincipal('cognito-identity.amazonaws.com', {
      StringEquals: { 'cognito-identity.amazonaws.com:aud': identityPool.ref },
      'ForAnyValue:StringLike': { 'cognito-identity.amazonaws.com:amr': 'authenticated' }
    }, 'sts:AssumeRoleWithWebIdentity')
  });
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
function good_case_9() {
  const app = new App();
  const stack = new Stack(app, 'TestStack');
  
  const props = {
    identityPoolName: 'myIdentityPool',
    allowUnauthenticatedIdentities: false
  };
  
  // ok: typescript_cdk_cognito_user_pool_no_unauthenticated_logins
  new cognito.CfnIdentityPool(stack, 'IdentityPool', props);
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
function good_case_10() {
  const app = new App();
  const stack = new Stack(app, 'TestStack');
  
  function createIdentityPoolProps() {
    return {
      allowUnauthenticatedIdentities: false,
      identityPoolName: 'myIdentityPool'
    };
  }
  
  // ok: typescript_cdk_cognito_user_pool_no_unauthenticated_logins
  new cognito.CfnIdentityPool(stack, 'IdentityPool', createIdentityPoolProps());
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
function good_case_11() {
  const app = new App();
  const stack = new Stack(app, 'TestStack');
  
  const isDevEnvironment = true;
  
  // ok: typescript_cdk_cognito_user_pool_no_unauthenticated_logins
  new cognito.CfnIdentityPool(stack, 'IdentityPool', {
    allowUnauthenticatedIdentities: false,
    identityPoolName: isDevEnvironment ? 'DevIdentityPool' : 'ProdIdentityPool'
  });
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
function good_case_12() {
  class AuthStack extends Stack {
    constructor(scope: Construct, id: string) {
      super(scope, id);
      
      // ok: typescript_cdk_cognito_user_pool_no_unauthenticated_logins
      const identityPool = new cognito.CfnIdentityPool(this, 'IdentityPool', {
        allowUnauthenticatedIdentities: false
      });
      
      // Set up roles for authenticated users only
      const authRole = new iam.Role(this, 'AuthRole', {
        assumedBy: new iam.FederatedPrincipal('cognito-identity.amazonaws.com', {}, 'sts:AssumeRoleWithWebIdentity')
      });
      
      new cognito.CfnIdentityPoolRoleAttachment(this, 'IdentityPoolRoleAttachment', {
        identityPoolId: identityPool.ref,
        roles: {
          'authenticated': authRole.roleArn
        }
      });
    }
  }
  
  const app = new App();
  new AuthStack(app, 'AuthStack');
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
function good_case_13() {
  const app = new App();
  const stack = new Stack(app, 'TestStack');
  
  // With metadata explaining why unauthenticated access is needed
  // ok: typescript_cdk_cognito_user_pool_no_unauthenticated_logins
  const identityPool = new cognito.CfnIdentityPool(stack, 'IdentityPool', {
    allowUnauthenticatedIdentities: false
  });
  
  // Add metadata to explain security considerations
  identityPool.cfnOptions.metadata = {
    securityNotes: 'Unauthenticated access is disabled as per security requirements.'
  };
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
function good_case_14() {
  const app = new App();
  const stack = new Stack(app, 'TestStack');
  
  const settings = {
    auth: {
      allowUnauthenticated: false
    }
  };
  
  // ok: typescript_cdk_cognito_user_pool_no_unauthenticated_logins
  new cognito.CfnIdentityPool(stack, 'IdentityPool', {
    allowUnauthenticatedIdentities: settings.auth.allowUnauthenticated
  });
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
function good_case_15() {
  const app = new App();
  const stack = new Stack(app, 'TestStack');
  
  // Using environment variables for configuration
  const allowUnauth = process.env.ALLOW_UNAUTH === 'true' ? true : false;
  
  // ok: typescript_cdk_cognito_user_pool_no_unauthenticated_logins
  new cognito.CfnIdentityPool(stack, 'IdentityPool', {
    allowUnauthenticatedIdentities: false, // Override any environment variable for security
    identityPoolName: 'SecureIdentityPool'
  });
}
// {/fact}