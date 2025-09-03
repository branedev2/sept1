// Angular imports
import { NgModule } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';
import { HttpClientModule } from '@angular/common/http';

// Bad case examples - Using wildcards in $sceDelegateProvider configurations

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_1() {
  // Configuring $sceDelegateProvider with wildcards in resourceUrlWhitelist
  const myAppModule = angular.module('myApp', [])
    .config(['$sceDelegateProvider', function($sceDelegateProvider) {
      // ruleid: typescript-detect-angular-resource-loading
      $sceDelegateProvider.resourceUrlWhitelist([
        'self',
        'http://*.example.com/**'  // Using wildcard for subdomain and path
      ]);
    }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_2() {
  // Using wildcard for all domains
  const securityConfig = angular.module('securityConfig', [])
    .config(['$sceDelegateProvider', function($sceDelegateProvider) {
      // ruleid: typescript-detect-angular-resource-loading
      $sceDelegateProvider.resourceUrlWhitelist([
        'self',
        'http://*/**'  // Extremely dangerous - allows any domain
      ]);
    }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_3() {
  // Using wildcards in multiple entries
  class SecurityModule {
    constructor() {
      angular.module('app.security', [])
        .config(['$sceDelegateProvider', function($sceDelegateProvider) {
          // ruleid: typescript-detect-angular-resource-loading
          $sceDelegateProvider.resourceUrlWhitelist([
            'self',
            'https://*.trusted-domain.com/**',
            'https://*.cdn-domain.net/**'
          ]);
        }]);
    }
  }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_4() {
  // Using wildcards with protocol wildcards
  const configureApp = () => {
    angular.module('myApp', [])
      .config(['$sceDelegateProvider', function($sceDelegateProvider) {
        // ruleid: typescript-detect-angular-resource-loading
        $sceDelegateProvider.resourceUrlWhitelist([
          'self',
          '*://*.example.com/**'  // Wildcard for protocol, subdomain, and path
        ]);
      }]);
  };
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_5() {
  // Using wildcards in resourceUrlBlacklist
  @NgModule({
    imports: [BrowserModule, HttpClientModule]
  })
  class AppModule {
    constructor() {
      angular.module('myApp', [])
        .config(['$sceDelegateProvider', function($sceDelegateProvider) {
          // ruleid: typescript-detect-angular-resource-loading
          $sceDelegateProvider.resourceUrlBlacklist([
            'http://*.evil.com/**'  // Using wildcards in blacklist is also risky
          ]);
        }]);
    }
  }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_6() {
  // Using wildcards with variable
  const trustedDomains = ['*.trusted-source.com/**'];
  
  angular.module('myApp', [])
    .config(['$sceDelegateProvider', function($sceDelegateProvider) {
      // ruleid: typescript-detect-angular-resource-loading
      $sceDelegateProvider.resourceUrlWhitelist([
        'self',
        ...trustedDomains  // Spreading array with wildcards
      ]);
    }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_7() {
  // Using wildcards with conditional logic
  const isDevEnvironment = process.env.NODE_ENV === 'development';
  
  angular.module('myApp', [])
    .config(['$sceDelegateProvider', function($sceDelegateProvider) {
      const whitelist = ['self'];
      
      if (isDevEnvironment) {
        whitelist.push('http://localhost:*/**');
      } else {
        // ruleid: typescript-detect-angular-resource-loading
        whitelist.push('https://*.production-domain.com/**');
      }
      
      $sceDelegateProvider.resourceUrlWhitelist(whitelist);
    }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_8() {
  // Using wildcards with template literals
  const domain = 'example';
  const tld = 'com';
  
  angular.module('myApp', [])
    .config(['$sceDelegateProvider', function($sceDelegateProvider) {
      // ruleid: typescript-detect-angular-resource-loading
      $sceDelegateProvider.resourceUrlWhitelist([
        'self',
        `https://*.${domain}.${tld}/**`  // Template literal with wildcards
      ]);
    }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_9() {
  // Using wildcards with function that returns configuration
  function getSecurityConfig() {
    return {
      whitelist: [
        'self',
        'https://*.trusted-domain.com/**'
      ]
    };
  }
  
  angular.module('myApp', [])
    .config(['$sceDelegateProvider', function($sceDelegateProvider) {
      const config = getSecurityConfig();
      // ruleid: typescript-detect-angular-resource-loading
      $sceDelegateProvider.resourceUrlWhitelist(config.whitelist);
    }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_10() {
  // Using wildcards with multiple protocols
  angular.module('myApp', [])
    .config(['$sceDelegateProvider', function($sceDelegateProvider) {
      // ruleid: typescript-detect-angular-resource-loading
      $sceDelegateProvider.resourceUrlWhitelist([
        'self',
        'http://*.example.com/**',
        'https://*.example.com/**',
        'ftp://*.example.com/**'
      ]);
    }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_11() {
  // Using wildcards with array concatenation
  const baseWhitelist = ['self'];
  const additionalSources = ['https://*.cdn.com/**', 'https://*.api.com/**'];
  
  angular.module('myApp', [])
    .config(['$sceDelegateProvider', function($sceDelegateProvider) {
      // ruleid: typescript-detect-angular-resource-loading
      $sceDelegateProvider.resourceUrlWhitelist(
        baseWhitelist.concat(additionalSources)
      );
    }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_12() {
  // Using wildcards with class property
  class SecurityConfigService {
    private whitelist = [
      'self',
      'https://*.trusted-source.org/**'
    ];
    
    configureApp() {
      angular.module('myApp', [])
        .config(['$sceDelegateProvider', function($sceDelegateProvider) {
          // ruleid: typescript-detect-angular-resource-loading
          $sceDelegateProvider.resourceUrlWhitelist(this.whitelist);
        }.bind(this)]);
    }
  }
  
  const securityService = new SecurityConfigService();
  securityService.configureApp();
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_13() {
  // Using wildcards with dynamic configuration based on environment
  const environments = {
    dev: {
      domains: ['https://*.dev-domain.com/**']
    },
    prod: {
      domains: ['https://*.prod-domain.com/**']
    }
  };
  
  const currentEnv = 'dev';
  
  angular.module('myApp', [])
    .config(['$sceDelegateProvider', function($sceDelegateProvider) {
      // ruleid: typescript-detect-angular-resource-loading
      $sceDelegateProvider.resourceUrlWhitelist([
        'self',
        ...environments[currentEnv].domains
      ]);
    }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_14() {
  // Using wildcards with both whitelist and blacklist
  angular.module('myApp', [])
    .config(['$sceDelegateProvider', function($sceDelegateProvider) {
      // ruleid: typescript-detect-angular-resource-loading
      $sceDelegateProvider.resourceUrlWhitelist([
        'self',
        'https://*.trusted-domain.com/**'
      ]);
      
      // ruleid: typescript-detect-angular-resource-loading
      $sceDelegateProvider.resourceUrlBlacklist([
        'https://*.untrusted-domain.com/**'
      ]);
    }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_15() {
  // Using wildcards with multiple configurations in one module
  angular.module('myApp', [])
    .config(['$sceDelegateProvider', '$httpProvider', function($sceDelegateProvider, $httpProvider) {
      // Security configuration
      // ruleid: typescript-detect-angular-resource-loading
      $sceDelegateProvider.resourceUrlWhitelist([
        'self',
        'https://*.example.com/**',
        'data:**'
      ]);
      
      // HTTP configuration
      $httpProvider.defaults.withCredentials = true;
    }]);
}
// {/fact}

// Good case examples - Secure configurations without wildcards or with minimal scope

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_1() {
  // Using specific domains without wildcards
  const myAppModule = angular.module('myApp', [])
    .config(['$sceDelegateProvider', function($sceDelegateProvider) {
      // ok: typescript-detect-angular-resource-loading
      $sceDelegateProvider.resourceUrlWhitelist([
        'self',
        'https://api.example.com/resources/',
        'https://cdn.example.com/assets/'
      ]);
    }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_2() {
  // Using specific subdomains without wildcards
  const securityConfig = angular.module('securityConfig', [])
    .config(['$sceDelegateProvider', function($sceDelegateProvider) {
      // ok: typescript-detect-angular-resource-loading
      $sceDelegateProvider.resourceUrlWhitelist([
        'self',
        'https://api.example.com/v1/',
        'https://api.example.com/v2/',
        'https://static.example.com/resources/'
      ]);
    }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_3() {
  // Using specific paths without wildcards
  class SecurityModule {
    constructor() {
      angular.module('app.security', [])
        .config(['$sceDelegateProvider', function($sceDelegateProvider) {
          // ok: typescript-detect-angular-resource-loading
          $sceDelegateProvider.resourceUrlWhitelist([
            'self',
            'https://trusted-domain.com/api/public',
            'https://trusted-domain.com/api/resources'
          ]);
        }]);
    }
  }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_4() {
  // Using specific protocols and domains
  const configureApp = () => {
    angular.module('myApp', [])
      .config(['$sceDelegateProvider', function($sceDelegateProvider) {
        // ok: typescript-detect-angular-resource-loading
        $sceDelegateProvider.resourceUrlWhitelist([
          'self',
          'https://example.com/api/',
          'https://example.com/public/'
        ]);
      }]);
  };
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_5() {
  // Using specific domains in blacklist
  @NgModule({
    imports: [BrowserModule, HttpClientModule]
  })
  class AppModule {
    constructor() {
      angular.module('myApp', [])
        .config(['$sceDelegateProvider', function($sceDelegateProvider) {
          // ok: typescript-detect-angular-resource-loading
          $sceDelegateProvider.resourceUrlBlacklist([
            'https://evil.com/malicious-script.js',
            'https://phishing-site.com/'
          ]);
        }]);
    }
  }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_6() {
  // Using specific domains with variables
  const trustedDomains = [
    'https://trusted-source.com/api/',
    'https://trusted-source.com/public/'
  ];
  
  angular.module('myApp', [])
    .config(['$sceDelegateProvider', function($sceDelegateProvider) {
      // ok: typescript-detect-angular-resource-loading
      $sceDelegateProvider.resourceUrlWhitelist([
        'self',
        ...trustedDomains
      ]);
    }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_7() {
  // Using specific domains with conditional logic
  const isDevEnvironment = process.env.NODE_ENV === 'development';
  
  angular.module('myApp', [])
    .config(['$sceDelegateProvider', function($sceDelegateProvider) {
      const whitelist = ['self'];
      
      if (isDevEnvironment) {
        whitelist.push('http://localhost:4200/');
      } else {
        whitelist.push('https://production-domain.com/api/');
      }
      
      // ok: typescript-detect-angular-resource-loading
      $sceDelegateProvider.resourceUrlWhitelist(whitelist);
    }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_8() {
  // Using specific domains with template literals
  const domain = 'example';
  const tld = 'com';
  
  angular.module('myApp', [])
    .config(['$sceDelegateProvider', function($sceDelegateProvider) {
      // ok: typescript-detect-angular-resource-loading
      $sceDelegateProvider.resourceUrlWhitelist([
        'self',
        `https://${domain}.${tld}/api/`,
        `https://cdn.${domain}.${tld}/resources/`
      ]);
    }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_9() {
  // Using specific domains with function that returns configuration
  function getSecurityConfig() {
    return {
      whitelist: [
        'self',
        'https://trusted-domain.com/api/',
        'https://trusted-domain.com/public/'
      ]
    };
  }
  
  angular.module('myApp', [])
    .config(['$sceDelegateProvider', function($sceDelegateProvider) {
      const config = getSecurityConfig();
      // ok: typescript-detect-angular-resource-loading
      $sceDelegateProvider.resourceUrlWhitelist(config.whitelist);
    }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_10() {
  // Using specific domains with multiple protocols
  angular.module('myApp', [])
    .config(['$sceDelegateProvider', function($sceDelegateProvider) {
      // ok: typescript-detect-angular-resource-loading
      $sceDelegateProvider.resourceUrlWhitelist([
        'self',
        'http://example.com/api/',
        'https://example.com/api/',
        'ftp://example.com/public/'
      ]);
    }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_11() {
  // Using specific domains with array concatenation
  const baseWhitelist = ['self'];
  const additionalSources = [
    'https://cdn.com/resources/',
    'https://api.com/v1/'
  ];
  
  angular.module('myApp', [])
    .config(['$sceDelegateProvider', function($sceDelegateProvider) {
      // ok: typescript-detect-angular-resource-loading
      $sceDelegateProvider.resourceUrlWhitelist(
        baseWhitelist.concat(additionalSources)
      );
    }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_12() {
  // Using specific domains with class property
  class SecurityConfigService {
    private whitelist = [
      'self',
      'https://trusted-source.org/api/',
      'https://trusted-source.org/public/'
    ];
    
    configureApp() {
      angular.module('myApp', [])
        .config(['$sceDelegateProvider', function($sceDelegateProvider) {
          // ok: typescript-detect-angular-resource-loading
          $sceDelegateProvider.resourceUrlWhitelist(this.whitelist);
        }.bind(this)]);
    }
  }
  
  const securityService = new SecurityConfigService();
  securityService.configureApp();
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_13() {
  // Using specific domains with dynamic configuration based on environment
  const environments = {
    dev: {
      domains: [
        'https://dev-domain.com/api/',
        'https://dev-domain.com/assets/'
      ]
    },
    prod: {
      domains: [
        'https://prod-domain.com/api/',
        'https://prod-domain.com/assets/'
      ]
    }
  };
  
  const currentEnv = 'dev';
  
  angular.module('myApp', [])
    .config(['$sceDelegateProvider', function($sceDelegateProvider) {
      // ok: typescript-detect-angular-resource-loading
      $sceDelegateProvider.resourceUrlWhitelist([
        'self',
        ...environments[currentEnv].domains
      ]);
    }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_14() {
  // Using specific domains with both whitelist and blacklist
  angular.module('myApp', [])
    .config(['$sceDelegateProvider', function($sceDelegateProvider) {
      // ok: typescript-detect-angular-resource-loading
      $sceDelegateProvider.resourceUrlWhitelist([
        'self',
        'https://trusted-domain.com/api/',
        'https://trusted-domain.com/public/'
      ]);
      
      // ok: typescript-detect-angular-resource-loading
      $sceDelegateProvider.resourceUrlBlacklist([
        'https://untrusted-domain.com/script.js'
      ]);
    }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_15() {
  // Using specific domains with multiple configurations in one module
  angular.module('myApp', [])
    .config(['$sceDelegateProvider', '$httpProvider', function($sceDelegateProvider, $httpProvider) {
      // Security configuration
      // ok: typescript-detect-angular-resource-loading
      $sceDelegateProvider.resourceUrlWhitelist([
        'self',
        'https://example.com/api/',
        'https://example.com/public/',
        'data:image/png;base64,'
      ]);
      
      // HTTP configuration
      $httpProvider.defaults.withCredentials = true;
    }]);
}
// {/fact}