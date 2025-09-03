// Angular SCE (Strict Contextual Escaping) Resource Loading Test Cases

// True Positives (Vulnerable Code)

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_1() {
  angular.module('myApp', [])
    .config(['$sceDelegateProvider', function($sceDelegateProvider) {
      // ruleid: javascript-detect-angular-resource-loading
      $sceDelegateProvider.resourceUrlWhitelist([
        'self',
        'http://**'  // Using wildcard for all HTTP domains
      ]);
    }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_2() {
  angular.module('securityApp', [])
    .config(['$sceDelegateProvider', function($sceDelegateProvider) {
      // ruleid: javascript-detect-angular-resource-loading
      $sceDelegateProvider.resourceUrlWhitelist([
        'self',
        'https://*.example.com/**'  // Wildcard for subdomains and paths
      ]);
    }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_3() {
  let app = angular.module('dashboardApp', []);
  app.config(['$sceDelegateProvider', function($sceDelegateProvider) {
    // ruleid: javascript-detect-angular-resource-loading
    $sceDelegateProvider.resourceUrlWhitelist([
      'self',
      '**'  // Extremely dangerous - allows all URLs
    ]);
  }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_4() {
  const myModule = angular.module('apiClient', []);
  myModule.config(function($sceDelegateProvider) {
    const domain = 'api.example.com';
    // ruleid: javascript-detect-angular-resource-loading
    $sceDelegateProvider.resourceUrlWhitelist([
      'self',
      `https://${domain}/**`  // Still using wildcards even with template literals
    ]);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_5() {
  angular.module('adminPanel', ['ngSanitize'])
    .config(['$sceDelegateProvider', function($sceDelegateProvider) {
      // ruleid: javascript-detect-angular-resource-loading
      $sceDelegateProvider.resourceUrlWhitelist(['**']);  // Single wildcard entry
    }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_6() {
  const trustedDomains = ['api.example.com', 'cdn.example.com'];
  
  angular.module('multiApiApp', [])
    .config(['$sceDelegateProvider', function($sceDelegateProvider) {
      const whitelist = ['self'];
      trustedDomains.forEach(domain => {
        whitelist.push(`https://${domain}/**`);  // Adding wildcards in a loop
      });
      
      // ruleid: javascript-detect-angular-resource-loading
      $sceDelegateProvider.resourceUrlWhitelist(whitelist);
    }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_7() {
  angular.module('hybridApp', [])
    .config(['$sceDelegateProvider', '$httpProvider', function($sceDelegateProvider, $httpProvider) {
      $httpProvider.defaults.useXDomain = true;
      // ruleid: javascript-detect-angular-resource-loading
      $sceDelegateProvider.resourceUrlWhitelist([
        'self',
        'http://legacy-api.example.org/**',  // Wildcard for HTTP endpoint
        'https://new-api.example.com/**'     // Wildcard for HTTPS endpoint
      ]);
    }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_8() {
  const envConfig = {
    isDevelopment: true,
    apiUrl: 'dev-api.example.com'
  };
  
  angular.module('configApp', [])
    .config(['$sceDelegateProvider', function($sceDelegateProvider) {
      const whitelist = ['self'];
      
      if (envConfig.isDevelopment) {
        whitelist.push(`http://${envConfig.apiUrl}/**`);  // Conditional wildcard based on environment
      } else {
        whitelist.push(`https://${envConfig.apiUrl}/**`);  // Still using wildcards
      }
      
      // ruleid: javascript-detect-angular-resource-loading
      $sceDelegateProvider.resourceUrlWhitelist(whitelist);
    }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_9() {
  angular.module('videoApp', [])
    .config(['$sceDelegateProvider', function($sceDelegateProvider) {
      // ruleid: javascript-detect-angular-resource-loading
      $sceDelegateProvider.resourceUrlWhitelist([
        'self',
        'https://www.youtube.com/embed/**',  // Wildcard for YouTube embeds
        'https://player.vimeo.com/video/**'  // Wildcard for Vimeo embeds
      ]);
    }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_10() {
  const securityConfig = {
    allowedDomains: ['api.example.com', 'static.example.com', 'cdn.example.net']
  };
  
  angular.module('enterpriseApp', [])
    .config(['$sceDelegateProvider', function($sceDelegateProvider) {
      const whitelist = ['self'];
      
      securityConfig.allowedDomains.forEach(domain => {
        if (domain.includes('example.com')) {
          whitelist.push(`https://${domain}/**`);  // Adding wildcards for specific domains
        }
      });
      
      // ruleid: javascript-detect-angular-resource-loading
      $sceDelegateProvider.resourceUrlWhitelist(whitelist);
    }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_11() {
  angular.module('legacySupport', [])
    .config(['$sceDelegateProvider', function($sceDelegateProvider) {
      const protocol = window.location.protocol;
      const baseUrl = protocol + '//api.example.com';
      
      // ruleid: javascript-detect-angular-resource-loading
      $sceDelegateProvider.resourceUrlWhitelist([
        'self',
        baseUrl + '/**'  // Dynamic protocol with wildcard
      ]);
    }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_12() {
  angular.module('i18nApp', [])
    .config(['$sceDelegateProvider', function($sceDelegateProvider) {
      const regions = ['us', 'eu', 'asia'];
      const whitelist = ['self'];
      
      regions.forEach(region => {
        whitelist.push(`https://${region}-api.example.com/**`);  // Regional APIs with wildcards
      });
      
      // ruleid: javascript-detect-angular-resource-loading
      $sceDelegateProvider.resourceUrlWhitelist(whitelist);
    }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_13() {
  angular.module('thirdPartyIntegration', [])
    .config(['$sceDelegateProvider', function($sceDelegateProvider) {
      // ruleid: javascript-detect-angular-resource-loading
      $sceDelegateProvider.resourceUrlWhitelist([
        'self',
        'https://api.stripe.com/**',  // Payment processor with wildcard
        'https://maps.googleapis.com/**'  // Maps API with wildcard
      ]);
    }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_14() {
  const wildcardPattern = '**';  // Extracting the wildcard to a variable
  
  angular.module('obfuscatedApp', [])
    .config(['$sceDelegateProvider', function($sceDelegateProvider) {
      // ruleid: javascript-detect-angular-resource-loading
      $sceDelegateProvider.resourceUrlWhitelist([
        'self',
        'https://api.example.com/' + wildcardPattern  // Concatenating the wildcard
      ]);
    }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_15() {
  angular.module('mixedContentApp', [])
    .config(['$sceDelegateProvider', function($sceDelegateProvider) {
      const whitelist = [
        'self',
        'https://secure.example.com/api/v1/endpoint',  // Specific endpoint (safe)
        'https://cdn.example.com/**'  // CDN with wildcard (unsafe)
      ];
      
      // ruleid: javascript-detect-angular-resource-loading
      $sceDelegateProvider.resourceUrlWhitelist(whitelist);
    }]);
}
// {/fact}

// True Negatives (Secure Code)

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_1() {
  angular.module('myApp', [])
    .config(['$sceDelegateProvider', function($sceDelegateProvider) {
      // ok: javascript-detect-angular-resource-loading
      $sceDelegateProvider.resourceUrlWhitelist([
        'self',
        'https://api.example.com/v1/endpoint'  // Specific URL without wildcards
      ]);
    }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_2() {
  angular.module('securityApp', [])
    .config(['$sceDelegateProvider', function($sceDelegateProvider) {
      // ok: javascript-detect-angular-resource-loading
      $sceDelegateProvider.resourceUrlWhitelist([
        'self',
        'https://cdn.example.com/assets/scripts/main.js',
        'https://cdn.example.com/assets/styles/main.css'
      ]);
    }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_3() {
  let app = angular.module('dashboardApp', []);
  app.config(['$sceDelegateProvider', function($sceDelegateProvider) {
    // ok: javascript-detect-angular-resource-loading
    $sceDelegateProvider.resourceUrlWhitelist([
      'self'  // Only allowing same-origin resources
    ]);
  }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_4() {
  const myModule = angular.module('apiClient', []);
  myModule.config(function($sceDelegateProvider) {
    const domain = 'api.example.com';
    // ok: javascript-detect-angular-resource-loading
    $sceDelegateProvider.resourceUrlWhitelist([
      'self',
      `https://${domain}/v1/data`,
      `https://${domain}/v1/users`
    ]);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_5() {
  angular.module('adminPanel', ['ngSanitize'])
    .config(['$sceDelegateProvider', function($sceDelegateProvider) {
      // ok: javascript-detect-angular-resource-loading
      $sceDelegateProvider.resourceUrlWhitelist([
        'self',
        'https://admin-api.example.com/v1/dashboard',
        'https://admin-api.example.com/v1/reports'
      ]);
    }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_6() {
  const trustedEndpoints = [
    'https://api.example.com/v1/users',
    'https://api.example.com/v1/products',
    'https://api.example.com/v1/orders'
  ];
  
  angular.module('multiApiApp', [])
    .config(['$sceDelegateProvider', function($sceDelegateProvider) {
      const whitelist = ['self'].concat(trustedEndpoints);
      
      // ok: javascript-detect-angular-resource-loading
      $sceDelegateProvider.resourceUrlWhitelist(whitelist);
    }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_7() {
  angular.module('hybridApp', [])
    .config(['$sceDelegateProvider', '$httpProvider', function($sceDelegateProvider, $httpProvider) {
      $httpProvider.defaults.useXDomain = true;
      // ok: javascript-detect-angular-resource-loading
      $sceDelegateProvider.resourceUrlWhitelist([
        'self',
        'https://legacy-api.example.org/v1/data',
        'https://new-api.example.com/v2/data'
      ]);
    }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_8() {
  const envConfig = {
    isDevelopment: true,
    apiEndpoints: [
      'https://dev-api.example.com/v1/users',
      'https://dev-api.example.com/v1/products'
    ]
  };
  
  angular.module('configApp', [])
    .config(['$sceDelegateProvider', function($sceDelegateProvider) {
      // ok: javascript-detect-angular-resource-loading
      $sceDelegateProvider.resourceUrlWhitelist(['self'].concat(envConfig.apiEndpoints));
    }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_9() {
  angular.module('videoApp', [])
    .config(['$sceDelegateProvider', function($sceDelegateProvider) {
      // ok: javascript-detect-angular-resource-loading
      $sceDelegateProvider.resourceUrlWhitelist([
        'self',
        'https://www.youtube.com/embed/dQw4w9WgXcQ',  // Specific YouTube video
        'https://player.vimeo.com/video/123456789'    // Specific Vimeo video
      ]);
    }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_10() {
  const securityConfig = {
    allowedEndpoints: [
      'https://api.example.com/v1/data',
      'https://static.example.com/assets/main.js',
      'https://cdn.example.net/styles/main.css'
    ]
  };
  
  angular.module('enterpriseApp', [])
    .config(['$sceDelegateProvider', function($sceDelegateProvider) {
      // ok: javascript-detect-angular-resource-loading
      $sceDelegateProvider.resourceUrlWhitelist(['self'].concat(securityConfig.allowedEndpoints));
    }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_11() {
  angular.module('legacySupport', [])
    .config(['$sceDelegateProvider', function($sceDelegateProvider) {
      const protocol = window.location.protocol;
      const baseUrl = protocol + '//api.example.com';
      
      // ok: javascript-detect-angular-resource-loading
      $sceDelegateProvider.resourceUrlWhitelist([
        'self',
        baseUrl + '/v1/data',
        baseUrl + '/v1/users'
      ]);
    }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_12() {
  angular.module('i18nApp', [])
    .config(['$sceDelegateProvider', function($sceDelegateProvider) {
      const regions = ['us', 'eu', 'asia'];
      const whitelist = ['self'];
      
      regions.forEach(region => {
        whitelist.push(`https://${region}-api.example.com/v1/translations`);
        whitelist.push(`https://${region}-api.example.com/v1/locales`);
      });
      
      // ok: javascript-detect-angular-resource-loading
      $sceDelegateProvider.resourceUrlWhitelist(whitelist);
    }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_13() {
  angular.module('thirdPartyIntegration', [])
    .config(['$sceDelegateProvider', function($sceDelegateProvider) {
      // ok: javascript-detect-angular-resource-loading
      $sceDelegateProvider.resourceUrlWhitelist([
        'self',
        'https://api.stripe.com/v1/charges',
        'https://maps.googleapis.com/maps/api/js'
      ]);
    }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_14() {
  // Using a function to generate specific allowed URLs
  function generateAllowedUrls() {
    const baseUrl = 'https://api.example.com';
    return [
      `${baseUrl}/v1/users`,
      `${baseUrl}/v1/products`,
      `${baseUrl}/v1/orders`
    ];
  }
  
  angular.module('dynamicUrlsApp', [])
    .config(['$sceDelegateProvider', function($sceDelegateProvider) {
      // ok: javascript-detect-angular-resource-loading
      $sceDelegateProvider.resourceUrlWhitelist(['self'].concat(generateAllowedUrls()));
    }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_15() {
  angular.module('mixedContentApp', [])
    .config(['$sceDelegateProvider', function($sceDelegateProvider) {
      // Using a more complex setup with specific endpoints
      const apiVersion = 'v1';
      const cdnVersion = '2023-05';
      
      // ok: javascript-detect-angular-resource-loading
      $sceDelegateProvider.resourceUrlWhitelist([
        'self',
        `https://secure.example.com/api/${apiVersion}/endpoint`,
        `https://cdn.example.com/assets/${cdnVersion}/scripts/main.js`,
        `https://cdn.example.com/assets/${cdnVersion}/styles/main.css`
      ]);
    }]);
}
// {/fact}