// angular-sce-test-cases.js

// Import Angular for context
// Note: In real applications, this would typically be included via a script tag in HTML

// True Positive Examples (Vulnerable Code)

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_1() {
  // Basic case of disabling SCE in an Angular module configuration
  angular.module('myApp', [])
    .config(['$sceProvider', function($sceProvider) {
      // ruleid: javascript-detect-angular-sce-disabled
      $sceProvider.enabled(false);
    }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_2() {
  // Disabling SCE with a variable
  angular.module('insecureApp', [])
    .config(function($sceProvider) {
      var securityEnabled = false;
      // ruleid: javascript-detect-angular-sce-disabled
      $sceProvider.enabled(securityEnabled);
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_3() {
  // Disabling SCE in a more complex config with multiple providers
  angular.module('multiConfigApp', ['ngRoute'])
    .config(['$routeProvider', '$sceProvider', function($routeProvider, $sceProvider) {
      $routeProvider.when('/', {
        templateUrl: 'home.html',
        controller: 'HomeController'
      });
      
      // ruleid: javascript-detect-angular-sce-disabled
      $sceProvider.enabled(false);
    }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_4() {
  // Disabling SCE with a conditional that always evaluates to false
  angular.module('conditionalApp', [])
    .config(['$sceProvider', function($sceProvider) {
      var debugMode = true;
      var productionMode = false;
      
      if (debugMode && !productionMode) {
        // ruleid: javascript-detect-angular-sce-disabled
        $sceProvider.enabled(false);
      }
    }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_5() {
  // Disabling SCE with a function that returns false
  angular.module('functionApp', [])
    .config(['$sceProvider', function($sceProvider) {
      function getSceConfig() {
        return false;
      }
      
      // ruleid: javascript-detect-angular-sce-disabled
      $sceProvider.enabled(getSceConfig());
    }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_6() {
  // Disabling SCE with a ternary operator
  angular.module('ternaryApp', [])
    .config(['$sceProvider', function($sceProvider) {
      var isProduction = false;
      
      // ruleid: javascript-detect-angular-sce-disabled
      $sceProvider.enabled(isProduction ? true : false);
    }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_7() {
  // Disabling SCE with object property
  angular.module('objectPropApp', [])
    .config(['$sceProvider', function($sceProvider) {
      var config = {
        security: {
          sceEnabled: false
        }
      };
      
      // ruleid: javascript-detect-angular-sce-disabled
      $sceProvider.enabled(config.security.sceEnabled);
    }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_8() {
  // Disabling SCE with logical NOT operator
  angular.module('notOperatorApp', [])
    .config(['$sceProvider', function($sceProvider) {
      var enableSecurity = false;
      
      // ruleid: javascript-detect-angular-sce-disabled
      $sceProvider.enabled(!!enableSecurity);
    }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_9() {
  // Disabling SCE with environment-based configuration
  angular.module('envApp', [])
    .config(['$sceProvider', function($sceProvider) {
      var env = {
        name: 'development',
        securityEnabled: false
      };
      
      // ruleid: javascript-detect-angular-sce-disabled
      $sceProvider.enabled(env.securityEnabled);
    }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_10() {
  // Disabling SCE with array access
  angular.module('arrayApp', [])
    .config(['$sceProvider', function($sceProvider) {
      var securitySettings = [true, false, true];
      
      // ruleid: javascript-detect-angular-sce-disabled
      $sceProvider.enabled(securitySettings[1]);
    }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_11() {
  // Disabling SCE with a more complex expression
  angular.module('complexApp', [])
    .config(['$sceProvider', function($sceProvider) {
      var a = true;
      var b = false;
      
      // ruleid: javascript-detect-angular-sce-disabled
      $sceProvider.enabled(a && b);
    }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_12() {
  // Disabling SCE with bitwise operations
  angular.module('bitwiseApp', [])
    .config(['$sceProvider', function($sceProvider) {
      var flags = 0;
      
      // ruleid: javascript-detect-angular-sce-disabled
      $sceProvider.enabled(flags & 1);
    }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_13() {
  // Disabling SCE with a computed property
  angular.module('computedPropApp', [])
    .config(['$sceProvider', function($sceProvider) {
      var settings = {
        getSecurity: function() {
          return false;
        }
      };
      
      // ruleid: javascript-detect-angular-sce-disabled
      $sceProvider.enabled(settings.getSecurity());
    }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_14() {
  // Disabling SCE with string conversion
  angular.module('stringConversionApp', [])
    .config(['$sceProvider', function($sceProvider) {
      var securityFlag = "false";
      
      // ruleid: javascript-detect-angular-sce-disabled
      $sceProvider.enabled(securityFlag === "true");
    }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_15() {
  // Disabling SCE with multiple module configurations
  var app = angular.module('multiModuleApp', []);
  
  app.config(['$compileProvider', function($compileProvider) {
    $compileProvider.debugInfoEnabled(true);
  }]);
  
  app.config(['$sceProvider', function($sceProvider) {
    // ruleid: javascript-detect-angular-sce-disabled
    $sceProvider.enabled(false);
  }]);
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_1() {
  // Basic case of keeping SCE enabled
  angular.module('secureApp', [])
    .config(['$sceProvider', function($sceProvider) {
      // ok: javascript-detect-angular-sce-disabled
      $sceProvider.enabled(true);
    }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_2() {
  // Explicitly enabling SCE with a variable
  angular.module('explicitSecureApp', [])
    .config(function($sceProvider) {
      var securityEnabled = true;
      // ok: javascript-detect-angular-sce-disabled
      $sceProvider.enabled(securityEnabled);
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_3() {
  // Not modifying SCE settings (defaults to enabled)
  angular.module('defaultSecureApp', [])
    .config(['$routeProvider', function($routeProvider) {
      $routeProvider.when('/', {
        templateUrl: 'home.html',
        controller: 'HomeController'
      });
      // SCE remains enabled by default
    }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_4() {
  // Enabling SCE with a conditional
  angular.module('conditionalSecureApp', [])
    .config(['$sceProvider', function($sceProvider) {
      var isProduction = true;
      
      if (isProduction) {
        // ok: javascript-detect-angular-sce-disabled
        $sceProvider.enabled(true);
      }
    }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_5() {
  // Enabling SCE with a function that returns true
  angular.module('functionSecureApp', [])
    .config(['$sceProvider', function($sceProvider) {
      function getSceConfig() {
        return true;
      }
      
      // ok: javascript-detect-angular-sce-disabled
      $sceProvider.enabled(getSceConfig());
    }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_6() {
  // Enabling SCE with a ternary operator
  angular.module('ternarySecureApp', [])
    .config(['$sceProvider', function($sceProvider) {
      var isProduction = true;
      
      // ok: javascript-detect-angular-sce-disabled
      $sceProvider.enabled(isProduction ? true : false);
    }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_7() {
  // Enabling SCE with object property
  angular.module('objectPropSecureApp', [])
    .config(['$sceProvider', function($sceProvider) {
      var config = {
        security: {
          sceEnabled: true
        }
      };
      
      // ok: javascript-detect-angular-sce-disabled
      $sceProvider.enabled(config.security.sceEnabled);
    }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_8() {
  // Using SCE with trusted resources
  angular.module('trustedResourceApp', ['ngSanitize'])
    .controller('MainController', ['$scope', '$sce', function($scope, $sce) {
      // Using SCE properly to mark trusted HTML
      $scope.trustedHtml = $sce.trustAsHtml('<b>Trusted HTML</b>');
    }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_9() {
  // Using SCE with environment-based configuration that keeps it enabled
  angular.module('secureEnvApp', [])
    .config(['$sceProvider', function($sceProvider) {
      var env = {
        name: 'production',
        securityEnabled: true
      };
      
      // ok: javascript-detect-angular-sce-disabled
      $sceProvider.enabled(env.securityEnabled);
    }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_10() {
  // Using SCE with array access that keeps it enabled
  angular.module('secureArrayApp', [])
    .config(['$sceProvider', function($sceProvider) {
      var securitySettings = [true, false, true];
      
      // ok: javascript-detect-angular-sce-disabled
      $sceProvider.enabled(securitySettings[0]);
    }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_11() {
  // Using SCE with a complex expression that evaluates to true
  angular.module('secureComplexApp', [])
    .config(['$sceProvider', function($sceProvider) {
      var a = true;
      var b = true;
      
      // ok: javascript-detect-angular-sce-disabled
      $sceProvider.enabled(a && b);
    }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_12() {
  // Using SCE with bitwise operations that evaluate to true
  angular.module('secureBitwiseApp', [])
    .config(['$sceProvider', function($sceProvider) {
      var flags = 1;
      
      // ok: javascript-detect-angular-sce-disabled
      $sceProvider.enabled(flags & 1);
    }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_13() {
  // Using SCE with a computed property that returns true
  angular.module('secureComputedPropApp', [])
    .config(['$sceProvider', function($sceProvider) {
      var settings = {
        getSecurity: function() {
          return true;
        }
      };
      
      // ok: javascript-detect-angular-sce-disabled
      $sceProvider.enabled(settings.getSecurity());
    }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_14() {
  // Using SCE with string conversion that evaluates to true
  angular.module('secureStringConversionApp', [])
    .config(['$sceProvider', function($sceProvider) {
      var securityFlag = "true";
      
      // ok: javascript-detect-angular-sce-disabled
      $sceProvider.enabled(securityFlag === "true");
    }]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_15() {
  // Using SCE with multiple module configurations, all secure
  var app = angular.module('secureMultiModuleApp', []);
  
  app.config(['$compileProvider', function($compileProvider) {
    $compileProvider.debugInfoEnabled(false);
  }]);
  
  app.config(['$sceProvider', function($sceProvider) {
    // ok: javascript-detect-angular-sce-disabled
    $sceProvider.enabled(true);
  }]);
}
// {/fact}