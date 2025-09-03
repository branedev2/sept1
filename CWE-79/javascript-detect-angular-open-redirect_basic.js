// File: angular-open-redirect-examples.js

// True Positive Examples (Vulnerable Code)

// Example 1: Direct use of URL parameter for redirection
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_1($scope, $window, $location) {
  $scope.redirectUser = function() {
    var redirectUrl = $location.search().redirectUrl;
    // ruleid: javascript-detect-angular-open-redirect
    $window.location.href = redirectUrl;
  };
}
// {/fact}

// Example 2: Using route parameters for redirection
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_2($scope, $window, $routeParams) {
  $scope.navigateToProfile = function() {
    var destination = $routeParams.destination;
    // ruleid: javascript-detect-angular-open-redirect
    $window.location.href = destination;
  };
}
// {/fact}

// Example 3: Using form input for redirection
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_3($scope, $window) {
  $scope.processForm = function() {
    var userInput = $scope.formData.redirectTo;
    // ruleid: javascript-detect-angular-open-redirect
    $window.location.href = userInput;
  };
}
// {/fact}

// Example 4: Using query parameters with string concatenation
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_4($scope, $window, $location) {
  $scope.redirect = function() {
    var path = $location.search().path;
    // ruleid: javascript-detect-angular-open-redirect
    $window.location.href = "https://example.com/" + path;
  };
}
// {/fact}

// Example 5: Using hash fragment from URL
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_5($scope, $window, $location) {
  $scope.goToSection = function() {
    var section = $location.hash();
    // ruleid: javascript-detect-angular-open-redirect
    $window.location.href = section;
  };
}
// {/fact}

// Example 6: Using URL parameter with template literals
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_6($scope, $window, $location) {
  $scope.navigateTo = function() {
    const target = $location.search().target;
    // ruleid: javascript-detect-angular-open-redirect
    $window.location.href = `${target}`;
  };
}
// {/fact}

// Example 7: Using URL parameter after basic string operations
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_7($scope, $window, $location) {
  $scope.goToPage = function() {
    var page = $location.search().page;
    page = page.trim();
    // ruleid: javascript-detect-angular-open-redirect
    $window.location.href = page;
  };
}
// {/fact}

// Example 8: Using URL parameter with conditional logic
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_8($scope, $window, $location) {
  $scope.conditionalRedirect = function() {
    var destination = $location.search().dest;
    if (destination) {
      // ruleid: javascript-detect-angular-open-redirect
      $window.location.href = destination;
    } else {
      $window.location.href = "/home";
    }
  };
}
// {/fact}

// Example 9: Using URL parameter from a service
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_9(RedirectService, $window) {
  this.performRedirect = function() {
    var url = RedirectService.getRedirectUrlFromUserInput();
    // ruleid: javascript-detect-angular-open-redirect
    $window.location.href = url;
  };
}
// {/fact}

// Example 10: Using URL parameter with promise
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_10($scope, $window, $http, $location) {
  $scope.fetchAndRedirect = function() {
    var targetId = $location.search().id;
    $http.get('/api/getUrl/' + targetId).then(function(response) {
      // ruleid: javascript-detect-angular-open-redirect
      $window.location.href = response.data.url;
    });
  };
}
// {/fact}

// Example 11: Using URL parameter with setTimeout
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_11($scope, $window, $location) {
  $scope.delayedRedirect = function() {
    var target = $location.search().target;
    setTimeout(function() {
      // ruleid: javascript-detect-angular-open-redirect
      $window.location.href = target;
    }, 1000);
  };
}
// {/fact}

// Example 12: Using URL parameter with object property access
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_12($scope, $window, $location) {
  $scope.redirectToSection = function() {
    var params = {
      destination: $location.search().destination
    };
    // ruleid: javascript-detect-angular-open-redirect
    $window.location.href = params.destination;
  };
}
// {/fact}

// Example 13: Using URL parameter with array indexing
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_13($scope, $window, $location) {
  $scope.multiRedirect = function() {
    var destinations = [$location.search().primary, $location.search().secondary];
    // ruleid: javascript-detect-angular-open-redirect
    $window.location.href = destinations[0];
  };
}
// {/fact}

// Example 14: Using URL parameter with ternary operator
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_14($scope, $window, $location) {
  $scope.smartRedirect = function() {
    var primary = $location.search().primary;
    var secondary = $location.search().secondary;
    // ruleid: javascript-detect-angular-open-redirect
    $window.location.href = primary ? primary : secondary;
  };
}
// {/fact}

// Example 15: Using URL parameter with destructuring
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_15($scope, $window, $location) {
  $scope.modernRedirect = function() {
    const { redirect } = { redirect: $location.search().redirect };
    // ruleid: javascript-detect-angular-open-redirect
    $window.location.href = redirect;
  };
}
// {/fact}

// True Negative Examples (Safe Code)

// Example 1: Using a whitelist for redirection URLs
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_1($scope, $window, $location) {
  $scope.redirectUser = function() {
    var redirectUrl = $location.search().redirectUrl;
    var allowedDomains = ['example.com', 'trusted-site.org', 'safe-domain.net'];
    
    var isAllowed = false;
    try {
      var urlObj = new URL(redirectUrl);
      isAllowed = allowedDomains.some(domain => urlObj.hostname === domain || urlObj.hostname.endsWith('.' + domain));
    } catch (e) {
      // Invalid URL, not allowed
    }
    
    // ok: javascript-detect-angular-open-redirect
    $window.location.href = isAllowed ? redirectUrl : '/default';
  };
}
// {/fact}

// Example 2: Using relative paths only
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_2($scope, $window, $location) {
  $scope.navigateToProfile = function() {
    var page = $location.search().page;
    // Ensure we only use relative paths
    if (page && page.startsWith('/') && !page.includes('://')) {
      // ok: javascript-detect-angular-open-redirect
      $window.location.href = page;
    } else {
      $window.location.href = '/home';
    }
  };
}
// {/fact}

// Example 3: Using hardcoded URLs
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_3($scope, $window) {
  $scope.goToLogin = function() {
    // ok: javascript-detect-angular-open-redirect
    $window.location.href = '/login';
  };
}
// {/fact}

// Example 4: Using a URL builder function
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_4($scope, $window, $location) {
  $scope.redirect = function() {
    var section = $location.search().section;
    
    function buildSafeUrl(section) {
      // Only allow specific sections
      var allowedSections = ['profile', 'settings', 'dashboard'];
      if (allowedSections.includes(section)) {
        return '/app/' + section;
      }
      return '/app/home';
    }
    
    // ok: javascript-detect-angular-open-redirect
    $window.location.href = buildSafeUrl(section);
  };
}
// {/fact}

// Example 5: Using a validation function
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_5($scope, $window, $location) {
  $scope.goToSection = function() {
    var url = $location.search().url;
    
    function isValidUrl(url) {
      // Only allow URLs from our domain
      if (!url) return false;
      try {
        const urlObj = new URL(url, window.location.origin);
        return urlObj.origin === window.location.origin;
      } catch (e) {
        return false;
      }
    }
    
    // ok: javascript-detect-angular-open-redirect
    $window.location.href = isValidUrl(url) ? url : '/home';
  };
}
// {/fact}

// Example 6: Using Angular's built-in routing instead of direct location change
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_6($scope, $location) {
  $scope.navigateTo = function() {
    var page = $location.search().page;
    var validPages = ['home', 'profile', 'settings', 'help'];
    
    // ok: javascript-detect-angular-open-redirect
    if (validPages.includes(page)) {
      $location.path('/' + page);
    } else {
      $location.path('/home');
    }
  };
}
// {/fact}

// Example 7: Using a mapping object for allowed redirects
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_7($scope, $window, $location) {
  $scope.goToPage = function() {
    var pageKey = $location.search().page;
    
    var pageMap = {
      'profile': '/user/profile',
      'settings': '/user/settings',
      'dashboard': '/user/dashboard',
      'help': '/support/help'
    };
    
    // ok: javascript-detect-angular-open-redirect
    $window.location.href = pageMap[pageKey] || '/home';
  };
}
// {/fact}

// Example 8: Using regex pattern matching for validation
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_8($scope, $window, $location) {
  $scope.conditionalRedirect = function() {
    var path = $location.search().path;
    
    // Only allow paths that match our expected format
    var validPathPattern = /^\/[a-zA-Z0-9\-\_\/]+$/;
    
    // ok: javascript-detect-angular-open-redirect
    if (path && validPathPattern.test(path)) {
      $window.location.href = path;
    } else {
      $window.location.href = '/home';
    }
  };
}
// {/fact}

// Example 9: Using a service with validation
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_9(RedirectService, $window) {
  this.performRedirect = function() {
    var url = RedirectService.getRedirectUrl();
    
    // The service handles validation internally
    // ok: javascript-detect-angular-open-redirect
    $window.location.href = url;
  };
}
// {/fact}

// Example 10: Using a promise with validation
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_10($scope, $window, $http, $location) {
  $scope.fetchAndRedirect = function() {
    var targetId = $location.search().id;
    
    $http.get('/api/getUrl/' + targetId).then(function(response) {
      var url = response.data.url;
      var isInternal = url.startsWith('/') && !url.includes('://');
      
      // ok: javascript-detect-angular-open-redirect
      $window.location.href = isInternal ? url : '/default';
    });
  };
}
// {/fact}

// Example 11: Using URL constructor for validation
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_11($scope, $window, $location) {
  $scope.safeRedirect = function() {
    var destination = $location.search().destination;
    
    try {
      var url = new URL(destination, window.location.origin);
      // Only allow same-origin URLs
      if (url.origin === window.location.origin) {
        // ok: javascript-detect-angular-open-redirect
        $window.location.href = url.href;
      } else {
        $window.location.href = '/';
      }
    } catch (e) {
      $window.location.href = '/';
    }
  };
}
// {/fact}

// Example 12: Using path normalization and validation
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_12($scope, $window, $location) {
  $scope.redirectToSection = function() {
    var path = $location.search().path || '';
    
    // Remove any protocol, domain, query params, or hash
    function normalizePath(path) {
      try {
        var url = new URL(path, 'http://example.com');
        return url.pathname;
      } catch (e) {
        // If it's not a valid URL, just take it as a path
        return path.split('?')[0].split('#')[0];
      }
    }
    
    var normalizedPath = normalizePath(path);
    
    // Ensure it's a relative path and doesn't try to go up directories
    if (normalizedPath.startsWith('/') && !normalizedPath.includes('..')) {
      // ok: javascript-detect-angular-open-redirect
      $window.location.href = normalizedPath;
    } else {
      $window.location.href = '/home';
    }
  };
}
// {/fact}

// Example 13: Using a security utility function
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_13($scope, $window, $location, SecurityUtils) {
  $scope.secureRedirect = function() {
    var url = $location.search().url;
    
    // SecurityUtils.validateRedirectUrl returns a safe URL or a default
    // ok: javascript-detect-angular-open-redirect
    $window.location.href = SecurityUtils.validateRedirectUrl(url, '/default');
  };
}
// {/fact}

// Example 14: Using strict origin checking
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_14($scope, $window, $location) {
  $scope.redirectExternal = function() {
    var externalUrl = $location.search().externalUrl;
    
    function isTrustedDomain(url) {
      var trustedDomains = ['partner.example.com', 'api.trusted-site.org'];
      try {
        var urlObj = new URL(url);
        return trustedDomains.includes(urlObj.hostname);
      } catch (e) {
        return false;
      }
    }
    
    // ok: javascript-detect-angular-open-redirect
    if (externalUrl && isTrustedDomain(externalUrl)) {
      $window.location.href = externalUrl;
    } else {
      $window.location.href = '/home';
    }
  };
}
// {/fact}

// Example 15: Using Angular's $sce service for URL sanitization
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_15($scope, $window, $location, $sce) {
  $scope.trustedRedirect = function() {
    var redirectUrl = $location.search().redirectUrl;
    
    // Only allow URLs within our application
    if (redirectUrl && redirectUrl.startsWith('/')) {
      // ok: javascript-detect-angular-open-redirect
      $window.location.href = $sce.trustAsResourceUrl(redirectUrl);
    } else {
      $window.location.href = '/home';
    }
  };
}
// {/fact}