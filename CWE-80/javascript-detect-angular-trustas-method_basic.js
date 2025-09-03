// Angular $sce.trustAs vulnerability test cases
// This file contains examples of secure and insecure uses of Angular's $sce.trustAs method

// ===== TRUE POSITIVES (VULNERABLE CODE) =====

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_1($sce, $http) {
  // Getting user input from URL parameter and passing directly to trustAs
  $http.get('/api/user-data').then(function(response) {
    const userData = response.data.userContent;
    // ruleid: javascript-detect-angular-trustas-method
    const trustedHtml = $sce.trustAs($sce.HTML, userData);
    document.getElementById('user-content').innerHTML = trustedHtml;
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_2($sce) {
  // Getting user input from a form and passing directly to trustAs
  const userInput = document.getElementById('user-comment').value;
  // ruleid: javascript-detect-angular-trustas-method
  const trustedJs = $sce.trustAs($sce.JS, userInput);
  eval(trustedJs);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_3($sce, $http) {
  // Getting user input from query parameters and passing to trustAs
  const urlParams = new URLSearchParams(window.location.search);
  const userHtml = urlParams.get('content');
  // ruleid: javascript-detect-angular-trustas-method
  return $sce.trustAs($sce.HTML, userHtml);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_4($sce, $http) {
  // Getting user input from AJAX request and passing to trustAs after minimal processing
  $http.post('/api/comments').then(function(response) {
    const userComment = response.data.comment;
    const processedComment = userComment.toUpperCase();
    // ruleid: javascript-detect-angular-trustas-method
    const trusted = $sce.trustAs($sce.HTML, processedComment);
    angular.element(document.querySelector('#comments')).append(trusted);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_5($sce) {
  // Getting user input from localStorage (which could have been set by user)
  const storedTemplate = localStorage.getItem('userTemplate');
  // ruleid: javascript-detect-angular-trustas-method
  const trustedTemplate = $sce.trustAs($sce.HTML, storedTemplate);
  document.getElementById('template-container').innerHTML = trustedTemplate;
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_6($sce, $cookies) {
  // Getting user input from cookies and passing to trustAs
  const userStyle = $cookies.get('userStyle');
  // ruleid: javascript-detect-angular-trustas-method
  const trustedStyle = $sce.trustAs($sce.CSS, userStyle);
  angular.element(document.querySelector('#user-styles')).append(trustedStyle);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_7($sce, $http) {
  // Getting user input from headers and passing to trustAs
  $http.get('/api/user-profile', {
    headers: { 'X-Custom-Header': 'some-value' }
  }).then(function(response) {
    const headerValue = response.headers('X-User-Content');
    // ruleid: javascript-detect-angular-trustas-method
    const trustedUrl = $sce.trustAs($sce.RESOURCE_URL, headerValue);
    document.getElementById('user-iframe').src = trustedUrl;
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_8($sce) {
  // Getting user input from WebSocket and passing to trustAs
  const socket = new WebSocket('ws://example.com/socket');
  socket.onmessage = function(event) {
    const userMessage = JSON.parse(event.data).message;
    // ruleid: javascript-detect-angular-trustas-method
    const trustedHtml = $sce.trustAs($sce.HTML, userMessage);
    document.getElementById('messages').innerHTML += trustedHtml;
  };
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_9($sce, $http) {
  // Getting user input from POST body and passing to trustAs with concatenation
  $http.post('/api/submit-template', { template: 'user template' })
    .then(function(response) {
      const prefix = '<div class="container">';
      const userTemplate = response.data.template;
      const suffix = '</div>';
      // ruleid: javascript-detect-angular-trustas-method
      const trustedHtml = $sce.trustAs($sce.HTML, prefix + userTemplate + suffix);
      document.getElementById('template').innerHTML = trustedHtml;
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_10($sce) {
  // Getting user input from IndexedDB and passing to trustAs
  const request = indexedDB.open("UserDatabase", 1);
  request.onsuccess = function(event) {
    const db = event.target.result;
    const transaction = db.transaction(["userContent"]);
    const objectStore = transaction.objectStore("userContent");
    const request = objectStore.get("savedContent");
    
    request.onsuccess = function(event) {
      const userData = request.result.content;
      // ruleid: javascript-detect-angular-trustas-method
      const trustedHtml = $sce.trustAs($sce.HTML, userData);
      document.getElementById('saved-content').innerHTML = trustedHtml;
    };
  };
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_11($sce, $http) {
  // Getting user input from JSON file and passing to trustAs
  $http.get('/api/user-config.json').then(function(response) {
    const userConfig = response.data;
    if (userConfig.customScript) {
      // ruleid: javascript-detect-angular-trustas-method
      const trustedJs = $sce.trustAs($sce.JS, userConfig.customScript);
      const scriptElement = document.createElement('script');
      scriptElement.textContent = trustedJs;
      document.body.appendChild(scriptElement);
    }
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_12($sce) {
  // Getting user input from sessionStorage and passing to trustAs
  const userWidget = sessionStorage.getItem('userWidget');
  if (userWidget) {
    // ruleid: javascript-detect-angular-trustas-method
    const trustedWidget = $sce.trustAs($sce.HTML, userWidget);
    document.getElementById('widget-container').innerHTML = trustedWidget;
  }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_13($sce, $http) {
  // Getting user input from a file upload and passing to trustAs
  document.getElementById('file-upload').addEventListener('change', function(event) {
    const file = event.target.files[0];
    const reader = new FileReader();
    reader.onload = function() {
      const fileContent = reader.result;
      // ruleid: javascript-detect-angular-trustas-method
      const trustedContent = $sce.trustAs($sce.HTML, fileContent);
      document.getElementById('file-preview').innerHTML = trustedContent;
    };
    reader.readAsText(file);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_14($sce, $http) {
  // Getting user input from multiple sources and passing to trustAs
  $http.get('/api/user-profile').then(function(response) {
    const userData = response.data;
    const urlParams = new URLSearchParams(window.location.search);
    const theme = urlParams.get('theme') || 'default';
    
    // Combining multiple user inputs
    const customizedProfile = `<div class="theme-${theme}">${userData.profileHtml}</div>`;
    
    // ruleid: javascript-detect-angular-trustas-method
    const trustedProfile = $sce.trustAs($sce.HTML, customizedProfile);
    document.getElementById('user-profile').innerHTML = trustedProfile;
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_15($sce, $http) {
  // Getting user input from a third-party API and passing to trustAs
  $http.jsonp('https://external-api.com/widget?callback=JSON_CALLBACK')
    .then(function(response) {
      const widgetHtml = response.data.html;
      // ruleid: javascript-detect-angular-trustas-method
      const trustedWidget = $sce.trustAs($sce.HTML, widgetHtml);
      document.getElementById('external-widget').innerHTML = trustedWidget;
    });
}
// {/fact}

// ===== TRUE NEGATIVES (SAFE CODE) =====

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_1($sce) {
  // Using static, hardcoded content with trustAs
  // ok: javascript-detect-angular-trustas-method
  const trustedHtml = $sce.trustAs($sce.HTML, '<div>Static content</div>');
  document.getElementById('content').innerHTML = trustedHtml;
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_2($sce, $sanitize) {
  // Sanitizing user input before passing to trustAs
  const userInput = document.getElementById('user-comment').value;
  const sanitizedInput = $sanitize(userInput);
  // ok: javascript-detect-angular-trustas-method
  const trustedHtml = $sce.trustAs($sce.HTML, sanitizedInput);
  document.getElementById('comments').innerHTML = trustedHtml;
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_3($sce, DOMPurify) {
  // Using DOMPurify to sanitize user input before passing to trustAs
  const urlParams = new URLSearchParams(window.location.search);
  const userHtml = urlParams.get('content');
  const sanitizedHtml = DOMPurify.sanitize(userHtml);
  // ok: javascript-detect-angular-trustas-method
  const trustedHtml = $sce.trustAs($sce.HTML, sanitizedHtml);
  document.getElementById('user-content').innerHTML = trustedHtml;
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_4($sce) {
  // Using a whitelist approach for user input
  const allowedValues = ['light', 'dark', 'blue'];
  const userTheme = document.getElementById('theme-selector').value;
  
  if (allowedValues.includes(userTheme)) {
    const themeHtml = `<div class="theme-${userTheme}">Themed content</div>`;
    // ok: javascript-detect-angular-trustas-method
    const trustedHtml = $sce.trustAs($sce.HTML, themeHtml);
    document.getElementById('themed-content').innerHTML = trustedHtml;
  }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_5($sce, $http) {
  // Using server-side rendered templates instead of client-side dynamic content
  $http.get('/api/get-rendered-template').then(function(response) {
    // The server has already rendered and sanitized this HTML
    // ok: javascript-detect-angular-trustas-method
    const trustedHtml = $sce.trustAs($sce.HTML, response.data.renderedHtml);
    document.getElementById('server-rendered').innerHTML = trustedHtml;
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_6($sce) {
  // Using Angular's built-in binding instead of trustAs
  // ok: javascript-detect-angular-trustas-method
  // No trustAs used here, using Angular's built-in binding instead
  angular.module('safeApp', [])
    .controller('SafeController', function($scope) {
      $scope.userContent = '<b>Bold text</b>';
    });
  // In the template: <div ng-bind-html="userContent"></div>
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_7($sce) {
  // Using constant values with trustAs
  const APP_TEMPLATES = {
    header: '<header>My App</header>',
    footer: '<footer>&copy; 2023</footer>'
  };
  
  // ok: javascript-detect-angular-trustas-method
  const trustedFooter = $sce.trustAs($sce.HTML, APP_TEMPLATES.footer);
  document.getElementById('app-footer').innerHTML = trustedFooter;
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_8($sce) {
  // Using trustAs with properly escaped content
  const userName = document.getElementById('user-name').value;
  const escapedName = escapeHtml(userName); // Properly escaping HTML
  const welcomeMessage = `<div>Welcome, ${escapedName}!</div>`;
  
  // ok: javascript-detect-angular-trustas-method
  const trustedMessage = $sce.trustAs($sce.HTML, welcomeMessage);
  document.getElementById('welcome').innerHTML = trustedMessage;
  
  function escapeHtml(str) {
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_9($sce) {
  // Using trustAs with content that doesn't contain user input
  const currentDate = new Date().toLocaleDateString();
  const dateDisplay = `<div>Today's date: ${currentDate}</div>`;
  
  // ok: javascript-detect-angular-trustas-method
  const trustedDate = $sce.trustAs($sce.HTML, dateDisplay);
  document.getElementById('date-display').innerHTML = trustedDate;
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_10($sce, $http) {
  // Using trustAs with server-validated content
  $http.post('/api/validate-content', {
    content: document.getElementById('user-content').value
  }).then(function(response) {
    if (response.data.isValid) {
      // Server has validated this content as safe
      // ok: javascript-detect-angular-trustas-method
      const trustedContent = $sce.trustAs($sce.HTML, response.data.validatedContent);
      document.getElementById('validated-content').innerHTML = trustedContent;
    }
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_11($sce) {
  // Using alternative approach without trustAs
  const userMessage = document.getElementById('user-message').value;
  
  // ok: javascript-detect-angular-trustas-method
  // Creating DOM elements programmatically instead of using trustAs
  const messageElement = document.createElement('div');
  messageElement.textContent = userMessage; // Automatically escapes HTML
  document.getElementById('message-container').appendChild(messageElement);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_12($sce) {
  // Using trustAs with content generated from safe inputs
  const selectedColor = document.getElementById('color-picker').value.match(/^#[0-9A-F]{6}$/i)[0];
  const colorStyle = `<style>.user-section { background-color: ${selectedColor}; }</style>`;
  
  // ok: javascript-detect-angular-trustas-method
  const trustedStyle = $sce.trustAs($sce.CSS, colorStyle);
  document.head.appendChild(document.createElement('div')).innerHTML = trustedStyle;
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_13($sce) {
  // Using trustAs with content from a trusted source
  // ok: javascript-detect-angular-trustas-method
  const trustedScriptUrl = $sce.trustAs($sce.RESOURCE_URL, 'https://trusted-cdn.example.com/script.js');
  
  const scriptElement = document.createElement('script');
  scriptElement.src = trustedScriptUrl;
  document.body.appendChild(scriptElement);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_14($sce) {
  // Using a safer alternative to trustAs
  const userInput = document.getElementById('user-input').value;
  
  // ok: javascript-detect-angular-trustas-method
  // Using textContent instead of innerHTML with trustAs
  document.getElementById('output').textContent = userInput;
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_15($sce, $compile) {
  // Using Angular's $compile service with a controlled template
  // ok: javascript-detect-angular-trustas-method
  // No trustAs used, using Angular's compile service with controlled templates
  angular.module('safeCompileApp', [])
    .controller('CompileController', function($scope, $compile) {
      $scope.compileTemplate = function() {
        const template = '<div>Safe, controlled template</div>';
        const compiledTemplate = $compile(template)($scope);
        angular.element(document.getElementById('compiled-output')).append(compiledTemplate);
      };
    });
}
// {/fact}