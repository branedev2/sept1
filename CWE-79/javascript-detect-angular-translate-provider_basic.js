// Angular Translate Provider Vulnerability Examples

// Import Angular for context
angular = require('angular');
require('angular-translate');

// True Positive Examples (Vulnerable Code)

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_1() {
    // Using user input directly in translations
    angular.module('myApp', ['pascalprecht.translate'])
        .config(['$translateProvider', function($translateProvider) {
            const userInput = new URLSearchParams(window.location.search).get('message');
            // ruleid: javascript-detect-angular-translate-provider
            $translateProvider.translations('en', {
                'GREETING': 'Hello ' + userInput
            });
        }]);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_2() {
    // Using multiple user inputs in translations object
    angular.module('myApp', ['pascalprecht.translate'])
        .config(['$translateProvider', function($translateProvider) {
            const userName = document.getElementById('userName').value;
            const userTitle = document.getElementById('userTitle').value;
            
            let translations = {
                'WELCOME': 'Welcome ' + userTitle + ' ' + userName,
                'GOODBYE': 'Goodbye ' + userName
            };
            
            // ruleid: javascript-detect-angular-translate-provider
            $translateProvider.translations('en', translations);
        }]);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_3() {
    // Using user input from cookies
    angular.module('myApp', ['pascalprecht.translate'])
        .config(['$translateProvider', function($translateProvider) {
            function getCookie(name) {
                const value = `; ${document.cookie}`;
                const parts = value.split(`; ${name}=`);
                if (parts.length === 2) return parts.pop().split(';').shift();
            }
            
            const userLang = getCookie('preferredLanguage');
            const userName = getCookie('userName');
            
            // ruleid: javascript-detect-angular-translate-provider
            $translateProvider.translations(userLang, {
                'HELLO': 'Hello ' + userName
            });
        }]);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_4() {
    // Using user input from localStorage
    angular.module('myApp', ['pascalprecht.translate'])
        .config(['$translateProvider', function($translateProvider) {
            const customMessage = localStorage.getItem('customMessage');
            
            // ruleid: javascript-detect-angular-translate-provider
            $translateProvider.translations('en', {
                'CUSTOM_MESSAGE': customMessage
            });
        }]);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_5() {
    // Using user input from form submission
    angular.module('myApp', ['pascalprecht.translate'])
        .controller('TranslationController', ['$translateProvider', function($translateProvider) {
            this.updateTranslations = function() {
                const form = document.getElementById('translationForm');
                const welcomeMsg = form.elements['welcomeMsg'].value;
                
                // ruleid: javascript-detect-angular-translate-provider
                $translateProvider.translations('en', {
                    'WELCOME': welcomeMsg
                });
            };
        }]);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_6() {
    // Using user input from AJAX request
    angular.module('myApp', ['pascalprecht.translate'])
        .service('TranslationService', ['$http', '$translateProvider', function($http, $translateProvider) {
            this.loadUserTranslations = function() {
                $http.get('/api/user-translations').then(function(response) {
                    // ruleid: javascript-detect-angular-translate-provider
                    $translateProvider.translations('en', response.data);
                });
            };
        }]);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_7() {
    // Using user input in dynamic key generation
    angular.module('myApp', ['pascalprecht.translate'])
        .config(['$translateProvider', function($translateProvider) {
            const userCategory = new URLSearchParams(window.location.search).get('category');
            const translations = {};
            
            translations[userCategory + '_TITLE'] = 'Title for ' + userCategory;
            translations[userCategory + '_CONTENT'] = 'Content for ' + userCategory;
            
            // ruleid: javascript-detect-angular-translate-provider
            $translateProvider.translations('en', translations);
        }]);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_8() {
    // Using user input in nested translation objects
    angular.module('myApp', ['pascalprecht.translate'])
        .config(['$translateProvider', function($translateProvider) {
            const userName = sessionStorage.getItem('userName');
            const userRole = sessionStorage.getItem('userRole');
            
            // ruleid: javascript-detect-angular-translate-provider
            $translateProvider.translations('en', {
                'USER': {
                    'GREETING': 'Hello ' + userName,
                    'ROLE': 'Your role is: ' + userRole
                }
            });
        }]);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_9() {
    // Using user input from URL hash
    angular.module('myApp', ['pascalprecht.translate'])
        .run(['$translateProvider', function($translateProvider) {
            const hashParams = new URLSearchParams(window.location.hash.substring(1));
            const theme = hashParams.get('theme');
            
            // ruleid: javascript-detect-angular-translate-provider
            $translateProvider.translations('en', {
                'THEME': 'Current theme: ' + theme
            });
        }]);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_10() {
    // Using user input from WebSocket
    angular.module('myApp', ['pascalprecht.translate'])
        .service('WebSocketService', ['$translateProvider', function($translateProvider) {
            const socket = new WebSocket('ws://example.com/socket');
            
            socket.onmessage = function(event) {
                const data = JSON.parse(event.data);
                
                // ruleid: javascript-detect-angular-translate-provider
                $translateProvider.translations('en', {
                    'LIVE_UPDATE': data.message
                });
            };
        }]);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_11() {
    // Using user input from IndexedDB
    angular.module('myApp', ['pascalprecht.translate'])
        .service('StorageService', ['$translateProvider', function($translateProvider) {
            const request = indexedDB.open('userPreferences', 1);
            
            request.onsuccess = function(event) {
                const db = event.target.result;
                const transaction = db.transaction(['preferences'], 'readonly');
                const store = transaction.objectStore('preferences');
                const request = store.get('customMessages');
                
                request.onsuccess = function() {
                    // ruleid: javascript-detect-angular-translate-provider
                    $translateProvider.translations('en', request.result);
                };
            };
        }]);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_12() {
    // Using user input from postMessage
    angular.module('myApp', ['pascalprecht.translate'])
        .run(['$translateProvider', function($translateProvider) {
            window.addEventListener('message', function(event) {
                if (event.origin !== 'https://trusted-source.com') {
                    return;
                }
                
                // ruleid: javascript-detect-angular-translate-provider
                $translateProvider.translations('en', {
                    'EXTERNAL_MESSAGE': event.data.message
                });
            });
        }]);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_13() {
    // Using user input from data attributes
    angular.module('myApp', ['pascalprecht.translate'])
        .directive('dynamicTranslation', ['$translateProvider', function($translateProvider) {
            return {
                link: function(scope, element) {
                    const userMessage = element.data('message');
                    
                    // ruleid: javascript-detect-angular-translate-provider
                    $translateProvider.translations('en', {
                        'DYNAMIC': userMessage
                    });
                }
            };
        }]);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_14() {
    // Using user input from multiple sources combined
    angular.module('myApp', ['pascalprecht.translate'])
        .controller('MultiSourceController', ['$translateProvider', function($translateProvider) {
            const urlParam = new URLSearchParams(window.location.search).get('greeting');
            const storedName = localStorage.getItem('userName');
            const combinedMessage = urlParam + ' ' + storedName;
            
            // ruleid: javascript-detect-angular-translate-provider
            $translateProvider.translations('en', {
                'COMBINED': combinedMessage
            });
        }]);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_15() {
    // Using user input from a third-party API
    angular.module('myApp', ['pascalprecht.translate'])
        .service('ExternalService', ['$http', '$translateProvider', function($http, $translateProvider) {
            this.fetchExternalTranslations = function() {
                $http.get('https://api.example.com/translations').then(function(response) {
                    const userContent = response.data.userGeneratedContent;
                    
                    // ruleid: javascript-detect-angular-translate-provider
                    $translateProvider.translations('en', {
                        'EXTERNAL_CONTENT': userContent
                    });
                });
            };
        }]);
}
// {/fact}

// True Negative Examples (Safe Code)

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_1() {
    // Using hardcoded translations (no user input)
    angular.module('myApp', ['pascalprecht.translate'])
        .config(['$translateProvider', function($translateProvider) {
            // ok: javascript-detect-angular-translate-provider
            $translateProvider.translations('en', {
                'GREETING': 'Hello World',
                'GOODBYE': 'Goodbye'
            });
        }]);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_2() {
    // Using sanitized user input
    angular.module('myApp', ['pascalprecht.translate'])
        .config(['$translateProvider', '$sanitize', function($translateProvider, $sanitize) {
            const userInput = new URLSearchParams(window.location.search).get('message');
            const sanitizedInput = $sanitize(userInput || '');
            
            // ok: javascript-detect-angular-translate-provider
            $translateProvider.translations('en', {
                'GREETING': 'Hello ' + sanitizedInput
            });
        }]);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_3() {
    // Using DOMPurify for sanitization
    angular.module('myApp', ['pascalprecht.translate'])
        .config(['$translateProvider', function($translateProvider) {
            const userInput = document.getElementById('userName').value;
            const sanitizedInput = DOMPurify.sanitize(userInput);
            
            // ok: javascript-detect-angular-translate-provider
            $translateProvider.translations('en', {
                'WELCOME': 'Welcome ' + sanitizedInput
            });
        }]);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_4() {
    // Using input validation to ensure only safe values are used
    angular.module('myApp', ['pascalprecht.translate'])
        .config(['$translateProvider', function($translateProvider) {
            const userLang = new URLSearchParams(window.location.search).get('lang');
            const allowedLanguages = ['en', 'fr', 'de', 'es'];
            
            const language = allowedLanguages.includes(userLang) ? userLang : 'en';
            
            // ok: javascript-detect-angular-translate-provider
            $translateProvider.translations(language, {
                'HELLO': 'Hello in ' + language
            });
        }]);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_5() {
    // Using a whitelist approach for user content
    angular.module('myApp', ['pascalprecht.translate'])
        .service('TranslationService', ['$translateProvider', function($translateProvider) {
            this.setUserTitle = function(title) {
                const allowedTitles = ['Mr', 'Mrs', 'Ms', 'Dr', 'Prof'];
                const safeTitle = allowedTitles.includes(title) ? title : 'Guest';
                
                // ok: javascript-detect-angular-translate-provider
                $translateProvider.translations('en', {
                    'TITLE': safeTitle
                });
            };
        }]);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_6() {
    // Using escapeHTML function for user input
    angular.module('myApp', ['pascalprecht.translate'])
        .config(['$translateProvider', function($translateProvider) {
            function escapeHTML(str) {
                return str.replace(/[&<>'"]/g, 
                    tag => ({
                        '&': '&amp;',
                        '<': '&lt;',
                        '>': '&gt;',
                        "'": '&#39;',
                        '"': '&quot;'
                    }[tag]));
            }
            
            const userInput = localStorage.getItem('customMessage');
            const safeInput = escapeHTML(userInput || '');
            
            // ok: javascript-detect-angular-translate-provider
            $translateProvider.translations('en', {
                'CUSTOM_MESSAGE': safeInput
            });
        }]);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_7() {
    // Using trusted translations from a secure source
    angular.module('myApp', ['pascalprecht.translate'])
        .service('SecureTranslationService', ['$translateProvider', function($translateProvider) {
            // Translations from a trusted, verified source
            const verifiedTranslations = {
                'WELCOME': 'Welcome to our application',
                'GOODBYE': 'Thank you for using our application'
            };
            
            // ok: javascript-detect-angular-translate-provider
            $translateProvider.translations('en', verifiedTranslations);
        }]);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_8() {
    // Using regex pattern matching to validate input
    angular.module('myApp', ['pascalprecht.translate'])
        .config(['$translateProvider', function($translateProvider) {
            const userName = sessionStorage.getItem('userName');
            const namePattern = /^[A-Za-z0-9_-]{3,16}$/;
            
            const validatedName = namePattern.test(userName) ? userName : 'Guest';
            
            // ok: javascript-detect-angular-translate-provider
            $translateProvider.translations('en', {
                'GREETING': 'Hello ' + validatedName
            });
        }]);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_9() {
    // Using a translation factory with validation
    angular.module('myApp', ['pascalprecht.translate'])
        .factory('TranslationFactory', function() {
            return {
                createSafeTranslations: function(userInput) {
                    // Remove any HTML or script tags
                    const cleanInput = userInput.replace(/<\/?[^>]+(>|$)/g, "");
                    return {
                        'USER_MESSAGE': cleanInput
                    };
                }
            };
        })
        .config(['$translateProvider', 'TranslationFactory', function($translateProvider, TranslationFactory) {
            const userInput = new URLSearchParams(window.location.search).get('message') || '';
            const safeTranslations = TranslationFactory.createSafeTranslations(userInput);
            
            // ok: javascript-detect-angular-translate-provider
            $translateProvider.translations('en', safeTranslations);
        }]);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_10() {
    // Using Angular's built-in $sce service
    angular.module('myApp', ['pascalprecht.translate'])
        .config(['$translateProvider', '$sce', function($translateProvider, $sce) {
            const userInput = document.getElementById('userMessage').value;
            const trustedInput = $sce.trustAsHtml(userInput).toString();
            
            // ok: javascript-detect-angular-translate-provider
            $translateProvider.translations('en', {
                'MESSAGE': trustedInput
            });
        }]);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_11() {
    // Using numeric input that doesn't need sanitization
    angular.module('myApp', ['pascalprecht.translate'])
        .config(['$translateProvider', function($translateProvider) {
            const userAge = parseInt(new URLSearchParams(window.location.search).get('age'), 10);
            const validAge = isNaN(userAge) ? 0 : Math.min(Math.max(userAge, 0), 120);
            
            // ok: javascript-detect-angular-translate-provider
            $translateProvider.translations('en', {
                'AGE_MESSAGE': 'Your age is: ' + validAge
            });
        }]);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_12() {
    // Using translations from a secure configuration file
    angular.module('myApp', ['pascalprecht.translate'])
        .constant('APP_TRANSLATIONS', {
            'en': {
                'WELCOME': 'Welcome to our application',
                'GOODBYE': 'Thank you for using our application'
            },
            'fr': {
                'WELCOME': 'Bienvenue dans notre application',
                'GOODBYE': 'Merci d\'utiliser notre application'
            }
        })
        .config(['$translateProvider', 'APP_TRANSLATIONS', function($translateProvider, APP_TRANSLATIONS) {
            // ok: javascript-detect-angular-translate-provider
            $translateProvider.translations('en', APP_TRANSLATIONS['en']);
            $translateProvider.translations('fr', APP_TRANSLATIONS['fr']);
        }]);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_13() {
    // Using a content security policy approach
    angular.module('myApp', ['pascalprecht.translate'])
        .config(['$translateProvider', function($translateProvider) {
            function applyCSP(obj) {
                const result = {};
                for (const key in obj) {
                    if (typeof obj[key] === 'string') {
                        // Remove potentially dangerous content
                        result[key] = obj[key].replace(/javascript:/gi, '')
                                              .replace(/on\w+=/gi, '')
                                              .replace(/<script/gi, '');
                    } else if (typeof obj[key] === 'object') {
                        result[key] = applyCSP(obj[key]);
                    } else {
                        result[key] = obj[key];
                    }
                }
                return result;
            }
            
            const userTranslations = JSON.parse(localStorage.getItem('translations') || '{}');
            const safeTranslations = applyCSP(userTranslations);
            
            // ok: javascript-detect-angular-translate-provider
            $translateProvider.translations('en', safeTranslations);
        }]);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_14() {
    // Using server-validated translations
    angular.module('myApp', ['pascalprecht.translate'])
        .service('ServerValidatedTranslations', ['$http', '$translateProvider', function($http, $translateProvider) {
            this.loadTranslations = function() {
                // User input is sent to server for validation before being used
                const userInput = new URLSearchParams(window.location.search).get('customText');
                
                $http.post('/api/validate-translation', { text: userInput }).then(function(response) {
                    // Server returns sanitized and validated translations
                    // ok: javascript-detect-angular-translate-provider
                    $translateProvider.translations('en', response.data.validatedTranslations);
                });
            };
        }]);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_15() {
    // Using a translation mapping approach
    angular.module('myApp', ['pascalprecht.translate'])
        .config(['$translateProvider', function($translateProvider) {
            const userPreference = new URLSearchParams(window.location.search).get('preference');
            
            // Map user input to predefined safe translations
            const translationMap = {
                'formal': {
                    'GREETING': 'Good day, valued user',
                    'GOODBYE': 'We wish you a pleasant day'
                },
                'casual': {
                    'GREETING': 'Hey there!',
                    'GOODBYE': 'See ya later!'
                },
                'business': {
                    'GREETING': 'Welcome to our service',
                    'GOODBYE': 'Thank you for your business'
                }
            };
            
            const selectedStyle = translationMap[userPreference] || translationMap['formal'];
            
            // ok: javascript-detect-angular-translate-provider
            $translateProvider.translations('en', selectedStyle);
        }]);
}
// {/fact}