// angular-translateprovider-translations-insecure-usage-ts-rule.ts

import { Component, NgModule, OnInit } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { TranslateModule, TranslateService } from '@ngx-translate/core';
import * as DOMPurify from 'dompurify';
import { $sanitize } from '@angular/core';
import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';

// True Positive Examples (Vulnerable Code)

// Bad Case 1: Directly using user input from URL in translations
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_1() {
  const configureTranslations = (app: any) => {
    app.config(['$translateProvider', ($translateProvider: any) => {
      const urlParams = new URLSearchParams(window.location.search);
      const userProvidedTranslation = urlParams.get('customMessage');
      
      const translations = {
        'WELCOME': 'Welcome to our site',
        'CUSTOM_MESSAGE': userProvidedTranslation // User input directly used
      };
      
      // ruleid: angular-translateprovider-translations-insecure-usage-ts-rule
      $translateProvider.translations('en', translations);
    }]);
  };
}
// {/fact}

// Bad Case 2: Using HTTP response directly in translations
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_2() {
  class TranslationConfigService {
    constructor(private http: HttpClient) {}
    
    configureTranslations(app: any) {
      app.config(['$translateProvider', ($translateProvider: any) => {
        this.http.get<any>('https://api.example.com/user-translations').subscribe(response => {
          // ruleid: angular-translateprovider-translations-insecure-usage-ts-rule
          $translateProvider.translations('en', response.data);
        });
      }]);
    }
  }
}
// {/fact}

// Bad Case 3: Using localStorage data (potentially user-controlled) in translations
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_3() {
  const setupTranslations = ($translateProvider: any) => {
    const savedTranslations = localStorage.getItem('userCustomTranslations');
    const parsedTranslations = savedTranslations ? JSON.parse(savedTranslations) : {};
    
    // ruleid: angular-translateprovider-translations-insecure-usage-ts-rule
    $translateProvider.translations('en', {
      'HEADER': parsedTranslations.header || 'Default Header',
      'FOOTER': parsedTranslations.footer || 'Default Footer'
    });
  };
}
// {/fact}

// Bad Case 4: Using data from cookies in translations
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_4() {
  const getCookieValue = (name: string): string => {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop()?.split(';').shift() || '';
    return '';
  };
  
  const initTranslations = ($translateProvider: any) => {
    const userLang = getCookieValue('userLanguage');
    const userCustomText = getCookieValue('customWelcomeText');
    
    // ruleid: angular-translateprovider-translations-insecure-usage-ts-rule
    $translateProvider.translations(userLang, {
      'WELCOME': userCustomText
    });
  };
}
// {/fact}

// Bad Case 5: Using form input for translations
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_5() {
  @Component({
    selector: 'app-translation-admin',
    template: `
      <form (ngSubmit)="saveTranslation()">
        <input [(ngModel)]="translationKey" name="key">
        <input [(ngModel)]="translationValue" name="value">
        <button type="submit">Save</button>
      </form>
    `
  })
  class TranslationAdminComponent {
    translationKey: string = '';
    translationValue: string = '';
    
    constructor(private translateService: TranslateService) {}
    
    saveTranslation() {
      const translations = {};
      translations[this.translationKey] = this.translationValue;
      
      // ruleid: angular-translateprovider-translations-insecure-usage-ts-rule
      this.translateService.setTranslation('en', translations, true);
    }
  }
}
// {/fact}

// Bad Case 6: Using data from sessionStorage in translations
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_6() {
  const configTranslations = ($translateProvider: any) => {
    const userSettings = JSON.parse(sessionStorage.getItem('userSettings') || '{}');
    
    // ruleid: angular-translateprovider-translations-insecure-usage-ts-rule
    $translateProvider.translations('en', {
      'GREETING': userSettings.greeting || 'Hello',
      'FAREWELL': userSettings.farewell || 'Goodbye'
    });
  };
}
// {/fact}

// Bad Case 7: Using postMessage data in translations
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_7() {
  window.addEventListener('message', (event) => {
    if (event.origin !== 'https://trusted-source.com') return;
    
    const app = angular.module('myApp', ['pascalprecht.translate']);
    app.config(['$translateProvider', ($translateProvider: any) => {
      // ruleid: angular-translateprovider-translations-insecure-usage-ts-rule
      $translateProvider.translations('en', event.data.translations);
    }]);
  });
}
// {/fact}

// Bad Case 8: Using URL fragment in translations
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_8() {
  const setupApp = () => {
    const fragment = window.location.hash.substring(1);
    const params = new URLSearchParams(fragment);
    const customText = params.get('text');
    
    const app = angular.module('myApp', ['pascalprecht.translate']);
    app.config(['$translateProvider', ($translateProvider: any) => {
      // ruleid: angular-translateprovider-translations-insecure-usage-ts-rule
      $translateProvider.translations('en', {
        'DYNAMIC_TEXT': customText
      });
    }]);
  };
}
// {/fact}

// Bad Case 9: Using WebSocket data in translations
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_9() {
  const socket = new WebSocket('wss://example.com/socket');
  
  socket.onmessage = (event) => {
    const data = JSON.parse(event.data);
    
    const app = angular.module('myApp', ['pascalprecht.translate']);
    app.config(['$translateProvider', ($translateProvider: any) => {
      // ruleid: angular-translateprovider-translations-insecure-usage-ts-rule
      $translateProvider.translations('en', data.translations);
    }]);
  };
}
// {/fact}

// Bad Case 10: Using IndexedDB data in translations
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_10() {
  const request = indexedDB.open('translationsDB', 1);
  
  request.onsuccess = (event) => {
    const db = request.result;
    const transaction = db.transaction(['translations'], 'readonly');
    const store = transaction.objectStore('translations');
    const getRequest = store.get('userTranslations');
    
    getRequest.onsuccess = () => {
      const userTranslations = getRequest.result;
      
      const app = angular.module('myApp', ['pascalprecht.translate']);
      app.config(['$translateProvider', ($translateProvider: any) => {
        // ruleid: angular-translateprovider-translations-insecure-usage-ts-rule
        $translateProvider.translations('en', userTranslations);
      }]);
    };
  };
}
// {/fact}

// Bad Case 11: Using data from HTTP headers in translations
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_11() {
  class TranslationService {
    constructor(private http: HttpClient) {}
    
    loadTranslations($translateProvider: any) {
      this.http.get('https://api.example.com/data', {
        observe: 'response'
      }).subscribe(response => {
        const customTranslation = response.headers.get('X-Custom-Translation');
        
        // ruleid: angular-translateprovider-translations-insecure-usage-ts-rule
        $translateProvider.translations('en', {
          'HEADER_DATA': customTranslation
        });
      });
    }
  }
}
// {/fact}

// Bad Case 12: Using data from a third-party API without sanitization
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_12() {
  class ExternalTranslationService {
    constructor(private http: HttpClient) {}
    
    importTranslations($translateProvider: any) {
      this.http.get<any>('https://third-party-api.com/translations').subscribe(data => {
        // ruleid: angular-translateprovider-translations-insecure-usage-ts-rule
        $translateProvider.translations('en', data.translations);
      });
    }
  }
}
// {/fact}

// Bad Case 13: Using data from URL parameters in multiple translations
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_13() {
  const initializeApp = () => {
    const urlParams = new URLSearchParams(window.location.search);
    const header = urlParams.get('header');
    const welcome = urlParams.get('welcome');
    const footer = urlParams.get('footer');
    
    const app = angular.module('myApp', ['pascalprecht.translate']);
    app.config(['$translateProvider', ($translateProvider: any) => {
      // ruleid: angular-translateprovider-translations-insecure-usage-ts-rule
      $translateProvider.translations('en', {
        'HEADER': header,
        'WELCOME': welcome,
        'FOOTER': footer
      });
    }]);
  };
}
// {/fact}

// Bad Case 14: Using data from a file upload in translations
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_14() {
  @Component({
    selector: 'app-translation-upload',
    template: `<input type="file" (change)="onFileSelected($event)">`
  })
  class TranslationUploadComponent {
    constructor(private translateService: TranslateService) {}
    
    onFileSelected(event: Event) {
      const file = (event.target as HTMLInputElement).files?.[0];
      if (file) {
        const reader = new FileReader();
        reader.onload = () => {
          try {
            const translations = JSON.parse(reader.result as string);
            // ruleid: angular-translateprovider-translations-insecure-usage-ts-rule
            this.translateService.setTranslation('en', translations, true);
          } catch (e) {
            console.error('Invalid JSON file');
          }
        };
        reader.readAsText(file);
      }
    }
  }
}
// {/fact}

// Bad Case 15: Using data from browser history state in translations
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_15() {
  window.addEventListener('popstate', (event) => {
    if (event.state && event.state.translations) {
      const app = angular.module('myApp', ['pascalprecht.translate']);
      app.config(['$translateProvider', ($translateProvider: any) => {
        // ruleid: angular-translateprovider-translations-insecure-usage-ts-rule
        $translateProvider.translations('en', event.state.translations);
      }]);
    }
  });
}
// {/fact}

// True Negative Examples (Safe Code)

// Good Case 1: Using hardcoded translations
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_1() {
  const configureTranslations = (app: any) => {
    app.config(['$translateProvider', ($translateProvider: any) => {
      // ok: angular-translateprovider-translations-insecure-usage-ts-rule
      $translateProvider.translations('en', {
        'WELCOME': 'Welcome to our site',
        'ABOUT': 'About us',
        'CONTACT': 'Contact us'
      });
    }]);
  };
}
// {/fact}

// Good Case 2: Sanitizing user input before using in translations
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_2() {
  const configureTranslations = (app: any) => {
    app.config(['$translateProvider', ($translateProvider: any) => {
      const urlParams = new URLSearchParams(window.location.search);
      const userProvidedTranslation = urlParams.get('customMessage');
      
      // Sanitize user input
      // ok: angular-translateprovider-translations-insecure-usage-ts-rule
      const sanitizedTranslation = DOMPurify.sanitize(userProvidedTranslation || '');
      
      $translateProvider.translations('en', {
        'WELCOME': 'Welcome to our site',
        'CUSTOM_MESSAGE': sanitizedTranslation
      });
    }]);
  };
}
// {/fact}

// Good Case 3: Using Angular's $sanitize for user input
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_3() {
  class TranslationService {
    constructor(private http: HttpClient) {}
    
    configureTranslations(app: any) {
      app.config(['$translateProvider', '$sanitize', ($translateProvider: any, $sanitize: any) => {
        this.http.get<any>('https://api.example.com/user-translations').subscribe(response => {
          const sanitizedData = {};
          
          // Sanitize each translation value
          // ok: angular-translateprovider-translations-insecure-usage-ts-rule
          Object.keys(response.data).forEach(key => {
            sanitizedData[key] = $sanitize(response.data[key]);
          });
          
          $translateProvider.translations('en', sanitizedData);
        });
      }]);
    }
  }
}
// {/fact}

// Good Case 4: Using a whitelist approach for translations
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_4() {
  const setupTranslations = ($translateProvider: any) => {
    const urlParams = new URLSearchParams(window.location.search);
    const theme = urlParams.get('theme');
    
    // Use whitelist approach for user input
    // ok: angular-translateprovider-translations-insecure-usage-ts-rule
    const allowedThemes = {
      'light': {
        'HEADER': 'Light Theme Header',
        'FOOTER': 'Light Theme Footer'
      },
      'dark': {
        'HEADER': 'Dark Theme Header',
        'FOOTER': 'Dark Theme Footer'
      }
    };
    
    const selectedTheme = theme && allowedThemes[theme] ? theme : 'light';
    $translateProvider.translations('en', allowedThemes[selectedTheme]);
  };
}
// {/fact}

// Good Case 5: Using server-side validated translations
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_5() {
  class SecureTranslationService {
    constructor(private http: HttpClient) {}
    
    loadTranslations($translateProvider: any) {
      // Server validates and sanitizes translations before sending
      // ok: angular-translateprovider-translations-insecure-usage-ts-rule
      this.http.get<any>('https://api.example.com/secure-translations').subscribe(data => {
        $translateProvider.translations('en', data);
      });
    }
  }
}
// {/fact}

// Good Case 6: Using translations from a trusted source
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_6() {
  const loadTranslationsFromCDN = ($translateProvider: any) => {
    // ok: angular-translateprovider-translations-insecure-usage-ts-rule
    fetch('https://trusted-cdn.example.com/translations/en.json')
      .then(response => response.json())
      .then(translations => {
        $translateProvider.translations('en', translations);
      });
  };
}
// {/fact}

// Good Case 7: Using a translation escaping strategy
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_7() {
  const configureTranslations = (app: any) => {
    app.config(['$translateProvider', ($translateProvider: any) => {
      // ok: angular-translateprovider-translations-insecure-usage-ts-rule
      $translateProvider.useSanitizeValueStrategy('sanitizeParameters');
      
      const urlParams = new URLSearchParams(window.location.search);
      const userMessage = urlParams.get('message') || '';
      
      $translateProvider.translations('en', {
        'USER_MESSAGE': userMessage
      });
    }]);
  };
}
// {/fact}

// Good Case 8: Using Angular's built-in security mechanisms
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_8() {
  @Component({
    selector: 'app-secure-translations',
    template: `<div [innerHTML]="'USER_CONTENT' | translate"></div>`
  })
  class SecureTranslationsComponent implements OnInit {
    constructor(private translateService: TranslateService) {}
    
    ngOnInit() {
      const userContent = localStorage.getItem('userContent') || '';
      
      // ok: angular-translateprovider-translations-insecure-usage-ts-rule
      // Angular's DomSanitizer is used in the template binding
      this.translateService.setTranslation('en', {
        'USER_CONTENT': userContent
      }, true);
    }
  }
}
// {/fact}

// Good Case 9: Using a custom sanitization function
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_9() {
  const sanitizeTranslations = (translations: Record<string, string>): Record<string, string> => {
    const result: Record<string, string> = {};
    for (const key in translations) {
      // Remove potentially dangerous HTML
      result[key] = translations[key].replace(/<[^>]*>/g, '');
    }
    return result;
  };
  
  const setupTranslations = ($translateProvider: any) => {
    const userTranslations = JSON.parse(localStorage.getItem('translations') || '{}');
    
    // ok: angular-translateprovider-translations-insecure-usage-ts-rule
    const safeTranslations = sanitizeTranslations(userTranslations);
    $translateProvider.translations('en', safeTranslations);
  };
}
// {/fact}

// Good Case 10: Using translations with content security policy
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_10() {
  const configureApp = () => {
    // Set Content Security Policy
    const meta = document.createElement('meta');
    meta.httpEquiv = 'Content-Security-Policy';
    meta.content = "default-src 'self'; script-src 'self'; object-src 'none'";
    document.head.appendChild(meta);
    
    const app = angular.module('myApp', ['pascalprecht.translate']);
    app.config(['$translateProvider', ($translateProvider: any) => {
      // ok: angular-translateprovider-translations-insecure-usage-ts-rule
      // With CSP in place, even if XSS is attempted, it will be blocked
      $translateProvider.translations('en', {
        'WELCOME': 'Welcome to our secure site'
      });
    }]);
  };
}
// {/fact}

// Good Case 11: Using translations with strict type checking
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_11() {
  interface SafeTranslations {
    WELCOME: string;
    ABOUT: string;
    CONTACT: string;
  }
  
  const configureTranslations = (app: any) => {
    app.config(['$translateProvider', ($translateProvider: any) => {
      // ok: angular-translateprovider-translations-insecure-usage-ts-rule
      const translations: SafeTranslations = {
        WELCOME: 'Welcome to our site',
        ABOUT: 'About us',
        CONTACT: 'Contact us'
      };
      
      $translateProvider.translations('en', translations);
    }]);
  };
}
// {/fact}

// Good Case 12: Using a validation function before adding translations
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_12() {
  const isValidTranslationValue = (value: any): boolean => {
    return typeof value === 'string' && value.length < 1000 && !/[<>]/.test(value);
  };
  
  const setupTranslations = ($translateProvider: any) => {
    const urlParams = new URLSearchParams(window.location.search);
    const userMessage = urlParams.get('message') || '';
    
    // ok: angular-translateprovider-translations-insecure-usage-ts-rule
    if (isValidTranslationValue(userMessage)) {
      $translateProvider.translations('en', {
        'USER_MESSAGE': userMessage
      });
    } else {
      $translateProvider.translations('en', {
        'USER_MESSAGE': 'Invalid message content'
      });
    }
  };
}
// {/fact}

// Good Case 13: Using translations with HTML encoding
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_13() {
  const htmlEncode = (str: string): string => {
    return str.replace(/&/g, '&amp;')
              .replace(/</g, '&lt;')
              .replace(/>/g, '&gt;')
              .replace(/"/g, '&quot;')
              .replace(/'/g, '&#39;');
  };
  
  const configureTranslations = (app: any) => {
    app.config(['$translateProvider', ($translateProvider: any) => {
      const urlParams = new URLSearchParams(window.location.search);
      const userContent = urlParams.get('content') || '';
      
      // ok: angular-translateprovider-translations-insecure-usage-ts-rule
      const safeContent = htmlEncode(userContent);
      
      $translateProvider.translations('en', {
        'USER_CONTENT': safeContent
      });
    }]);
  };
}
// {/fact}

// Good Case 14: Using translations with input validation regex
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_14() {
  const configureTranslations = (app: any) => {
    app.config(['$translateProvider', ($translateProvider: any) => {
      const urlParams = new URLSearchParams(window.location.search);
      let userName = urlParams.get('name') || '';
      
      // ok: angular-translateprovider-translations-insecure-usage-ts-rule
      // Only allow alphanumeric characters and spaces
      if (!/^[a-zA-Z0-9 ]*$/.test(userName)) {
        userName = 'Guest';
      }
      
      $translateProvider.translations('en', {
        'GREETING': `Hello, ${userName}!`
      });
    }]);
  };
}
// {/fact}

// Good Case 15: Using translations with server-side validation token
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_15() {
  class ValidatedTranslationService {
    constructor(private http: HttpClient) {}
    
    loadTranslations($translateProvider: any) {
      const urlParams = new URLSearchParams(window.location.search);
      const userContent = urlParams.get('content') || '';
      const validationToken = urlParams.get('token') || '';
      
      // ok: angular-translateprovider-translations-insecure-usage-ts-rule
      // Validate content server-side before using it
      this.http.post<any>('https://api.example.com/validate-content', {
        content: userContent,
        token: validationToken
      }).subscribe(response => {
        if (response.valid) {
          $translateProvider.translations('en', {
            'USER_CONTENT': response.sanitizedContent
          });
        }
      });
    }
  }
}
// {/fact}