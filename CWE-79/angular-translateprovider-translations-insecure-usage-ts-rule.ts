// Angular TranslateProvider Insecure Usage Examples
import { NgModule } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';
import { TranslateModule, TranslateLoader } from '@ngx-translate/core';
import { HttpClient, HttpClientModule } from '@angular/common/http';
import { ActivatedRoute } from '@angular/router';
import { DomSanitizer } from '@angular/platform-browser';
import * as DOMPurify from 'dompurify';

// True Positive Examples (Vulnerable Code)

// Example 1: Direct user input into translations
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_1(http: HttpClient) {
  return {
    configureTranslations: function($translateProvider: any) {
      http.get('/api/user-content').subscribe(response => {
        const userContent = response.body.content;
        // ruleid: angular-translateprovider-translations-insecure-usage-ts-rule
        $translateProvider.translations('en', {
          'USER_CONTENT': userContent
        });
      });
    }
  };
}
// {/fact}

// Example 2: Using URL parameters directly in translations
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_2($translateProvider: any, route: ActivatedRoute) {
  route.queryParams.subscribe(params => {
    const welcomeMessage = params['welcome'];
    // ruleid: angular-translateprovider-translations-insecure-usage-ts-rule
    $translateProvider.translations('en', {
      'WELCOME': welcomeMessage
    });
  });
}
// {/fact}

// Example 3: Using localStorage data in translations
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_3($translateProvider: any) {
  const userCustomizations = JSON.parse(localStorage.getItem('userCustomizations') || '{}');
  // ruleid: angular-translateprovider-translations-insecure-usage-ts-rule
  $translateProvider.translations('en', {
    'CUSTOM_HEADER': userCustomizations.headerText
  });
}
// {/fact}

// Example 4: Using data from HTTP POST request
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_4(http: HttpClient) {
  return {
    setupTranslations: function($translateProvider: any) {
      http.post('/api/get-translations', {userId: 123}).subscribe(data => {
        // ruleid: angular-translateprovider-translations-insecure-usage-ts-rule
        $translateProvider.translations('en', {
          'DYNAMIC_CONTENT': data.userGeneratedContent
        });
      });
    }
  };
}
// {/fact}

// Example 5: Using data from cookies
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_5($translateProvider: any, document: Document) {
  const getCookie = (name: string) => {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop()?.split(';').shift();
    return '';
  };
  
  const userLanguage = getCookie('userLanguage');
  const userGreeting = getCookie('customGreeting');
  
  // ruleid: angular-translateprovider-translations-insecure-usage-ts-rule
  $translateProvider.translations(userLanguage, {
    'GREETING': userGreeting
  });
}
// {/fact}

// Example 6: Using data from WebSocket
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_6($translateProvider: any) {
  const socket = new WebSocket('wss://example.com/socket');
  
  socket.onmessage = (event) => {
    const data = JSON.parse(event.data);
    // ruleid: angular-translateprovider-translations-insecure-usage-ts-rule
    $translateProvider.translations('en', {
      'LIVE_UPDATE': data.message
    });
  };
}
// {/fact}

// Example 7: Using data from IndexedDB
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_7($translateProvider: any) {
  const request = indexedDB.open("UserDatabase", 1);
  
  request.onsuccess = (event) => {
    const db = request.result;
    const transaction = db.transaction(["preferences"], "readonly");
    const objectStore = transaction.objectStore("preferences");
    const getRequest = objectStore.get("userTranslations");
    
    getRequest.onsuccess = () => {
      const userTranslations = getRequest.result;
      // ruleid: angular-translateprovider-translations-insecure-usage-ts-rule
      $translateProvider.translations('en', userTranslations);
    };
  };
}
// {/fact}

// Example 8: Using data from sessionStorage
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_8($translateProvider: any) {
  const sessionData = JSON.parse(sessionStorage.getItem('translationData') || '{}');
  // ruleid: angular-translateprovider-translations-insecure-usage-ts-rule
  $translateProvider.translations('en', {
    'SESSION_MESSAGE': sessionData.message
  });
}
// {/fact}

// Example 9: Using data from a form submission
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_9($translateProvider: any) {
  document.getElementById('translationForm')?.addEventListener('submit', (event) => {
    event.preventDefault();
    const form = event.target as HTMLFormElement;
    const formData = new FormData(form);
    const customText = formData.get('customText') as string;
    
    // ruleid: angular-translateprovider-translations-insecure-usage-ts-rule
    $translateProvider.translations('en', {
      'FORM_CONTENT': customText
    });
  });
}
// {/fact}

// Example 10: Using data from URL fragment
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_10($translateProvider: any) {
  const hashParams = new URLSearchParams(window.location.hash.substring(1));
  const messageParam = hashParams.get('message');
  
  // ruleid: angular-translateprovider-translations-insecure-usage-ts-rule
  $translateProvider.translations('en', {
    'HASH_MESSAGE': messageParam
  });
}
// {/fact}

// Example 11: Using data from postMessage API
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_11($translateProvider: any) {
  window.addEventListener('message', (event) => {
    if (event.origin !== 'https://trusted-source.com') return;
    
    const receivedData = event.data;
    // ruleid: angular-translateprovider-translations-insecure-usage-ts-rule
    $translateProvider.translations('en', {
      'EXTERNAL_MESSAGE': receivedData.content
    });
  });
}
// {/fact}

// Example 12: Using data from Fetch API
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_12($translateProvider: any) {
  fetch('/api/user-translations')
    .then(response => response.json())
    .then(data => {
      // ruleid: angular-translateprovider-translations-insecure-usage-ts-rule
      $translateProvider.translations('en', {
        'API_CONTENT': data.userContent
      });
    });
}
// {/fact}

// Example 13: Using data from XMLHttpRequest
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_13($translateProvider: any) {
  const xhr = new XMLHttpRequest();
  xhr.open('GET', '/api/translations', true);
  xhr.onload = function() {
    if (xhr.status === 200) {
      const response = JSON.parse(xhr.responseText);
      // ruleid: angular-translateprovider-translations-insecure-usage-ts-rule
      $translateProvider.translations('en', {
        'XHR_CONTENT': response.dynamicContent
      });
    }
  };
  xhr.send();
}
// {/fact}

// Example 14: Using data from Server-Sent Events
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_14($translateProvider: any) {
  const eventSource = new EventSource('/api/events');
  
  eventSource.onmessage = (event) => {
    const data = JSON.parse(event.data);
    // ruleid: angular-translateprovider-translations-insecure-usage-ts-rule
    $translateProvider.translations('en', {
      'LIVE_NOTIFICATION': data.notification
    });
  };
}
// {/fact}

// Example 15: Using data from multiple untrusted sources combined
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_15($translateProvider: any, http: HttpClient, route: ActivatedRoute) {
  const localData = localStorage.getItem('userPreferences') || '{}';
  const preferences = JSON.parse(localData);
  
  route.queryParams.subscribe(params => {
    http.get(`/api/translations/${params['lang']}`).subscribe(response => {
      const combinedData = {
        ...preferences,
        ...response,
        queryParam: params['message']
      };
      
      // ruleid: angular-translateprovider-translations-insecure-usage-ts-rule
      $translateProvider.translations('en', combinedData);
    });
  });
}
// {/fact}

// True Negative Examples (Secure Code)

// Example 1: Using sanitized user input
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_1(http: HttpClient, sanitizer: DomSanitizer) {
  return {
    configureTranslations: function($translateProvider: any) {
      http.get('/api/user-content').subscribe(response => {
        const userContent = response.body.content;
        const sanitizedContent = sanitizer.sanitize(1, userContent);
        // ok: angular-translateprovider-translations-insecure-usage-ts-rule
        $translateProvider.translations('en', {
          'USER_CONTENT': sanitizedContent
        });
      });
    }
  };
}
// {/fact}

// Example 2: Using DOMPurify to sanitize URL parameters
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_2($translateProvider: any, route: ActivatedRoute) {
  route.queryParams.subscribe(params => {
    const welcomeMessage = params['welcome'];
    const sanitizedMessage = DOMPurify.sanitize(welcomeMessage);
    // ok: angular-translateprovider-translations-insecure-usage-ts-rule
    $translateProvider.translations('en', {
      'WELCOME': sanitizedMessage
    });
  });
}
// {/fact}

// Example 3: Using Angular's $sanitize for localStorage data
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_3($translateProvider: any, $sanitize: any) {
  const userCustomizations = JSON.parse(localStorage.getItem('userCustomizations') || '{}');
  // ok: angular-translateprovider-translations-insecure-usage-ts-rule
  $translateProvider.translations('en', {
    'CUSTOM_HEADER': $sanitize(userCustomizations.headerText)
  });
}
// {/fact}

// Example 4: Using hardcoded translations (no user input)
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_4($translateProvider: any) {
  // ok: angular-translateprovider-translations-insecure-usage-ts-rule
  $translateProvider.translations('en', {
    'WELCOME': 'Welcome to our application',
    'GOODBYE': 'Thank you for using our application'
  });
}
// {/fact}

// Example 5: Using validated and escaped user input
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_5($translateProvider: any, document: Document) {
  const getCookie = (name: string) => {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop()?.split(';').shift();
    return '';
  };
  
  const userLanguage = getCookie('userLanguage') || 'en';
  const userGreeting = getCookie('customGreeting');
  
  const escapeHtml = (unsafe: string) => {
    return unsafe
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  };
  
  // ok: angular-translateprovider-translations-insecure-usage-ts-rule
  $translateProvider.translations(userLanguage, {
    'GREETING': escapeHtml(userGreeting)
  });
}
// {/fact}

// Example 6: Using server-side validated data
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_6($translateProvider: any, http: HttpClient) {
  http.get('/api/safe-translations').subscribe(data => {
    // Server has already validated and sanitized this data
    // ok: angular-translateprovider-translations-insecure-usage-ts-rule
    $translateProvider.translations('en', data);
  });
}
// {/fact}

// Example 7: Using constant values from a trusted source
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_7($translateProvider: any) {
  import('./assets/translations.json').then(translations => {
    // Translations from a trusted source (bundled with the application)
    // ok: angular-translateprovider-translations-insecure-usage-ts-rule
    $translateProvider.translations('en', translations);
  });
}
// {/fact}

// Example 8: Using Angular's bypassSecurityTrustHtml for intentionally trusted HTML
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_8($translateProvider: any, sanitizer: DomSanitizer, http: HttpClient) {
  http.get('/api/admin-content', {
    headers: {
      'Authorization': 'Bearer admin-token'
    }
  }).subscribe(response => {
    // Content from a trusted admin source, explicitly trusted
    const trustedContent = sanitizer.bypassSecurityTrustHtml(response.body.content);
    // ok: angular-translateprovider-translations-insecure-usage-ts-rule
    $translateProvider.translations('en', {
      'ADMIN_CONTENT': trustedContent
    });
  });
}
// {/fact}

// Example 9: Using a whitelist approach for user input
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_9($translateProvider: any, route: ActivatedRoute) {
  route.queryParams.subscribe(params => {
    const themeColor = params['theme'];
    const allowedThemes = ['light', 'dark', 'blue', 'green'];
    
    const safeTheme = allowedThemes.includes(themeColor) ? themeColor : 'light';
    
    // ok: angular-translateprovider-translations-insecure-usage-ts-rule
    $translateProvider.translations('en', {
      'THEME': `Selected theme: ${safeTheme}`
    });
  });
}
// {/fact}

// Example 10: Using a validation function before setting translations
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_10($translateProvider: any, http: HttpClient) {
  const validateTranslations = (obj: any) => {
    const result: Record<string, string> = {};
    for (const key in obj) {
      if (typeof obj[key] === 'string') {
        // Remove any potentially dangerous HTML
        result[key] = DOMPurify.sanitize(obj[key]);
      }
    }
    return result;
  };
  
  http.get('/api/user-translations').subscribe(data => {
    const safeTranslations = validateTranslations(data);
    // ok: angular-translateprovider-translations-insecure-usage-ts-rule
    $translateProvider.translations('en', safeTranslations);
  });
}
// {/fact}

// Example 11: Using a custom sanitization service
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_11($translateProvider: any, http: HttpClient) {
  class SanitizationService {
    sanitize(input: string): string {
      return input.replace(/<[^>]*>/g, '');
    }
  }
  
  const sanitizer = new SanitizationService();
  
  http.get('/api/messages').subscribe(response => {
    const sanitizedMessage = sanitizer.sanitize(response.body.message);
    // ok: angular-translateprovider-translations-insecure-usage-ts-rule
    $translateProvider.translations('en', {
      'MESSAGE': sanitizedMessage
    });
  });
}
// {/fact}

// Example 12: Using translations from a trusted configuration file
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_12($translateProvider: any) {
  const translations = {
    'WELCOME': 'Welcome to our application',
    'ABOUT': 'About Us',
    'CONTACT': 'Contact Us',
    'FOOTER': '© 2023 Company Name'
  };
  
  // ok: angular-translateprovider-translations-insecure-usage-ts-rule
  $translateProvider.translations('en', translations);
}
// {/fact}

// Example 13: Using a translation factory with validation
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_13($translateProvider: any, http: HttpClient) {
  class TranslationFactory {
    static createSafeTranslations(data: any): Record<string, string> {
      const result: Record<string, string> = {};
      
      for (const key in data) {
        if (typeof data[key] === 'string') {
          // Sanitize each value
          result[key] = DOMPurify.sanitize(data[key]);
        }
      }
      
      return result;
    }
  }
  
  http.get('/api/dynamic-content').subscribe(data => {
    const safeTranslations = TranslationFactory.createSafeTranslations(data);
    // ok: angular-translateprovider-translations-insecure-usage-ts-rule
    $translateProvider.translations('en', safeTranslations);
  });
}
// {/fact}

// Example 14: Using a combination of trusted and sanitized content
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_14($translateProvider: any, http: HttpClient, sanitizer: DomSanitizer) {
  const staticTranslations = {
    'HEADER': 'Welcome to our platform',
    'FOOTER': '© 2023 All rights reserved'
  };
  
  http.get('/api/dynamic-sections').subscribe(data => {
    const dynamicTranslations: Record<string, string> = {};
    
    for (const key in data) {
      dynamicTranslations[key] = sanitizer.sanitize(1, data[key]);
    }
    
    // ok: angular-translateprovider-translations-insecure-usage-ts-rule
    $translateProvider.translations('en', {
      ...staticTranslations,
      ...dynamicTranslations
    });
  });
}
// {/fact}

// Example 15: Using a content security policy and sanitization
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_15($translateProvider: any, http: HttpClient) {
  // Set Content Security Policy header
  const meta = document.createElement('meta');
  meta.httpEquiv = 'Content-Security-Policy';
  meta.content = "default-src 'self'; script-src 'self'; object-src 'none'";
  document.head.appendChild(meta);
  
  http.get('/api/user-content').subscribe(response => {
    const sanitizedContent = DOMPurify.sanitize(response.body.content);
    // ok: angular-translateprovider-translations-insecure-usage-ts-rule
    $translateProvider.translations('en', {
      'USER_CONTENT': sanitizedContent
    });
  });
}
// {/fact}

@NgModule({
  imports: [
    BrowserModule,
    HttpClientModule,
    TranslateModule.forRoot()
  ]
})
export class AppModule { }