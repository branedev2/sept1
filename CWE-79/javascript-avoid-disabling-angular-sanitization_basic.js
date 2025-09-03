import { Component, OnInit } from '@angular/core';
import { DomSanitizer, SafeHtml, SafeResourceUrl, SafeScript, SafeStyle, SafeUrl } from '@angular/platform-browser';
import { HttpClient } from '@angular/common/http';

// TRUE POSITIVES (Vulnerable Code)

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_1() {
  @Component({
    selector: 'app-unsafe',
    template: '<div [innerHTML]="unsafeHtml"></div>'
  })
  class UnsafeComponent implements OnInit {
    unsafeHtml: SafeHtml;
    
    constructor(private sanitizer: DomSanitizer, private http: HttpClient) {}
    
    ngOnInit() {
      this.http.get('https://api.example.com/content', { responseType: 'text' }).subscribe(data => {
        // ruleid: javascript-avoid-disabling-angular-sanitization
        this.unsafeHtml = this.sanitizer.bypassSecurityTrustHtml(data);
      });
    }
  }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_2() {
  @Component({
    selector: 'app-unsafe-script',
    template: '<div [innerHTML]="dynamicScript"></div>'
  })
  class UnsafeScriptComponent {
    dynamicScript: SafeScript;
    
    constructor(private sanitizer: DomSanitizer) {
      const userInput = document.getElementById('userScript').textContent;
      // ruleid: javascript-avoid-disabling-angular-sanitization
      this.dynamicScript = this.sanitizer.bypassSecurityTrustScript(userInput);
    }
  }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_3() {
  @Component({
    selector: 'app-unsafe-style',
    template: '<div [style]="userStyle"></div>'
  })
  class UnsafeStyleComponent implements OnInit {
    userStyle: SafeStyle;
    
    constructor(private sanitizer: DomSanitizer, private http: HttpClient) {}
    
    ngOnInit() {
      this.http.get('/api/user-preferences/style', { responseType: 'text' }).subscribe(style => {
        // ruleid: javascript-avoid-disabling-angular-sanitization
        this.userStyle = this.sanitizer.bypassSecurityTrustStyle(style);
      });
    }
  }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_4() {
  @Component({
    selector: 'app-unsafe-url',
    template: '<a [href]="dynamicUrl">Click me</a>'
  })
  class UnsafeUrlComponent {
    dynamicUrl: SafeUrl;
    
    constructor(private sanitizer: DomSanitizer) {
      const urlParam = new URLSearchParams(window.location.search).get('redirect');
      // ruleid: javascript-avoid-disabling-angular-sanitization
      this.dynamicUrl = this.sanitizer.bypassSecurityTrustUrl(urlParam);
    }
  }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_5() {
  @Component({
    selector: 'app-unsafe-resource',
    template: '<iframe [src]="videoUrl"></iframe>'
  })
  class UnsafeResourceComponent implements OnInit {
    videoUrl: SafeResourceUrl;
    
    constructor(private sanitizer: DomSanitizer, private http: HttpClient) {}
    
    ngOnInit() {
      this.http.get('/api/videos/recommended', { responseType: 'text' }).subscribe(url => {
        // ruleid: javascript-avoid-disabling-angular-sanitization
        this.videoUrl = this.sanitizer.bypassSecurityTrustResourceUrl(url);
      });
    }
  }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_6() {
  @Component({
    selector: 'app-comment-display',
    template: '<div [innerHTML]="commentHtml"></div>'
  })
  class CommentDisplayComponent {
    commentHtml: SafeHtml;
    
    constructor(private sanitizer: DomSanitizer) {}
    
    displayComment(comment) {
      // ruleid: javascript-avoid-disabling-angular-sanitization
      this.commentHtml = this.sanitizer.bypassSecurityTrustHtml(comment);
    }
    
    loadComments() {
      fetch('/api/comments')
        .then(response => response.json())
        .then(comments => {
          comments.forEach(comment => this.displayComment(comment.text));
        });
    }
  }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_7() {
  @Component({
    selector: 'app-dynamic-template',
    template: '<div *ngFor="let section of pageSections" [innerHTML]="section.content"></div>'
  })
  class DynamicTemplateComponent implements OnInit {
    pageSections = [];
    
    constructor(private sanitizer: DomSanitizer, private http: HttpClient) {}
    
    ngOnInit() {
      this.http.get('/api/page-content').subscribe((sections: any[]) => {
        this.pageSections = sections.map(section => {
          return {
            id: section.id,
            // ruleid: javascript-avoid-disabling-angular-sanitization
            content: this.sanitizer.bypassSecurityTrustHtml(section.html)
          };
        });
      });
    }
  }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_8() {
  @Component({
    selector: 'app-markdown-renderer',
    template: '<div [innerHTML]="renderedMarkdown"></div>'
  })
  class MarkdownRendererComponent {
    renderedMarkdown: SafeHtml;
    
    constructor(private sanitizer: DomSanitizer) {}
    
    renderMarkdown(markdown) {
      const html = convertMarkdownToHtml(markdown); // Assume this function exists
      // ruleid: javascript-avoid-disabling-angular-sanitization
      this.renderedMarkdown = this.sanitizer.bypassSecurityTrustHtml(html);
    }
    
    convertMarkdownToHtml(markdown) {
      // Simple markdown conversion
      return markdown.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
    }
  }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_9() {
  @Component({
    selector: 'app-external-widget',
    template: '<div [innerHTML]="widgetCode"></div>'
  })
  class ExternalWidgetComponent implements OnInit {
    widgetCode: SafeHtml;
    
    constructor(private sanitizer: DomSanitizer, private http: HttpClient) {}
    
    ngOnInit() {
      const widgetId = localStorage.getItem('preferred-widget');
      this.http.get(`/api/widgets/${widgetId}`).subscribe((response: any) => {
        // ruleid: javascript-avoid-disabling-angular-sanitization
        this.widgetCode = this.sanitizer.bypassSecurityTrustHtml(response.embedCode);
      });
    }
  }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_10() {
  @Component({
    selector: 'app-dynamic-form',
    template: '<div [innerHTML]="formHtml"></div>'
  })
  class DynamicFormComponent {
    formHtml: SafeHtml;
    
    constructor(private sanitizer: DomSanitizer) {}
    
    loadForm(formId) {
      fetch(`/api/forms/${formId}`)
        .then(response => response.text())
        .then(html => {
          // ruleid: javascript-avoid-disabling-angular-sanitization
          this.formHtml = this.sanitizer.bypassSecurityTrustHtml(html);
        });
    }
  }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_11() {
  @Component({
    selector: 'app-custom-style-injector',
    template: '<div [style]="customStyles"></div>'
  })
  class CustomStyleInjectorComponent {
    customStyles: SafeStyle;
    
    constructor(private sanitizer: DomSanitizer) {}
    
    applyUserStyles() {
      const userStyles = document.getElementById('style-input').value;
      // ruleid: javascript-avoid-disabling-angular-sanitization
      this.customStyles = this.sanitizer.bypassSecurityTrustStyle(userStyles);
    }
  }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_12() {
  @Component({
    selector: 'app-dynamic-iframe',
    template: '<iframe [src]="frameUrl"></iframe>'
  })
  class DynamicIframeComponent {
    frameUrl: SafeResourceUrl;
    
    constructor(private sanitizer: DomSanitizer) {}
    
    loadFrame() {
      const url = new URLSearchParams(window.location.search).get('embed');
      // ruleid: javascript-avoid-disabling-angular-sanitization
      this.frameUrl = this.sanitizer.bypassSecurityTrustResourceUrl(url);
    }
  }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_13() {
  @Component({
    selector: 'app-javascript-executor',
    template: '<div [innerHTML]="scriptContainer"></div>'
  })
  class JavascriptExecutorComponent {
    scriptContainer: SafeHtml;
    
    constructor(private sanitizer: DomSanitizer) {}
    
    executeScript(code) {
      const scriptTag = `<script>${code}</script>`;
      // ruleid: javascript-avoid-disabling-angular-sanitization
      this.scriptContainer = this.sanitizer.bypassSecurityTrustHtml(scriptTag);
    }
    
    runUserScript() {
      const userCode = document.getElementById('code-editor').value;
      this.executeScript(userCode);
    }
  }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_14() {
  @Component({
    selector: 'app-dynamic-link',
    template: '<a [href]="profileUrl">View Profile</a>'
  })
  class DynamicLinkComponent {
    profileUrl: SafeUrl;
    
    constructor(private sanitizer: DomSanitizer, private http: HttpClient) {}
    
    loadUserProfile(userId) {
      this.http.get(`/api/users/${userId}/profile-link`).subscribe((response: any) => {
        // ruleid: javascript-avoid-disabling-angular-sanitization
        this.profileUrl = this.sanitizer.bypassSecurityTrustUrl(response.url);
      });
    }
  }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_15() {
  @Component({
    selector: 'app-wysiwyg-editor',
    template: '<div [innerHTML]="editorContent"></div>'
  })
  class WysiwygEditorComponent {
    editorContent: SafeHtml;
    
    constructor(private sanitizer: DomSanitizer) {}
    
    updateContent() {
      const content = document.getElementById('editor').innerHTML;
      // ruleid: javascript-avoid-disabling-angular-sanitization
      this.editorContent = this.sanitizer.bypassSecurityTrustHtml(content);
    }
  }
}
// {/fact}

// TRUE NEGATIVES (Safe Code)

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_1() {
  @Component({
    selector: 'app-safe',
    template: '<div [innerHTML]="safeHtml"></div>'
  })
  class SafeComponent implements OnInit {
    safeHtml: string;
    
    constructor(private http: HttpClient) {}
    
    ngOnInit() {
      this.http.get('https://api.example.com/content', { responseType: 'text' }).subscribe(data => {
        // ok: javascript-avoid-disabling-angular-sanitization
        this.safeHtml = data; // Angular's built-in sanitization will handle this
      });
    }
  }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_2() {
  @Component({
    selector: 'app-safe-script',
    template: '<div>{{ scriptContent }}</div>'
  })
  class SafeScriptComponent {
    scriptContent: string;
    
    constructor() {
      const userInput = document.getElementById('userScript').textContent;
      // ok: javascript-avoid-disabling-angular-sanitization
      this.scriptContent = userInput; // Displayed as text, not executed as script
    }
  }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_3() {
  @Component({
    selector: 'app-safe-style',
    template: '<div [ngStyle]="userStyleObject"></div>'
  })
  class SafeStyleComponent implements OnInit {
    userStyleObject = {};
    
    constructor(private http: HttpClient) {}
    
    ngOnInit() {
      this.http.get('/api/user-preferences/style').subscribe((styleData: any) => {
        // ok: javascript-avoid-disabling-angular-sanitization
        // Convert to safe style object instead of raw CSS string
        this.userStyleObject = {
          color: styleData.textColor || 'black',
          backgroundColor: styleData.bgColor || 'white',
          fontSize: styleData.fontSize ? `${styleData.fontSize}px` : '16px'
        };
      });
    }
  }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_4() {
  @Component({
    selector: 'app-safe-url',
    template: '<a [href]="safeUrl()">Click me</a>'
  })
  class SafeUrlComponent {
    redirectUrl: string;
    
    constructor() {
      this.redirectUrl = new URLSearchParams(window.location.search).get('redirect') || '#';
    }
    
    // ok: javascript-avoid-disabling-angular-sanitization
    safeUrl() {
      // Validate URL before using
      const urlPattern = /^(https?:\/\/example\.com\/|\/[a-zA-Z0-9\/-]+|#.*)$/;
      return urlPattern.test(this.redirectUrl) ? this.redirectUrl : '#';
    }
  }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_5() {
  @Component({
    selector: 'app-safe-resource',
    template: '<iframe [src]="videoUrl"></iframe>'
  })
  class SafeResourceComponent implements OnInit {
    videoUrl: string;
    allowedDomains = ['youtube.com', 'vimeo.com'];
    
    constructor(private http: HttpClient) {}
    
    ngOnInit() {
      this.http.get('/api/videos/recommended', { responseType: 'text' }).subscribe(url => {
        // ok: javascript-avoid-disabling-angular-sanitization
        try {
          const urlObj = new URL(url);
          if (this.allowedDomains.some(domain => urlObj.hostname.includes(domain))) {
            this.videoUrl = url; // Angular's built-in sanitization will handle this
          } else {
            this.videoUrl = 'about:blank'; // Fallback to empty iframe
          }
        } catch (e) {
          this.videoUrl = 'about:blank';
        }
      });
    }
  }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_6() {
  @Component({
    selector: 'app-comment-display-safe',
    template: '<div>{{ commentText }}</div>'
  })
  class CommentDisplaySafeComponent {
    commentText: string;
    
    constructor() {}
    
    displayComment(comment) {
      // ok: javascript-avoid-disabling-angular-sanitization
      this.commentText = comment; // Displayed as text, not HTML
    }
    
    loadComments() {
      fetch('/api/comments')
        .then(response => response.json())
        .then(comments => {
          comments.forEach(comment => this.displayComment(comment.text));
        });
    }
  }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_7() {
  @Component({
    selector: 'app-dynamic-template-safe',
    template: `
      <div *ngFor="let section of pageSections">
        <h2>{{ section.title }}</h2>
        <p>{{ section.content }}</p>
      </div>
    `
  })
  class DynamicTemplateSafeComponent implements OnInit {
    pageSections = [];
    
    constructor(private http: HttpClient) {}
    
    ngOnInit() {
      this.http.get('/api/page-content').subscribe((sections: any[]) => {
        // ok: javascript-avoid-disabling-angular-sanitization
        this.pageSections = sections.map(section => {
          return {
            id: section.id,
            title: section.title,
            content: section.text // Using text content instead of HTML
          };
        });
      });
    }
  }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_8() {
  @Component({
    selector: 'app-markdown-renderer-safe',
    template: '<div>{{ renderedText }}</div>'
  })
  class MarkdownRendererSafeComponent {
    renderedText: string;
    
    constructor() {}
    
    renderMarkdown(markdown) {
      // ok: javascript-avoid-disabling-angular-sanitization
      // Just convert to plain text with formatting indicators
      this.renderedText = markdown
        .replace(/\*\*(.*?)\*\*/g, '$1 (bold)')
        .replace(/\*(.*?)\*/g, '$1 (italic)');
    }
  }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_9() {
  @Component({
    selector: 'app-external-widget-safe',
    template: `
      <div class="widget-container">
        <h3>{{ widget.title }}</h3>
        <p>{{ widget.description }}</p>
        <button (click)="interactWithWidget()">Interact</button>
      </div>
    `
  })
  class ExternalWidgetSafeComponent implements OnInit {
    widget = { title: '', description: '' };
    
    constructor(private http: HttpClient) {}
    
    ngOnInit() {
      const widgetId = localStorage.getItem('preferred-widget');
      // ok: javascript-avoid-disabling-angular-sanitization
      this.http.get(`/api/widgets/${widgetId}`).subscribe((response: any) => {
        this.widget = {
          title: response.title,
          description: response.description
        };
      });
    }
    
    interactWithWidget() {
      // Safe interaction with widget
      console.log('Widget interaction');
    }
  }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_10() {
  @Component({
    selector: 'app-dynamic-form-safe',
    template: `
      <form>
        <div *ngFor="let field of formFields">
          <label [for]="field.id">{{ field.label }}</label>
          <input 
            [type]="field.type" 
            [id]="field.id" 
            [name]="field.name"
            [placeholder]="field.placeholder">
        </div>
        <button type="submit">Submit</button>
      </form>
    `
  })
  class DynamicFormSafeComponent {
    formFields = [];
    
    constructor() {}
    
    loadForm(formId) {
      fetch(`/api/forms/${formId}`)
        .then(response => response.json())
        .then(formData => {
          // ok: javascript-avoid-disabling-angular-sanitization
          this.formFields = formData.fields.map(field => ({
            id: field.id,
            name: field.name,
            label: field.label,
            type: this.getSafeInputType(field.type),
            placeholder: field.placeholder || ''
          }));
        });
    }
    
    getSafeInputType(type) {
      const safeTypes = ['text', 'email', 'number', 'date', 'checkbox'];
      return safeTypes.includes(type) ? type : 'text';
    }
  }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_11() {
  @Component({
    selector: 'app-custom-style-injector-safe',
    template: '<div [ngStyle]="parsedStyles"></div>'
  })
  class CustomStyleInjectorSafeComponent {
    parsedStyles = {};
    allowedProperties = ['color', 'backgroundColor', 'fontSize', 'fontWeight', 'margin', 'padding'];
    
    constructor() {}
    
    applyUserStyles() {
      const userStylesText = document.getElementById('style-input').value;
      // ok: javascript-avoid-disabling-angular-sanitization
      try {
        const stylesObj = JSON.parse(userStylesText);
        this.parsedStyles = Object.keys(stylesObj)
          .filter(key => this.allowedProperties.includes(key))
          .reduce((obj, key) => {
            obj[key] = stylesObj[key];
            return obj;
          }, {});
      } catch (e) {
        this.parsedStyles = {};
        console.error('Invalid style JSON');
      }
    }
  }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_12() {
  @Component({
    selector: 'app-dynamic-iframe-safe',
    template: `
      <iframe *ngIf="isUrlAllowed" [src]="frameUrl"></iframe>
      <div *ngIf="!isUrlAllowed">Content from this source cannot be displayed</div>
    `
  })
  class DynamicIframeSafeComponent {
    frameUrl: string;
    isUrlAllowed = false;
    allowedDomains = ['trusted-site.com', 'example.org', 'safe-content.net'];
    
    constructor() {}
    
    loadFrame() {
      const url = new URLSearchParams(window.location.search).get('embed');
      
      // ok: javascript-avoid-disabling-angular-sanitization
      try {
        const urlObj = new URL(url);
        this.isUrlAllowed = this.allowedDomains.some(domain => 
          urlObj.hostname === domain || urlObj.hostname.endsWith('.' + domain)
        );
        
        if (this.isUrlAllowed) {
          this.frameUrl = url; // Angular's built-in sanitization will handle this
        }
      } catch (e) {
        this.isUrlAllowed = false;
      }
    }
  }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_13() {
  @Component({
    selector: 'app-javascript-executor-safe',
    template: '<pre><code>{{ scriptContent }}</code></pre>'
  })
  class JavascriptExecutorSafeComponent {
    scriptContent: string;
    
    constructor() {}
    
    showScript(code) {
      // ok: javascript-avoid-disabling-angular-sanitization
      this.scriptContent = code; // Display as text, not executed
    }
    
    runUserScript() {
      const userCode = document.getElementById('code-editor').value;
      this.showScript(userCode);
      
      // Instead of executing arbitrary code, use a safe approach
      try {
        // Validate and execute in a controlled way
        const allowedFunctions = ['calculateSum', 'formatText', 'sortItems'];
        const functionName = userCode.split('(')[0].trim();
        
        if (allowedFunctions.includes(functionName)) {
          // Execute only pre-defined functions with controlled inputs
          this.executeControlledFunction(functionName, userCode);
        }
      } catch (e) {
        console.error('Invalid function call');
      }
    }
    
    executeControlledFunction(name, code) {
      // Implementation of controlled function execution
      console.log(`Executing controlled function: ${name}`);
    }
  }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_14() {
  @Component({
    selector: 'app-dynamic-link-safe',
    template: '<a [href]="safeProfileUrl">View Profile</a>'
  })
  class DynamicLinkSafeComponent {
    safeProfileUrl: string;
    
    constructor(private http: HttpClient) {}
    
    loadUserProfile(userId) {
      this.http.get(`/api/users/${userId}/profile-link`).subscribe((response: any) => {
        // ok: javascript-avoid-disabling-angular-sanitization
        // Validate URL before using
        try {
          const url = new URL(response.url);
          // Only allow specific domains and protocols
          if (
            (url.protocol === 'http:' || url.protocol === 'https:') &&
            (url.hostname === 'example.com' || url.hostname.endsWith('.example.com'))
          ) {
            this.safeProfileUrl = response.url;
          } else {
            this.safeProfileUrl = '#';
          }
        } catch (e) {
          this.safeProfileUrl = '#';
        }
      });
    }
  }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_15() {
  @Component({
    selector: 'app-wysiwyg-editor-safe',
    template: `
      <div>
        <h3>Editor Preview:</h3>
        <div>{{ plainTextContent }}</div>
        <div *ngFor="let tag of allowedHtmlElements">
          <span [innerHTML]="sanitizedContent[tag]"></span>
        </div>
      </div>
    `
  })
  class WysiwygEditorSafeComponent {
    plainTextContent: string = '';
    sanitizedContent: {[key: string]: string} = {};
    allowedHtmlElements = ['p', 'h1', 'h2', 'ul', 'ol', 'li'];
    
    constructor() {}
    
    updateContent() {
      const content = document.getElementById('editor').innerHTML;
      
      // ok: javascript-avoid-disabling-angular-sanitization
      // Extract plain text
      this.plainTextContent = content.replace(/<[^>]*>/g, '');
      
      // Parse and sanitize HTML by element type
      this.allowedHtmlElements.forEach(tag => {
        const regex = new RegExp(`<${tag}[^>]*>(.*?)<\/${tag}>`, 'g');
        const matches = content.match(regex) || [];
        
        // Basic sanitization - remove scripts, event handlers, etc.
        this.sanitizedContent[tag] = matches
          .map(match => match.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
                             .replace(/on\w+="[^"]*"/g, '')
                             .replace(/javascript:/g, ''))
          .join('');
      });
    }
  }
}
// {/fact}