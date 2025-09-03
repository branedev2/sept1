// File: angular_trustas_examples.ts
import { Component, OnInit, Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable } from 'rxjs';
import { DomSanitizer, SafeHtml, SafeResourceUrl, SafeScript, SafeStyle, SafeUrl } from '@angular/platform-browser';

// True Positive Examples (Vulnerable Code)

@Component({
  selector: 'app-vulnerable-component-1',
  template: '<div [innerHTML]="htmlContent"></div>'
})
export class BadCase1Component implements OnInit {
  htmlContent: any;
  
  constructor(private http: HttpClient, private $sce: any) { }
  
  ngOnInit() {
    this.http.get<string>('https://api.example.com/content', { responseType: 'text' as 'json' }).subscribe(data => {
      // ruleid: typescript-detect-angular-trustas-method
      this.htmlContent = this.$sce.trustAs('html', data);
    });
  }
}

@Component({
  selector: 'app-vulnerable-component-2',
  template: '<iframe [src]="frameUrl"></iframe>'
})
export class BadCase2Component implements OnInit {
  frameUrl: any;
  
  constructor(private http: HttpClient, private $sce: any) { }
  
  ngOnInit() {
    this.http.get<{url: string}>('https://api.example.com/iframe-url').subscribe(response => {
      // ruleid: typescript-detect-angular-trustas-method
      this.frameUrl = this.$sce.trustAs('resourceUrl', response.url);
    });
  }
}

@Injectable({
  providedIn: 'root'
})
export class BadCase3Service {
  constructor(private http: HttpClient, private $sce: any) { }
  
  processUserScript(userId: string): Observable<any> {
    return new Observable(observer => {
      this.http.get<{script: string}>(`https://api.example.com/users/${userId}/script`).subscribe(data => {
        // ruleid: typescript-detect-angular-trustas-method
        const trustedScript = this.$sce.trustAs('script', data.script);
        observer.next(trustedScript);
        observer.complete();
      });
    });
  }
}

@Component({
  selector: 'app-vulnerable-component-4',
  template: '<div [style]="userStyle"></div>'
})
export class BadCase4Component implements OnInit {
  userStyle: any;
  
  constructor(private http: HttpClient, private $sce: any) { }
  
  ngOnInit() {
    const headers = new HttpHeaders().set('Content-Type', 'application/json');
    this.http.get<{style: string}>('https://api.example.com/user-style', { headers }).subscribe(data => {
      // ruleid: typescript-detect-angular-trustas-method
      this.userStyle = this.$sce.trustAs('style', data.style);
    });
  }
}

@Component({
  selector: 'app-vulnerable-component-5',
  template: '<a [href]="linkUrl">Click me</a>'
})
export class BadCase5Component implements OnInit {
  linkUrl: any;
  
  constructor(private http: HttpClient, private $sce: any) { }
  
  ngOnInit() {
    this.http.post<{url: string}>('https://api.example.com/get-link', { id: 123 }).subscribe(response => {
      // ruleid: typescript-detect-angular-trustas-method
      this.linkUrl = this.$sce.trustAs('url', response.url);
    });
  }
}

@Component({
  selector: 'app-vulnerable-component-6',
  template: '<div [innerHTML]="commentHtml"></div>'
})
export class BadCase6Component implements OnInit {
  commentHtml: any;
  
  constructor(private http: HttpClient, private $sce: any) { }
  
  ngOnInit() {
    const commentId = location.search.split('id=')[1];
    this.http.get<{content: string}>(`https://api.example.com/comments/${commentId}`).subscribe(data => {
      // ruleid: typescript-detect-angular-trustas-method
      this.commentHtml = this.$sce.trustAs('html', data.content);
    });
  }
}

@Component({
  selector: 'app-vulnerable-component-7',
  template: '<div [innerHTML]="messageContent"></div>'
})
export class BadCase7Component implements OnInit {
  messageContent: any;
  
  constructor(private http: HttpClient, private $sce: any) { }
  
  ngOnInit() {
    const headers = new HttpHeaders().set('Authorization', 'Bearer token123');
    this.http.get<{message: string}>('https://api.example.com/messages/latest', { headers }).subscribe(data => {
      let content = data.message;
      if (content.length > 100) {
        content = content.substring(0, 100) + '...';
      }
      // ruleid: typescript-detect-angular-trustas-method
      this.messageContent = this.$sce.trustAs('html', content);
    });
  }
}

@Injectable({
  providedIn: 'root'
})
export class BadCase8Service {
  constructor(private http: HttpClient, private $sce: any) { }
  
  getExternalWidget(widgetId: string): any {
    return new Observable(observer => {
      this.http.get<{widgetHtml: string, widgetScript: string}>(`https://widgets.example.com/${widgetId}`).subscribe(data => {
        const result = {
          // ruleid: typescript-detect-angular-trustas-method
          html: this.$sce.trustAs('html', data.widgetHtml),
          // ruleid: typescript-detect-angular-trustas-method
          script: this.$sce.trustAs('script', data.widgetScript)
        };
        observer.next(result);
        observer.complete();
      });
    });
  }
}

@Component({
  selector: 'app-vulnerable-component-9',
  template: '<div [innerHTML]="profileData"></div>'
})
export class BadCase9Component implements OnInit {
  profileData: any;
  
  constructor(private http: HttpClient, private $sce: any) { }
  
  ngOnInit() {
    const userId = document.cookie.split('userId=')[1].split(';')[0];
    this.http.get<{profile: string}>(`https://api.example.com/users/${userId}/profile`).subscribe(data => {
      // ruleid: typescript-detect-angular-trustas-method
      this.profileData = this.$sce.trustAs('html', data.profile);
    });
  }
}

@Component({
  selector: 'app-vulnerable-component-10',
  template: '<iframe [src]="videoUrl"></iframe>'
})
export class BadCase10Component implements OnInit {
  videoUrl: any;
  
  constructor(private http: HttpClient, private $sce: any) { }
  
  ngOnInit() {
    const videoId = new URLSearchParams(window.location.search).get('video');
    this.http.get<{embedUrl: string}>(`https://api.example.com/videos/${videoId}`).subscribe(data => {
      // ruleid: typescript-detect-angular-trustas-method
      this.videoUrl = this.$sce.trustAs('resourceUrl', data.embedUrl);
    });
  }
}

@Component({
  selector: 'app-vulnerable-component-11',
  template: '<div [innerHTML]="notificationContent"></div>'
})
export class BadCase11Component implements OnInit {
  notificationContent: any;
  
  constructor(private http: HttpClient, private $sce: any) { }
  
  ngOnInit() {
    const headers = new HttpHeaders().set('X-User-Token', localStorage.getItem('token') || '');
    this.http.get<{notifications: {id: number, content: string}[]}>('https://api.example.com/notifications', { headers })
      .subscribe(data => {
        if (data.notifications.length > 0) {
          // ruleid: typescript-detect-angular-trustas-method
          this.notificationContent = this.$sce.trustAs('html', data.notifications[0].content);
        }
      });
  }
}

@Component({
  selector: 'app-vulnerable-component-12',
  template: '<div [style]="customStyle"></div>'
})
export class BadCase12Component implements OnInit {
  customStyle: any;
  
  constructor(private http: HttpClient, private $sce: any) { }
  
  ngOnInit() {
    const themeId = localStorage.getItem('themeId') || 'default';
    this.http.get<{css: string}>(`https://api.example.com/themes/${themeId}`).subscribe(data => {
      // ruleid: typescript-detect-angular-trustas-method
      this.customStyle = this.$sce.trustAs('style', data.css);
    });
  }
}

@Component({
  selector: 'app-vulnerable-component-13',
  template: '<div [innerHTML]="articleContent"></div>'
})
export class BadCase13Component implements OnInit {
  articleContent: any;
  
  constructor(private http: HttpClient, private $sce: any) { }
  
  ngOnInit() {
    const articleId = window.location.pathname.split('/').pop();
    this.http.get<{content: string}>(`https://api.example.com/articles/${articleId}`).subscribe(data => {
      let processedContent = data.content.replace(/\n/g, '<br>');
      // ruleid: typescript-detect-angular-trustas-method
      this.articleContent = this.$sce.trustAs('html', processedContent);
    });
  }
}

@Component({
  selector: 'app-vulnerable-component-14',
  template: '<div [innerHTML]="helpContent"></div>'
})
export class BadCase14Component implements OnInit {
  helpContent: any;
  
  constructor(private http: HttpClient, private $sce: any) { }
  
  ngOnInit() {
    const helpTopic = new URLSearchParams(window.location.search).get('topic') || 'general';
    this.http.get<{content: string}>(`https://api.example.com/help/${helpTopic}`).subscribe(data => {
      // ruleid: typescript-detect-angular-trustas-method
      this.helpContent = this.$sce.trustAs('html', data.content);
    });
  }
}

@Component({
  selector: 'app-vulnerable-component-15',
  template: '<div [innerHTML]="feedbackMessage"></div>'
})
export class BadCase15Component implements OnInit {
  feedbackMessage: any;
  
  constructor(private http: HttpClient, private $sce: any) { }
  
  ngOnInit() {
    const feedbackId = sessionStorage.getItem('lastFeedbackId');
    if (feedbackId) {
      this.http.get<{message: string}>(`https://api.example.com/feedback/${feedbackId}/response`).subscribe(data => {
        // ruleid: typescript-detect-angular-trustas-method
        this.feedbackMessage = this.$sce.trustAs('html', data.message);
      });
    }
  }
}

// True Negative Examples (Safe Code)

@Component({
  selector: 'app-safe-component-1',
  template: '<div [innerHTML]="htmlContent"></div>'
})
export class GoodCase1Component implements OnInit {
  htmlContent: SafeHtml;
  
  constructor(private http: HttpClient, private sanitizer: DomSanitizer) { }
  
  ngOnInit() {
    this.http.get<string>('https://api.example.com/content', { responseType: 'text' as 'json' }).subscribe(data => {
      // ok: typescript-detect-angular-trustas-method
      this.htmlContent = this.sanitizer.bypassSecurityTrustHtml(data);
    });
  }
}

@Component({
  selector: 'app-safe-component-2',
  template: '<iframe [src]="frameUrl"></iframe>'
})
export class GoodCase2Component implements OnInit {
  frameUrl: SafeResourceUrl;
  
  constructor(private http: HttpClient, private sanitizer: DomSanitizer) { }
  
  ngOnInit() {
    this.http.get<{url: string}>('https://api.example.com/iframe-url').subscribe(response => {
      // Validate URL format before trusting
      if (this.isValidUrl(response.url)) {
        // ok: typescript-detect-angular-trustas-method
        this.frameUrl = this.sanitizer.bypassSecurityTrustResourceUrl(response.url);
      }
    });
  }
  
  private isValidUrl(url: string): boolean {
    try {
      const parsedUrl = new URL(url);
      return ['https:', 'http:'].includes(parsedUrl.protocol) && 
             parsedUrl.hostname.endsWith('trusted-domain.com');
    } catch {
      return false;
    }
  }
}

@Injectable({
  providedIn: 'root'
})
export class GoodCase3Service {
  private allowedScripts = [
    'console.log("Hello World");',
    'alert("Welcome!");'
  ];
  
  constructor(private http: HttpClient, private sanitizer: DomSanitizer) { }
  
  processUserScript(userId: string): Observable<SafeScript | null> {
    return new Observable(observer => {
      this.http.get<{script: string}>(`https://api.example.com/users/${userId}/script`).subscribe(data => {
        // Check if script is in the allowlist
        if (this.allowedScripts.includes(data.script)) {
          // ok: typescript-detect-angular-trustas-method
          const trustedScript = this.sanitizer.bypassSecurityTrustScript(data.script);
          observer.next(trustedScript);
        } else {
          observer.next(null);
        }
        observer.complete();
      });
    });
  }
}

@Component({
  selector: 'app-safe-component-4',
  template: '<div [style]="userStyle"></div>'
})
export class GoodCase4Component implements OnInit {
  userStyle: SafeStyle;
  
  constructor(private http: HttpClient, private sanitizer: DomSanitizer) { }
  
  ngOnInit() {
    const headers = new HttpHeaders().set('Content-Type', 'application/json');
    this.http.get<{style: string}>('https://api.example.com/user-style', { headers }).subscribe(data => {
      // Sanitize CSS to prevent CSS injection attacks
      const sanitizedStyle = this.sanitizeCss(data.style);
      // ok: typescript-detect-angular-trustas-method
      this.userStyle = this.sanitizer.bypassSecurityTrustStyle(sanitizedStyle);
    });
  }
  
  private sanitizeCss(css: string): string {
    // Remove potentially dangerous CSS
    return css.replace(
      /(expression|javascript|behavior|eval|vbscript):/gi, 
      'invalid:'
    );
  }
}

@Component({
  selector: 'app-safe-component-5',
  template: '<a [href]="linkUrl">Click me</a>'
})
export class GoodCase5Component implements OnInit {
  linkUrl: SafeUrl;
  
  constructor(private http: HttpClient, private sanitizer: DomSanitizer) { }
  
  ngOnInit() {
    this.http.post<{url: string}>('https://api.example.com/get-link', { id: 123 }).subscribe(response => {
      // Validate URL protocol to prevent javascript: URLs
      if (response.url.startsWith('http:') || response.url.startsWith('https:')) {
        // ok: typescript-detect-angular-trustas-method
        this.linkUrl = this.sanitizer.bypassSecurityTrustUrl(response.url);
      }
    });
  }
}

@Component({
  selector: 'app-safe-component-6',
  template: '<div [innerHTML]="commentHtml"></div>'
})
export class GoodCase6Component implements OnInit {
  commentHtml: string;
  
  constructor(private http: HttpClient) { }
  
  ngOnInit() {
    const commentId = location.search.split('id=')[1];
    this.http.get<{content: string}>(`https://api.example.com/comments/${commentId}`).subscribe(data => {
      // ok: typescript-detect-angular-trustas-method
      // Using textContent instead of innerHTML to prevent XSS
      this.commentHtml = this.escapeHtml(data.content);
    });
  }
  
  private escapeHtml(unsafe: string): string {
    return unsafe
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }
}

@Component({
  selector: 'app-safe-component-7',
  template: '<div>{{messageContent}}</div>'
})
export class GoodCase7Component implements OnInit {
  messageContent: string;
  
  constructor(private http: HttpClient) { }
  
  ngOnInit() {
    const headers = new HttpHeaders().set('Authorization', 'Bearer token123');
    this.http.get<{message: string}>('https://api.example.com/messages/latest', { headers }).subscribe(data => {
      let content = data.message;
      if (content.length > 100) {
        content = content.substring(0, 100) + '...';
      }
      // ok: typescript-detect-angular-trustas-method
      // Using interpolation binding which automatically escapes HTML
      this.messageContent = content;
    });
  }
}

@Injectable({
  providedIn: 'root'
})
export class GoodCase8Service {
  constructor(private http: HttpClient, private sanitizer: DomSanitizer) { }
  
  getExternalWidget(widgetId: string): Observable<{html: SafeHtml, script: null}> {
    return new Observable(observer => {
      this.http.get<{widgetHtml: string, widgetScript: string}>(`https://widgets.example.com/${widgetId}`).subscribe(data => {
        // Sanitize HTML content
        const sanitizedHtml = this.sanitizeHtml(data.widgetHtml);
        
        const result = {
          // ok: typescript-detect-angular-trustas-method
          html: this.sanitizer.bypassSecurityTrustHtml(sanitizedHtml),
          // Don't trust external scripts at all
          script: null
        };
        observer.next(result);
        observer.complete();
      });
    });
  }
  
  private sanitizeHtml(html: string): string {
    // Use DOMPurify or similar library in real implementation
    return html.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');
  }
}

@Component({
  selector: 'app-safe-component-9',
  template: '<div>{{profileData}}</div>'
})
export class GoodCase9Component implements OnInit {
  profileData: string;
  
  constructor(private http: HttpClient) { }
  
  ngOnInit() {
    const userId = document.cookie.split('userId=')[1].split(';')[0];
    this.http.get<{profile: string}>(`https://api.example.com/users/${userId}/profile`).subscribe(data => {
      // ok: typescript-detect-angular-trustas-method
      // Using text interpolation which automatically escapes HTML
      this.profileData = data.profile;
    });
  }
}

@Component({
  selector: 'app-safe-component-10',
  template: '<iframe [src]="videoUrl"></iframe>'
})
export class GoodCase10Component implements OnInit {
  videoUrl: SafeResourceUrl | null = null;
  
  constructor(private http: HttpClient, private sanitizer: DomSanitizer) { }
  
  ngOnInit() {
    const videoId = new URLSearchParams(window.location.search).get('video');
    this.http.get<{embedUrl: string}>(`https://api.example.com/videos/${videoId}`).subscribe(data => {
      // Validate URL is from trusted video providers
      if (this.isValidVideoUrl(data.embedUrl)) {
        // ok: typescript-detect-angular-trustas-method
        this.videoUrl = this.sanitizer.bypassSecurityTrustResourceUrl(data.embedUrl);
      }
    });
  }
  
  private isValidVideoUrl(url: string): boolean {
    const trustedDomains = ['youtube.com', 'vimeo.com', 'dailymotion.com'];
    try {
      const parsedUrl = new URL(url);
      return trustedDomains.some(domain => parsedUrl.hostname.endsWith(domain));
    } catch {
      return false;
    }
  }
}

@Component({
  selector: 'app-safe-component-11',
  template: '<ul><li *ngFor="let notification of notifications">{{notification.content}}</li></ul>'
})
export class GoodCase11Component implements OnInit {
  notifications: {id: number, content: string}[] = [];
  
  constructor(private http: HttpClient) { }
  
  ngOnInit() {
    const headers = new HttpHeaders().set('X-User-Token', localStorage.getItem('token') || '');
    this.http.get<{notifications: {id: number, content: string}[]}>('https://api.example.com/notifications', { headers })
      .subscribe(data => {
        // ok: typescript-detect-angular-trustas-method
        // Using ngFor with text interpolation which automatically escapes HTML
        this.notifications = data.notifications;
      });
  }
}

@Component({
  selector: 'app-safe-component-12',
  template: '<div [ngStyle]="customStyle"></div>'
})
export class GoodCase12Component implements OnInit {
  customStyle: {[key: string]: string} = {};
  
  constructor(private http: HttpClient) { }
  
  ngOnInit() {
    const themeId = localStorage.getItem('themeId') || 'default';
    this.http.get<{backgroundColor: string, color: string, fontSize: string}>(`https://api.example.com/themes/${themeId}/properties`).subscribe(data => {
      // ok: typescript-detect-angular-trustas-method
      // Using ngStyle with individual style properties instead of raw CSS
      this.customStyle = {
        'background-color': data.backgroundColor,
        'color': data.color,
        'font-size': data.fontSize
      };
    });
  }
}

@Component({
  selector: 'app-safe-component-13',
  template: '<div [innerHTML]="articleContent"></div>'
})
export class GoodCase13Component implements OnInit {
  articleContent: SafeHtml;
  
  constructor(private http: HttpClient, private sanitizer: DomSanitizer) { }
  
  ngOnInit() {
    const articleId = window.location.pathname.split('/').pop();
    this.http.get<{content: string}>(`https://api.example.com/articles/${articleId}`).subscribe(data => {
      // Use a proper HTML sanitizer library
      const sanitizedContent = this.sanitizeArticleContent(data.content);
      // ok: typescript-detect-angular-trustas-method
      this.articleContent = this.sanitizer.bypassSecurityTrustHtml(sanitizedContent);
    });
  }
  
  private sanitizeArticleContent(content: string): string {
    // In a real app, use DOMPurify or similar library
    // This is a simplified example
    const allowedTags = ['p', 'b', 'i', 'em', 'strong', 'a', 'ul', 'ol', 'li', 'br'];
    let doc = new DOMParser().parseFromString(content, 'text/html');
    
    // Remove disallowed tags
    const allElements = doc.querySelectorAll('*');
    for (let i = 0; i < allElements.length; i++) {
      const el = allElements[i];
      if (!allowedTags.includes(el.tagName.toLowerCase())) {
        el.parentNode?.removeChild(el);
      }
      
      // Remove all attributes except href on anchors
      Array.from(el.attributes).forEach(attr => {
        if (!(el.tagName.toLowerCase() === 'a' && attr.name === 'href')) {
          el.removeAttribute(attr.name);
        }
      });
      
      // Ensure all hrefs are http or https
      if (el.tagName.toLowerCase() === 'a' && el.getAttribute('href')) {
        const href = el.getAttribute('href');
        if (href && !href.startsWith('http:') && !href.startsWith('https:')) {
          el.setAttribute('href', '#');
        }
      }
    }
    
    return doc.body.innerHTML;
  }
}

@Component({
  selector: 'app-safe-component-14',
  template: '<div [innerHTML]="helpContent"></div>'
})
export class GoodCase14Component implements OnInit {
  helpContent: SafeHtml;
  
  constructor(private http: HttpClient, private sanitizer: DomSanitizer) { }
  
  ngOnInit() {
    const helpTopic = new URLSearchParams(window.location.search).get('topic') || 'general';
    // Validate topic parameter to prevent path traversal
    if (/^[a-z0-9-]+$/.test(helpTopic)) {
      this.http.get<{content: string}>(`https://api.example.com/help/${helpTopic}`).subscribe(data => {
        // Server should return pre-sanitized content from a CMS
        // Additional client-side sanitization
        // ok: typescript-detect-angular-trustas-method
        this.helpContent = this.sanitizer.bypassSecurityTrustHtml(data.content);
      });
    }
  }
}

@Component({
  selector: 'app-safe-component-15',
  template: '<div>{{feedbackMessage}}</div>'
})
export class GoodCase15Component implements OnInit {
  feedbackMessage: string = '';
  
  constructor(private http: HttpClient) { }
  
  ngOnInit() {
    const feedbackId = sessionStorage.getItem('lastFeedbackId');
    if (feedbackId) {
      this.http.get<{message: string}>(`https://api.example.com/feedback/${feedbackId}/response`).subscribe(data => {
        // ok: typescript-detect-angular-trustas-method
        // Using text interpolation which automatically escapes HTML
        this.feedbackMessage = data.message;
      });
    }
  }
}