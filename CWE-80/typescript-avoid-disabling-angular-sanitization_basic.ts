import { Component, OnInit } from '@angular/core';
import { DomSanitizer, SafeHtml, SafeResourceUrl, SafeScript, SafeStyle, SafeUrl } from '@angular/platform-browser';
import { HttpClient } from '@angular/common/http';

// True Positive Examples (Vulnerable Code)

@Component({
  selector: 'app-bad-example-1',
  template: '<div [innerHTML]="unsafeHtml"></div>'
})
export class BadCase1Component implements OnInit {
  unsafeHtml: SafeHtml;
  
  constructor(private sanitizer: DomSanitizer, private http: HttpClient) {}
  
  ngOnInit() {
    this.http.get<string>('/api/content').subscribe(content => {
      // ruleid: typescript-avoid-disabling-angular-sanitization
      this.unsafeHtml = this.sanitizer.bypassSecurityTrustHtml(content);
    });
  }
}

@Component({
  selector: 'app-bad-example-2',
  template: '<iframe [src]="videoUrl"></iframe>'
})
export class BadCase2Component implements OnInit {
  videoUrl: SafeResourceUrl;
  
  constructor(private sanitizer: DomSanitizer, private http: HttpClient) {}
  
  ngOnInit() {
    this.http.get<{url: string}>('/api/video-url').subscribe(response => {
      // ruleid: typescript-avoid-disabling-angular-sanitization
      this.videoUrl = this.sanitizer.bypassSecurityTrustResourceUrl(response.url);
    });
  }
}

@Component({
  selector: 'app-bad-example-3',
  template: '<div [style]="userStyle"></div>'
})
export class BadCase3Component implements OnInit {
  userStyle: SafeStyle;
  
  constructor(private sanitizer: DomSanitizer, private http: HttpClient) {}
  
  ngOnInit() {
    this.http.get<{style: string}>('/api/user-style').subscribe(response => {
      // ruleid: typescript-avoid-disabling-angular-sanitization
      this.userStyle = this.sanitizer.bypassSecurityTrustStyle(response.style);
    });
  }
}

@Component({
  selector: 'app-bad-example-4',
  template: '<a [href]="dynamicUrl">Click me</a>'
})
export class BadCase4Component implements OnInit {
  dynamicUrl: SafeUrl;
  
  constructor(private sanitizer: DomSanitizer, private http: HttpClient) {}
  
  ngOnInit() {
    this.http.get<{url: string}>('/api/redirect-url').subscribe(response => {
      // ruleid: typescript-avoid-disabling-angular-sanitization
      this.dynamicUrl = this.sanitizer.bypassSecurityTrustUrl(response.url);
    });
  }
}

@Component({
  selector: 'app-bad-example-5',
  template: '<script [src]="scriptUrl"></script>'
})
export class BadCase5Component implements OnInit {
  scriptUrl: SafeScript;
  
  constructor(private sanitizer: DomSanitizer, private http: HttpClient) {}
  
  ngOnInit() {
    this.http.get<{script: string}>('/api/script-url').subscribe(response => {
      // ruleid: typescript-avoid-disabling-angular-sanitization
      this.scriptUrl = this.sanitizer.bypassSecurityTrustScript(response.script);
    });
  }
}

@Component({
  selector: 'app-bad-example-6',
  template: '<div [innerHTML]="commentHtml"></div>'
})
export class BadCase6Component implements OnInit {
  commentHtml: SafeHtml;
  
  constructor(private sanitizer: DomSanitizer, private http: HttpClient) {}
  
  ngOnInit() {
    const commentId = new URLSearchParams(window.location.search).get('commentId');
    this.http.get<{html: string}>(`/api/comments/${commentId}`).subscribe(response => {
      // ruleid: typescript-avoid-disabling-angular-sanitization
      this.commentHtml = this.sanitizer.bypassSecurityTrustHtml(response.html);
    });
  }
}

@Component({
  selector: 'app-bad-example-7',
  template: '<div [innerHTML]="profileData"></div>'
})
export class BadCase7Component implements OnInit {
  profileData: SafeHtml;
  
  constructor(private sanitizer: DomSanitizer, private http: HttpClient) {}
  
  ngOnInit() {
    const headers = { 'Content-Type': 'application/json' };
    this.http.post<{html: string}>('/api/profile', { userId: 123 }, { headers }).subscribe(response => {
      // ruleid: typescript-avoid-disabling-angular-sanitization
      this.profileData = this.sanitizer.bypassSecurityTrustHtml(response.html);
    });
  }
}

@Component({
  selector: 'app-bad-example-8',
  template: '<div [innerHTML]="dynamicContent"></div>'
})
export class BadCase8Component implements OnInit {
  dynamicContent: SafeHtml;
  
  constructor(private sanitizer: DomSanitizer) {}
  
  ngOnInit() {
    const userInput = document.getElementById('user-input') as HTMLInputElement;
    userInput.addEventListener('input', (event) => {
      const content = (event.target as HTMLInputElement).value;
      // ruleid: typescript-avoid-disabling-angular-sanitization
      this.dynamicContent = this.sanitizer.bypassSecurityTrustHtml(content);
    });
  }
}

@Component({
  selector: 'app-bad-example-9',
  template: '<iframe [src]="embedUrl"></iframe>'
})
export class BadCase9Component implements OnInit {
  embedUrl: SafeResourceUrl;
  
  constructor(private sanitizer: DomSanitizer, private http: HttpClient) {}
  
  ngOnInit() {
    const urlParams = new URLSearchParams(window.location.search);
    const embedSource = urlParams.get('embed');
    if (embedSource) {
      // ruleid: typescript-avoid-disabling-angular-sanitization
      this.embedUrl = this.sanitizer.bypassSecurityTrustResourceUrl(embedSource);
    }
  }
}

@Component({
  selector: 'app-bad-example-10',
  template: '<div [innerHTML]="messageContent"></div>'
})
export class BadCase10Component implements OnInit {
  messageContent: SafeHtml;
  
  constructor(private sanitizer: DomSanitizer, private http: HttpClient) {}
  
  ngOnInit() {
    const socket = new WebSocket('ws://example.com/chat');
    socket.onmessage = (event) => {
      const message = JSON.parse(event.data);
      // ruleid: typescript-avoid-disabling-angular-sanitization
      this.messageContent = this.sanitizer.bypassSecurityTrustHtml(message.content);
    };
  }
}

@Component({
  selector: 'app-bad-example-11',
  template: '<div [innerHTML]="notificationHtml"></div>'
})
export class BadCase11Component implements OnInit {
  notificationHtml: SafeHtml;
  
  constructor(private sanitizer: DomSanitizer, private http: HttpClient) {}
  
  ngOnInit() {
    this.http.get<{notifications: Array<{id: number, content: string}>}>('/api/notifications').subscribe(response => {
      for (const notification of response.notifications) {
        if (notification.id === 1) {
          // ruleid: typescript-avoid-disabling-angular-sanitization
          this.notificationHtml = this.sanitizer.bypassSecurityTrustHtml(notification.content);
          break;
        }
      }
    });
  }
}

@Component({
  selector: 'app-bad-example-12',
  template: '<div [style]="headerStyle"></div>'
})
export class BadCase12Component implements OnInit {
  headerStyle: SafeStyle;
  
  constructor(private sanitizer: DomSanitizer) {}
  
  ngOnInit() {
    const cookieValue = document.cookie
      .split('; ')
      .find(row => row.startsWith('theme='))
      ?.split('=')[1];
    
    if (cookieValue) {
      // ruleid: typescript-avoid-disabling-angular-sanitization
      this.headerStyle = this.sanitizer.bypassSecurityTrustStyle(cookieValue);
    }
  }
}

@Component({
  selector: 'app-bad-example-13',
  template: '<div [innerHTML]="articleContent"></div>'
})
export class BadCase13Component implements OnInit {
  articleContent: SafeHtml;
  
  constructor(private sanitizer: DomSanitizer, private http: HttpClient) {}
  
  ngOnInit() {
    const articleId = localStorage.getItem('current_article_id');
    this.http.get<{content: string}>(`/api/articles/${articleId}`).subscribe(response => {
      // ruleid: typescript-avoid-disabling-angular-sanitization
      this.articleContent = this.sanitizer.bypassSecurityTrustHtml(response.content);
    });
  }
}

@Component({
  selector: 'app-bad-example-14',
  template: '<div [innerHTML]="widgetContent"></div>'
})
export class BadCase14Component implements OnInit {
  widgetContent: SafeHtml;
  
  constructor(private sanitizer: DomSanitizer, private http: HttpClient) {}
  
  ngOnInit() {
    const widgetConfig = sessionStorage.getItem('widget_config');
    if (widgetConfig) {
      const config = JSON.parse(widgetConfig);
      this.http.get<{html: string}>(`/api/widgets/${config.id}`).subscribe(response => {
        // ruleid: typescript-avoid-disabling-angular-sanitization
        this.widgetContent = this.sanitizer.bypassSecurityTrustHtml(response.html);
      });
    }
  }
}

@Component({
  selector: 'app-bad-example-15',
  template: '<div [innerHTML]="feedbackMessage"></div>'
})
export class BadCase15Component implements OnInit {
  feedbackMessage: SafeHtml;
  
  constructor(private sanitizer: DomSanitizer, private http: HttpClient) {}
  
  ngOnInit() {
    const form = document.getElementById('feedback-form') as HTMLFormElement;
    form.addEventListener('submit', (event) => {
      event.preventDefault();
      const formData = new FormData(form);
      this.http.post<{message: string}>('/api/feedback', formData).subscribe(response => {
        // ruleid: typescript-avoid-disabling-angular-sanitization
        this.feedbackMessage = this.sanitizer.bypassSecurityTrustHtml(response.message);
      });
    });
  }
}

// True Negative Examples (Safe Code)

@Component({
  selector: 'app-good-example-1',
  template: '<div [innerHTML]="safeHtml"></div>'
})
export class GoodCase1Component implements OnInit {
  safeHtml: string;
  
  constructor(private http: HttpClient) {}
  
  ngOnInit() {
    this.http.get<string>('/api/content').subscribe(content => {
      // ok: typescript-avoid-disabling-angular-sanitization
      this.safeHtml = content; // Angular's built-in sanitization will handle this
    });
  }
}

@Component({
  selector: 'app-good-example-2',
  template: '<iframe [src]="videoUrl | safe: \'resourceUrl\'"></iframe>'
})
export class GoodCase2Component implements OnInit {
  videoUrl: string;
  
  constructor(private http: HttpClient) {}
  
  ngOnInit() {
    // Using a custom pipe that validates URLs before sanitizing
    this.http.get<{url: string}>('/api/video-url').subscribe(response => {
      // ok: typescript-avoid-disabling-angular-sanitization
      if (this.isValidVideoUrl(response.url)) {
        this.videoUrl = response.url;
      }
    });
  }
  
  private isValidVideoUrl(url: string): boolean {
    // Validate that URL is from trusted domains only
    const trustedDomains = ['youtube.com', 'vimeo.com'];
    try {
      const urlObj = new URL(url);
      return trustedDomains.some(domain => urlObj.hostname.endsWith(domain));
    } catch {
      return false;
    }
  }
}

@Component({
  selector: 'app-good-example-3',
  template: '<div [ngStyle]="userStyle"></div>'
})
export class GoodCase3Component implements OnInit {
  userStyle: {[key: string]: string};
  
  constructor(private http: HttpClient) {}
  
  ngOnInit() {
    this.http.get<{style: string}>('/api/user-style').subscribe(response => {
      // ok: typescript-avoid-disabling-angular-sanitization
      // Parse and validate style properties instead of using bypassSecurityTrustStyle
      const parsedStyle = this.parseAndValidateStyle(response.style);
      this.userStyle = parsedStyle;
    });
  }
  
  private parseAndValidateStyle(styleStr: string): {[key: string]: string} {
    const result: {[key: string]: string} = {};
    // Only allow specific safe CSS properties
    const allowedProperties = ['color', 'background-color', 'font-size', 'text-align'];
    
    try {
      const stylePairs = styleStr.split(';').filter(s => s.trim());
      for (const pair of stylePairs) {
        const [property, value] = pair.split(':').map(s => s.trim());
        if (allowedProperties.includes(property)) {
          result[property] = value;
        }
      }
    } catch {
      // Handle parsing errors
    }
    
    return result;
  }
}

@Component({
  selector: 'app-good-example-4',
  template: '<a [href]="safeUrl()">Click me</a>'
})
export class GoodCase4Component implements OnInit {
  private url: string = '';
  
  constructor(private http: HttpClient) {}
  
  ngOnInit() {
    this.http.get<{url: string}>('/api/redirect-url').subscribe(response => {
      // ok: typescript-avoid-disabling-angular-sanitization
      // Validate URL before using
      if (this.isValidUrl(response.url)) {
        this.url = response.url;
      }
    });
  }
  
  safeUrl(): string {
    // Return validated URL - Angular will sanitize it automatically
    return this.url;
  }
  
  private isValidUrl(url: string): boolean {
    try {
      const urlObj = new URL(url);
      return urlObj.protocol === 'https:' || urlObj.protocol === 'http:';
    } catch {
      return false;
    }
  }
}

@Component({
  selector: 'app-good-example-5',
  template: '<div>{{scriptContent}}</div>'
})
export class GoodCase5Component implements OnInit {
  scriptContent: string;
  
  constructor(private http: HttpClient) {}
  
  ngOnInit() {
    this.http.get<{script: string}>('/api/script-content').subscribe(response => {
      // ok: typescript-avoid-disabling-angular-sanitization
      // Display script content as text rather than executing it
      this.scriptContent = response.script;
    });
  }
}

@Component({
  selector: 'app-good-example-6',
  template: '<div>{{commentText}}</div>'
})
export class GoodCase6Component implements OnInit {
  commentText: string;
  
  constructor(private http: HttpClient) {}
  
  ngOnInit() {
    const commentId = new URLSearchParams(window.location.search).get('commentId');
    this.http.get<{text: string}>(`/api/comments/${commentId}`).subscribe(response => {
      // ok: typescript-avoid-disabling-angular-sanitization
      // Use interpolation which automatically escapes HTML
      this.commentText = response.text;
    });
  }
}

@Component({
  selector: 'app-good-example-7',
  template: '<div>{{profileData}}</div>'
})
export class GoodCase7Component implements OnInit {
  profileData: string;
  
  constructor(private http: HttpClient) {}
  
  ngOnInit() {
    const headers = { 'Content-Type': 'application/json' };
    this.http.post<{text: string}>('/api/profile', { userId: 123 }, { headers }).subscribe(response => {
      // ok: typescript-avoid-disabling-angular-sanitization
      // Use interpolation which automatically escapes HTML
      this.profileData = response.text;
    });
  }
}

@Component({
  selector: 'app-good-example-8',
  template: '<div>{{dynamicContent}}</div>'
})
export class GoodCase8Component implements OnInit {
  dynamicContent: string;
  
  constructor() {}
  
  ngOnInit() {
    const userInput = document.getElementById('user-input') as HTMLInputElement;
    userInput.addEventListener('input', (event) => {
      // ok: typescript-avoid-disabling-angular-sanitization
      // Use interpolation which automatically escapes HTML
      this.dynamicContent = (event.target as HTMLInputElement).value;
    });
  }
}

@Component({
  selector: 'app-good-example-9',
  template: '<iframe *ngIf="isTrustedSource(embedUrl)" [src]="embedUrl | safe: \'resourceUrl\'"></iframe>'
})
export class GoodCase9Component implements OnInit {
  embedUrl: string;
  
  constructor() {}
  
  ngOnInit() {
    const urlParams = new URLSearchParams(window.location.search);
    const embedSource = urlParams.get('embed');
    if (embedSource) {
      // ok: typescript-avoid-disabling-angular-sanitization
      // Only set the URL if it's from a trusted source
      if (this.isTrustedSource(embedSource)) {
        this.embedUrl = embedSource;
      }
    }
  }
  
  isTrustedSource(url: string): boolean {
    const trustedDomains = ['youtube.com', 'vimeo.com', 'trusted-domain.com'];
    try {
      const urlObj = new URL(url);
      return trustedDomains.some(domain => urlObj.hostname.endsWith(domain));
    } catch {
      return false;
    }
  }
}

@Component({
  selector: 'app-good-example-10',
  template: '<div>{{messageContent}}</div>'
})
export class GoodCase10Component implements OnInit {
  messageContent: string;
  
  constructor() {}
  
  ngOnInit() {
    const socket = new WebSocket('ws://example.com/chat');
    socket.onmessage = (event) => {
      const message = JSON.parse(event.data);
      // ok: typescript-avoid-disabling-angular-sanitization
      // Use interpolation which automatically escapes HTML
      this.messageContent = message.content;
    };
  }
}

@Component({
  selector: 'app-good-example-11',
  template: '<div *ngFor="let notification of notifications">{{notification.content}}</div>'
})
export class GoodCase11Component implements OnInit {
  notifications: Array<{id: number, content: string}> = [];
  
  constructor(private http: HttpClient) {}
  
  ngOnInit() {
    this.http.get<{notifications: Array<{id: number, content: string}>}>('/api/notifications').subscribe(response => {
      // ok: typescript-avoid-disabling-angular-sanitization
      // Use interpolation which automatically escapes HTML
      this.notifications = response.notifications;
    });
  }
}

@Component({
  selector: 'app-good-example-12',
  template: '<div [ngStyle]="safeHeaderStyle"></div>'
})
export class GoodCase12Component implements OnInit {
  safeHeaderStyle: {[key: string]: string} = {};
  
  constructor() {}
  
  ngOnInit() {
    const cookieValue = document.cookie
      .split('; ')
      .find(row => row.startsWith('theme='))
      ?.split('=')[1];
    
    if (cookieValue) {
      // ok: typescript-avoid-disabling-angular-sanitization
      // Only allow specific safe CSS properties
      const allowedThemes = ['light', 'dark', 'blue'];
      if (allowedThemes.includes(cookieValue)) {
        this.safeHeaderStyle = this.getThemeStyles(cookieValue);
      }
    }
  }
  
  private getThemeStyles(theme: string): {[key: string]: string} {
    const themes = {
      'light': { 'background-color': '#ffffff', 'color': '#000000' },
      'dark': { 'background-color': '#333333', 'color': '#ffffff' },
      'blue': { 'background-color': '#0000ff', 'color': '#ffffff' }
    };
    return themes[theme as keyof typeof themes] || themes['light'];
  }
}

@Component({
  selector: 'app-good-example-13',
  template: '<div [innerHTML]="sanitizedArticleContent"></div>'
})
export class GoodCase13Component implements OnInit {
  sanitizedArticleContent: string;
  
  constructor(private http: HttpClient) {}
  
  ngOnInit() {
    const articleId = localStorage.getItem('current_article_id');
    this.http.get<{content: string}>(`/api/articles/${articleId}`).subscribe(response => {
      // ok: typescript-avoid-disabling-angular-sanitization
      // Use a custom sanitizer that removes dangerous HTML
      this.sanitizedArticleContent = this.sanitizeHtml(response.content);
    });
  }
  
  private sanitizeHtml(html: string): string {
    // A simple example of custom sanitization
    // In a real app, use a proper HTML sanitizer library
    const div = document.createElement('div');
    div.innerHTML = html;
    
    // Remove potentially dangerous elements
    const dangerousTags = ['script', 'iframe', 'object', 'embed'];
    dangerousTags.forEach(tag => {
      const elements = div.getElementsByTagName(tag);
      while (elements.length > 0) {
        elements[0].parentNode?.removeChild(elements[0]);
      }
    });
    
    // Remove on* attributes
    const allElements = div.getElementsByTagName('*');
    for (let i = 0; i < allElements.length; i++) {
      const attributes = allElements[i].attributes;
      for (let j = attributes.length - 1; j >= 0; j--) {
        const attrName = attributes[j].name;
        if (attrName.startsWith('on')) {
          allElements[i].removeAttribute(attrName);
        }
      }
    }
    
    return div.innerHTML;
  }
}

@Component({
  selector: 'app-good-example-14',
  template: '<div>{{widgetContent}}</div>'
})
export class GoodCase14Component implements OnInit {
  widgetContent: string;
  
  constructor(private http: HttpClient) {}
  
  ngOnInit() {
    const widgetConfig = sessionStorage.getItem('widget_config');
    if (widgetConfig) {
      const config = JSON.parse(widgetConfig);
      this.http.get<{html: string}>(`/api/widgets/${config.id}`).subscribe(response => {
        // ok: typescript-avoid-disabling-angular-sanitization
        // Use interpolation which automatically escapes HTML
        this.widgetContent = response.html;
      });
    }
  }
}

@Component({
  selector: 'app-good-example-15',
  template: '<div>{{feedbackMessage}}</div>'
})
export class GoodCase15Component implements OnInit {
  feedbackMessage: string;
  
  constructor(private http: HttpClient) {}
  
  ngOnInit() {
    const form = document.getElementById('feedback-form') as HTMLFormElement;
    form.addEventListener('submit', (event) => {
      event.preventDefault();
      const formData = new FormData(form);
      this.http.post<{message: string}>('/api/feedback', formData).subscribe(response => {
        // ok: typescript-avoid-disabling-angular-sanitization
        // Use interpolation which automatically escapes HTML
        this.feedbackMessage = response.message;
      });
    });
  }
}