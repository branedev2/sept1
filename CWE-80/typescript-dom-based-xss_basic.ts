// DOM-based XSS Test Cases
// This file contains examples of vulnerable and safe DOM manipulation in TypeScript

// Import common libraries for HTTP handling
import express from 'express';
import axios from 'axios';

// True Positive Examples (Vulnerable Code)

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_1() {
    // Get user input from URL parameter
    const urlParams = new URLSearchParams(window.location.search);
    const userInput = urlParams.get('name');
    
    // Using innerHTML with unsanitized user input
    const element = document.getElementById('greeting');
    if (element) {
        // ruleid: typescript-dom-based-xss
        element.innerHTML = `Hello, ${userInput}!`;
    }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_2() {
    // Get user input from hash fragment
    const hashValue = window.location.hash.substring(1);
    
    // Using outerHTML with unsanitized user input
    const profileElement = document.querySelector('.user-profile');
    if (profileElement) {
        // ruleid: typescript-dom-based-xss
        profileElement.outerHTML = `<div class="user-profile">${hashValue}</div>`;
    }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_3() {
    // Get user input from localStorage (which could have been set from untrusted source)
    const storedUserData = localStorage.getItem('userData');
    
    // Using document.write with unsanitized user input
    if (storedUserData) {
        // ruleid: typescript-dom-based-xss
        document.write(`<p>Welcome back, ${storedUserData}</p>`);
    }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_4() {
    // Get user input from a cookie
    const cookies = document.cookie.split(';');
    let userTheme = '';
    for (const cookie of cookies) {
        const [name, value] = cookie.trim().split('=');
        if (name === 'theme') {
            userTheme = value;
            break;
        }
    }
    
    // Using document.writeln with unsanitized user input
    // ruleid: typescript-dom-based-xss
    document.writeln(`<div class="theme-container" style="${userTheme}"></div>`);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_5() {
    // Fetch data from an API and use it unsafely
    axios.get('/api/userProfile')
        .then(response => {
            const userData = response.data;
            const element = document.getElementById('profile');
            if (element) {
                // ruleid: typescript-dom-based-xss
                element.innerHTML = `<h2>${userData.name}</h2><div>${userData.bio}</div>`;
            }
        });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_6() {
    // Get input from form submission
    document.getElementById('userForm')?.addEventListener('submit', (event) => {
        event.preventDefault();
        const formData = new FormData(event.target as HTMLFormElement);
        const userComment = formData.get('comment') as string;
        
        const commentsSection = document.getElementById('comments');
        if (commentsSection) {
            // ruleid: typescript-dom-based-xss
            commentsSection.innerHTML += `<div class="comment">${userComment}</div>`;
        }
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_7() {
    // Get data from postMessage event
    window.addEventListener('message', (event) => {
        // Should verify origin, but missing that check
        const messageData = event.data;
        
        const notificationArea = document.getElementById('notifications');
        if (notificationArea && typeof messageData.notification === 'string') {
            // ruleid: typescript-dom-based-xss
            notificationArea.innerHTML = `<div class="alert">${messageData.notification}</div>`;
        }
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_8() {
    // Using template literals with innerHTML in a complex structure
    const searchParams = new URLSearchParams(window.location.search);
    const query = searchParams.get('q') || '';
    const category = searchParams.get('category') || 'All';
    
    const searchResultsElement = document.getElementById('searchResults');
    if (searchResultsElement) {
        // ruleid: typescript-dom-based-xss
        searchResultsElement.innerHTML = `
            <div class="results-header">
                <h2>Search Results for: ${query}</h2>
                <span class="category-label">Category: ${category}</span>
            </div>
            <div class="results-body">Loading...</div>
        `;
    }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_9() {
    // Using innerHTML with data from sessionStorage
    const savedView = sessionStorage.getItem('lastView');
    
    const contentArea = document.getElementById('dynamicContent');
    if (contentArea && savedView) {
        // ruleid: typescript-dom-based-xss
        contentArea.innerHTML = savedView;
    }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_10() {
    // Using a more complex data structure but still vulnerable
    interface UserData {
        name: string;
        role: string;
        preferences: {
            theme: string;
            sidebar: boolean;
            customCSS?: string;
        }
    }
    
    // Get data from IndexedDB (simplified for example)
    const userData: UserData = JSON.parse(localStorage.getItem('userData') || '{}');
    
    const userProfileElement = document.getElementById('userProfile');
    if (userProfileElement && userData.preferences?.customCSS) {
        // ruleid: typescript-dom-based-xss
        userProfileElement.innerHTML = `
            <style>${userData.preferences.customCSS}</style>
            <div class="profile-header">${userData.name} - ${userData.role}</div>
        `;
    }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_11() {
    // Using URL fragment for dynamic content loading
    window.addEventListener('hashchange', () => {
        const pageName = window.location.hash.substring(1);
        
        const pageContent = document.getElementById('pageContent');
        if (pageContent) {
            // ruleid: typescript-dom-based-xss
            pageContent.innerHTML = `<div class="dynamic-page" id="${pageName}">Loading ${pageName}...</div>`;
        }
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_12() {
    // Using Fetch API and then inserting content
    const articleId = new URLSearchParams(window.location.search).get('id');
    
    if (articleId) {
        fetch(`/api/articles/${articleId}/comments`)
            .then(response => response.json())
            .then(comments => {
                const commentsContainer = document.getElementById('comments');
                if (commentsContainer) {
                    let commentsHTML = '';
                    comments.forEach((comment: {author: string, text: string}) => {
                        commentsHTML += `<div class="comment"><strong>${comment.author}</strong>: ${comment.text}</div>`;
                    });
                    
                    // ruleid: typescript-dom-based-xss
                    commentsContainer.innerHTML = commentsHTML;
                }
            });
    }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_13() {
    // Using Web Components but still vulnerable to XSS
    class UserCard extends HTMLElement {
        connectedCallback() {
            const username = this.getAttribute('username') || '';
            const bio = this.getAttribute('bio') || '';
            
            // ruleid: typescript-dom-based-xss
            this.innerHTML = `
                <div class="user-card">
                    <h3>${username}</h3>
                    <p>${bio}</p>
                </div>
            `;
        }
    }
    
    customElements.define('user-card', UserCard);
    
    // Usage elsewhere
    const userDataFromApi = { name: "user input", bio: "user input" };
    const card = document.createElement('user-card');
    card.setAttribute('username', userDataFromApi.name);
    card.setAttribute('bio', userDataFromApi.bio);
    document.body.appendChild(card);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_14() {
    // Using third-party library data (e.g., from a charting library)
    interface ChartConfig {
        title: string;
        labels: string[];
        data: number[];
        customHTML?: string;
    }
    
    // Assume this comes from an API or user configuration
    const chartConfig: ChartConfig = JSON.parse(localStorage.getItem('chartConfig') || '{}');
    
    const chartContainer = document.getElementById('chartContainer');
    if (chartContainer && chartConfig.customHTML) {
        // ruleid: typescript-dom-based-xss
        chartContainer.innerHTML = chartConfig.customHTML;
    }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_15() {
    // Dynamically loading content based on user preferences
    interface UserPreferences {
        layout: string;
        widgets: Array<{
            id: string;
            title: string;
            content: string;
        }>;
    }
    
    // Get user preferences (could be from an API or local storage)
    const preferences: UserPreferences = JSON.parse(sessionStorage.getItem('preferences') || '{}');
    
    // Render user widgets
    const dashboardElement = document.getElementById('dashboard');
    if (dashboardElement && preferences.widgets) {
        preferences.widgets.forEach(widget => {
            const widgetElement = document.createElement('div');
            widgetElement.className = 'widget';
            // ruleid: typescript-dom-based-xss
            widgetElement.innerHTML = `
                <div class="widget-header">${widget.title}</div>
                <div class="widget-content">${widget.content}</div>
            `;
            dashboardElement.appendChild(widgetElement);
        });
    }
}
// {/fact}

// True Negative Examples (Safe Code)

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_1() {
    // Get user input from URL parameter
    const urlParams = new URLSearchParams(window.location.search);
    const userInput = urlParams.get('name');
    
    // Using textContent instead of innerHTML
    const element = document.getElementById('greeting');
    if (element) {
        // ok: typescript-dom-based-xss
        element.textContent = `Hello, ${userInput}!`;
    }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_2() {
    // Get user input from hash fragment
    const hashValue = window.location.hash.substring(1);
    
    // Creating elements safely
    const profileElement = document.querySelector('.user-profile');
    if (profileElement) {
        const newDiv = document.createElement('div');
        newDiv.className = 'user-profile';
        // ok: typescript-dom-based-xss
        newDiv.textContent = hashValue;
        
        profileElement.parentNode?.replaceChild(newDiv, profileElement);
    }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_3() {
    // Get user input from localStorage
    const storedUserData = localStorage.getItem('userData');
    
    // Using DOM methods to create elements safely
    if (storedUserData) {
        const paragraph = document.createElement('p');
        // ok: typescript-dom-based-xss
        paragraph.textContent = `Welcome back, ${storedUserData}`;
        document.body.appendChild(paragraph);
    }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_4() {
    // Get user input from a cookie
    const cookies = document.cookie.split(';');
    let userTheme = '';
    for (const cookie of cookies) {
        const [name, value] = cookie.trim().split('=');
        if (name === 'theme') {
            userTheme = value;
            break;
        }
    }
    
    // Using setAttribute for styling instead of innerHTML
    const themeContainer = document.createElement('div');
    themeContainer.className = 'theme-container';
    // ok: typescript-dom-based-xss
    themeContainer.setAttribute('style', userTheme);
    document.body.appendChild(themeContainer);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_5() {
    // Fetch data from an API and use it safely
    axios.get('/api/userProfile')
        .then(response => {
            const userData = response.data;
            const element = document.getElementById('profile');
            if (element) {
                const heading = document.createElement('h2');
                // ok: typescript-dom-based-xss
                heading.textContent = userData.name;
                
                const bioDiv = document.createElement('div');
                bioDiv.textContent = userData.bio;
                
                element.appendChild(heading);
                element.appendChild(bioDiv);
            }
        });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_6() {
    // Using DOMPurify to sanitize HTML
    // First, import DOMPurify
    import DOMPurify from 'dompurify';
    
    // Get input from form submission
    document.getElementById('userForm')?.addEventListener('submit', (event) => {
        event.preventDefault();
        const formData = new FormData(event.target as HTMLFormElement);
        const userComment = formData.get('comment') as string;
        
        const commentsSection = document.getElementById('comments');
        if (commentsSection) {
            // ok: typescript-dom-based-xss
            const sanitizedComment = DOMPurify.sanitize(userComment);
            commentsSection.innerHTML += `<div class="comment">${sanitizedComment}</div>`;
        }
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_7() {
    // Get data from postMessage event with origin check
    window.addEventListener('message', (event) => {
        // Verify origin
        if (event.origin !== 'https://trusted-source.com') {
            return;
        }
        
        const messageData = event.data;
        const notificationArea = document.getElementById('notifications');
        
        if (notificationArea && typeof messageData.notification === 'string') {
            const alertDiv = document.createElement('div');
            alertDiv.className = 'alert';
            // ok: typescript-dom-based-xss
            alertDiv.textContent = messageData.notification;
            notificationArea.appendChild(alertDiv);
        }
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_8() {
    // Using innerText for search results display
    const searchParams = new URLSearchParams(window.location.search);
    const query = searchParams.get('q') || '';
    const category = searchParams.get('category') || 'All';
    
    const searchResultsElement = document.getElementById('searchResults');
    if (searchResultsElement) {
        const headerDiv = document.createElement('div');
        headerDiv.className = 'results-header';
        
        const heading = document.createElement('h2');
        // ok: typescript-dom-based-xss
        heading.innerText = `Search Results for: ${query}`;
        
        const categorySpan = document.createElement('span');
        categorySpan.className = 'category-label';
        categorySpan.innerText = `Category: ${category}`;
        
        headerDiv.appendChild(heading);
        headerDiv.appendChild(categorySpan);
        
        const bodyDiv = document.createElement('div');
        bodyDiv.className = 'results-body';
        bodyDiv.innerText = 'Loading...';
        
        searchResultsElement.appendChild(headerDiv);
        searchResultsElement.appendChild(bodyDiv);
    }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_9() {
    // Using a custom sanitizer function
    function sanitizeHTML(html: string): string {
        const tempDiv = document.createElement('div');
        tempDiv.textContent = html;
        return tempDiv.innerHTML;
    }
    
    // Using sessionStorage with sanitization
    const savedView = sessionStorage.getItem('lastView');
    
    const contentArea = document.getElementById('dynamicContent');
    if (contentArea && savedView) {
        // ok: typescript-dom-based-xss
        contentArea.innerHTML = sanitizeHTML(savedView);
    }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_10() {
    // Using a more complex data structure safely
    interface UserData {
        name: string;
        role: string;
        preferences: {
            theme: string;
            sidebar: boolean;
            customCSS?: string;
        }
    }
    
    // Get data from IndexedDB (simplified for example)
    const userData: UserData = JSON.parse(localStorage.getItem('userData') || '{}');
    
    const userProfileElement = document.getElementById('userProfile');
    if (userProfileElement) {
        // Create elements safely
        const profileHeader = document.createElement('div');
        profileHeader.className = 'profile-header';
        // ok: typescript-dom-based-xss
        profileHeader.textContent = `${userData.name} - ${userData.role}`;
        
        // For CSS, use style element properties instead of innerHTML
        if (userData.preferences?.customCSS) {
            const styleElement = document.createElement('style');
            styleElement.type = 'text/css';
            styleElement.appendChild(document.createTextNode(userData.preferences.customCSS));
            userProfileElement.appendChild(styleElement);
        }
        
        userProfileElement.appendChild(profileHeader);
    }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_11() {
    // Using URL fragment for dynamic content loading safely
    window.addEventListener('hashchange', () => {
        const pageName = window.location.hash.substring(1);
        
        const pageContent = document.getElementById('pageContent');
        if (pageContent) {
            const dynamicPage = document.createElement('div');
            dynamicPage.className = 'dynamic-page';
            // ok: typescript-dom-based-xss
            dynamicPage.id = pageName;
            dynamicPage.textContent = `Loading ${pageName}...`;
            
            // Clear previous content and add new content
            pageContent.innerHTML = '';
            pageContent.appendChild(dynamicPage);
        }
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_12() {
    // Using Fetch API and then inserting content safely
    const articleId = new URLSearchParams(window.location.search).get('id');
    
    if (articleId) {
        fetch(`/api/articles/${articleId}/comments`)
            .then(response => response.json())
            .then(comments => {
                const commentsContainer = document.getElementById('comments');
                if (commentsContainer) {
                    // Clear existing comments
                    commentsContainer.innerHTML = '';
                    
                    // Add each comment safely
                    comments.forEach((comment: {author: string, text: string}) => {
                        const commentDiv = document.createElement('div');
                        commentDiv.className = 'comment';
                        
                        const authorStrong = document.createElement('strong');
                        // ok: typescript-dom-based-xss
                        authorStrong.textContent = comment.author;
                        
                        commentDiv.appendChild(authorStrong);
                        commentDiv.appendChild(document.createTextNode(': ' + comment.text));
                        
                        commentsContainer.appendChild(commentDiv);
                    });
                }
            });
    }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_13() {
    // Using Web Components safely
    class UserCard extends HTMLElement {
        connectedCallback() {
            const username = this.getAttribute('username') || '';
            const bio = this.getAttribute('bio') || '';
            
            // Create elements safely
            const card = document.createElement('div');
            card.className = 'user-card';
            
            const heading = document.createElement('h3');
            // ok: typescript-dom-based-xss
            heading.textContent = username;
            
            const paragraph = document.createElement('p');
            paragraph.textContent = bio;
            
            card.appendChild(heading);
            card.appendChild(paragraph);
            
            // Clear and append
            this.innerHTML = '';
            this.appendChild(card);
        }
    }
    
    customElements.define('user-card', UserCard);
    
    // Usage elsewhere
    const userDataFromApi = { name: "user input", bio: "user input" };
    const card = document.createElement('user-card');
    card.setAttribute('username', userDataFromApi.name);
    card.setAttribute('bio', userDataFromApi.bio);
    document.body.appendChild(card);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_14() {
    // Using a trusted HTML template library (simplified example)
    class SafeHTML {
        static sanitize(html: string): string {
            // This would be a real sanitizer implementation
            return html.replace(/</g, '&lt;').replace(/>/g, '&gt;');
        }
        
        static createTrusted(strings: TemplateStringsArray, ...values: any[]): string {
            let result = strings[0];
            for (let i = 0; i < values.length; i++) {
                result += this.sanitize(String(values[i])) + strings[i + 1];
            }
            return result;
        }
    }
    
    // Using the safe template with third-party data
    interface ChartConfig {
        title: string;
        labels: string[];
        data: number[];
        customHTML?: string;
    }
    
    const chartConfig: ChartConfig = JSON.parse(localStorage.getItem('chartConfig') || '{}');
    
    const chartContainer = document.getElementById('chartContainer');
    if (chartContainer && chartConfig.customHTML) {
        // ok: typescript-dom-based-xss
        chartContainer.innerHTML = SafeHTML.sanitize(chartConfig.customHTML);
    }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_15() {
    // Dynamically loading content based on user preferences safely
    interface UserPreferences {
        layout: string;
        widgets: Array<{
            id: string;
            title: string;
            content: string;
        }>;
    }
    
    // Import DOMPurify
    import DOMPurify from 'dompurify';
    
    // Get user preferences
    const preferences: UserPreferences = JSON.parse(sessionStorage.getItem('preferences') || '{}');
    
    // Render user widgets safely
    const dashboardElement = document.getElementById('dashboard');
    if (dashboardElement && preferences.widgets) {
        preferences.widgets.forEach(widget => {
            const widgetElement = document.createElement('div');
            widgetElement.className = 'widget';
            
            const headerDiv = document.createElement('div');
            headerDiv.className = 'widget-header';
            // ok: typescript-dom-based-xss
            headerDiv.textContent = widget.title;
            
            const contentDiv = document.createElement('div');
            contentDiv.className = 'widget-content';
            
            // If we need to render HTML content, sanitize it first
            if (widget.content.includes('<')) {
                contentDiv.innerHTML = DOMPurify.sanitize(widget.content);
            } else {
                contentDiv.textContent = widget.content;
            }
            
            widgetElement.appendChild(headerDiv);
            widgetElement.appendChild(contentDiv);
            dashboardElement.appendChild(widgetElement);
        });
    }
}
// {/fact}