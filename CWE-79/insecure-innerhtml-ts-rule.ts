// File: insecure-innerhtml-test-cases.ts

import express from 'express';
import { Request, Response } from 'express';
import axios from 'axios';
import DOMPurify from 'dompurify';
import { JSDOM } from 'jsdom';
import { sanitizeHtml } from 'sanitize-html';

// True Positive Examples (Vulnerable Code)

// Bad Case 1: Direct assignment of query parameter to innerHTML
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_1() {
    const app = express();
    
    app.get('/profile', (req: Request, res: Response) => {
        const username = req.query.username as string;
        const element = document.getElementById('user-info');
        if (element) {
            // ruleid: insecure-innerhtml-ts-rule
            element.innerHTML = username;
        }
        res.send('Profile updated');
    });
}
// {/fact}

// Bad Case 2: Using POST body data in innerHTML
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_2() {
    const app = express();
    
    app.post('/comment', express.json(), (req: Request, res: Response) => {
        const commentText = req.body.comment;
        const commentSection = document.getElementById('comments');
        if (commentSection) {
            // ruleid: insecure-innerhtml-ts-rule
            commentSection.innerHTML = commentText;
        }
        res.send('Comment posted');
    });
}
// {/fact}

// Bad Case 3: Using request header in innerHTML
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_3() {
    const app = express();
    
    app.get('/custom-page', (req: Request, res: Response) => {
        const theme = req.headers['x-theme'] as string;
        const themeElement = document.getElementById('theme-container');
        if (themeElement) {
            // ruleid: insecure-innerhtml-ts-rule
            themeElement.innerHTML = `<div class="${theme}">Custom Theme</div>`;
        }
        res.send('Theme applied');
    });
}
// {/fact}

// Bad Case 4: Using cookie data in innerHTML
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_4() {
    const app = express();
    
    app.get('/welcome', (req: Request, res: Response) => {
        const userPrefs = req.cookies.preferences;
        const welcomeBox = document.getElementById('welcome-message');
        if (welcomeBox) {
            // ruleid: insecure-innerhtml-ts-rule
            welcomeBox.innerHTML = `<h2>Welcome back!</h2><div>${userPrefs}</div>`;
        }
        res.send('Welcome page loaded');
    });
}
// {/fact}

// Bad Case 5: Using URL parameter with string concatenation
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_5() {
    const app = express();
    
    app.get('/search', (req: Request, res: Response) => {
        const searchQuery = req.query.q as string;
        const resultsDiv = document.getElementById('search-results');
        if (resultsDiv) {
            // ruleid: insecure-innerhtml-ts-rule
            resultsDiv.innerHTML = '<h3>Results for: ' + searchQuery + '</h3><div>...</div>';
        }
        res.send('Search completed');
    });
}
// {/fact}

// Bad Case 6: Using data from external API in innerHTML
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_6() {
    const app = express();
    
    app.get('/news', async (req: Request, res: Response) => {
        try {
            const response = await axios.get('https://api.example.com/news');
            const newsData = response.data.content;
            const newsContainer = document.getElementById('news-feed');
            if (newsContainer) {
                // ruleid: insecure-innerhtml-ts-rule
                newsContainer.innerHTML = newsData;
            }
            res.send('News loaded');
        } catch (error) {
            res.status(500).send('Error loading news');
        }
    });
}
// {/fact}

// Bad Case 7: Using template literals with multiple user inputs
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_7() {
    const app = express();
    
    app.get('/user-card', (req: Request, res: Response) => {
        const name = req.query.name as string;
        const title = req.query.title as string;
        const bio = req.query.bio as string;
        
        const cardElement = document.getElementById('user-card');
        if (cardElement) {
            // ruleid: insecure-innerhtml-ts-rule
            cardElement.innerHTML = `
                <div class="card">
                    <h2>${name}</h2>
                    <h3>${title}</h3>
                    <p>${bio}</p>
                </div>
            `;
        }
        res.send('User card created');
    });
}
// {/fact}

// Bad Case 8: Using innerHTML with processed but unsanitized data
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_8() {
    const app = express();
    
    app.get('/message', (req: Request, res: Response) => {
        let message = req.query.msg as string;
        // This processing doesn't sanitize HTML
        message = message.toUpperCase().trim();
        
        const messageBox = document.getElementById('message-box');
        if (messageBox) {
            // ruleid: insecure-innerhtml-ts-rule
            messageBox.innerHTML = message;
        }
        res.send('Message displayed');
    });
}
// {/fact}

// Bad Case 9: Using innerHTML in a loop with array of user inputs
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_9() {
    const app = express();
    
    app.post('/list-items', express.json(), (req: Request, res: Response) => {
        const items = req.body.items as string[];
        const listContainer = document.getElementById('item-list');
        
        if (listContainer) {
            let listContent = '';
            for (const item of items) {
                listContent += `<li>${item}</li>`;
            }
            // ruleid: insecure-innerhtml-ts-rule
            listContainer.innerHTML = listContent;
        }
        res.send('List updated');
    });
}
// {/fact}

// Bad Case 10: Using innerHTML with conditional user input
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_10() {
    const app = express();
    
    app.get('/conditional-content', (req: Request, res: Response) => {
        const userType = req.query.type as string;
        const content = req.query.content as string;
        
        const contentDiv = document.getElementById('dynamic-content');
        if (contentDiv) {
            let htmlContent = '';
            if (userType === 'admin') {
                htmlContent = `<div class="admin-panel">${content}</div>`;
            } else {
                htmlContent = `<div class="user-view">${content}</div>`;
            }
            // ruleid: insecure-innerhtml-ts-rule
            contentDiv.innerHTML = htmlContent;
        }
        res.send('Content loaded');
    });
}
// {/fact}

// Bad Case 11: Using innerHTML with object property from request
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_11() {
    const app = express();
    
    app.post('/update-profile', express.json(), (req: Request, res: Response) => {
        const profile = req.body.profile;
        const profileDiv = document.getElementById('profile-section');
        
        if (profileDiv && profile) {
            // ruleid: insecure-innerhtml-ts-rule
            profileDiv.innerHTML = `
                <h2>${profile.name}</h2>
                <p>${profile.bio}</p>
                <div>${profile.customHtml}</div>
            `;
        }
        res.send('Profile updated');
    });
}
// {/fact}

// Bad Case 12: Using innerHTML with URL fragment
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_12() {
    const app = express();
    
    app.get('/page', (req: Request, res: Response) => {
        // Get URL fragment from a custom header
        const fragment = req.headers['x-fragment'] as string;
        const contentArea = document.getElementById('content-area');
        
        if (contentArea) {
            // ruleid: insecure-innerhtml-ts-rule
            contentArea.innerHTML = `<div id="${fragment}">Content for ${fragment}</div>`;
        }
        res.send('Page loaded');
    });
}
// {/fact}

// Bad Case 13: Using innerHTML with user input in an event handler
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_13() {
    const app = express();
    
    app.get('/interactive', (req: Request, res: Response) => {
        const initialText = req.query.text as string;
        const interactiveDiv = document.getElementById('interactive-area');
        
        if (interactiveDiv) {
            const button = document.createElement('button');
            button.textContent = 'Click me';
            button.onclick = () => {
                // ruleid: insecure-innerhtml-ts-rule
                interactiveDiv.innerHTML = initialText;
            };
            interactiveDiv.appendChild(button);
        }
        res.send('Interactive page loaded');
    });
}
// {/fact}

// Bad Case 14: Using innerHTML with data from localStorage that originated from request
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_14() {
    const app = express();
    
    app.get('/save-preference', (req: Request, res: Response) => {
        const preference = req.query.pref as string;
        // Save to localStorage
        localStorage.setItem('userPreference', preference);
        res.send('Preference saved');
    });
    
    app.get('/load-preference', (req: Request, res: Response) => {
        // Load from localStorage
        const savedPreference = localStorage.getItem('userPreference');
        const prefDiv = document.getElementById('preference-display');
        
        if (prefDiv && savedPreference) {
            // ruleid: insecure-innerhtml-ts-rule
            prefDiv.innerHTML = `<div>Your preference: ${savedPreference}</div>`;
        }
        res.send('Preference loaded');
    });
}
// {/fact}

// Bad Case 15: Using innerHTML with user input in a custom component
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_15() {
    class UserProfileComponent {
        private element: HTMLElement;
        
        constructor(elementId: string) {
            this.element = document.getElementById(elementId) as HTMLElement;
        }
        
        updateFromRequest(req: Request) {
            const userData = req.body.user;
            if (this.element && userData) {
                // ruleid: insecure-innerhtml-ts-rule
                this.element.innerHTML = `
                    <div class="profile">
                        <img src="${userData.avatar}" alt="Profile picture">
                        <h2>${userData.name}</h2>
                        <div>${userData.description}</div>
                    </div>
                `;
            }
        }
    }
    
    const app = express();
    
    app.post('/update-component', express.json(), (req: Request, res: Response) => {
        const profileComponent = new UserProfileComponent('profile-container');
        profileComponent.updateFromRequest(req);
        res.send('Component updated');
    });
}
// {/fact}

// True Negative Examples (Safe Code)

// Good Case 1: Using textContent instead of innerHTML
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_1() {
    const app = express();
    
    app.get('/profile', (req: Request, res: Response) => {
        const username = req.query.username as string;
        const element = document.getElementById('user-info');
        if (element) {
            // ok: insecure-innerhtml-ts-rule
            element.textContent = username;
        }
        res.send('Profile updated');
    });
}
// {/fact}

// Good Case 2: Using DOMPurify to sanitize HTML before using innerHTML
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_2() {
    const app = express();
    const window = new JSDOM('').window;
    const purify = DOMPurify(window);
    
    app.post('/comment', express.json(), (req: Request, res: Response) => {
        const commentText = req.body.comment;
        const commentSection = document.getElementById('comments');
        if (commentSection) {
            // ok: insecure-innerhtml-ts-rule
            commentSection.innerHTML = purify.sanitize(commentText);
        }
        res.send('Comment posted');
    });
}
// {/fact}

// Good Case 3: Using a sanitization library
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_3() {
    const app = express();
    
    app.get('/custom-page', (req: Request, res: Response) => {
        const theme = req.headers['x-theme'] as string;
        const themeElement = document.getElementById('theme-container');
        if (themeElement) {
            // ok: insecure-innerhtml-ts-rule
            themeElement.innerHTML = sanitizeHtml(`<div class="${theme}">Custom Theme</div>`);
        }
        res.send('Theme applied');
    });
}
// {/fact}

// Good Case 4: Using a safe subset of HTML with strict validation
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_4() {
    const app = express();
    
    app.get('/welcome', (req: Request, res: Response) => {
        const userPrefs = req.cookies.preferences;
        const welcomeBox = document.getElementById('welcome-message');
        
        // Validate that userPrefs only contains allowed values
        const allowedPrefs = ['light', 'dark', 'system'];
        const safePrefs = allowedPrefs.includes(userPrefs) ? userPrefs : 'system';
        
        if (welcomeBox) {
            // ok: insecure-innerhtml-ts-rule
            welcomeBox.innerHTML = `<h2>Welcome back!</h2><div>Theme: ${safePrefs}</div>`;
        }
        res.send('Welcome page loaded');
    });
}
// {/fact}

// Good Case 5: Using createElement instead of innerHTML
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_5() {
    const app = express();
    
    app.get('/search', (req: Request, res: Response) => {
        const searchQuery = req.query.q as string;
        const resultsDiv = document.getElementById('search-results');
        
        if (resultsDiv) {
            // Clear previous results
            while (resultsDiv.firstChild) {
                resultsDiv.removeChild(resultsDiv.firstChild);
            }
            
            // Create elements safely
            const heading = document.createElement('h3');
            heading.textContent = `Results for: ${searchQuery}`;
            
            const content = document.createElement('div');
            content.textContent = '...';
            
            // ok: insecure-innerhtml-ts-rule
            resultsDiv.appendChild(heading);
            resultsDiv.appendChild(content);
        }
        res.send('Search completed');
    });
}
// {/fact}

// Good Case 6: Using a template with safe substitution
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_6() {
    const app = express();
    const window = new JSDOM('').window;
    const purify = DOMPurify(window);
    
    app.get('/news', async (req: Request, res: Response) => {
        try {
            const response = await axios.get('https://api.example.com/news');
            const newsData = response.data.content;
            const newsContainer = document.getElementById('news-feed');
            
            if (newsContainer) {
                // ok: insecure-innerhtml-ts-rule
                newsContainer.innerHTML = purify.sanitize(newsData, {
                    ALLOWED_TAGS: ['p', 'b', 'i', 'em', 'strong', 'a'],
                    ALLOWED_ATTR: ['href']
                });
            }
            res.send('News loaded');
        } catch (error) {
            res.status(500).send('Error loading news');
        }
    });
}
// {/fact}

// Good Case 7: Using HTML encoding for user inputs
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_7() {
    const app = express();
    
    function encodeHTML(str: string): string {
        return str
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }
    
    app.get('/user-card', (req: Request, res: Response) => {
        const name = req.query.name as string;
        const title = req.query.title as string;
        const bio = req.query.bio as string;
        
        const cardElement = document.getElementById('user-card');
        if (cardElement) {
            // ok: insecure-innerhtml-ts-rule
            cardElement.innerHTML = `
                <div class="card">
                    <h2>${encodeHTML(name)}</h2>
                    <h3>${encodeHTML(title)}</h3>
                    <p>${encodeHTML(bio)}</p>
                </div>
            `;
        }
        res.send('User card created');
    });
}
// {/fact}

// Good Case 8: Using a whitelist approach for allowed HTML
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_8() {
    const app = express();
    
    app.get('/message', (req: Request, res: Response) => {
        let message = req.query.msg as string;
        
        // Only allow specific tags and attributes
        const options = {
            allowedTags: ['b', 'i', 'em', 'strong', 'a', 'p'],
            allowedAttributes: {
                'a': ['href']
            },
            allowedIframeHostnames: []
        };
        
        const messageBox = document.getElementById('message-box');
        if (messageBox) {
            // ok: insecure-innerhtml-ts-rule
            messageBox.innerHTML = sanitizeHtml(message, options);
        }
        res.send('Message displayed');
    });
}
// {/fact}

// Good Case 9: Using a custom sanitizer function
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_9() {
    const app = express();
    
    function customSanitizer(input: string): string {
        // Remove all HTML tags
        const noTags = input.replace(/<\/?[^>]+(>|$)/g, "");
        // Encode special characters
        return noTags
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }
    
    app.post('/list-items', express.json(), (req: Request, res: Response) => {
        const items = req.body.items as string[];
        const listContainer = document.getElementById('item-list');
        
        if (listContainer) {
            let listContent = '';
            for (const item of items) {
                listContent += `<li>${customSanitizer(item)}</li>`;
            }
            // ok: insecure-innerhtml-ts-rule
            listContainer.innerHTML = listContent;
        }
        res.send('List updated');
    });
}
// {/fact}

// Good Case 10: Using static content with user data in attributes
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_10() {
    const app = express();
    
    app.get('/conditional-content', (req: Request, res: Response) => {
        const userType = req.query.type as string;
        const content = req.query.content as string;
        
        const contentDiv = document.getElementById('dynamic-content');
        if (contentDiv) {
            // Create elements programmatically
            const div = document.createElement('div');
            div.className = userType === 'admin' ? 'admin-panel' : 'user-view';
            div.textContent = content;
            
            // Clear previous content
            while (contentDiv.firstChild) {
                contentDiv.removeChild(contentDiv.firstChild);
            }
            
            // ok: insecure-innerhtml-ts-rule
            contentDiv.appendChild(div);
        }
        res.send('Content loaded');
    });
}
// {/fact}

// Good Case 11: Using a trusted template system
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_11() {
    const app = express();
    const window = new JSDOM('').window;
    const purify = DOMPurify(window);
    
    app.post('/update-profile', express.json(), (req: Request, res: Response) => {
        const profile = req.body.profile;
        const profileDiv = document.getElementById('profile-section');
        
        if (profileDiv && profile) {
            const template = `
                <h2>{{name}}</h2>
                <p>{{bio}}</p>
                <div>{{customHtml}}</div>
            `;
            
            // Replace template variables with sanitized content
            const rendered = template
                .replace('{{name}}', purify.sanitize(profile.name))
                .replace('{{bio}}', purify.sanitize(profile.bio))
                .replace('{{customHtml}}', purify.sanitize(profile.customHtml));
            
            // ok: insecure-innerhtml-ts-rule
            profileDiv.innerHTML = rendered;
        }
        res.send('Profile updated');
    });
}
// {/fact}

// Good Case 12: Using setAttribute instead of innerHTML for dynamic IDs
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_12() {
    const app = express();
    
    app.get('/page', (req: Request, res: Response) => {
        // Get URL fragment from a custom header
        const fragment = req.headers['x-fragment'] as string;
        const contentArea = document.getElementById('content-area');
        
        if (contentArea) {
            // Create elements safely
            const div = document.createElement('div');
            // Sanitize the ID to prevent XSS via ID attribute
            const safeId = fragment.replace(/[^\w-]/g, '');
            div.setAttribute('id', safeId);
            
            const text = document.createTextNode(`Content for ${fragment}`);
            div.appendChild(text);
            
            // ok: insecure-innerhtml-ts-rule
            contentArea.appendChild(div);
        }
        res.send('Page loaded');
    });
}
// {/fact}

// Good Case 13: Using a safe event handler pattern
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_13() {
    const app = express();
    
    app.get('/interactive', (req: Request, res: Response) => {
        const initialText = req.query.text as string;
        const interactiveDiv = document.getElementById('interactive-area');
        
        if (interactiveDiv) {
            const button = document.createElement('button');
            button.textContent = 'Click me';
            button.onclick = () => {
                // ok: insecure-innerhtml-ts-rule
                interactiveDiv.textContent = initialText;
            };
            interactiveDiv.appendChild(button);
        }
        res.send('Interactive page loaded');
    });
}
// {/fact}

// Good Case 14: Using a content security policy with innerHTML
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_14() {
    const app = express();
    
    app.get('/save-preference', (req: Request, res: Response) => {
        const preference = req.query.pref as string;
        // Save to localStorage
        localStorage.setItem('userPreference', preference);
        res.send('Preference saved');
    });
    
    app.get('/load-preference', (req: Request, res: Response) => {
        // Load from localStorage
        const savedPreference = localStorage.getItem('userPreference');
        const prefDiv = document.getElementById('preference-display');
        
        if (prefDiv && savedPreference) {
            // Sanitize the preference
            const window = new JSDOM('').window;
            const purify = DOMPurify(window);
            
            // ok: insecure-innerhtml-ts-rule
            prefDiv.innerHTML = purify.sanitize(`<div>Your preference: ${savedPreference}</div>`);
        }
        res.send('Preference loaded');
    });
}
// {/fact}

// Good Case 15: Using a custom component with safe rendering
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_15() {
    class SafeUserProfileComponent {
        private element: HTMLElement;
        
        constructor(elementId: string) {
            this.element = document.getElementById(elementId) as HTMLElement;
        }
        
        updateFromRequest(req: Request) {
            const userData = req.body.user;
            if (this.element && userData) {
                // Clear existing content
                while (this.element.firstChild) {
                    this.element.removeChild(this.element.firstChild);
                }
                
                // Create profile container
                const profileDiv = document.createElement('div');
                profileDiv.className = 'profile';
                
                // Create and add image
                const img = document.createElement('img');
                img.src = userData.avatar;
                img.alt = 'Profile picture';
                
                // Create and add name
                const name = document.createElement('h2');
                name.textContent = userData.name;
                
                // Create and add description
                const desc = document.createElement('div');
                desc.textContent = userData.description;
                
                // ok: insecure-innerhtml-ts-rule
                profileDiv.appendChild(img);
                profileDiv.appendChild(name);
                profileDiv.appendChild(desc);
                this.element.appendChild(profileDiv);
            }
        }
    }
    
    const app = express();
    
    app.post('/update-component', express.json(), (req: Request, res: Response) => {
        const profileComponent = new SafeUserProfileComponent('profile-container');
        profileComponent.updateFromRequest(req);
        res.send('Component updated');
    });
}
// {/fact}