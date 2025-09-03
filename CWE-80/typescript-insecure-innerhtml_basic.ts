// Import necessary modules
import express from 'express';
import axios from 'axios';
import * as DOMPurify from 'dompurify';
import { JSDOM } from 'jsdom';
import * as sanitizeHtml from 'sanitize-html';

// Initialize Express app for examples
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Initialize DOMPurify
const window = new JSDOM('').window;
const purify = DOMPurify(window);

// ==================== TRUE POSITIVES (Vulnerable Code) ====================

// Case 1: Direct assignment of query parameter to innerHTML
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_1() {
    app.get('/profile', (req, res) => {
        const username = req.query.username as string;
        const element = document.getElementById('user-profile');
        if (element) {
            // ruleid: insecure-innerhtml-ts-rule
            element.innerHTML = username;
        }
        res.send('Profile updated');
    });
}
// {/fact}

// Case 2: Using innerHTML with concatenated user input from POST body
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_2() {
    app.post('/comment', (req, res) => {
        const comment = req.body.comment;
        const commentSection = document.getElementById('comments');
        if (commentSection) {
            // ruleid: insecure-innerhtml-ts-rule
            commentSection.innerHTML = '<div class="comment">' + comment + '</div>';
        }
        res.send('Comment added');
    });
}
// {/fact}

// Case 3: Using innerHTML with template literals containing user input
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_3() {
    app.get('/search', (req, res) => {
        const searchTerm = req.query.q as string;
        const resultsDiv = document.getElementById('search-results');
        if (resultsDiv) {
            // ruleid: insecure-innerhtml-ts-rule
            resultsDiv.innerHTML = `<h2>Search results for: ${searchTerm}</h2>`;
        }
        res.send('Search completed');
    });
}
// {/fact}

// Case 4: Using innerHTML with data from request headers
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_4() {
    app.get('/header-display', (req, res) => {
        const userAgent = req.headers['user-agent'] as string;
        const headerInfo = document.getElementById('header-info');
        if (headerInfo) {
            // ruleid: insecure-innerhtml-ts-rule
            headerInfo.innerHTML = `Your browser: ${userAgent}`;
        }
        res.send('Header info displayed');
    });
}
// {/fact}

// Case 5: Using innerHTML with data from cookies
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_5() {
    app.get('/preferences', (req, res) => {
        const theme = req.cookies.theme;
        const prefsDiv = document.getElementById('user-preferences');
        if (prefsDiv) {
            // ruleid: insecure-innerhtml-ts-rule
            prefsDiv.innerHTML = `<p>Your theme preference: ${theme}</p>`;
        }
        res.send('Preferences loaded');
    });
}
// {/fact}

// Case 6: Using innerHTML with data from URL parameters via window.location
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_6() {
    const displayMessage = () => {
        const urlParams = new URLSearchParams(window.location.search);
        const message = urlParams.get('message');
        const messageBox = document.getElementById('message-box');
        if (messageBox) {
            // ruleid: insecure-innerhtml-ts-rule
            messageBox.innerHTML = message || 'No message provided';
        }
    };
    displayMessage();
}
// {/fact}

// Case 7: Using innerHTML with data from an API response
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_7() {
    app.get('/news', async (req, res) => {
        try {
            const response = await axios.get(`https://api.example.com/news?category=${req.query.category}`);
            const newsData = response.data.content; // Untrusted data from external API
            const newsContainer = document.getElementById('news-container');
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

// Case 8: Using innerHTML with data from localStorage
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_8() {
    const loadUserNotes = () => {
        const savedNotes = localStorage.getItem('userNotes'); // Could contain malicious content
        const notesContainer = document.getElementById('notes-container');
        if (notesContainer && savedNotes) {
            // ruleid: insecure-innerhtml-ts-rule
            notesContainer.innerHTML = savedNotes;
        }
    };
    loadUserNotes();
}
// {/fact}

// Case 9: Using innerHTML with data from a form input
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_9() {
    const handleFormSubmit = (event: Event) => {
        event.preventDefault();
        const form = event.target as HTMLFormElement;
        const formData = new FormData(form);
        const bio = formData.get('bio') as string;
        const bioDisplay = document.getElementById('bio-display');
        if (bioDisplay) {
            // ruleid: insecure-innerhtml-ts-rule
            bioDisplay.innerHTML = bio;
        }
    };
    
    const form = document.getElementById('profile-form');
    if (form) {
        form.addEventListener('submit', handleFormSubmit);
    }
}
// {/fact}

// Case 10: Using innerHTML with data from sessionStorage
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_10() {
    const loadUserProfile = () => {
        const userProfile = sessionStorage.getItem('userProfile'); // Could contain malicious content
        const profileContainer = document.getElementById('profile-container');
        if (profileContainer && userProfile) {
            // ruleid: insecure-innerhtml-ts-rule
            profileContainer.innerHTML = userProfile;
        }
    };
    loadUserProfile();
}
// {/fact}

// Case 11: Using innerHTML with data from URL hash
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_11() {
    const loadHashContent = () => {
        const hash = window.location.hash.substring(1); // Remove the # symbol
        const contentDiv = document.getElementById('hash-content');
        if (contentDiv) {
            // ruleid: insecure-innerhtml-ts-rule
            contentDiv.innerHTML = decodeURIComponent(hash);
        }
    };
    window.addEventListener('hashchange', loadHashContent);
    loadHashContent();
}
// {/fact}

// Case 12: Using innerHTML with minimal processing of user input
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_12() {
    app.get('/welcome', (req, res) => {
        let username = req.query.name as string;
        // Minimal processing that doesn't prevent XSS
        username = username.replace(/script/gi, '');
        
        const welcomeDiv = document.getElementById('welcome-message');
        if (welcomeDiv) {
            // ruleid: insecure-innerhtml-ts-rule
            welcomeDiv.innerHTML = `<h1>Welcome, ${username}!</h1>`;
        }
        res.send('Welcome message displayed');
    });
}
// {/fact}

// Case 13: Using innerHTML with data from WebSocket
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_13() {
    const setupWebSocket = () => {
        const socket = new WebSocket('wss://example.com/socket');
        
        socket.onmessage = (event) => {
            const message = JSON.parse(event.data).message;
            const chatBox = document.getElementById('chat-box');
            if (chatBox) {
                // ruleid: insecure-innerhtml-ts-rule
                chatBox.innerHTML += `<div class="message">${message}</div>`;
            }
        };
    };
    setupWebSocket();
}
// {/fact}

// Case 14: Using innerHTML with data from IndexedDB
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_14() {
    const loadUserData = () => {
        const request = indexedDB.open('UserDatabase', 1);
        
        request.onsuccess = (event) => {
            const db = (event.target as IDBOpenDBRequest).result;
            const transaction = db.transaction(['userData'], 'readonly');
            const objectStore = transaction.objectStore('userData');
            const getRequest = objectStore.get('profile');
            
            getRequest.onsuccess = () => {
                const userData = getRequest.result;
                const profileDiv = document.getElementById('user-profile');
                if (profileDiv && userData) {
                    // ruleid: insecure-innerhtml-ts-rule
                    profileDiv.innerHTML = userData.bio;
                }
            };
        };
    };
    loadUserData();
}
// {/fact}

// Case 15: Using innerHTML with data from postMessage
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_15() {
    window.addEventListener('message', (event) => {
        // Check origin but still vulnerable to XSS
        if (event.origin === 'https://trusted-source.com') {
            const messageData = event.data.content;
            const messageDisplay = document.getElementById('message-display');
            if (messageDisplay) {
                // ruleid: insecure-innerhtml-ts-rule
                messageDisplay.innerHTML = messageData;
            }
        }
    });
}
// {/fact}

// ==================== TRUE NEGATIVES (Safe Code) ====================

// Case 1: Using textContent instead of innerHTML
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_1() {
    app.get('/profile', (req, res) => {
        const username = req.query.username as string;
        const element = document.getElementById('user-profile');
        if (element) {
            // ok: insecure-innerhtml-ts-rule
            element.textContent = username;
        }
        res.send('Profile updated safely');
    });
}
// {/fact}

// Case 2: Using DOMPurify to sanitize user input before using innerHTML
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_2() {
    app.post('/comment', (req, res) => {
        const comment = req.body.comment;
        const commentSection = document.getElementById('comments');
        if (commentSection) {
            // ok: insecure-innerhtml-ts-rule
            commentSection.innerHTML = purify.sanitize('<div class="comment">' + comment + '</div>');
        }
        res.send('Comment added safely');
    });
}
// {/fact}

// Case 3: Using sanitize-html library to sanitize user input
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_3() {
    app.get('/search', (req, res) => {
        const searchTerm = req.query.q as string;
        const resultsDiv = document.getElementById('search-results');
        if (resultsDiv) {
            // ok: insecure-innerhtml-ts-rule
            resultsDiv.innerHTML = sanitizeHtml(`<h2>Search results for: ${searchTerm}</h2>`);
        }
        res.send('Search completed safely');
    });
}
// {/fact}

// Case 4: Using static trusted content with innerHTML
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_4() {
    const displayStaticMessage = () => {
        const messageBox = document.getElementById('message-box');
        if (messageBox) {
            // ok: insecure-innerhtml-ts-rule
            messageBox.innerHTML = '<h1>Welcome to our website!</h1><p>This is a static message.</p>';
        }
    };
    displayStaticMessage();
}
// {/fact}

// Case 5: Using a custom sanitization function before innerHTML
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_5() {
    app.get('/header-display', (req, res) => {
        const userAgent = req.headers['user-agent'] as string;
        
        // Custom sanitization function
        const sanitize = (input: string): string => {
            return input.replace(/[<>]/g, '');
        };
        
        const headerInfo = document.getElementById('header-info');
        if (headerInfo) {
            // ok: insecure-innerhtml-ts-rule
            headerInfo.innerHTML = `Your browser: ${sanitize(userAgent)}`;
        }
        res.send('Header info displayed safely');
    });
}
// {/fact}

// Case 6: Using a whitelist approach for HTML elements
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_6() {
    app.post('/format-text', (req, res) => {
        const userText = req.body.text;
        
        const sanitizeOptions = {
            allowedTags: ['b', 'i', 'em', 'strong', 'p', 'br'],
            allowedAttributes: {}
        };
        
        const formattedText = sanitizeHtml(userText, sanitizeOptions);
        const textDisplay = document.getElementById('formatted-text');
        
        if (textDisplay) {
            // ok: insecure-innerhtml-ts-rule
            textDisplay.innerHTML = formattedText;
        }
        res.send('Text formatted safely');
    });
}
// {/fact}

// Case 7: Using createElement and appendChild instead of innerHTML
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_7() {
    app.get('/user-info', (req, res) => {
        const username = req.query.username as string;
        const container = document.getElementById('user-container');
        
        if (container) {
            // ok: insecure-innerhtml-ts-rule
            const userElement = document.createElement('div');
            userElement.textContent = username;
            container.appendChild(userElement);
        }
        res.send('User info displayed safely');
    });
}
// {/fact}

// Case 8: Using a template with safe substitution
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_8() {
    app.get('/product', (req, res) => {
        const productName = req.query.name as string;
        const productPrice = req.query.price as string;
        
        // Create a template element
        const template = document.createElement('template');
        template.innerHTML = '<div class="product"><h2></h2><p class="price"></p></div>';
        
        // Safe substitution
        const productElement = template.content.cloneNode(true) as DocumentFragment;
        const nameElement = productElement.querySelector('h2');
        const priceElement = productElement.querySelector('.price');
        
        if (nameElement && priceElement) {
            // ok: insecure-innerhtml-ts-rule
            nameElement.textContent = productName;
            priceElement.textContent = `$${productPrice}`;
        }
        
        const productContainer = document.getElementById('product-container');
        if (productContainer) {
            productContainer.appendChild(productElement);
        }
        
        res.send('Product displayed safely');
    });
}
// {/fact}

// Case 9: Using a strict Content Security Policy
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_9() {
    app.get('/csp-protected', (req, res) => {
        // Set strict CSP headers
        res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'");
        
        const message = req.query.message as string;
        const messageDiv = document.getElementById('message');
        
        if (messageDiv) {
            // Even with innerHTML, CSP provides an additional layer of protection
            // ok: insecure-innerhtml-ts-rule
            messageDiv.textContent = message; // Still using textContent for best practice
        }
        
        res.send('CSP protected page loaded');
    });
}
// {/fact}

// Case 10: Using a trusted template system
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_10() {
    app.get('/template-render', (req, res) => {
        const userData = {
            name: req.query.name as string,
            email: req.query.email as string
        };
        
        // Simulating a trusted template system like Handlebars or EJS
        const renderTemplate = (template: string, data: any): string => {
            // This is a simplified example. Real template engines handle escaping properly.
            return template.replace(/\{\{(\w+)\}\}/g, (_, key) => {
                return data[key] ? String(data[key]).replace(/[&<>"']/g, (c) => {
                    return {
                        '&': '&amp;',
                        '<': '&lt;',
                        '>': '&gt;',
                        '"': '&quot;',
                        "'": '&#39;'
                    }[c] || c;
                }) : '';
            });
        };
        
        const template = '<div><h2>User: {{name}}</h2><p>Email: {{email}}</p></div>';
        const renderedHTML = renderTemplate(template, userData);
        
        const userContainer = document.getElementById('user-container');
        if (userContainer) {
            // ok: insecure-innerhtml-ts-rule
            userContainer.innerHTML = renderedHTML;
        }
        
        res.send('Template rendered safely');
    });
}
// {/fact}

// Case 11: Using a library that handles HTML escaping
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_11() {
    app.get('/library-escape', (req, res) => {
        const userInput = req.query.input as string;
        
        // Simulating a library function that handles HTML escaping
        const escapeHTML = (str: string): string => {
            return str.replace(/[&<>"']/g, (m) => {
                return {
                    '&': '&amp;',
                    '<': '&lt;',
                    '>': '&gt;',
                    '"': '&quot;',
                    "'": '&#39;'
                }[m] || m;
            });
        };
        
        const escapedInput = escapeHTML(userInput);
        const container = document.getElementById('content-container');
        
        if (container) {
            // ok: insecure-innerhtml-ts-rule
            container.innerHTML = `<div>${escapedInput}</div>`;
        }
        
        res.send('Content displayed with escaping');
    });
}
// {/fact}

// Case 12: Using trusted data from a verified source
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_12() {
    app.get('/admin-panel', (req, res) => {
        // Verify user is admin through proper authentication
        if (req.session && req.session.userRole === 'admin') {
            // This data comes from a trusted database, not user input
            const getAdminDashboardHTML = (): string => {
                return '<div class="admin-panel"><h1>Admin Dashboard</h1><p>Welcome to the secure admin area.</p></div>';
            };
            
            const adminContainer = document.getElementById('admin-container');
            if (adminContainer) {
                // ok: insecure-innerhtml-ts-rule
                adminContainer.innerHTML = getAdminDashboardHTML();
            }
            
            res.send('Admin panel loaded');
        } else {
            res.status(403).send('Unauthorized');
        }
    });
}
// {/fact}

// Case 13: Using a combination of DOMPurify and CSP
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_13() {
    app.post('/rich-content', (req, res) => {
        // Set CSP headers as an additional layer of protection
        res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'none'");
        
        const richContent = req.body.content;
        
        // Configure DOMPurify with strict options
        const purifyOptions = {
            FORBID_TAGS: ['script', 'style', 'iframe', 'form'],
            FORBID_ATTR: ['onerror', 'onload', 'onclick']
        };
        
        const sanitizedContent = purify.sanitize(richContent, purifyOptions);
        const contentContainer = document.getElementById('rich-content');
        
        if (contentContainer) {
            // ok: insecure-innerhtml-ts-rule
            contentContainer.innerHTML = sanitizedContent;
        }
        
        res.send('Rich content displayed safely');
    });
}
// {/fact}

// Case 14: Using a dedicated rendering function with strict validation
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_14() {
    app.get('/user-badge', (req, res) => {
        const username = req.query.username as string;
        const badgeType = req.query.type as string;
        
        // Strict validation of inputs
        const isValidUsername = /^[a-zA-Z0-9_]{3,16}$/.test(username);
        const validBadgeTypes = ['gold', 'silver', 'bronze'];
        
        if (!isValidUsername || !validBadgeTypes.includes(badgeType)) {
            res.status(400).send('Invalid input');
            return;
        }
        
        // Render badge with validated inputs
        const renderBadge = (name: string, type: string): string => {
            return `<div class="badge ${type}-badge">${name}</div>`;
        };
        
        const badgeContainer = document.getElementById('badge-container');
        if (badgeContainer) {
            // ok: insecure-innerhtml-ts-rule
            badgeContainer.innerHTML = renderBadge(username, badgeType);
        }
        
        res.send('Badge displayed safely');
    });
}
// {/fact}

// Case 15: Using innerHTML with constant string literals only
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_15() {
    const setupUI = () => {
        const navItems = [
            { title: 'Home', url: '/' },
            { title: 'About', url: '/about' },
            { title: 'Contact', url: '/contact' }
        ];
        
        const navContainer = document.getElementById('navigation');
        if (navContainer) {
            let navHTML = '<ul class="nav-list">';
            
            // Using only constant string literals and safe properties
            for (const item of navItems) {
                navHTML += `<li><a href="${item.url}">${item.title}</a></li>`;
            }
            
            navHTML += '</ul>';
            
            // ok: insecure-innerhtml-ts-rule
            navContainer.innerHTML = navHTML;
        }
    };
    setupUI();
}
// {/fact}