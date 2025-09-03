import $ from 'jquery';
import axios from 'axios';
import * as HtmlUtils from './html-utils'; // Simulating edX's HtmlUtils

// True Positive Examples (Vulnerable Code)

// Example 1: Basic case - directly using user input from URL parameter
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_1() {
    const urlParams = new URLSearchParams(window.location.search);
    const userInput = urlParams.get('message');
    
    // ruleid: prohibit-jquery-html-ts-rule
    $('#message-container').html(userInput);
}
// {/fact}

// Example 2: Using input from a POST request with axios
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_2() {
    axios.post('/api/comments')
        .then(response => {
            const userComment = response.data.comment;
            // ruleid: prohibit-jquery-html-ts-rule
            $('#comments-section').html(userComment);
        });
}
// {/fact}

// Example 3: Using input from localStorage that could have been tampered with
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_3() {
    const savedMessage = localStorage.getItem('userMessage');
    
    // ruleid: prohibit-jquery-html-ts-rule
    $('.saved-message').html(savedMessage);
}
// {/fact}

// Example 4: Using input from a cookie
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_4() {
    const getCookie = (name: string): string => {
        const value = `; ${document.cookie}`;
        const parts = value.split(`; ${name}=`);
        if (parts.length === 2) return parts.pop()?.split(';').shift() || '';
        return '';
    };
    
    const userPreference = getCookie('userPreference');
    
    // ruleid: prohibit-jquery-html-ts-rule
    $('#preference-display').html(userPreference);
}
// {/fact}

// Example 5: Using input from a form submission
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_5() {
    document.getElementById('user-form')?.addEventListener('submit', (event) => {
        event.preventDefault();
        const formData = new FormData(event.target as HTMLFormElement);
        const userBio = formData.get('bio') as string;
        
        // ruleid: prohibit-jquery-html-ts-rule
        $('#bio-container').html(userBio);
    });
}
// {/fact}

// Example 6: Using input from WebSocket
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_6() {
    const socket = new WebSocket('wss://example.com/socket');
    
    socket.onmessage = (event) => {
        const message = JSON.parse(event.data).message;
        
        // ruleid: prohibit-jquery-html-ts-rule
        $('#chat-messages').html(message);
    };
}
// {/fact}

// Example 7: Using input from IndexedDB
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_7() {
    const request = indexedDB.open('UserDatabase', 1);
    
    request.onsuccess = (event) => {
        const db = (event.target as IDBOpenDBRequest).result;
        const transaction = db.transaction(['notes'], 'readonly');
        const objectStore = transaction.objectStore('notes');
        const noteRequest = objectStore.get(1);
        
        noteRequest.onsuccess = () => {
            const note = noteRequest.result.content;
            
            // ruleid: prohibit-jquery-html-ts-rule
            $('#note-display').html(note);
        };
    };
}
// {/fact}

// Example 8: Using input from sessionStorage
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_8() {
    const tempData = sessionStorage.getItem('tempUserData');
    
    if (tempData) {
        const parsedData = JSON.parse(tempData);
        
        // ruleid: prohibit-jquery-html-ts-rule
        $('#temp-profile').html(parsedData.description);
    }
}
// {/fact}

// Example 9: Using input from a custom event
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_9() {
    document.addEventListener('custom-message', (event: Event) => {
        const customEvent = event as CustomEvent;
        const message = customEvent.detail.message;
        
        // ruleid: prohibit-jquery-html-ts-rule
        $('#event-message').html(message);
    });
}
// {/fact}

// Example 10: Using input from URL hash fragment
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_10() {
    window.addEventListener('hashchange', () => {
        const hashContent = window.location.hash.substring(1);
        
        // ruleid: prohibit-jquery-html-ts-rule
        $('#hash-content').html(decodeURIComponent(hashContent));
    });
}
// {/fact}

// Example 11: Using input from fetch API
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_11() {
    fetch('/api/user-profile')
        .then(response => response.json())
        .then(data => {
            // ruleid: prohibit-jquery-html-ts-rule
            $('#user-profile').html(data.profileHtml);
        });
}
// {/fact}

// Example 12: Using input from XMLHttpRequest
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_12() {
    const xhr = new XMLHttpRequest();
    xhr.open('GET', '/api/announcement');
    xhr.onload = function() {
        if (xhr.status === 200) {
            const response = JSON.parse(xhr.responseText);
            
            // ruleid: prohibit-jquery-html-ts-rule
            $('#announcement').html(response.content);
        }
    };
    xhr.send();
}
// {/fact}

// Example 13: Using input from postMessage API
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_13() {
    window.addEventListener('message', (event) => {
        if (event.origin === 'https://trusted-source.com') {
            const receivedData = event.data;
            
            // ruleid: prohibit-jquery-html-ts-rule
            $('#iframe-content').html(receivedData.content);
        }
    });
}
// {/fact}

// Example 14: Using input from a third-party API
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_14() {
    axios.get('https://api.external-service.com/widget')
        .then(response => {
            // ruleid: prohibit-jquery-html-ts-rule
            $('#external-widget').html(response.data.widgetHtml);
        });
}
// {/fact}

// Example 15: Using input from URL and doing minimal processing
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_15() {
    const urlParams = new URLSearchParams(window.location.search);
    const userName = urlParams.get('name') || 'Guest';
    const welcomeMessage = `Welcome, ${userName}!`;
    
    // ruleid: prohibit-jquery-html-ts-rule
    $('#welcome').html(welcomeMessage);
}
// {/fact}

// True Negative Examples (Safe Code)

// Example 1: Using text() instead of html() for user input
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_1() {
    const urlParams = new URLSearchParams(window.location.search);
    const userInput = urlParams.get('message');
    
    // ok: prohibit-jquery-html-ts-rule
    $('#message-container').text(userInput);
}
// {/fact}

// Example 2: Using HtmlUtils.setHtml() for proper sanitization
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_2() {
    axios.post('/api/comments')
        .then(response => {
            const userComment = response.data.comment;
            
            // ok: prohibit-jquery-html-ts-rule
            HtmlUtils.setHtml($('#comments-section'), userComment);
        });
}
// {/fact}

// Example 3: Using DOMPurify for sanitization before using html()
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_3() {
    const DOMPurify = require('dompurify');
    const savedMessage = localStorage.getItem('userMessage');
    
    // ok: prohibit-jquery-html-ts-rule
    $('.saved-message').html(DOMPurify.sanitize(savedMessage));
}
// {/fact}

// Example 4: Using a custom sanitization function
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_4() {
    const getCookie = (name: string): string => {
        const value = `; ${document.cookie}`;
        const parts = value.split(`; ${name}=`);
        if (parts.length === 2) return parts.pop()?.split(';').shift() || '';
        return '';
    };
    
    const sanitizeHtml = (html: string): string => {
        const tempDiv = document.createElement('div');
        tempDiv.textContent = html;
        return tempDiv.innerHTML;
    };
    
    const userPreference = getCookie('userPreference');
    
    // ok: prohibit-jquery-html-ts-rule
    $('#preference-display').html(sanitizeHtml(userPreference));
}
// {/fact}

// Example 5: Using static, trusted HTML content
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_5() {
    const trustedHtml = '<p>This is <strong>static</strong> content created by developers.</p>';
    
    // ok: prohibit-jquery-html-ts-rule
    $('#static-content').html(trustedHtml);
}
// {/fact}

// Example 6: Using text() with WebSocket data
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_6() {
    const socket = new WebSocket('wss://example.com/socket');
    
    socket.onmessage = (event) => {
        const message = JSON.parse(event.data).message;
        
        // ok: prohibit-jquery-html-ts-rule
        $('#chat-messages').text(message);
    };
}
// {/fact}

// Example 7: Using a template system that handles escaping
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_7() {
    const template = require('handlebars');
    
    fetch('/api/user-data')
        .then(response => response.json())
        .then(data => {
            const compiledTemplate = template.compile('<div>{{name}}</div>');
            const html = compiledTemplate(data);
            
            // ok: prohibit-jquery-html-ts-rule
            $('#template-content').html(html); // Safe because handlebars escapes by default
        });
}
// {/fact}

// Example 8: Using React's dangerouslySetInnerHTML with sanitization
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_8() {
    const DOMPurify = require('dompurify');
    const React = require('react');
    const ReactDOM = require('react-dom');
    
    fetch('/api/content')
        .then(response => response.json())
        .then(data => {
            const sanitizedHtml = DOMPurify.sanitize(data.html);
            
            // ok: prohibit-jquery-html-ts-rule
            ReactDOM.render(
                React.createElement('div', { 
                    dangerouslySetInnerHTML: { __html: sanitizedHtml } 
                }),
                document.getElementById('react-container')
            );
        });
}
// {/fact}

// Example 9: Using a whitelist approach for allowed HTML tags
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_9() {
    const allowedTags = ['b', 'i', 'u', 'p', 'br', 'span'];
    
    const sanitizeWithWhitelist = (input: string): string => {
        const tempDiv = document.createElement('div');
        tempDiv.innerHTML = input;
        
        const allElements = tempDiv.getElementsByTagName('*');
        for (let i = allElements.length - 1; i >= 0; i--) {
            const element = allElements[i];
            if (!allowedTags.includes(element.tagName.toLowerCase())) {
                element.parentNode?.replaceChild(
                    document.createTextNode(element.outerHTML),
                    element
                );
            }
        }
        
        return tempDiv.innerHTML;
    };
    
    const userInput = localStorage.getItem('formattedText') || '';
    
    // ok: prohibit-jquery-html-ts-rule
    $('#formatted-content').html(sanitizeWithWhitelist(userInput));
}
// {/fact}

// Example 10: Using server-side rendered HTML that's already sanitized
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_10() {
    axios.get('/api/pre-rendered-content')
        .then(response => {
            // Server has already sanitized this content
            // ok: prohibit-jquery-html-ts-rule
            $('#server-content').html(response.data.sanitizedHtml);
        });
}
// {/fact}

// Example 11: Using a constant string with no user input
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_11() {
    const staticMessage = '<div class="alert">System maintenance scheduled.</div>';
    
    // ok: prohibit-jquery-html-ts-rule
    $('#system-message').html(staticMessage);
}
// {/fact}

// Example 12: Using html() with numeric data that can't contain XSS
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_12() {
    fetch('/api/statistics')
        .then(response => response.json())
        .then(data => {
            // Numeric data can't contain XSS
            // ok: prohibit-jquery-html-ts-rule
            $('#stats').html(`<strong>${data.count}</strong> users online`);
        });
}
// {/fact}

// Example 13: Using a dedicated HTML sanitizer library
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_13() {
    const sanitizeHtml = require('sanitize-html');
    
    fetch('/api/user-content')
        .then(response => response.json())
        .then(data => {
            const clean = sanitizeHtml(data.content, {
                allowedTags: ['b', 'i', 'em', 'strong', 'a', 'p'],
                allowedAttributes: {
                    'a': ['href']
                }
            });
            
            // ok: prohibit-jquery-html-ts-rule
            $('#user-content').html(clean);
        });
}
// {/fact}

// Example 14: Using a boolean value that can't contain XSS
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_14() {
    const isActive = true;
    
    // ok: prohibit-jquery-html-ts-rule
    $('#status').html(isActive ? '<span class="active">Active</span>' : '<span class="inactive">Inactive</span>');
}
// {/fact}

// Example 15: Using a mapping function to create safe HTML
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_15() {
    fetch('/api/items')
        .then(response => response.json())
        .then(items => {
            const safeListItems = items.map((item: {id: number, name: string}) => 
                `<li data-id="${item.id}">${$('<div>').text(item.name).html()}</li>`
            ).join('');
            
            // ok: prohibit-jquery-html-ts-rule
            $('#item-list').html(`<ul>${safeListItems}</ul>`);
        });
}
// {/fact}