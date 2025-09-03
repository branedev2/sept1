// Import jQuery for demonstration purposes
// In a real environment, jQuery would be loaded via a script tag or module system
const $ = jQuery = require('jquery');

// True Positive Examples (Vulnerable Code)

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_1() {
    // Get user input from URL parameter
    const userInput = new URL(window.location.href).searchParams.get('q');
    
    // Direct use of user input in jQuery selector
    // ruleid: javascript-unsafe-jquery-plugin
    const elements = $(userInput);
    
    document.getElementById('results').appendChild(elements[0]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_2() {
    // Get user input from form field
    const userInput = document.getElementById('search-input').value;
    
    // Using jQuery with user input
    // ruleid: javascript-unsafe-jquery-plugin
    jQuery(userInput).addClass('highlight');
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_3() {
    // Get user input from URL hash
    const userInput = window.location.hash.substring(1);
    
    // Using jQuery with concatenated user input
    // ruleid: javascript-unsafe-jquery-plugin
    const container = $('#container');
    const elements = $(userInput + ' .item');
    
    container.append(elements);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_4() {
    // Get user input from cookie
    const cookies = document.cookie.split(';');
    let userInput = '';
    for (let i = 0; i < cookies.length; i++) {
        const cookie = cookies[i].trim();
        if (cookie.startsWith('userSelector=')) {
            userInput = cookie.substring('userSelector='.length);
            break;
        }
    }
    
    // Using jQuery with user input in a callback
    fetch('/api/data')
        .then(response => response.json())
        .then(data => {
            // ruleid: javascript-unsafe-jquery-plugin
            $(userInput).html(data.content);
        });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_5() {
    // Get user input from localStorage
    const userInput = localStorage.getItem('savedSelector');
    
    // Using jQuery with user input in event handler
    document.getElementById('apply-button').addEventListener('click', function() {
        // ruleid: javascript-unsafe-jquery-plugin
        $(userInput).show();
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_6() {
    // Get user input from sessionStorage
    const userInput = sessionStorage.getItem('tempSelector');
    
    // Using jQuery with user input and chaining methods
    // ruleid: javascript-unsafe-jquery-plugin
    $(userInput).css('color', 'red').appendTo('#container');
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_7() {
    // Get user input from POST body via XMLHttpRequest
    const xhr = new XMLHttpRequest();
    xhr.open('POST', '/api/process', true);
    xhr.onload = function() {
        if (xhr.status === 200) {
            const response = JSON.parse(xhr.responseText);
            const userInput = response.selector;
            
            // Using jQuery with user input in a complex expression
            // ruleid: javascript-unsafe-jquery-plugin
            $('div').replaceWith($(userInput));
        }
    };
    xhr.send(new FormData(document.getElementById('form')));
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_8() {
    // Get user input from URL parameter with fetch API
    fetch('/api/user-preferences')
        .then(response => response.json())
        .then(data => {
            const userInput = data.preferredSelector;
            
            // Using jQuery with user input in a conditional
            if (data.shouldApply) {
                // ruleid: javascript-unsafe-jquery-plugin
                const elements = $(userInput);
                elements.addClass('user-selected');
            }
        });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_9() {
    // Get user input from WebSocket
    const socket = new WebSocket('wss://example.com/socket');
    socket.onmessage = function(event) {
        const data = JSON.parse(event.data);
        const userInput = data.selector;
        
        // Using jQuery with user input in a timer
        setTimeout(function() {
            // ruleid: javascript-unsafe-jquery-plugin
            $(userInput).fadeIn();
        }, 1000);
    };
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_10() {
    // Get user input from IndexedDB
    const request = indexedDB.open('UserDatabase', 1);
    request.onsuccess = function(event) {
        const db = event.target.result;
        const transaction = db.transaction(['preferences'], 'readonly');
        const store = transaction.objectStore('preferences');
        const getRequest = store.get('selector');
        
        getRequest.onsuccess = function() {
            const userInput = getRequest.result;
            
            // Using jQuery with user input in a promise chain
            Promise.resolve().then(() => {
                // ruleid: javascript-unsafe-jquery-plugin
                $(userInput).trigger('custom-event');
            });
        };
    };
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_11() {
    // Get user input from a custom data attribute
    const element = document.querySelector('[data-user-selector]');
    const userInput = element.dataset.userSelector;
    
    // Using jQuery with user input in an IIFE
    (function() {
        // ruleid: javascript-unsafe-jquery-plugin
        const result = $(userInput);
        $('#output').append(result);
    })();
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_12() {
    // Get user input from Broadcast Channel API
    const channel = new BroadcastChannel('app_channel');
    channel.onmessage = function(event) {
        const userInput = event.data.selector;
        
        // Using jQuery with user input and multiple operations
        // ruleid: javascript-unsafe-jquery-plugin
        const elements = $(userInput);
        elements.find('span').text('Updated');
        elements.closest('div').addClass('modified');
    };
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_13() {
    // Get user input from URL and process it
    const params = new URLSearchParams(window.location.search);
    const rawInput = params.get('element');
    const userInput = rawInput ? decodeURIComponent(rawInput) : '';
    
    // Using jQuery with processed user input
    if (userInput.length > 0) {
        // ruleid: javascript-unsafe-jquery-plugin
        const result = $(userInput);
        result.each(function() {
            this.style.border = '1px solid red';
        });
    }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_14() {
    // Get user input from multiple sources
    const inputField = document.getElementById('selector-input');
    const storedValue = localStorage.getItem('selector');
    const userInput = inputField.value || storedValue || '.default';
    
    // Using jQuery with user input in an async function
    async function updateElements() {
        await new Promise(resolve => setTimeout(resolve, 100));
        // ruleid: javascript-unsafe-jquery-plugin
        $(userInput).attr('aria-selected', 'true');
    }
    
    updateElements();
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_15() {
    // Get user input from a custom event
    document.addEventListener('custom-selector', function(e) {
        const userInput = e.detail.selector;
        
        // Using jQuery with user input in a try-catch block
        try {
            // ruleid: javascript-unsafe-jquery-plugin
            const elements = $(userInput);
            console.log(`Found ${elements.length} elements`);
        } catch (error) {
            console.error('Error processing selector:', error);
        }
    });
    
    // Dispatch the custom event
    const event = new CustomEvent('custom-selector', {
        detail: { selector: window.location.hash }
    });
    document.dispatchEvent(event);
}
// {/fact}

// True Negative Examples (Safe Code)

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_1() {
    // Get user input from URL parameter
    const userInput = new URL(window.location.href).searchParams.get('q');
    
    // Using jQuery.find() instead of direct selector
    // ok: javascript-unsafe-jquery-plugin
    const container = $('#container');
    const elements = container.find(userInput);
    
    document.getElementById('results').appendChild(elements[0]);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_2() {
    // Get user input from form field
    const userInput = document.getElementById('search-input').value;
    
    // Using document.querySelector instead of jQuery
    // ok: javascript-unsafe-jquery-plugin
    const elements = document.querySelectorAll(userInput);
    elements.forEach(el => el.classList.add('highlight'));
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_3() {
    // Get user input from URL hash
    const userInput = window.location.hash.substring(1);
    
    // Using jQuery.find() with a safe parent selector
    const container = $('#container');
    // ok: javascript-unsafe-jquery-plugin
    const elements = container.find(userInput);
    
    container.append(elements);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_4() {
    // Get user input from cookie
    const cookies = document.cookie.split(';');
    let userInput = '';
    for (let i = 0; i < cookies.length; i++) {
        const cookie = cookies[i].trim();
        if (cookie.startsWith('userSelector=')) {
            userInput = cookie.substring('userSelector='.length);
            break;
        }
    }
    
    // Using a fixed selector, not user input
    // ok: javascript-unsafe-jquery-plugin
    const elements = $('.item');
    elements.html('<span>Safe content</span>');
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_5() {
    // Get user input from localStorage
    const userInput = localStorage.getItem('savedSelector');
    
    // Using jQuery with a hardcoded selector
    // ok: javascript-unsafe-jquery-plugin
    $('#user-content').text(userInput);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_6() {
    // Get user input from sessionStorage
    const userInput = sessionStorage.getItem('tempSelector');
    
    // Using jQuery.find() with a safe parent
    const parent = $('#container');
    // ok: javascript-unsafe-jquery-plugin
    const elements = parent.find(userInput);
    elements.css('color', 'red');
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_7() {
    // Get user input from POST body via XMLHttpRequest
    const xhr = new XMLHttpRequest();
    xhr.open('POST', '/api/process', true);
    xhr.onload = function() {
        if (xhr.status === 200) {
            const response = JSON.parse(xhr.responseText);
            const userInput = response.selector;
            
            // Using document.querySelector instead of jQuery
            // ok: javascript-unsafe-jquery-plugin
            const elements = document.querySelectorAll(userInput);
            elements.forEach(el => {
                el.textContent = 'Updated content';
            });
        }
    };
    xhr.send(new FormData(document.getElementById('form')));
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_8() {
    // Get user input from URL parameter with fetch API
    fetch('/api/user-preferences')
        .then(response => response.json())
        .then(data => {
            const userInput = data.preferredSelector;
            
            // Using jQuery.find() with a safe parent
            const container = $('#app');
            // ok: javascript-unsafe-jquery-plugin
            const elements = container.find(userInput);
            elements.addClass('user-selected');
        });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_9() {
    // Get user input from WebSocket
    const socket = new WebSocket('wss://example.com/socket');
    socket.onmessage = function(event) {
        const data = JSON.parse(event.data);
        const userInput = data.selector;
        
        // Using a whitelist approach for selectors
        const allowedSelectors = ['.item', '.card', '.product'];
        if (allowedSelectors.includes(userInput)) {
            // ok: javascript-unsafe-jquery-plugin
            $(userInput).fadeIn();
        } else {
            console.error('Invalid selector');
        }
    };
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_10() {
    // Get user input from IndexedDB
    const request = indexedDB.open('UserDatabase', 1);
    request.onsuccess = function(event) {
        const db = event.target.result;
        const transaction = db.transaction(['preferences'], 'readonly');
        const store = transaction.objectStore('preferences');
        const getRequest = store.get('selector');
        
        getRequest.onsuccess = function() {
            const userInput = getRequest.result;
            
            // Using jQuery.find() with a safe parent
            const root = $('#root');
            // ok: javascript-unsafe-jquery-plugin
            const elements = root.find(userInput);
            elements.trigger('custom-event');
        };
    };
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_11() {
    // Get user input from a custom data attribute
    const element = document.querySelector('[data-user-selector]');
    const userInput = element.dataset.userSelector;
    
    // Sanitizing the selector before use
    const sanitizedSelector = userInput.replace(/[<>]/g, '');
    
    // Using jQuery with sanitized input
    // ok: javascript-unsafe-jquery-plugin
    const container = $('#container');
    const result = container.find(sanitizedSelector);
    $('#output').append(result);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_12() {
    // Get user input from Broadcast Channel API
    const channel = new BroadcastChannel('app_channel');
    channel.onmessage = function(event) {
        const userInput = event.data.selector;
        
        // Using jQuery.find() with a safe parent
        const container = $('#main');
        // ok: javascript-unsafe-jquery-plugin
        const elements = container.find(userInput);
        elements.find('span').text('Updated');
        elements.closest('div').addClass('modified');
    };
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_13() {
    // Get user input from URL and process it
    const params = new URLSearchParams(window.location.search);
    const rawInput = params.get('element');
    const userInput = rawInput ? decodeURIComponent(rawInput) : '';
    
    // Using a regex to validate the selector is safe
    const selectorRegex = /^[a-zA-Z0-9_\-\.#\[\]="'~^$:,\s]+$/;
    if (userInput.length > 0 && selectorRegex.test(userInput)) {
        // ok: javascript-unsafe-jquery-plugin
        const container = $('#app');
        const result = container.find(userInput);
        result.each(function() {
            this.style.border = '1px solid red';
        });
    }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_14() {
    // Get user input from multiple sources
    const inputField = document.getElementById('selector-input');
    const storedValue = localStorage.getItem('selector');
    const userInput = inputField.value || storedValue || '.default';
    
    // Using jQuery.find() with a safe parent in an async function
    async function updateElements() {
        await new Promise(resolve => setTimeout(resolve, 100));
        const container = $('#container');
        // ok: javascript-unsafe-jquery-plugin
        container.find(userInput).attr('aria-selected', 'true');
    }
    
    updateElements();
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_15() {
    // Get user input from a custom event
    document.addEventListener('custom-selector', function(e) {
        const userInput = e.detail.selector;
        
        // Using a safe approach with document.querySelector
        try {
            // ok: javascript-unsafe-jquery-plugin
            const elements = document.querySelectorAll(userInput);
            console.log(`Found ${elements.length} elements`);
        } catch (error) {
            console.error('Error processing selector:', error);
        }
    });
    
    // Dispatch the custom event
    const event = new CustomEvent('custom-selector', {
        detail: { selector: window.location.hash }
    });
    document.dispatchEvent(event);
}
// {/fact}