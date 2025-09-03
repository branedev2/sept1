// File: angular_element_test_cases.js

// Import Angular and related dependencies
const angular = require('angular');
const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const sanitizeHtml = require('sanitize-html');
const DOMPurify = require('dompurify');

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// TRUE POSITIVES - Vulnerable code examples

// Example 1: Direct use of query parameter in angular.element
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_1(req, res) {
    const userInput = req.query.content;
    
    // ruleid: javascript-detect-angular-element-taint
    const element = angular.element(userInput);
    
    res.send('Element created');
}
// {/fact}

// Example 2: Using URL parameter with string concatenation
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_2(req, res) {
    const userId = req.params.id;
    const template = '<div>' + userId + '</div>';
    
    // ruleid: javascript-detect-angular-element-taint
    const element = angular.element(template);
    
    res.send('Element created with user ID');
}
// {/fact}

// Example 3: Using POST body data
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_3(req, res) {
    const userData = req.body.userData;
    
    // ruleid: javascript-detect-angular-element-taint
    const userElement = angular.element(userData);
    
    res.send('User element created');
}
// {/fact}

// Example 4: Using request header
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_4(req, res) {
    const customHeader = req.headers['x-custom-header'];
    
    // ruleid: javascript-detect-angular-element-taint
    const headerElement = angular.element(customHeader);
    
    res.send('Header element created');
}
// {/fact}

// Example 5: Using cookie value
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_5(req, res) {
    const userPreference = req.cookies.preference;
    
    // ruleid: javascript-detect-angular-element-taint
    const prefElement = angular.element(userPreference);
    
    res.send('Preference element created');
}
// {/fact}

// Example 6: Using template literals with user input
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_6(req, res) {
    const userName = req.query.name;
    const template = `<div class="user-profile">${userName}</div>`;
    
    // ruleid: javascript-detect-angular-element-taint
    const profileElement = angular.element(template);
    
    res.send('Profile created');
}
// {/fact}

// Example 7: Using input after basic transformation
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_7(req, res) {
    const userComment = req.body.comment;
    const processedComment = userComment.toUpperCase();
    
    // ruleid: javascript-detect-angular-element-taint
    const commentElement = angular.element(processedComment);
    
    res.send('Comment processed');
}
// {/fact}

// Example 8: Using input in a more complex HTML structure
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_8(req, res) {
    const searchTerm = req.query.search;
    const resultHtml = `<div class="search-result">
        <h3>Results for: ${searchTerm}</h3>
        <div class="result-content">No matches found for ${searchTerm}</div>
    </div>`;
    
    // ruleid: javascript-detect-angular-element-taint
    const searchResultElement = angular.element(resultHtml);
    
    res.send('Search completed');
}
// {/fact}

// Example 9: Using multiple inputs in one element
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_9(req, res) {
    const firstName = req.query.firstName;
    const lastName = req.query.lastName;
    const fullNameHtml = `<div>${firstName} ${lastName}</div>`;
    
    // ruleid: javascript-detect-angular-element-taint
    const nameElement = angular.element(fullNameHtml);
    
    res.send('Name element created');
}
// {/fact}

// Example 10: Using input after conditional processing
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_10(req, res) {
    let content = req.query.content;
    
    if (content.length > 100) {
        content = content.substring(0, 100) + '...';
    }
    
    // ruleid: javascript-detect-angular-element-taint
    const truncatedElement = angular.element(content);
    
    res.send('Content truncated');
}
// {/fact}

// Example 11: Using input from URL fragment
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_11(req, res) {
    const fragment = req.query.fragment;
    
    // ruleid: javascript-detect-angular-element-taint
    const fragmentElement = angular.element(`<div id="fragment-${fragment}">${fragment}</div>`);
    
    res.send('Fragment processed');
}
// {/fact}

// Example 12: Using input in a callback function
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_12(req, res) {
    const userId = req.query.id;
    
    fetchUserData(userId, function(userData) {
        // ruleid: javascript-detect-angular-element-taint
        const userElement = angular.element(`<div>${userData}</div>`);
        updateUI(userElement);
    });
    
    res.send('User data requested');
    
    function fetchUserData(id, callback) {
        // Simulate fetching data
        callback(`User ${id} data`);
    }
    
    function updateUI(element) {
        // Update UI with element
    }
}
// {/fact}

// Example 13: Using input in an arrow function
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_13(req, res) {
    const message = req.body.message;
    
    processMessage(message, (processedMsg) => {
        // ruleid: javascript-detect-angular-element-taint
        const msgElement = angular.element(processedMsg);
        displayMessage(msgElement);
    });
    
    res.send('Message processed');
    
    function processMessage(msg, callback) {
        // Process the message
        callback(`<p>${msg}</p>`);
    }
    
    function displayMessage(element) {
        // Display the message
    }
}
// {/fact}

// Example 14: Using input with array map operation
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_14(req, res) {
    const tags = req.body.tags;
    
    const tagElements = tags.map(tag => {
        // ruleid: javascript-detect-angular-element-taint
        return angular.element(`<span class="tag">${tag}</span>`);
    });
    
    res.send('Tags processed');
}
// {/fact}

// Example 15: Using input with promise
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_15(req, res) {
    const productId = req.query.productId;
    
    fetchProductDetails(productId)
        .then(details => {
            // ruleid: javascript-detect-angular-element-taint
            const productElement = angular.element(`<div class="product">${details}</div>`);
            updateProductDisplay(productElement);
        });
    
    res.send('Product details requested');
    
    function fetchProductDetails(id) {
        return Promise.resolve(`Product ${id} details`);
    }
    
    function updateProductDisplay(element) {
        // Update product display
    }
}
// {/fact}

// TRUE NEGATIVES - Safe code examples

// Example 1: Using static content
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_1(req, res) {
    // ok: javascript-detect-angular-element-taint
    const element = angular.element('<div>Static content</div>');
    
    res.send('Element created safely');
}
// {/fact}

// Example 2: Using sanitized user input
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_2(req, res) {
    const userInput = req.query.content;
    const sanitized = sanitizeHtml(userInput);
    
    // ok: javascript-detect-angular-element-taint
    const element = angular.element(sanitized);
    
    res.send('Element created safely');
}
// {/fact}

// Example 3: Using DOMPurify for sanitization
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_3(req, res) {
    const userData = req.body.userData;
    const clean = DOMPurify.sanitize(userData);
    
    // ok: javascript-detect-angular-element-taint
    const userElement = angular.element(clean);
    
    res.send('User element created safely');
}
// {/fact}

// Example 4: Using text node instead of HTML
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_4(req, res) {
    const userComment = req.body.comment;
    
    // Create a text node instead of parsing HTML
    // ok: javascript-detect-angular-element-taint
    const element = angular.element(document.createTextNode(userComment));
    
    res.send('Comment added safely');
}
// {/fact}

// Example 5: Using Angular's built-in sanitization
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_5(req, res) {
    const userHtml = req.query.html;
    const $sanitize = angular.injector(['ngSanitize']).get('$sanitize');
    const sanitized = $sanitize(userHtml);
    
    // ok: javascript-detect-angular-element-taint
    const element = angular.element(sanitized);
    
    res.send('Element sanitized with Angular');
}
// {/fact}

// Example 6: Using a whitelist approach
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_6(req, res) {
    const userType = req.query.type;
    let template;
    
    // Whitelist of allowed values
    const allowedTypes = {
        'info': '<div class="info-box"></div>',
        'warning': '<div class="warning-box"></div>',
        'error': '<div class="error-box"></div>'
    };
    
    // Use only whitelisted values
    template = allowedTypes[userType] || allowedTypes['info'];
    
    // ok: javascript-detect-angular-element-taint
    const element = angular.element(template);
    
    res.send('Safe element created');
}
// {/fact}

// Example 7: Using static content with dynamic attributes
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_7(req, res) {
    const userId = req.params.id;
    
    // Create element safely
    // ok: javascript-detect-angular-element-taint
    const element = angular.element('<div class="user-profile"></div>');
    
    // Set attributes safely after creation
    element.attr('data-user-id', userId);
    
    res.send('Element with safe attributes');
}
// {/fact}

// Example 8: Using a template function
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_8(req, res) {
    // ok: javascript-detect-angular-element-taint
    const template = createSafeTemplate();
    const element = angular.element(template);
    
    res.send('Safe template used');
    
    function createSafeTemplate() {
        return '<div class="container"><h1>Safe Template</h1></div>';
    }
}
// {/fact}

// Example 9: Using a constant template with safe interpolation
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_9(req, res) {
    const userName = req.query.name;
    
    // Create element with safe structure
    // ok: javascript-detect-angular-element-taint
    const element = angular.element('<div class="user-greeting"></div>');
    
    // Set text content safely
    element.text('Hello, ' + userName);
    
    res.send('Safe greeting created');
}
// {/fact}

// Example 10: Using Angular's jqLite to create elements safely
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_10(req, res) {
    const items = req.body.items;
    
    // ok: javascript-detect-angular-element-taint
    const listElement = angular.element('<ul class="item-list"></ul>');
    
    // Add items safely
    items.forEach(item => {
        const itemElement = angular.element('<li></li>');
        itemElement.text(item);
        listElement.append(itemElement);
    });
    
    res.send('Safe list created');
}
// {/fact}

// Example 11: Using a factory function for safe elements
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_11(req, res) {
    const type = req.query.type;
    
    // ok: javascript-detect-angular-element-taint
    const element = createSafeElement(type);
    
    res.send('Safe element created');
    
    function createSafeElement(elementType) {
        const safeTypes = {
            'div': '<div></div>',
            'span': '<span></span>',
            'p': '<p></p>'
        };
        
        return angular.element(safeTypes[elementType] || safeTypes['div']);
    }
}
// {/fact}

// Example 12: Using numeric input that can't contain HTML
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_12(req, res) {
    let count = parseInt(req.query.count, 10);
    
    // Ensure it's a number
    count = isNaN(count) ? 0 : count;
    
    // ok: javascript-detect-angular-element-taint
    const element = angular.element(`<div>${count} items</div>`);
    
    res.send('Safe numeric content');
}
// {/fact}

// Example 13: Using boolean input that can't contain HTML
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_13(req, res) {
    const isActive = req.query.active === 'true';
    
    // ok: javascript-detect-angular-element-taint
    const element = angular.element(`<div>${isActive ? 'Active' : 'Inactive'}</div>`);
    
    res.send('Safe boolean content');
}
// {/fact}

// Example 14: Using regex to strip all HTML
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_14(req, res) {
    const userInput = req.body.content;
    
    // Strip all HTML tags
    const strippedContent = userInput.replace(/<[^>]*>/g, '');
    
    // ok: javascript-detect-angular-element-taint
    const element = angular.element(`<div>${strippedContent}</div>`);
    
    res.send('Content with HTML stripped');
}
// {/fact}

// Example 15: Using a custom sanitizer function
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_15(req, res) {
    const userHtml = req.query.html;
    const sanitized = customSanitizer(userHtml);
    
    // ok: javascript-detect-angular-element-taint
    const element = angular.element(sanitized);
    
    res.send('Custom sanitized content');
    
    function customSanitizer(html) {
        // Example custom sanitizer that only allows specific tags
        return sanitizeHtml(html, {
            allowedTags: ['b', 'i', 'em', 'strong', 'a'],
            allowedAttributes: {
                'a': ['href']
            }
        });
    }
}
// {/fact}

// Export the app for testing
module.exports = app;