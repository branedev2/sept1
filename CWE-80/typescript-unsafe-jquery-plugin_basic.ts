import * as express from 'express';
import * as jQuery from 'jquery';
import * as $ from 'jquery';
import { sanitizeHtml } from 'sanitize-html';
import { escape } from 'html-escaper';
import { DOMPurify } from 'dompurify';

// True Positives (Vulnerable Code)

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_1() {
    const app = express();
    
    app.get('/search', (req, res) => {
        const userInput = req.query.q as string;
        
        // ruleid: typescript-unsafe-jquery-plugin
        $(userInput).hide(); // Direct use of user input as jQuery selector
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_2() {
    const app = express();
    
    app.post('/process', (req, res) => {
        const elementId = req.body.elementId;
        
        // ruleid: typescript-unsafe-jquery-plugin
        jQuery(elementId).addClass('highlighted'); // User input from POST body used as selector
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_3() {
    const app = express();
    
    app.get('/toggle', (req, res) => {
        const selector = req.query.selector as string;
        
        // ruleid: typescript-unsafe-jquery-plugin
        $(selector).toggle(); // Query parameter used directly as selector
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_4() {
    const app = express();
    
    app.get('/api/elements', (req, res) => {
        const className = req.query.class as string;
        const selector = '.' + className; // Simple concatenation doesn't make it safe
        
        // ruleid: typescript-unsafe-jquery-plugin
        $(selector).css('color', 'red');
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_5() {
    const app = express();
    
    app.get('/update', (req, res) => {
        const header = req.headers['x-element-id'] as string;
        
        // ruleid: typescript-unsafe-jquery-plugin
        jQuery(header).text('Updated via header'); // Header value used as selector
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_6() {
    const app = express();
    
    app.get('/complex', (req, res) => {
        const param = req.query.param as string;
        let selector = '';
        
        if (param.length > 5) {
            selector = param.substring(0, 5);
        } else {
            selector = param;
        }
        
        // ruleid: typescript-unsafe-jquery-plugin
        $(selector).remove(); // Still unsafe despite some processing
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_7() {
    const app = express();
    
    app.post('/multi-select', (req, res) => {
        const ids = req.body.ids as string[];
        const selector = ids.join(', '); // Joining array elements doesn't sanitize
        
        // ruleid: typescript-unsafe-jquery-plugin
        $(selector).addClass('selected');
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_8() {
    const app = express();
    
    app.get('/cookie-selector', (req, res) => {
        const cookieValue = req.cookies.elementSelector;
        
        // ruleid: typescript-unsafe-jquery-plugin
        jQuery(cookieValue).fadeOut(); // Cookie value used as selector
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_9() {
    const app = express();
    
    app.get('/template', (req, res) => {
        const type = req.query.type as string;
        const selector = `input[type="${type}"]`; // Template literal with user input
        
        // ruleid: typescript-unsafe-jquery-plugin
        $(selector).prop('disabled', true);
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_10() {
    const app = express();
    
    app.get('/attribute', (req, res) => {
        const attr = req.query.attr as string;
        const value = req.query.value as string;
        const selector = `[${attr}="${value}"]`; // Both parts from user input
        
        // ruleid: typescript-unsafe-jquery-plugin
        jQuery(selector).hide();
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_11() {
    const app = express();
    
    app.post('/complex-selector', (req, res) => {
        const tag = req.body.tag;
        const className = req.body.class;
        const selector = tag + '.' + className; // Concatenating multiple user inputs
        
        // ruleid: typescript-unsafe-jquery-plugin
        $(selector).on('click', () => {
            console.log('Clicked');
        });
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_12() {
    const app = express();
    
    app.get('/indirect', (req, res) => {
        const userInput = req.query.selector as string;
        const options = {
            selector: userInput
        };
        
        // ruleid: typescript-unsafe-jquery-plugin
        $(options.selector).slideToggle(); // Indirect usage through object
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_13() {
    const app = express();
    
    app.get('/conditional', (req, res) => {
        const userInput = req.query.id as string;
        const selector = userInput ? '#' + userInput : 'body';
        
        // ruleid: typescript-unsafe-jquery-plugin
        jQuery(selector).append('<div>New content</div>'); // Conditional with user input
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_14() {
    const app = express();
    
    app.get('/transform', (req, res) => {
        const userInput = req.query.selector as string;
        const selector = userInput.toLowerCase(); // Simple transformation doesn't sanitize
        
        // ruleid: typescript-unsafe-jquery-plugin
        $(selector).parent().addClass('modified');
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_15() {
    const app = express();
    
    app.get('/dynamic-method', (req, res) => {
        const userInput = req.query.element as string;
        const method = req.query.method as string || 'hide';
        
        // ruleid: typescript-unsafe-jquery-plugin
        const $element = $(userInput);
        if (typeof $element[method] === 'function') {
            $element[method]();
        }
    });
}
// {/fact}

// True Negatives (Safe Code)

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_1() {
    const app = express();
    
    app.get('/search', (req, res) => {
        const userInput = req.query.q as string;
        
        // ok: typescript-unsafe-jquery-plugin
        $('#search-results').text(userInput); // Safe: using fixed selector
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_2() {
    const app = express();
    
    app.post('/process', (req, res) => {
        const elementId = req.body.elementId;
        
        // ok: typescript-unsafe-jquery-plugin
        if (/^[a-zA-Z0-9_-]+$/.test(elementId)) { // Validate input
            $('#' + elementId).addClass('highlighted');
        }
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_3() {
    const app = express();
    
    app.get('/toggle', (req, res) => {
        const selector = req.query.selector as string;
        const safeSelector = escape(selector); // Escape HTML
        
        // ok: typescript-unsafe-jquery-plugin
        $('#container').find(`[data-id="${safeSelector}"]`).toggle(); // Using escaped value in attribute
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_4() {
    const app = express();
    
    app.get('/api/elements', (req, res) => {
        // ok: typescript-unsafe-jquery-plugin
        const validClasses = ['success', 'error', 'warning', 'info'];
        const className = req.query.class as string;
        
        if (validClasses.includes(className)) {
            $('.' + className).css('color', 'red'); // Whitelist validation
        }
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_5() {
    const app = express();
    
    app.get('/update', (req, res) => {
        const header = req.headers['x-element-id'] as string;
        
        // ok: typescript-unsafe-jquery-plugin
        document.getElementById(header)?.setAttribute('data-updated', 'true'); // Not using jQuery selector
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_6() {
    const app = express();
    
    app.get('/safe-id', (req, res) => {
        const id = req.query.id as string;
        
        // ok: typescript-unsafe-jquery-plugin
        if (typeof id === 'string' && /^[a-zA-Z0-9_-]+$/.test(id)) {
            $(`#${id}`).show(); // Validated ID in template literal
        }
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_7() {
    const app = express();
    
    app.post('/add-class', (req, res) => {
        const elements = ['header', 'footer', 'sidebar', 'content'];
        const target = req.body.target;
        
        // ok: typescript-unsafe-jquery-plugin
        if (elements.includes(target)) {
            $(`#${target}`).addClass('active'); // Whitelist validation
        }
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_8() {
    const app = express();
    
    app.get('/sanitized', (req, res) => {
        const userInput = req.query.html as string;
        const sanitized = sanitizeHtml(userInput); // Proper sanitization
        
        // ok: typescript-unsafe-jquery-plugin
        $('#content').html(sanitized); // Using sanitized content with fixed selector
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_9() {
    const app = express();
    
    app.get('/data-attribute', (req, res) => {
        const value = req.query.value as string;
        
        // ok: typescript-unsafe-jquery-plugin
        $('[data-role="button"]').attr('data-value', value); // Fixed selector, user input as attribute value
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_10() {
    const app = express();
    
    app.get('/purified', (req, res) => {
        const userInput = req.query.content as string;
        
        // ok: typescript-unsafe-jquery-plugin
        $('.content').html(DOMPurify.sanitize(userInput)); // Using DOMPurify to sanitize
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_11() {
    const app = express();
    
    app.post('/element-by-id', (req, res) => {
        const id = req.body.id;
        
        // ok: typescript-unsafe-jquery-plugin
        const element = document.getElementById(id); // Using DOM API instead of jQuery
        if (element) {
            element.classList.add('selected');
        }
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_12() {
    const app = express();
    
    app.get('/fixed-selector', (req, res) => {
        const userInput = req.query.text as string;
        
        // ok: typescript-unsafe-jquery-plugin
        $('div.user-content').each(function() {
            $(this).text(userInput); // Fixed selector with user content as text
        });
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_13() {
    const app = express();
    
    app.get('/numeric-id', (req, res) => {
        const id = req.query.id as string;
        const numId = parseInt(id, 10);
        
        // ok: typescript-unsafe-jquery-plugin
        if (!isNaN(numId) && numId > 0 && numId < 1000) {
            $(`#item-${numId}`).show(); // Using validated numeric ID
        }
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_14() {
    const app = express();
    
    app.get('/enum-value', (req, res) => {
        const status = req.query.status as string;
        
        // ok: typescript-unsafe-jquery-plugin
        const validStatuses = ['active', 'pending', 'completed', 'cancelled'];
        if (validStatuses.includes(status)) {
            $(`.status-${status}`).show(); // Using validated enum value
        }
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_15() {
    const app = express();
    
    app.get('/data-binding', (req, res) => {
        const userId = req.query.userId as string;
        
        // ok: typescript-unsafe-jquery-plugin
        // Using a fixed selector and setting user input as data attribute
        $('#user-profile').attr('data-user-id', userId)
            .find('.user-content').text(`User ID: ${userId}`);
    });
}
// {/fact}