import express from 'express';
import sanitizeHtml from 'sanitize-html';
import DOMPurify from 'dompurify';
import { JSDOM } from 'jsdom';

const app = express();
app.use(express.json());
const window = new JSDOM('').window;
const purify = DOMPurify(window);

// True Positives (Vulnerable Code)

// Bad case 1: Simple string replacement for < and >
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_1(req: express.Request, res: express.Response) {
    const userInput = req.query.comment as string;
    // ruleid: detect-replaceall-sanitization-ts-rule
    const sanitized = userInput.replaceAll('<', '&lt;').replaceAll('>', '&gt;');
    res.send(`<div>${sanitized}</div>`);
}
// {/fact}

// Bad case 2: Using replace with regex for script tags
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_2(req: express.Request, res: express.Response) {
    const userInput = req.query.message as string;
    // ruleid: detect-replaceall-sanitization-ts-rule
    const sanitized = userInput.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');
    res.send(`<p>${sanitized}</p>`);
}
// {/fact}

// Bad case 3: Attempting to sanitize multiple HTML tags
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_3(req: express.Request, res: express.Response) {
    const userContent = req.body.content;
    // ruleid: detect-replaceall-sanitization-ts-rule
    const sanitized = userContent
        .replaceAll('<script>', '')
        .replaceAll('</script>', '')
        .replaceAll('<img', '&lt;img')
        .replaceAll('<iframe', '&lt;iframe');
    res.send(`<div class="user-content">${sanitized}</div>`);
}
// {/fact}

// Bad case 4: Using string replacement in a template literal
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_4(req: express.Request, res: express.Response) {
    const userName = req.query.name as string;
    // ruleid: detect-replaceall-sanitization-ts-rule
    const sanitized = `${userName}`.replaceAll('<', '&lt;').replaceAll('>', '&gt;');
    res.send(`<h1>Welcome, ${sanitized}!</h1>`);
}
// {/fact}

// Bad case 5: Sanitizing with multiple replacements in a loop
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_5(req: express.Request, res: express.Response) {
    const userBio = req.body.bio;
    const dangerousTags = ['<script>', '<iframe>', '<object>', '<embed>', '<link>'];
    let sanitized = userBio;
    
    for (const tag of dangerousTags) {
        // ruleid: detect-replaceall-sanitization-ts-rule
        sanitized = sanitized.replaceAll(tag, '');
    }
    
    res.send(`<div class="bio">${sanitized}</div>`);
}
// {/fact}

// Bad case 6: Sanitizing with string replacement in a utility function
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_6(req: express.Request, res: express.Response) {
    const userComment = req.body.comment;
    
    function sanitizeInput(input: string): string {
        // ruleid: detect-replaceall-sanitization-ts-rule
        return input
            .replaceAll('<', '&lt;')
            .replaceAll('>', '&gt;')
            .replaceAll('"', '&quot;')
            .replaceAll("'", '&#39;');
    }
    
    const sanitized = sanitizeInput(userComment);
    res.send(`<div class="comment">${sanitized}</div>`);
}
// {/fact}

// Bad case 7: Using replace with global flag
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_7(req: express.Request, res: express.Response) {
    const userInput = req.query.text as string;
    // ruleid: detect-replaceall-sanitization-ts-rule
    const sanitized = userInput.replace(/<script>/g, '').replace(/<\/script>/g, '');
    res.send(`<p>${sanitized}</p>`);
}
// {/fact}

// Bad case 8: Sanitizing with conditional replacement
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_8(req: express.Request, res: express.Response) {
    const userInput = req.query.input as string;
    let sanitized = userInput;
    
    if (sanitized.includes('<script>')) {
        // ruleid: detect-replaceall-sanitization-ts-rule
        sanitized = sanitized.replaceAll('<script>', '').replaceAll('</script>', '');
    }
    
    res.send(`<div>${sanitized}</div>`);
}
// {/fact}

// Bad case 9: Using string replacement with template strings
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_9(req: express.Request, res: express.Response) {
    const userProfile = req.body.profile;
    // ruleid: detect-replaceall-sanitization-ts-rule
    const sanitized = `${userProfile}`.replace(/[<>]/g, match => {
        return match === '<' ? '&lt;' : '&gt;';
    });
    
    res.send(`<section>${sanitized}</section>`);
}
// {/fact}

// Bad case 10: Sanitizing with a map of replacements
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_10(req: express.Request, res: express.Response) {
    const userMessage = req.query.message as string;
    const replacements: Record<string, string> = {
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
    };
    
    let sanitized = userMessage;
    for (const [char, entity] of Object.entries(replacements)) {
        // ruleid: detect-replaceall-sanitization-ts-rule
        sanitized = sanitized.replaceAll(char, entity);
    }
    
    res.send(`<p>${sanitized}</p>`);
}
// {/fact}

// Bad case 11: Using string replacement in an arrow function
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_11(req: express.Request, res: express.Response) {
    const userInput = req.query.input as string;
    
    const sanitize = (input: string) => {
        // ruleid: detect-replaceall-sanitization-ts-rule
        return input.replace(/<.*?>/g, '');
    };
    
    const sanitized = sanitize(userInput);
    res.send(`<div>${sanitized}</div>`);
}
// {/fact}

// Bad case 12: Sanitizing with string replacement and chained methods
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_12(req: express.Request, res: express.Response) {
    const userInput = req.query.data as string;
    // ruleid: detect-replaceall-sanitization-ts-rule
    const sanitized = userInput
        .trim()
        .toLowerCase()
        .replaceAll('<script>', '')
        .replaceAll('</script>', '');
    
    res.send(`<div>${sanitized}</div>`);
}
// {/fact}

// Bad case 13: Using string replacement with a switch statement
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_13(req: express.Request, res: express.Response) {
    const userInput = req.query.text as string;
    const sanitizationType = req.query.type as string;
    
    let sanitized = userInput;
    switch (sanitizationType) {
        case 'basic':
            // ruleid: detect-replaceall-sanitization-ts-rule
            sanitized = sanitized.replaceAll('<', '&lt;').replaceAll('>', '&gt;');
            break;
        case 'scripts':
            // ruleid: detect-replaceall-sanitization-ts-rule
            sanitized = sanitized.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');
            break;
        default:
            // ruleid: detect-replaceall-sanitization-ts-rule
            sanitized = sanitized.replace(/[<>'"]/g, '');
    }
    
    res.send(`<div>${sanitized}</div>`);
}
// {/fact}

// Bad case 14: Using string replacement with try-catch
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_14(req: express.Request, res: express.Response) {
    const userInput = req.query.content as string;
    
    let sanitized = '';
    try {
        // ruleid: detect-replaceall-sanitization-ts-rule
        sanitized = userInput
            .replaceAll('<script>', '')
            .replaceAll('</script>', '')
            .replaceAll('javascript:', '');
    } catch (error) {
        sanitized = 'Error processing content';
    }
    
    res.send(`<div>${sanitized}</div>`);
}
// {/fact}

// Bad case 15: Using string replacement with a custom function
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_15(req: express.Request, res: express.Response) {
    const userInput = req.body.html;
    
    function customSanitizer(html: string): string {
        const dangerousTags = ['script', 'iframe', 'object', 'embed'];
        let result = html;
        
        for (const tag of dangerousTags) {
            const openRegex = new RegExp(`<${tag}[^>]*>`, 'gi');
            const closeRegex = new RegExp(`</${tag}>`, 'gi');
            // ruleid: detect-replaceall-sanitization-ts-rule
            result = result.replace(openRegex, '').replace(closeRegex, '');
        }
        
        return result;
    }
    
    const sanitized = customSanitizer(userInput);
    res.send(`<div>${sanitized}</div>`);
}
// {/fact}

// True Negatives (Safe Code)

// Good case 1: Using sanitize-html library
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_1(req: express.Request, res: express.Response) {
    const userInput = req.query.comment as string;
    // ok: detect-replaceall-sanitization-ts-rule
    const sanitized = sanitizeHtml(userInput, {
        allowedTags: ['b', 'i', 'em', 'strong', 'a'],
        allowedAttributes: {
            'a': ['href']
        }
    });
    res.send(`<div>${sanitized}</div>`);
}
// {/fact}

// Good case 2: Using DOMPurify
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_2(req: express.Request, res: express.Response) {
    const userInput = req.query.message as string;
    // ok: detect-replaceall-sanitization-ts-rule
    const sanitized = purify.sanitize(userInput);
    res.send(`<p>${sanitized}</p>`);
}
// {/fact}

// Good case 3: Using sanitize-html with custom options
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_3(req: express.Request, res: express.Response) {
    const userContent = req.body.content;
    // ok: detect-replaceall-sanitization-ts-rule
    const sanitized = sanitizeHtml(userContent, {
        allowedTags: [],
        allowedAttributes: {},
        disallowedTagsMode: 'recursiveEscape'
    });
    res.send(`<div class="user-content">${sanitized}</div>`);
}
// {/fact}

// Good case 4: Using DOMPurify with config options
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_4(req: express.Request, res: express.Response) {
    const userName = req.query.name as string;
    // ok: detect-replaceall-sanitization-ts-rule
    const sanitized = purify.sanitize(userName, {
        FORBID_TAGS: ['style', 'script'],
        FORBID_ATTR: ['onerror', 'onload']
    });
    res.send(`<h1>Welcome, ${sanitized}!</h1>`);
}
// {/fact}

// Good case 5: Using sanitize-html in a utility function
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_5(req: express.Request, res: express.Response) {
    const userBio = req.body.bio;
    
    function sanitizeInput(input: string): string {
        // ok: detect-replaceall-sanitization-ts-rule
        return sanitizeHtml(input, {
            allowedTags: ['b', 'i', 'em', 'strong'],
            allowedAttributes: {}
        });
    }
    
    const sanitized = sanitizeInput(userBio);
    res.send(`<div class="bio">${sanitized}</div>`);
}
// {/fact}

// Good case 6: Using DOMPurify with a conditional
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_6(req: express.Request, res: express.Response) {
    const userComment = req.body.comment;
    let sanitized = '';
    
    if (typeof userComment === 'string') {
        // ok: detect-replaceall-sanitization-ts-rule
        sanitized = purify.sanitize(userComment);
    } else {
        sanitized = 'Invalid comment';
    }
    
    res.send(`<div class="comment">${sanitized}</div>`);
}
// {/fact}

// Good case 7: Using sanitize-html with try-catch
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_7(req: express.Request, res: express.Response) {
    const userInput = req.query.text as string;
    
    let sanitized = '';
    try {
        // ok: detect-replaceall-sanitization-ts-rule
        sanitized = sanitizeHtml(userInput);
    } catch (error) {
        sanitized = 'Error processing content';
    }
    
    res.send(`<p>${sanitized}</p>`);
}
// {/fact}

// Good case 8: Using DOMPurify in an arrow function
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_8(req: express.Request, res: express.Response) {
    const userInput = req.query.input as string;
    
    const sanitize = (input: string) => {
        // ok: detect-replaceall-sanitization-ts-rule
        return purify.sanitize(input);
    };
    
    const sanitized = sanitize(userInput);
    res.send(`<div>${sanitized}</div>`);
}
// {/fact}

// Good case 9: Using sanitize-html with a switch statement
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_9(req: express.Request, res: express.Response) {
    const userProfile = req.body.profile;
    const profileType = req.body.type;
    
    let sanitized = '';
    switch (profileType) {
        case 'basic':
            // ok: detect-replaceall-sanitization-ts-rule
            sanitized = sanitizeHtml(userProfile, { allowedTags: [] });
            break;
        case 'formatted':
            // ok: detect-replaceall-sanitization-ts-rule
            sanitized = sanitizeHtml(userProfile, {
                allowedTags: ['b', 'i', 'em', 'strong']
            });
            break;
        default:
            // ok: detect-replaceall-sanitization-ts-rule
            sanitized = sanitizeHtml(userProfile);
    }
    
    res.send(`<section>${sanitized}</section>`);
}
// {/fact}

// Good case 10: Using DOMPurify with template literals
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_10(req: express.Request, res: express.Response) {
    const userMessage = req.query.message as string;
    // ok: detect-replaceall-sanitization-ts-rule
    const sanitized = purify.sanitize(`${userMessage}`);
    res.send(`<p>${sanitized}</p>`);
}
// {/fact}

// Good case 11: Using sanitize-html with a custom function
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_11(req: express.Request, res: express.Response) {
    const userInput = req.query.input as string;
    
    function customSanitizer(html: string): string {
        // ok: detect-replaceall-sanitization-ts-rule
        return sanitizeHtml(html, {
            allowedTags: ['p', 'br', 'strong', 'em'],
            allowedAttributes: {}
        });
    }
    
    const sanitized = customSanitizer(userInput);
    res.send(`<div>${sanitized}</div>`);
}
// {/fact}

// Good case 12: Using DOMPurify with chained methods
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_12(req: express.Request, res: express.Response) {
    const userInput = req.query.data as string;
    // ok: detect-replaceall-sanitization-ts-rule
    const sanitized = purify.sanitize(userInput.trim().toLowerCase());
    res.send(`<div>${sanitized}</div>`);
}
// {/fact}

// Good case 13: Using sanitize-html with a map of configurations
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_13(req: express.Request, res: express.Response) {
    const userInput = req.query.text as string;
    const sanitizationType = req.query.type as string;
    
    const configMap: Record<string, sanitizeHtml.IOptions> = {
        'basic': { allowedTags: [] },
        'formatted': { allowedTags: ['b', 'i', 'em', 'strong'] },
        'links': { allowedTags: ['a'], allowedAttributes: { 'a': ['href'] } }
    };
    
    const config = configMap[sanitizationType] || { allowedTags: [] };
    // ok: detect-replaceall-sanitization-ts-rule
    const sanitized = sanitizeHtml(userInput, config);
    
    res.send(`<div>${sanitized}</div>`);
}
// {/fact}

// Good case 14: Using DOMPurify with a wrapper class
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_14(req: express.Request, res: express.Response) {
    const userInput = req.query.content as string;
    
    class HtmlSanitizer {
        static sanitize(html: string): string {
            // ok: detect-replaceall-sanitization-ts-rule
            return purify.sanitize(html);
        }
    }
    
    const sanitized = HtmlSanitizer.sanitize(userInput);
    res.send(`<div>${sanitized}</div>`);
}
// {/fact}

// Good case 15: Using sanitize-html with async/await
// {fact rule=autoescape-disabled@v1.0 defects=0}
async function good_case_15(req: express.Request, res: express.Response) {
    const userInput = req.body.html;
    
    const sanitizeAsync = async (input: string): Promise<string> => {
        // Simulating async operation
        return new Promise((resolve) => {
            setTimeout(() => {
                // ok: detect-replaceall-sanitization-ts-rule
                resolve(sanitizeHtml(input));
            }, 10);
        });
    };
    
    const sanitized = await sanitizeAsync(userInput);
    res.send(`<div>${sanitized}</div>`);
}
// {/fact}

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});