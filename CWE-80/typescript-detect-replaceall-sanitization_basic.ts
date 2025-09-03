import express from 'express';
import sanitizeHtml from 'sanitize-html';
import DOMPurify from 'dompurify';
import { JSDOM } from 'jsdom';

const app = express();
app.use(express.json());
const window = new JSDOM('').window;
const purify = DOMPurify(window);

// True Positives (Vulnerable Code)

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_1() {
    const app = express();
    app.get('/vulnerable', (req, res) => {
        const userInput = req.query.input as string;
        // Attempting to sanitize HTML with replaceAll
        // ruleid: detect-replaceall-sanitization-ts-rule
        const sanitized = userInput.replaceAll('<script>', '').replaceAll('</script>', '');
        res.send(`<div>${sanitized}</div>`);
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_2() {
    const app = express();
    app.post('/profile', (req, res) => {
        const bio = req.body.bio;
        // Trying to sanitize by replacing common XSS vectors
        // ruleid: detect-replaceall-sanitization-ts-rule
        const cleanBio = bio.replaceAll('<', '&lt;').replaceAll('>', '&gt;');
        res.send(`<section class="bio">${cleanBio}</section>`);
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_3() {
    const app = express();
    app.get('/search', (req, res) => {
        const searchTerm = req.query.q as string;
        // Attempting to sanitize with multiple replacements
        // ruleid: detect-replaceall-sanitization-ts-rule
        const sanitizedSearch = searchTerm
            .replaceAll('<script>', '')
            .replaceAll('</script>', '')
            .replaceAll('javascript:', '');
        res.send(`<p>Search results for: ${sanitizedSearch}</p>`);
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_4() {
    const app = express();
    app.get('/comment', (req, res) => {
        const comment = req.query.text as string;
        // Custom sanitization function using replaceAll
        // ruleid: detect-replaceall-sanitization-ts-rule
        const sanitized = comment.replaceAll(/<.*?>/g, '');
        res.send(`<div class="comment">${sanitized}</div>`);
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_5() {
    const app = express();
    app.post('/message', (req, res) => {
        const message = req.body.message;
        // Attempting to sanitize with multiple replacements
        // ruleid: detect-replaceall-sanitization-ts-rule
        const cleanMessage = message
            .replaceAll('&', '&amp;')
            .replaceAll('<', '&lt;')
            .replaceAll('>', '&gt;')
            .replaceAll('"', '&quot;');
        res.send(`<div>${cleanMessage}</div>`);
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_6() {
    const app = express();
    app.get('/title', (req, res) => {
        const title = req.query.title as string;
        // Attempting to sanitize HTML with replaceAll
        // ruleid: detect-replaceall-sanitization-ts-rule
        const cleanTitle = title.replaceAll('<', '').replaceAll('>', '');
        document.title = cleanTitle;
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_7() {
    const app = express();
    app.post('/article', (req, res) => {
        const content = req.body.content;
        // Attempting to sanitize with replaceAll
        // ruleid: detect-replaceall-sanitization-ts-rule
        const sanitizedContent = content.replaceAll(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');
        res.send(`<article>${sanitizedContent}</article>`);
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_8() {
    const app = express();
    app.get('/username', (req, res) => {
        const username = req.query.name as string;
        // Attempting to sanitize with replaceAll
        // ruleid: detect-replaceall-sanitization-ts-rule
        const cleanUsername = username.replaceAll(/[<>]/g, '');
        res.send(`<h1>Welcome, ${cleanUsername}!</h1>`);
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_9() {
    const app = express();
    app.post('/review', (req, res) => {
        const review = req.body.review;
        // Attempting to sanitize with replaceAll
        // ruleid: detect-replaceall-sanitization-ts-rule
        const safeReview = review.replaceAll('onerror', '').replaceAll('onclick', '');
        res.send(`<div class="review">${safeReview}</div>`);
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_10() {
    const app = express();
    app.get('/product', (req, res) => {
        const description = req.query.description as string;
        // Attempting to sanitize with replaceAll
        // ruleid: detect-replaceall-sanitization-ts-rule
        const cleanDesc = description.replaceAll(/<.*?script.*?>/g, '');
        res.send(`<p>${cleanDesc}</p>`);
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_11() {
    const app = express();
    app.post('/feedback', (req, res) => {
        const feedback = req.body.feedback;
        // Attempting to sanitize with replaceAll
        // ruleid: detect-replaceall-sanitization-ts-rule
        const cleanFeedback = feedback.replaceAll('eval(', '').replaceAll('alert(', '');
        res.send(`<div>${cleanFeedback}</div>`);
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_12() {
    const app = express();
    app.get('/tag', (req, res) => {
        const tag = req.query.tag as string;
        // Attempting to sanitize with replaceAll
        // ruleid: detect-replaceall-sanitization-ts-rule
        const safeTag = tag.replaceAll('<', '[').replaceAll('>', ']');
        res.send(`<div>Popular tag: ${safeTag}</div>`);
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_13() {
    const app = express();
    app.post('/note', (req, res) => {
        const note = req.body.note;
        // Attempting to sanitize with replaceAll
        // ruleid: detect-replaceall-sanitization-ts-rule
        const cleanNote = note.replaceAll(/<iframe.*?>.*?<\/iframe>/g, '');
        res.send(`<section>${cleanNote}</section>`);
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_14() {
    const app = express();
    app.get('/link', (req, res) => {
        const url = req.query.url as string;
        // Attempting to sanitize with replaceAll
        // ruleid: detect-replaceall-sanitization-ts-rule
        const safeUrl = url.replaceAll('javascript:', 'https:');
        res.send(`<a href="${safeUrl}">Click here</a>`);
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_15() {
    const app = express();
    app.post('/html-content', (req, res) => {
        const html = req.body.html;
        // Complex but still vulnerable sanitization
        // ruleid: detect-replaceall-sanitization-ts-rule
        const sanitized = html
            .replaceAll(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
            .replaceAll(/javascript:/gi, '')
            .replaceAll(/on\w+=/gi, '')
            .replaceAll(/<iframe[^>]*>.*?<\/iframe>/gi, '');
        res.send(`<div class="content">${sanitized}</div>`);
    });
}
// {/fact}

// True Negatives (Safe Code)

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_1() {
    const app = express();
    app.get('/safe', (req, res) => {
        const userInput = req.query.input as string;
        // Using proper sanitization library
        // ok: detect-replaceall-sanitization-ts-rule
        const sanitized = sanitizeHtml(userInput);
        res.send(`<div>${sanitized}</div>`);
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_2() {
    const app = express();
    app.post('/profile', (req, res) => {
        const bio = req.body.bio;
        // Using DOMPurify for sanitization
        // ok: detect-replaceall-sanitization-ts-rule
        const cleanBio = purify.sanitize(bio);
        res.send(`<section class="bio">${cleanBio}</section>`);
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_3() {
    const app = express();
    app.get('/search', (req, res) => {
        const searchTerm = req.query.q as string;
        // Using sanitizeHtml with custom options
        // ok: detect-replaceall-sanitization-ts-rule
        const sanitizedSearch = sanitizeHtml(searchTerm, {
            allowedTags: [],
            allowedAttributes: {}
        });
        res.send(`<p>Search results for: ${sanitizedSearch}</p>`);
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_4() {
    const app = express();
    app.get('/comment', (req, res) => {
        const comment = req.query.text as string;
        // Using DOMPurify with config
        // ok: detect-replaceall-sanitization-ts-rule
        const sanitized = purify.sanitize(comment, { FORBID_TAGS: ['script', 'style'] });
        res.send(`<div class="comment">${sanitized}</div>`);
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_5() {
    const app = express();
    app.post('/message', (req, res) => {
        const message = req.body.message;
        // Using sanitizeHtml with specific allowed tags
        // ok: detect-replaceall-sanitization-ts-rule
        const cleanMessage = sanitizeHtml(message, {
            allowedTags: ['b', 'i', 'em', 'strong'],
            allowedAttributes: {}
        });
        res.send(`<div>${cleanMessage}</div>`);
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_6() {
    const app = express();
    app.get('/title', (req, res) => {
        const title = req.query.title as string;
        // Using DOMPurify for sanitization
        // ok: detect-replaceall-sanitization-ts-rule
        const cleanTitle = purify.sanitize(title, { RETURN_DOM_TEXT: true });
        document.title = cleanTitle;
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_7() {
    const app = express();
    app.post('/article', (req, res) => {
        const content = req.body.content;
        // Using sanitizeHtml with custom options
        // ok: detect-replaceall-sanitization-ts-rule
        const sanitizedContent = sanitizeHtml(content, {
            allowedTags: ['p', 'h1', 'h2', 'h3', 'ul', 'li', 'b', 'i'],
            allowedAttributes: {
                'p': ['class'],
                'h1': ['id']
            }
        });
        res.send(`<article>${sanitizedContent}</article>`);
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_8() {
    const app = express();
    app.get('/username', (req, res) => {
        const username = req.query.name as string;
        // Using DOMPurify with strict config
        // ok: detect-replaceall-sanitization-ts-rule
        const cleanUsername = purify.sanitize(username, { ALLOWED_TAGS: [] });
        res.send(`<h1>Welcome, ${cleanUsername}!</h1>`);
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_9() {
    const app = express();
    app.post('/review', (req, res) => {
        const review = req.body.review;
        // Using sanitizeHtml with specific disallowed tags
        // ok: detect-replaceall-sanitization-ts-rule
        const safeReview = sanitizeHtml(review, {
            disallowedTagsMode: 'discard',
            allowedTags: sanitizeHtml.defaults.allowedTags.filter(tag => tag !== 'script')
        });
        res.send(`<div class="review">${safeReview}</div>`);
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_10() {
    const app = express();
    app.get('/product', (req, res) => {
        const description = req.query.description as string;
        // Using DOMPurify with hooks
        // ok: detect-replaceall-sanitization-ts-rule
        const cleanDesc = purify.sanitize(description, {
            FORBID_ATTR: ['onerror', 'onclick', 'onload']
        });
        res.send(`<p>${cleanDesc}</p>`);
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_11() {
    const app = express();
    app.post('/feedback', (req, res) => {
        const feedback = req.body.feedback;
        // Using sanitizeHtml with custom transformers
        // ok: detect-replaceall-sanitization-ts-rule
        const cleanFeedback = sanitizeHtml(feedback, {
            transformTags: {
                'a': sanitizeHtml.simpleTransform('a', { target: '_blank', rel: 'noopener noreferrer' })
            }
        });
        res.send(`<div>${cleanFeedback}</div>`);
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_12() {
    const app = express();
    app.get('/tag', (req, res) => {
        const tag = req.query.tag as string;
        // Using DOMPurify with text-only output
        // ok: detect-replaceall-sanitization-ts-rule
        const safeTag = purify.sanitize(tag, { RETURN_DOM_TEXT: true });
        res.send(`<div>Popular tag: ${safeTag}</div>`);
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_13() {
    const app = express();
    app.post('/note', (req, res) => {
        const note = req.body.note;
        // Using sanitizeHtml with specific allowed URI schemes
        // ok: detect-replaceall-sanitization-ts-rule
        const cleanNote = sanitizeHtml(note, {
            allowedTags: ['a', 'p', 'br'],
            allowedAttributes: {
                'a': ['href']
            },
            allowedSchemes: ['http', 'https', 'mailto']
        });
        res.send(`<section>${cleanNote}</section>`);
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_14() {
    const app = express();
    app.get('/link', (req, res) => {
        const url = req.query.url as string;
        // Using proper URL validation and sanitization
        try {
            const urlObj = new URL(url);
            // ok: detect-replaceall-sanitization-ts-rule
            if (urlObj.protocol === 'http:' || urlObj.protocol === 'https:') {
                res.send(`<a href="${sanitizeHtml(url)}">Click here</a>`);
            } else {
                res.send(`<p>Invalid URL protocol</p>`);
            }
        } catch (e) {
            res.send(`<p>Invalid URL</p>`);
        }
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_15() {
    const app = express();
    app.post('/html-content', (req, res) => {
        const html = req.body.html;
        // Using DOMPurify with comprehensive configuration
        // ok: detect-replaceall-sanitization-ts-rule
        const sanitized = purify.sanitize(html, {
            ALLOWED_TAGS: ['p', 'div', 'span', 'br', 'b', 'i', 'strong', 'em', 'ul', 'ol', 'li'],
            ALLOWED_ATTR: ['class', 'id', 'style'],
            FORBID_CONTENTS: ['script', 'style', 'iframe', 'form'],
            WHOLE_DOCUMENT: false,
            SANITIZE_DOM: true
        });
        res.send(`<div class="content">${sanitized}</div>`);
    });
}
// {/fact}

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});