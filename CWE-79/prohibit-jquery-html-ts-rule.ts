// File: jquery-html-examples.ts

import $ from 'jquery';
import axios from 'axios';
import * as express from 'express';
import { Request, Response } from 'express';
import { HtmlUtils } from '@edx/edx-ui-toolkit';

// True Positive Examples (Vulnerable Code)

// Example 1: Basic usage of jQuery html with user input from URL parameter
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_1() {
    const app = express();
    
    app.get('/profile', (req: Request, res: Response) => {
        const username = req.query.username as string;
        
        // Fetch user data and render it
        axios.get(`/api/users/${username}`)
            .then(response => {
                const userData = response.data;
                // ruleid: prohibit-jquery-html-ts-rule
                $('#user-profile').html(userData.bio);
                res.send('Profile loaded');
            });
    });
}
// {/fact}

// Example 2: Using jQuery html with POST data
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_2() {
    const app = express();
    
    app.post('/comments', (req: Request, res: Response) => {
        const comment = req.body.comment;
        
        // ruleid: prohibit-jquery-html-ts-rule
        $('#comments-section').html(`<div class="comment">${comment}</div>`);
        
        res.json({ success: true });
    });
}
// {/fact}

// Example 3: Using jQuery html with request headers
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_3() {
    const app = express();
    
    app.get('/custom-page', (req: Request, res: Response) => {
        const theme = req.headers['x-theme'] as string;
        
        // ruleid: prohibit-jquery-html-ts-rule
        $('#theme-container').html(`<div class="theme-${theme}">Custom theme applied</div>`);
        
        res.send('Theme applied');
    });
}
// {/fact}

// Example 4: Using jQuery html with cookie data
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_4() {
    const app = express();
    
    app.get('/preferences', (req: Request, res: Response) => {
        const preferences = req.cookies.userPrefs;
        
        // ruleid: prohibit-jquery-html-ts-rule
        $('#user-preferences').html(preferences);
        
        res.send('Preferences loaded');
    });
}
// {/fact}

// Example 5: Using jQuery html with data from external API
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_5() {
    const app = express();
    
    app.get('/news', (req: Request, res: Response) => {
        const newsSource = req.query.source as string;
        
        axios.get(`https://api.news.com/feed?source=${newsSource}`)
            .then(response => {
                // ruleid: prohibit-jquery-html-ts-rule
                $('#news-container').html(response.data.content);
                res.send('News loaded');
            });
    });
}
// {/fact}

// Example 6: Using jQuery html with template literals and user input
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_6() {
    const app = express();
    
    app.get('/welcome', (req: Request, res: Response) => {
        const name = req.query.name as string;
        const role = req.query.role as string;
        
        // ruleid: prohibit-jquery-html-ts-rule
        $('#welcome-message').html(`<h1>Welcome ${name}!</h1><p>Role: ${role}</p>`);
        
        res.send('Welcome page loaded');
    });
}
// {/fact}

// Example 7: Using jQuery html in an event handler with user input
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_7() {
    const app = express();
    
    app.get('/search', (req: Request, res: Response) => {
        const query = req.query.q as string;
        
        $('#search-button').on('click', function() {
            // ruleid: prohibit-jquery-html-ts-rule
            $('#search-results').html(`<div>Results for: ${query}</div>`);
        });
        
        res.send('Search page loaded');
    });
}
// {/fact}

// Example 8: Using jQuery html with processed but unsanitized data
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_8() {
    const app = express();
    
    app.get('/article', (req: Request, res: Response) => {
        const articleId = req.query.id as string;
        
        axios.get(`/api/articles/${articleId}`)
            .then(response => {
                const article = response.data;
                const formattedContent = article.content.replace(/\n/g, '<br>');
                
                // ruleid: prohibit-jquery-html-ts-rule
                $('#article-content').html(formattedContent);
                res.send('Article loaded');
            });
    });
}
// {/fact}

// Example 9: Using jQuery html with multiple elements and user input
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_9() {
    const app = express();
    
    app.get('/dashboard', (req: Request, res: Response) => {
        const userId = req.query.userId as string;
        
        axios.get(`/api/user-widgets/${userId}`)
            .then(response => {
                const widgets = response.data;
                
                widgets.forEach((widget: any, index: number) => {
                    // ruleid: prohibit-jquery-html-ts-rule
                    $(`#widget-${index}`).html(widget.content);
                });
                
                res.send('Dashboard loaded');
            });
    });
}
// {/fact}

// Example 10: Using jQuery html with conditional rendering and user input
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_10() {
    const app = express();
    
    app.get('/product', (req: Request, res: Response) => {
        const productId = req.query.id as string;
        const showReviews = req.query.reviews === 'true';
        
        axios.get(`/api/products/${productId}`)
            .then(response => {
                const product = response.data;
                
                if (showReviews) {
                    // ruleid: prohibit-jquery-html-ts-rule
                    $('#product-reviews').html(product.reviewsHtml);
                } else {
                    // ruleid: prohibit-jquery-html-ts-rule
                    $('#product-description').html(product.description);
                }
                
                res.send('Product page loaded');
            });
    });
}
// {/fact}

// Example 11: Using jQuery html with user input in an AJAX success callback
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_11() {
    const app = express();
    
    app.get('/messages', (req: Request, res: Response) => {
        const conversationId = req.query.convId as string;
        
        $.ajax({
            url: `/api/messages/${conversationId}`,
            success: function(data) {
                // ruleid: prohibit-jquery-html-ts-rule
                $('#message-thread').html(data.messages.join('<br>'));
            }
        });
        
        res.send('Messages page loaded');
    });
}
// {/fact}

// Example 12: Using jQuery html with user input in a complex UI update
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_12() {
    const app = express();
    
    app.get('/forum', (req: Request, res: Response) => {
        const topicId = req.query.topic as string;
        const page = req.query.page as string || '1';
        
        axios.get(`/api/forum-posts?topic=${topicId}&page=${page}`)
            .then(response => {
                const posts = response.data;
                let postsHtml = '';
                
                posts.forEach((post: any) => {
                    postsHtml += `<div class="post">${post.content}</div>`;
                });
                
                // ruleid: prohibit-jquery-html-ts-rule
                $('#forum-posts').html(postsHtml);
                res.send('Forum loaded');
            });
    });
}
// {/fact}

// Example 13: Using jQuery html with user input in a dynamic form generation
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_13() {
    const app = express();
    
    app.get('/form-builder', (req: Request, res: Response) => {
        const formTemplate = req.query.template as string;
        
        axios.get(`/api/form-templates/${formTemplate}`)
            .then(response => {
                const template = response.data;
                
                // ruleid: prohibit-jquery-html-ts-rule
                $('#form-container').html(template.html);
                res.send('Form builder loaded');
            });
    });
}
// {/fact}

// Example 14: Using jQuery html with user input in a component initialization
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_14() {
    const app = express();
    
    app.get('/widget', (req: Request, res: Response) => {
        const widgetType = req.query.type as string;
        const widgetData = req.query.data as string;
        
        class WidgetRenderer {
            render(container: string, data: string) {
                // ruleid: prohibit-jquery-html-ts-rule
                $(container).html(data);
            }
        }
        
        const renderer = new WidgetRenderer();
        renderer.render('#widget-container', widgetData);
        
        res.send('Widget loaded');
    });
}
// {/fact}

// Example 15: Using jQuery html with user input in a multi-step process
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_15() {
    const app = express();
    
    app.get('/wizard', (req: Request, res: Response) => {
        const step = req.query.step as string;
        const userData = req.query.data as string;
        
        function loadStep(stepNumber: string, data: string) {
            axios.get(`/api/wizard-steps/${stepNumber}`)
                .then(response => {
                    const stepTemplate = response.data.template;
                    const processedTemplate = stepTemplate.replace('{{USER_DATA}}', data);
                    
                    // ruleid: prohibit-jquery-html-ts-rule
                    $('#wizard-container').html(processedTemplate);
                });
        }
        
        loadStep(step, userData);
        res.send('Wizard step loaded');
    });
}
// {/fact}

// True Negative Examples (Safe Code)

// Example 1: Using jQuery text instead of html for user input
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_1() {
    const app = express();
    
    app.get('/profile', (req: Request, res: Response) => {
        const username = req.query.username as string;
        
        axios.get(`/api/users/${username}`)
            .then(response => {
                const userData = response.data;
                // ok: prohibit-jquery-html-ts-rule
                $('#user-profile').text(userData.bio);
                res.send('Profile loaded safely');
            });
    });
}
// {/fact}

// Example 2: Using HtmlUtils.setHtml for user input
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_2() {
    const app = express();
    
    app.post('/comments', (req: Request, res: Response) => {
        const comment = req.body.comment;
        
        // ok: prohibit-jquery-html-ts-rule
        HtmlUtils.setHtml($('#comments-section'), comment);
        
        res.json({ success: true });
    });
}
// {/fact}

// Example 3: Using jQuery html with static, trusted content
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_3() {
    const app = express();
    
    app.get('/static-page', (req: Request, res: Response) => {
        // ok: prohibit-jquery-html-ts-rule
        $('#static-container').html('<div class="static">This is static, trusted HTML content</div>');
        
        res.send('Static page loaded');
    });
}
// {/fact}

// Example 4: Using jQuery text with user input from cookies
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_4() {
    const app = express();
    
    app.get('/preferences', (req: Request, res: Response) => {
        const preferences = req.cookies.userPrefs;
        
        // ok: prohibit-jquery-html-ts-rule
        $('#user-preferences').text(preferences);
        
        res.send('Preferences loaded safely');
    });
}
// {/fact}

// Example 5: Using HtmlUtils.setHtml with data from external API
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_5() {
    const app = express();
    
    app.get('/news', (req: Request, res: Response) => {
        const newsSource = req.query.source as string;
        
        axios.get(`https://api.news.com/feed?source=${newsSource}`)
            .then(response => {
                // ok: prohibit-jquery-html-ts-rule
                HtmlUtils.setHtml($('#news-container'), response.data.content);
                res.send('News loaded safely');
            });
    });
}
// {/fact}

// Example 6: Using jQuery text with template literals and user input
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_6() {
    const app = express();
    
    app.get('/welcome', (req: Request, res: Response) => {
        const name = req.query.name as string;
        const role = req.query.role as string;
        
        // ok: prohibit-jquery-html-ts-rule
        $('#welcome-name').text(name);
        $('#welcome-role').text(role);
        
        res.send('Welcome page loaded safely');
    });
}
// {/fact}

// Example 7: Using jQuery text in an event handler with user input
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_7() {
    const app = express();
    
    app.get('/search', (req: Request, res: Response) => {
        const query = req.query.q as string;
        
        $('#search-button').on('click', function() {
            // ok: prohibit-jquery-html-ts-rule
            $('#search-results').text(`Results for: ${query}`);
        });
        
        res.send('Search page loaded safely');
    });
}
// {/fact}

// Example 8: Using a sanitizer before jQuery html
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_8() {
    const app = express();
    const DOMPurify = require('dompurify');
    
    app.get('/article', (req: Request, res: Response) => {
        const articleId = req.query.id as string;
        
        axios.get(`/api/articles/${articleId}`)
            .then(response => {
                const article = response.data;
                const sanitizedContent = DOMPurify.sanitize(article.content);
                
                // ok: prohibit-jquery-html-ts-rule
                $('#article-content').html(sanitizedContent);
                res.send('Article loaded safely');
            });
    });
}
// {/fact}

// Example 9: Using jQuery text with multiple elements and user input
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_9() {
    const app = express();
    
    app.get('/dashboard', (req: Request, res: Response) => {
        const userId = req.query.userId as string;
        
        axios.get(`/api/user-widgets/${userId}`)
            .then(response => {
                const widgets = response.data;
                
                widgets.forEach((widget: any, index: number) => {
                    // ok: prohibit-jquery-html-ts-rule
                    $(`#widget-${index}`).text(widget.content);
                });
                
                res.send('Dashboard loaded safely');
            });
    });
}
// {/fact}

// Example 10: Using HtmlUtils.setHtml with conditional rendering and user input
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_10() {
    const app = express();
    
    app.get('/product', (req: Request, res: Response) => {
        const productId = req.query.id as string;
        const showReviews = req.query.reviews === 'true';
        
        axios.get(`/api/products/${productId}`)
            .then(response => {
                const product = response.data;
                
                if (showReviews) {
                    // ok: prohibit-jquery-html-ts-rule
                    HtmlUtils.setHtml($('#product-reviews'), product.reviewsHtml);
                } else {
                    // ok: prohibit-jquery-html-ts-rule
                    HtmlUtils.setHtml($('#product-description'), product.description);
                }
                
                res.send('Product page loaded safely');
            });
    });
}
// {/fact}

// Example 11: Using jQuery text with user input in an AJAX success callback
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_11() {
    const app = express();
    
    app.get('/messages', (req: Request, res: Response) => {
        const conversationId = req.query.convId as string;
        
        $.ajax({
            url: `/api/messages/${conversationId}`,
            success: function(data) {
                // Create elements safely
                const messageContainer = $('#message-thread');
                messageContainer.empty();
                
                data.messages.forEach((message: string) => {
                    // ok: prohibit-jquery-html-ts-rule
                    $('<div>').text(message).appendTo(messageContainer);
                });
            }
        });
        
        res.send('Messages page loaded safely');
    });
}
// {/fact}

// Example 12: Using HtmlUtils.setHtml with user input in a complex UI update
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_12() {
    const app = express();
    
    app.get('/forum', (req: Request, res: Response) => {
        const topicId = req.query.topic as string;
        const page = req.query.page as string || '1';
        
        axios.get(`/api/forum-posts?topic=${topicId}&page=${page}`)
            .then(response => {
                const posts = response.data;
                const forumContainer = $('#forum-posts');
                forumContainer.empty();
                
                posts.forEach((post: any) => {
                    // ok: prohibit-jquery-html-ts-rule
                    const postElement = $('<div>').addClass('post');
                    HtmlUtils.setHtml(postElement, post.content);
                    forumContainer.append(postElement);
                });
                
                res.send('Forum loaded safely');
            });
    });
}
// {/fact}

// Example 13: Using a custom sanitizer function before jQuery html
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_13() {
    const app = express();
    
    app.get('/form-builder', (req: Request, res: Response) => {
        const formTemplate = req.query.template as string;
        
        function sanitizeHtml(html: string): string {
            // Implementation of a proper HTML sanitizer
            const allowedTags = ['div', 'span', 'p', 'h1', 'h2', 'h3', 'label', 'input'];
            const allowedAttrs = ['class', 'id', 'type', 'placeholder'];
            
            // This is a simplified example - in real code, use a proper sanitizer library
            const sanitized = html.replace(/<\/?([^>]+)>/g, (match, tag) => {
                const tagName = tag.split(' ')[0];
                if (allowedTags.includes(tagName)) {
                    return match;
                }
                return '';
            });
            
            return sanitized;
        }
        
        axios.get(`/api/form-templates/${formTemplate}`)
            .then(response => {
                const template = response.data;
                const sanitizedHtml = sanitizeHtml(template.html);
                
                // ok: prohibit-jquery-html-ts-rule
                $('#form-container').html(sanitizedHtml);
                res.send('Form builder loaded safely');
            });
    });
}
// {/fact}

// Example 14: Using jQuery text with user input in a component initialization
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_14() {
    const app = express();
    
    app.get('/widget', (req: Request, res: Response) => {
        const widgetType = req.query.type as string;
        const widgetData = req.query.data as string;
        
        class SafeWidgetRenderer {
            renderSafely(container: string, data: string) {
                // ok: prohibit-jquery-html-ts-rule
                $(container).text(data);
            }
        }
        
        const renderer = new SafeWidgetRenderer();
        renderer.renderSafely('#widget-container', widgetData);
        
        res.send('Widget loaded safely');
    });
}
// {/fact}

// Example 15: Using HtmlUtils.setHtml with user input in a multi-step process
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_15() {
    const app = express();
    
    app.get('/wizard', (req: Request, res: Response) => {
        const step = req.query.step as string;
        const userData = req.query.data as string;
        
        function loadStepSafely(stepNumber: string, data: string) {
            axios.get(`/api/wizard-steps/${stepNumber}`)
                .then(response => {
                    const stepTemplate = response.data.template;
                    
                    // Create elements safely
                    const wizardContainer = $('#wizard-container');
                    wizardContainer.empty();
                    
                    const stepElement = $('<div>').addClass('wizard-step');
                    // ok: prohibit-jquery-html-ts-rule
                    HtmlUtils.setHtml(stepElement, stepTemplate);
                    
                    // Add user data safely
                    const userDataElement = $('<div>').addClass('user-data');
                    userDataElement.text(data);
                    stepElement.append(userDataElement);
                    
                    wizardContainer.append(stepElement);
                });
        }
        
        loadStepSafely(step, userData);
        res.send('Wizard step loaded safely');
    });
}
// {/fact}