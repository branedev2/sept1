import express from 'express';
import axios from 'axios';

// True Positives (Vulnerable Code)

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_1() {
    const app = express();
    
    app.get('/profile', (req, res) => {
        const userName = req.query.name as string;
        const userBio = req.query.bio as string;
        
        const htmlParts = ['<div class="user-profile">', 
                          `<h2>${userName}</h2>`, 
                          `<p>${userBio}</p>`, 
                          '</div>'];
        
        // ruleid: typescript-do-not-use-raw-html-in-join
        const profileHtml = htmlParts.join('');
        
        res.send(profileHtml);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_2() {
    const app = express();
    
    app.post('/comments', (req, res) => {
        const comment = req.body.comment;
        const author = req.body.author;
        
        const commentElements = [
            '<div class="comment">',
            `<h3>${author}</h3>`,
            `<p>${comment}</p>`,
            '</div>'
        ];
        
        // ruleid: typescript-do-not-use-raw-html-in-join
        const commentHtml = commentElements.join('\n');
        
        res.send({ html: commentHtml });
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_3() {
    const app = express();
    
    app.get('/search', async (req, res) => {
        const query = req.query.q as string;
        const response = await axios.get(`https://api.example.com/search?q=${query}`);
        const results = response.data.results;
        
        const htmlFragments = results.map((result: any) => 
            `<li><a href="${result.url}">${result.title}</a> - ${result.description}</li>`
        );
        
        // ruleid: typescript-do-not-use-raw-html-in-join
        const resultsList = htmlFragments.join('');
        
        res.send(`<ul>${resultsList}</ul>`);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_4() {
    const app = express();
    
    app.get('/table', (req, res) => {
        const headers = req.query.headers?.toString().split(',') || [];
        const rows = JSON.parse(req.query.data as string || '[]');
        
        const tableRows = rows.map((row: string[]) => {
            const cells = row.map(cell => `<td>${cell}</td>`);
            // ruleid: typescript-do-not-use-raw-html-in-join
            return `<tr>${cells.join('')}</tr>`;
        });
        
        // ruleid: typescript-do-not-use-raw-html-in-join
        const tableBody = tableRows.join('');
        
        res.send(`<table>${tableBody}</table>`);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_5() {
    const app = express();
    
    app.get('/menu', (req, res) => {
        const items = req.query.items?.toString().split(',') || [];
        const links = req.query.links?.toString().split(',') || [];
        
        const menuItems = items.map((item, index) => {
            return `<li><a href="${links[index]}">${item}</a></li>`;
        });
        
        // ruleid: typescript-do-not-use-raw-html-in-join
        const menu = menuItems.join('');
        
        res.send(`<ul class="menu">${menu}</ul>`);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_6() {
    const app = express();
    
    app.get('/gallery', (req, res) => {
        const imageUrls = JSON.parse(req.query.images as string || '[]');
        const captions = JSON.parse(req.query.captions as string || '[]');
        
        const imageElements = imageUrls.map((url: string, i: number) => {
            return `<figure>
                <img src="${url}" alt="${captions[i]}">
                <figcaption>${captions[i]}</figcaption>
            </figure>`;
        });
        
        // ruleid: typescript-do-not-use-raw-html-in-join
        const galleryHtml = imageElements.join('\n');
        
        res.send(`<div class="gallery">${galleryHtml}</div>`);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_7() {
    const app = express();
    
    app.get('/breadcrumbs', (req, res) => {
        const path = req.query.path as string;
        const segments = path.split('/').filter(Boolean);
        
        const breadcrumbItems = segments.map((segment, index) => {
            const url = '/' + segments.slice(0, index + 1).join('/');
            return `<li><a href="${url}">${segment}</a></li>`;
        });
        
        // ruleid: typescript-do-not-use-raw-html-in-join
        const breadcrumbsHtml = breadcrumbItems.join(' > ');
        
        res.send(`<nav aria-label="Breadcrumb"><ol>${breadcrumbsHtml}</ol></nav>`);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_8() {
    const app = express();
    
    app.post('/form-builder', (req, res) => {
        const formFields = req.body.fields || [];
        
        const formElements = formFields.map((field: any) => {
            return `<div class="form-group">
                <label for="${field.id}">${field.label}</label>
                <input type="${field.type}" id="${field.id}" name="${field.name}" ${field.required ? 'required' : ''}>
            </div>`;
        });
        
        // ruleid: typescript-do-not-use-raw-html-in-join
        const formHtml = formElements.join('\n');
        
        res.send(`<form>${formHtml}</form>`);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_9() {
    const app = express();
    
    app.get('/notification', (req, res) => {
        const message = req.query.message as string;
        const type = req.query.type as string;
        
        const notificationParts = [
            `<div class="notification ${type}">`,
            `<span class="icon">${type === 'error' ? '❌' : '✅'}</span>`,
            `<p>${message}</p>`,
            `<button class="close">×</button>`,
            `</div>`
        ];
        
        // ruleid: typescript-do-not-use-raw-html-in-join
        const notificationHtml = notificationParts.join('');
        
        res.send(notificationHtml);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_10() {
    const app = express();
    
    app.get('/tags', (req, res) => {
        const tags = req.query.tags?.toString().split(',') || [];
        const colors = req.query.colors?.toString().split(',') || [];
        
        const tagElements = tags.map((tag, index) => {
            const color = colors[index] || 'blue';
            return `<span class="tag" style="background-color: ${color}">${tag}</span>`;
        });
        
        // ruleid: typescript-do-not-use-raw-html-in-join
        const tagsHtml = tagElements.join(' ');
        
        res.send(`<div class="tags-container">${tagsHtml}</div>`);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_11() {
    const app = express();
    
    app.get('/timeline', (req, res) => {
        const events = JSON.parse(req.query.events as string || '[]');
        
        const timelineItems = events.map((event: any) => {
            return `<li class="timeline-item">
                <div class="timestamp">${event.date}</div>
                <div class="content">
                    <h3>${event.title}</h3>
                    <p>${event.description}</p>
                </div>
            </li>`;
        });
        
        // ruleid: typescript-do-not-use-raw-html-in-join
        const timelineHtml = timelineItems.join('');
        
        res.send(`<ul class="timeline">${timelineHtml}</ul>`);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_12() {
    const app = express();
    
    app.get('/rating', (req, res) => {
        const score = parseInt(req.query.score as string) || 0;
        
        const stars = Array(5).fill(0).map((_, i) => {
            return i < score 
                ? '<span class="star filled">★</span>' 
                : '<span class="star">☆</span>';
        });
        
        // ruleid: typescript-do-not-use-raw-html-in-join
        const ratingHtml = stars.join('');
        
        res.send(`<div class="rating">${ratingHtml}</div>`);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_13() {
    const app = express();
    
    app.get('/accordion', (req, res) => {
        const sections = JSON.parse(req.query.sections as string || '[]');
        
        const accordionItems = sections.map((section: any, index: number) => {
            return `<div class="accordion-item">
                <button id="header-${index}" aria-expanded="false">${section.title}</button>
                <div id="panel-${index}" aria-hidden="true">
                    <p>${section.content}</p>
                </div>
            </div>`;
        });
        
        // ruleid: typescript-do-not-use-raw-html-in-join
        const accordionHtml = accordionItems.join('');
        
        res.send(`<div class="accordion">${accordionHtml}</div>`);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_14() {
    const app = express();
    
    app.get('/social-links', (req, res) => {
        const networks = req.query.networks?.toString().split(',') || [];
        const urls = req.query.urls?.toString().split(',') || [];
        
        const linkElements = networks.map((network, index) => {
            return `<a href="${urls[index]}" class="social-link ${network.toLowerCase()}">
                <i class="icon-${network.toLowerCase()}"></i> ${network}
            </a>`;
        });
        
        // ruleid: typescript-do-not-use-raw-html-in-join
        const socialLinksHtml = linkElements.join('');
        
        res.send(`<div class="social-links">${socialLinksHtml}</div>`);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_15() {
    const app = express();
    
    app.get('/progress', (req, res) => {
        const steps = req.query.steps?.toString().split(',') || [];
        const currentStep = parseInt(req.query.current as string) || 0;
        
        const stepElements = steps.map((step, index) => {
            const status = index < currentStep ? 'completed' : (index === currentStep ? 'current' : 'upcoming');
            return `<li class="step ${status}">
                <div class="step-number">${index + 1}</div>
                <div class="step-label">${step}</div>
            </li>`;
        });
        
        // ruleid: typescript-do-not-use-raw-html-in-join
        const progressHtml = stepElements.join('');
        
        res.send(`<ol class="progress-tracker">${progressHtml}</ol>`);
    });
}
// {/fact}

// True Negatives (Safe Code)

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_1() {
    const app = express();
    
    app.get('/profile', (req, res) => {
        const userName = req.query.name as string;
        const userBio = req.query.bio as string;
        
        // ok: typescript-do-not-use-raw-html-in-join
        const container = document.createElement('div');
        container.className = 'user-profile';
        
        const heading = document.createElement('h2');
        heading.textContent = userName;
        container.appendChild(heading);
        
        const paragraph = document.createElement('p');
        paragraph.textContent = userBio;
        container.appendChild(paragraph);
        
        res.send(container.outerHTML);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_2() {
    const app = express();
    
    app.post('/comments', (req, res) => {
        const comment = req.body.comment;
        const author = req.body.author;
        
        // ok: typescript-do-not-use-raw-html-in-join
        const commentDiv = document.createElement('div');
        commentDiv.className = 'comment';
        
        const authorHeading = document.createElement('h3');
        authorHeading.textContent = author;
        commentDiv.appendChild(authorHeading);
        
        const commentPara = document.createElement('p');
        commentPara.textContent = comment;
        commentDiv.appendChild(commentPara);
        
        res.send({ html: commentDiv.outerHTML });
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_3() {
    const app = express();
    
    app.get('/search', async (req, res) => {
        const query = req.query.q as string;
        const response = await axios.get(`https://api.example.com/search?q=${query}`);
        const results = response.data.results;
        
        // ok: typescript-do-not-use-raw-html-in-join
        const ul = document.createElement('ul');
        
        results.forEach((result: any) => {
            const li = document.createElement('li');
            
            const a = document.createElement('a');
            a.href = result.url;
            a.textContent = result.title;
            li.appendChild(a);
            
            li.appendChild(document.createTextNode(' - ' + result.description));
            
            ul.appendChild(li);
        });
        
        res.send(ul.outerHTML);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_4() {
    const app = express();
    
    app.get('/table', (req, res) => {
        const headers = req.query.headers?.toString().split(',') || [];
        const rows = JSON.parse(req.query.data as string || '[]');
        
        // ok: typescript-do-not-use-raw-html-in-join
        const table = document.createElement('table');
        
        rows.forEach((row: string[]) => {
            const tr = document.createElement('tr');
            
            row.forEach(cell => {
                const td = document.createElement('td');
                td.textContent = cell;
                tr.appendChild(td);
            });
            
            table.appendChild(tr);
        });
        
        res.send(table.outerHTML);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_5() {
    const app = express();
    
    app.get('/menu', (req, res) => {
        const items = req.query.items?.toString().split(',') || [];
        const links = req.query.links?.toString().split(',') || [];
        
        // ok: typescript-do-not-use-raw-html-in-join
        const ul = document.createElement('ul');
        ul.className = 'menu';
        
        items.forEach((item, index) => {
            const li = document.createElement('li');
            const a = document.createElement('a');
            a.href = links[index];
            a.textContent = item;
            li.appendChild(a);
            ul.appendChild(li);
        });
        
        res.send(ul.outerHTML);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_6() {
    const app = express();
    
    app.get('/gallery', (req, res) => {
        const imageUrls = JSON.parse(req.query.images as string || '[]');
        const captions = JSON.parse(req.query.captions as string || '[]');
        
        // ok: typescript-do-not-use-raw-html-in-join
        const gallery = document.createElement('div');
        gallery.className = 'gallery';
        
        imageUrls.forEach((url: string, i: number) => {
            const figure = document.createElement('figure');
            
            const img = document.createElement('img');
            img.src = url;
            img.alt = captions[i];
            figure.appendChild(img);
            
            const figcaption = document.createElement('figcaption');
            figcaption.textContent = captions[i];
            figure.appendChild(figcaption);
            
            gallery.appendChild(figure);
        });
        
        res.send(gallery.outerHTML);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_7() {
    const app = express();
    
    app.get('/breadcrumbs', (req, res) => {
        const path = req.query.path as string;
        const segments = path.split('/').filter(Boolean);
        
        // ok: typescript-do-not-use-raw-html-in-join
        const nav = document.createElement('nav');
        nav.setAttribute('aria-label', 'Breadcrumb');
        
        const ol = document.createElement('ol');
        
        segments.forEach((segment, index) => {
            const li = document.createElement('li');
            const a = document.createElement('a');
            a.href = '/' + segments.slice(0, index + 1).join('/');
            a.textContent = segment;
            li.appendChild(a);
            ol.appendChild(li);
            
            if (index < segments.length - 1) {
                ol.appendChild(document.createTextNode(' > '));
            }
        });
        
        nav.appendChild(ol);
        res.send(nav.outerHTML);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_8() {
    const app = express();
    
    app.post('/form-builder', (req, res) => {
        const formFields = req.body.fields || [];
        
        // ok: typescript-do-not-use-raw-html-in-join
        const form = document.createElement('form');
        
        formFields.forEach((field: any) => {
            const div = document.createElement('div');
            div.className = 'form-group';
            
            const label = document.createElement('label');
            label.setAttribute('for', field.id);
            label.textContent = field.label;
            div.appendChild(label);
            
            const input = document.createElement('input');
            input.type = field.type;
            input.id = field.id;
            input.name = field.name;
            if (field.required) {
                input.required = true;
            }
            div.appendChild(input);
            
            form.appendChild(div);
        });
        
        res.send(form.outerHTML);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_9() {
    const app = express();
    
    app.get('/notification', (req, res) => {
        const message = req.query.message as string;
        const type = req.query.type as string;
        
        // ok: typescript-do-not-use-raw-html-in-join
        const div = document.createElement('div');
        div.className = `notification ${type}`;
        
        const icon = document.createElement('span');
        icon.className = 'icon';
        icon.textContent = type === 'error' ? '❌' : '✅';
        div.appendChild(icon);
        
        const p = document.createElement('p');
        p.textContent = message;
        div.appendChild(p);
        
        const button = document.createElement('button');
        button.className = 'close';
        button.textContent = '×';
        div.appendChild(button);
        
        res.send(div.outerHTML);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_10() {
    const app = express();
    
    app.get('/tags', (req, res) => {
        const tags = req.query.tags?.toString().split(',') || [];
        const colors = req.query.colors?.toString().split(',') || [];
        
        // ok: typescript-do-not-use-raw-html-in-join
        const container = document.createElement('div');
        container.className = 'tags-container';
        
        tags.forEach((tag, index) => {
            const span = document.createElement('span');
            span.className = 'tag';
            span.style.backgroundColor = colors[index] || 'blue';
            span.textContent = tag;
            container.appendChild(span);
            
            // Add space between tags
            if (index < tags.length - 1) {
                container.appendChild(document.createTextNode(' '));
            }
        });
        
        res.send(container.outerHTML);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_11() {
    const app = express();
    
    app.get('/timeline', (req, res) => {
        const events = JSON.parse(req.query.events as string || '[]');
        
        // ok: typescript-do-not-use-raw-html-in-join
        const ul = document.createElement('ul');
        ul.className = 'timeline';
        
        events.forEach((event: any) => {
            const li = document.createElement('li');
            li.className = 'timeline-item';
            
            const timestamp = document.createElement('div');
            timestamp.className = 'timestamp';
            timestamp.textContent = event.date;
            li.appendChild(timestamp);
            
            const content = document.createElement('div');
            content.className = 'content';
            
            const h3 = document.createElement('h3');
            h3.textContent = event.title;
            content.appendChild(h3);
            
            const p = document.createElement('p');
            p.textContent = event.description;
            content.appendChild(p);
            
            li.appendChild(content);
            ul.appendChild(li);
        });
        
        res.send(ul.outerHTML);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_12() {
    const app = express();
    
    app.get('/rating', (req, res) => {
        const score = parseInt(req.query.score as string) || 0;
        
        // ok: typescript-do-not-use-raw-html-in-join
        const div = document.createElement('div');
        div.className = 'rating';
        
        for (let i = 0; i < 5; i++) {
            const span = document.createElement('span');
            span.className = i < score ? 'star filled' : 'star';
            span.textContent = i < score ? '★' : '☆';
            div.appendChild(span);
        }
        
        res.send(div.outerHTML);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_13() {
    const app = express();
    
    app.get('/accordion', (req, res) => {
        const sections = JSON.parse(req.query.sections as string || '[]');
        
        // ok: typescript-do-not-use-raw-html-in-join
        const accordion = document.createElement('div');
        accordion.className = 'accordion';
        
        sections.forEach((section: any, index: number) => {
            const item = document.createElement('div');
            item.className = 'accordion-item';
            
            const button = document.createElement('button');
            button.id = `header-${index}`;
            button.setAttribute('aria-expanded', 'false');
            button.textContent = section.title;
            item.appendChild(button);
            
            const panel = document.createElement('div');
            panel.id = `panel-${index}`;
            panel.setAttribute('aria-hidden', 'true');
            
            const p = document.createElement('p');
            p.textContent = section.content;
            panel.appendChild(p);
            
            item.appendChild(panel);
            accordion.appendChild(item);
        });
        
        res.send(accordion.outerHTML);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_14() {
    const app = express();
    
    app.get('/social-links', (req, res) => {
        const networks = req.query.networks?.toString().split(',') || [];
        const urls = req.query.urls?.toString().split(',') || [];
        
        // ok: typescript-do-not-use-raw-html-in-join
        const div = document.createElement('div');
        div.className = 'social-links';
        
        networks.forEach((network, index) => {
            const a = document.createElement('a');
            a.href = urls[index];
            a.className = `social-link ${network.toLowerCase()}`;
            
            const i = document.createElement('i');
            i.className = `icon-${network.toLowerCase()}`;
            a.appendChild(i);
            
            a.appendChild(document.createTextNode(' ' + network));
            
            div.appendChild(a);
        });
        
        res.send(div.outerHTML);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_15() {
    const app = express();
    
    app.get('/progress', (req, res) => {
        const steps = req.query.steps?.toString().split(',') || [];
        const currentStep = parseInt(req.query.current as string) || 0;
        
        // ok: typescript-do-not-use-raw-html-in-join
        const ol = document.createElement('ol');
        ol.className = 'progress-tracker';
        
        steps.forEach((step, index) => {
            const li = document.createElement('li');
            const status = index < currentStep ? 'completed' : (index === currentStep ? 'current' : 'upcoming');
            li.className = `step ${status}`;
            
            const stepNumber = document.createElement('div');
            stepNumber.className = 'step-number';
            stepNumber.textContent = (index + 1).toString();
            li.appendChild(stepNumber);
            
            const stepLabel = document.createElement('div');
            stepLabel.className = 'step-label';
            stepLabel.textContent = step;
            li.appendChild(stepLabel);
            
            ol.appendChild(li);
        });
        
        res.send(ol.outerHTML);
    });
}
// {/fact}