const express = require('express');
const app = express();
const sanitizeHtml = require('sanitize-html');
const { escape } = require('html-escaper');
const DOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');
const window = new JSDOM('').window;
const purify = DOMPurify(window);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// TRUE POSITIVES (Vulnerable Code)

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_1(req, res) {
  const userInput = req.query.name;
  // ruleid: javascript-express-unsanitized-route
  res.send(`<div>Hello, ${userInput}!</div>`);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_2(req, res) {
  const userMessage = req.body.message;
  // ruleid: javascript-express-unsanitized-route
  res.send(`<p>Your message: ${userMessage}</p>`);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_3(req, res) {
  const userComment = req.params.comment;
  // ruleid: javascript-express-unsanitized-route
  res.write(`<div class="comment">${userComment}</div>`);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_4(req, res) {
  const userName = req.query.username;
  const userAge = req.query.age;
  // ruleid: javascript-express-unsanitized-route
  res.render('profile', { name: userName, age: userAge });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_5(req, res) {
  const searchTerm = req.query.q;
  let results = [`Result for: ${searchTerm}`];
  // ruleid: javascript-express-unsanitized-route
  res.send(`<div class="search-results">${results.join('')}</div>`);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_6(req, res) {
  const userHeader = req.headers['x-custom-header'];
  // ruleid: javascript-express-unsanitized-route
  res.send(`<h1>${userHeader}</h1>`);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_7(req, res) {
  const userCookie = req.cookies.preference;
  // ruleid: javascript-express-unsanitized-route
  res.write(`<div>Your preference: ${userCookie}</div>`);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_8(req, res) {
  const userInput = req.query.input;
  const processedInput = userInput.toUpperCase();
  // ruleid: javascript-express-unsanitized-route
  res.send(`<div>${processedInput}</div>`);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_9(req, res) {
  let userData = '';
  for (const key in req.query) {
    userData += `${key}: ${req.query[key]}<br>`;
  }
  // ruleid: javascript-express-unsanitized-route
  res.send(`<div class="user-data">${userData}</div>`);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_10(req, res) {
  const userTitle = req.body.title || 'Default Title';
  // ruleid: javascript-express-unsanitized-route
  res.render('page', { title: userTitle });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_11(req, res) {
  if (req.query.error) {
    // ruleid: javascript-express-unsanitized-route
    res.send(`<div class="error">${req.query.error}</div>`);
  } else {
    res.send('<div>No errors</div>');
  }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_12(req, res) {
  const userHtml = req.body.html;
  // ruleid: javascript-express-unsanitized-route
  res.write(`<div class="user-content">${userHtml}</div>`);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_13(req, res) {
  const userName = req.query.name;
  const userEmail = req.query.email;
  const template = {
    name: userName,
    email: userEmail
  };
  // ruleid: javascript-express-unsanitized-route
  res.render('email-template', template);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_14(req, res) {
  const userStyle = req.query.style;
  // ruleid: javascript-express-unsanitized-route
  res.send(`<div style="${userStyle}">Styled content</div>`);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_15(req, res) {
  const userScript = req.body.script;
  let content = '<div>Content</div>';
  if (userScript) {
    content += `<script>${userScript}</script>`;
  }
  // ruleid: javascript-express-unsanitized-route
  res.send(content);
}
// {/fact}

// TRUE NEGATIVES (Safe Code)

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_1(req, res) {
  const userInput = req.query.name;
  const sanitizedInput = escape(userInput);
  // ok: javascript-express-unsanitized-route
  res.send(`<div>Hello, ${sanitizedInput}!</div>`);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_2(req, res) {
  const userMessage = req.body.message;
  const sanitizedMessage = sanitizeHtml(userMessage);
  // ok: javascript-express-unsanitized-route
  res.send(`<p>Your message: ${sanitizedMessage}</p>`);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_3(req, res) {
  const userComment = req.params.comment;
  const sanitizedComment = purify.sanitize(userComment);
  // ok: javascript-express-unsanitized-route
  res.write(`<div class="comment">${sanitizedComment}</div>`);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_4(req, res) {
  const userName = escape(req.query.username);
  const userAge = parseInt(req.query.age) || 0;
  // ok: javascript-express-unsanitized-route
  res.render('profile', { name: userName, age: userAge });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_5(req, res) {
  const searchTerm = escape(req.query.q);
  let results = [`Result for: ${searchTerm}`];
  // ok: javascript-express-unsanitized-route
  res.send(`<div class="search-results">${results.join('')}</div>`);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_6(req, res) {
  const userHeader = req.headers['x-custom-header'];
  const sanitizedHeader = sanitizeHtml(userHeader);
  // ok: javascript-express-unsanitized-route
  res.send(`<h1>${sanitizedHeader}</h1>`);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_7(req, res) {
  // Static content, no user input
  // ok: javascript-express-unsanitized-route
  res.write('<div>Welcome to our site!</div>');
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_8(req, res) {
  const userInput = req.query.input;
  // No HTML context, just JSON response
  // ok: javascript-express-unsanitized-route
  res.json({ input: userInput });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_9(req, res) {
  // Static render with no user input
  // ok: javascript-express-unsanitized-route
  res.render('welcome', { title: 'Welcome' });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_10(req, res) {
  let userData = {};
  for (const key in req.query) {
    userData[key] = escape(req.query[key]);
  }
  // ok: javascript-express-unsanitized-route
  res.send(`<div class="user-data">${userData.name || ''}</div>`);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_11(req, res) {
  const userTitle = req.body.title || 'Default Title';
  // ok: javascript-express-unsanitized-route
  res.render('page', { title: sanitizeHtml(userTitle) });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_12(req, res) {
  if (req.query.error) {
    const safeError = purify.sanitize(req.query.error);
    // ok: javascript-express-unsanitized-route
    res.send(`<div class="error">${safeError}</div>`);
  } else {
    res.send('<div>No errors</div>');
  }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_13(req, res) {
  // Using a whitelist of allowed values
  const allowedStyles = ['dark', 'light', 'blue'];
  const userStyle = req.query.style;
  const style = allowedStyles.includes(userStyle) ? userStyle : 'light';
  // ok: javascript-express-unsanitized-route
  res.send(`<div class="theme-${style}">Styled content</div>`);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_14(req, res) {
  // Content-Type that doesn't render HTML
  // ok: javascript-express-unsanitized-route
  res.set('Content-Type', 'text/plain');
  res.send(req.query.text);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_15(req, res) {
  const userHtml = req.body.html;
  const config = {
    allowedTags: ['b', 'i', 'em', 'strong', 'p'],
    allowedAttributes: {}
  };
  const sanitizedHtml = sanitizeHtml(userHtml, config);
  // ok: javascript-express-unsanitized-route
  res.write(`<div class="user-content">${sanitizedHtml}</div>`);
}
// {/fact}

// Set up routes
app.get('/hello', bad_case_1);
app.post('/message', bad_case_2);
app.get('/comment/:comment', bad_case_3);
app.get('/profile', bad_case_4);
app.get('/search', bad_case_5);
app.get('/header', bad_case_6);
app.get('/preferences', bad_case_7);
app.get('/process', bad_case_8);
app.get('/user-data', bad_case_9);
app.post('/page', bad_case_10);
app.get('/error', bad_case_11);
app.post('/content', bad_case_12);
app.get('/email', bad_case_13);
app.get('/styled', bad_case_14);
app.post('/script', bad_case_15);

app.get('/safe/hello', good_case_1);
app.post('/safe/message', good_case_2);
app.get('/safe/comment/:comment', good_case_3);
app.get('/safe/profile', good_case_4);
app.get('/safe/search', good_case_5);
app.get('/safe/header', good_case_6);
app.get('/safe/welcome', good_case_7);
app.get('/safe/api', good_case_8);
app.get('/safe/welcome-page', good_case_9);
app.get('/safe/user-data', good_case_10);
app.post('/safe/page', good_case_11);
app.get('/safe/error', good_case_12);
app.get('/safe/styled', good_case_13);
app.get('/safe/text', good_case_14);
app.post('/safe/content', good_case_15);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});