// Required imports
const express = require('express');
const DOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');
const window = new JSDOM('').window;
const purify = DOMPurify(window);
const sanitizeHtml = require('sanitize-html');
const escapeHtml = require('escape-html');
const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// TRUE POSITIVES - Vulnerable code examples

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_1(req, res) {
  const username = req.query.username;
  // ruleid: javascript-insecure-html-string
  const htmlString = '<div class="user-profile">Welcome, ' + username + '!</div>';
  res.send(htmlString);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_2(req, res) {
  const searchTerm = req.query.q;
  // ruleid: javascript-insecure-html-string
  const resultsHtml = `
    <div class="search-results">
      <h2>Results for: ${searchTerm}</h2>
      <p>Found 10 matches</p>
    </div>
  `;
  res.send(resultsHtml);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_3(req, res) {
  const commentText = req.body.comment;
  const author = req.body.author;
  // ruleid: javascript-insecure-html-string
  const commentHtml = '<div class="comment"><strong>' + author + '</strong>: ' + commentText + '</div>';
  res.send(commentHtml);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_4(req, res) {
  const productId = req.params.id;
  const userReview = req.body.review;
  // ruleid: javascript-insecure-html-string
  let reviewSection = '<section id="review-' + productId + '">';
  reviewSection += '<p class="review-text">' + userReview + '</p>';
  reviewSection += '</section>';
  res.send(reviewSection);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_5(req, res) {
  const profileData = req.body;
  // ruleid: javascript-insecure-html-string
  const profileHtml = `
    <div class="profile">
      <h1>${profileData.name}</h1>
      <p>${profileData.bio}</p>
      <div class="contact">${profileData.email}</div>
    </div>
  `;
  res.send(profileHtml);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_6(req, res) {
  const errorMsg = req.query.error;
  if (errorMsg) {
    // ruleid: javascript-insecure-html-string
    const alertHtml = '<div class="alert alert-danger">' + errorMsg + '</div>';
    res.send(alertHtml);
  } else {
    res.send('<div>No errors</div>');
  }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_7(req, res) {
  const links = JSON.parse(req.body.links);
  let linksHtml = '<ul class="nav-links">';
  
  for (let i = 0; i < links.length; i++) {
    // ruleid: javascript-insecure-html-string
    linksHtml += '<li><a href="' + links[i].url + '">' + links[i].text + '</a></li>';
  }
  
  linksHtml += '</ul>';
  res.send(linksHtml);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_8(req, res) {
  const userInput = req.query.input;
  let result;
  
  try {
    // Some processing
    result = processUserInput(userInput);
  } catch (error) {
    // ruleid: javascript-insecure-html-string
    const errorHtml = '<div class="error"><h3>Error</h3><p>' + error.message + '</p><pre>' + userInput + '</pre></div>';
    return res.send(errorHtml);
  }
  
  res.send('<div>Success</div>');
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_9(req, res) {
  const title = req.query.title;
  const content = req.body.content;
  
  // ruleid: javascript-insecure-html-string
  const articleHtml = `
    <article>
      <header>
        <h1>${title}</h1>
      </header>
      <div class="content">
        ${content}
      </div>
    </article>
  `;
  
  res.send(articleHtml);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_10(req, res) {
  const searchQuery = req.query.q;
  const category = req.query.category || 'All';
  
  // ruleid: javascript-insecure-html-string
  const searchFormHtml = `
    <form action="/search" method="GET">
      <input type="text" name="q" value="${searchQuery}">
      <input type="hidden" name="category" value="${category}">
      <button type="submit">Search</button>
    </form>
  `;
  
  res.send(searchFormHtml);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_11(req, res) {
  const username = req.cookies.username;
  const theme = req.query.theme || 'light';
  
  // ruleid: javascript-insecure-html-string
  const welcomeHtml = '<div class="welcome ' + theme + '">Welcome back, ' + username + '!</div>';
  res.send(welcomeHtml);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_12(req, res) {
  const items = JSON.parse(req.body.items);
  let tableHtml = '<table><thead><tr><th>Item</th><th>Price</th></tr></thead><tbody>';
  
  for (const item of items) {
    // ruleid: javascript-insecure-html-string
    tableHtml += '<tr><td>' + item.name + '</td><td>$' + item.price + '</td></tr>';
  }
  
  tableHtml += '</tbody></table>';
  res.send(tableHtml);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_13(req, res) {
  const userMessage = req.body.message;
  const recipient = req.body.recipient;
  
  // ruleid: javascript-insecure-html-string
  const messagePreview = `
    <div class="message-preview">
      <p>Your message to ${recipient}:</p>
      <blockquote>${userMessage}</blockquote>
      <button>Send</button>
    </div>
  `;
  
  res.send(messagePreview);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_14(req, res) {
  const customCss = req.body.css;
  const customJs = req.body.js;
  
  // ruleid: javascript-insecure-html-string
  const customPage = `
    <!DOCTYPE html>
    <html>
    <head>
      <style>${customCss}</style>
    </head>
    <body>
      <div id="content"></div>
      <script>${customJs}</script>
    </body>
    </html>
  `;
  
  res.send(customPage);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_15(req, res) {
  const userData = {
    name: req.body.name,
    email: req.body.email,
    website: req.body.website
  };
  
  // ruleid: javascript-insecure-html-string
  const contactCard = `
    <div class="contact-card">
      <h3>${userData.name}</h3>
      <p>Email: <a href="mailto:${userData.email}">${userData.email}</a></p>
      <p>Website: <a href="${userData.website}" target="_blank">${userData.website}</a></p>
    </div>
  `;
  
  res.send(contactCard);
}
// {/fact}

// TRUE NEGATIVES - Secure code examples

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_1(req, res) {
  const username = req.query.username;
  // ok: javascript-insecure-html-string
  const safeUsername = escapeHtml(username);
  const htmlString = '<div class="user-profile">Welcome, ' + safeUsername + '!</div>';
  res.send(htmlString);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_2(req, res) {
  const searchTerm = req.query.q;
  // ok: javascript-insecure-html-string
  const safeSearchTerm = escapeHtml(searchTerm);
  const resultsHtml = `
    <div class="search-results">
      <h2>Results for: ${safeSearchTerm}</h2>
      <p>Found 10 matches</p>
    </div>
  `;
  res.send(resultsHtml);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_3(req, res) {
  const commentText = req.body.comment;
  const author = req.body.author;
  
  // ok: javascript-insecure-html-string
  const safeAuthor = escapeHtml(author);
  const safeComment = escapeHtml(commentText);
  const commentHtml = '<div class="comment"><strong>' + safeAuthor + '</strong>: ' + safeComment + '</div>';
  res.send(commentHtml);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_4(req, res) {
  const productId = req.params.id;
  const userReview = req.body.review;
  
  // ok: javascript-insecure-html-string
  const safeProductId = escapeHtml(productId);
  const safeReview = escapeHtml(userReview);
  
  let reviewSection = '<section id="review-' + safeProductId + '">';
  reviewSection += '<p class="review-text">' + safeReview + '</p>';
  reviewSection += '</section>';
  res.send(reviewSection);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_5(req, res) {
  const profileData = req.body;
  
  // ok: javascript-insecure-html-string
  const sanitizedProfile = {
    name: escapeHtml(profileData.name),
    bio: escapeHtml(profileData.bio),
    email: escapeHtml(profileData.email)
  };
  
  const profileHtml = `
    <div class="profile">
      <h1>${sanitizedProfile.name}</h1>
      <p>${sanitizedProfile.bio}</p>
      <div class="contact">${sanitizedProfile.email}</div>
    </div>
  `;
  res.send(profileHtml);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_6(req, res) {
  const errorMsg = req.query.error;
  
  if (errorMsg) {
    // ok: javascript-insecure-html-string
    const safeErrorMsg = escapeHtml(errorMsg);
    const alertHtml = '<div class="alert alert-danger">' + safeErrorMsg + '</div>';
    res.send(alertHtml);
  } else {
    res.send('<div>No errors</div>');
  }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_7(req, res) {
  const links = JSON.parse(req.body.links);
  let linksHtml = '<ul class="nav-links">';
  
  for (let i = 0; i < links.length; i++) {
    // ok: javascript-insecure-html-string
    const safeUrl = escapeHtml(links[i].url);
    const safeText = escapeHtml(links[i].text);
    linksHtml += '<li><a href="' + safeUrl + '">' + safeText + '</a></li>';
  }
  
  linksHtml += '</ul>';
  res.send(linksHtml);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_8(req, res) {
  // Using a template engine like EJS, Handlebars, or React
  const username = req.query.username;
  
  // ok: javascript-insecure-html-string
  res.render('profile', { username: username });
  // The template engine automatically escapes the variables
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_9(req, res) {
  const title = req.query.title;
  const content = req.body.content;
  
  // ok: javascript-insecure-html-string
  const sanitizedContent = sanitizeHtml(content, {
    allowedTags: ['p', 'b', 'i', 'em', 'strong', 'a'],
    allowedAttributes: {
      'a': ['href']
    }
  });
  
  const articleHtml = `
    <article>
      <header>
        <h1>${escapeHtml(title)}</h1>
      </header>
      <div class="content">
        ${sanitizedContent}
      </div>
    </article>
  `;
  
  res.send(articleHtml);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_10(req, res) {
  const searchQuery = req.query.q;
  const category = req.query.category || 'All';
  
  // ok: javascript-insecure-html-string
  const safeSearchQuery = escapeHtml(searchQuery);
  const safeCategory = escapeHtml(category);
  
  const searchFormHtml = `
    <form action="/search" method="GET">
      <input type="text" name="q" value="${safeSearchQuery}">
      <input type="hidden" name="category" value="${safeCategory}">
      <button type="submit">Search</button>
    </form>
  `;
  
  res.send(searchFormHtml);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_11(req, res) {
  // Using DOMPurify to sanitize HTML
  const userHtml = req.body.customHtml;
  
  // ok: javascript-insecure-html-string
  const cleanHtml = purify.sanitize(userHtml);
  res.send(cleanHtml);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_12(req, res) {
  // Using DOM API to create elements safely
  const username = req.query.username;
  
  // ok: javascript-insecure-html-string
  const div = window.document.createElement('div');
  div.className = 'user-profile';
  div.textContent = 'Welcome, ' + username + '!';
  
  res.send(div.outerHTML);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_13(req, res) {
  // Using a dedicated HTML builder library
  const items = JSON.parse(req.body.items);
  
  // ok: javascript-insecure-html-string
  const { htmlBuilder } = require('html-builder-library'); // Fictional library for example
  
  const table = htmlBuilder.table()
    .withHeader(['Item', 'Price'])
    .withRows(items.map(item => [
      escapeHtml(item.name),
      '$' + escapeHtml(item.price)
    ]));
  
  res.send(table.toString());
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_14(req, res) {
  // Using React's server-side rendering
  const React = require('react');
  const ReactDOMServer = require('react-dom/server');
  
  const userData = {
    name: req.body.name,
    email: req.body.email
  };
  
  // ok: javascript-insecure-html-string
  const UserProfile = (props) => {
    return React.createElement('div', { className: 'profile' },
      React.createElement('h1', null, props.name),
      React.createElement('p', null, props.email)
    );
  };
  
  const html = ReactDOMServer.renderToString(
    React.createElement(UserProfile, userData)
  );
  
  res.send(html);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_15(req, res) {
  // Using a dedicated HTML templating function
  const message = req.query.message;
  
  // ok: javascript-insecure-html-string
  function createSafeHtml(strings, ...values) {
    return strings.reduce((result, string, i) => {
      const value = values[i] || '';
      return result + string + escapeHtml(value);
    }, '');
  }
  
  const html = createSafeHtml`
    <div class="message">
      <p>${message}</p>
    </div>
  `;
  
  res.send(html);
}
// {/fact}

// Helper function for bad_case_8
function processUserInput(input) {
  if (!input) {
    throw new Error("Input cannot be empty");
  }
  return input.toUpperCase();
}

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});