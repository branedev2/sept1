// Filename: nodemailer_examples.js

const express = require('express');
const nodemailer = require('nodemailer');
const sanitizeHtml = require('sanitize-html');
const { escape } = require('html-escaper');
const DOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');
const window = new JSDOM('').window;
const purify = DOMPurify(window);

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Create a reusable transporter object
const transporter = nodemailer.createTransport({
  host: 'smtp.example.com',
  port: 587,
  secure: false,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// TRUE POSITIVES (Vulnerable Code)

// Case 1: Direct use of user input in email subject
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_1(req, res) {
  const userSubject = req.query.subject;
  
  // ruleid: javascript-unsanitized-input-sendmail
  transporter.sendMail({
    from: 'sender@example.com',
    to: 'recipient@example.com',
    subject: userSubject,
    html: '<p>Email content</p>'
  });
  
  res.send('Email sent');
}
// {/fact}

// Case 2: Direct use of user input in email HTML body
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_2(req, res) {
  const userMessage = req.body.message;
  
  // ruleid: javascript-unsanitized-input-sendmail
  transporter.sendMail({
    from: 'sender@example.com',
    to: 'recipient@example.com',
    subject: 'Hello',
    html: `<p>${userMessage}</p>`
  });
  
  res.send('Email sent');
}
// {/fact}

// Case 3: User input in both subject and body
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_3(req, res) {
  const { subject, message } = req.body;
  
  // ruleid: javascript-unsanitized-input-sendmail
  transporter.sendMail({
    from: 'sender@example.com',
    to: 'recipient@example.com',
    subject: subject,
    html: `<div>
      <h1>${subject}</h1>
      <p>${message}</p>
    </div>`
  });
  
  res.send('Email sent');
}
// {/fact}

// Case 4: User input in email recipient
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_4(req, res) {
  const recipient = req.query.email;
  const message = "Welcome to our service!";
  
  // ruleid: javascript-unsanitized-input-sendmail
  transporter.sendMail({
    from: 'sender@example.com',
    to: recipient,
    subject: 'Welcome',
    html: `<p>${message}</p>`
  });
  
  res.send('Email sent');
}
// {/fact}

// Case 5: User input in email sender name
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_5(req, res) {
  const senderName = req.body.name;
  
  // ruleid: javascript-unsanitized-input-sendmail
  transporter.sendMail({
    from: `"${senderName}" <sender@example.com>`,
    to: 'recipient@example.com',
    subject: 'Hello',
    html: '<p>Email content</p>'
  });
  
  res.send('Email sent');
}
// {/fact}

// Case 6: User input in email with minimal processing
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_6(req, res) {
  let message = req.body.message;
  message = message.replace(/bad/g, '***');  // Not sufficient for XSS protection
  
  // ruleid: javascript-unsanitized-input-sendmail
  transporter.sendMail({
    from: 'sender@example.com',
    to: 'recipient@example.com',
    subject: 'Message',
    html: `<p>${message}</p>`
  });
  
  res.send('Email sent');
}
// {/fact}

// Case 7: User input in email template with variable substitution
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_7(req, res) {
  const username = req.query.username;
  const template = `
    <div>
      <h1>Welcome ${username}!</h1>
      <p>Thank you for registering.</p>
    </div>
  `;
  
  // ruleid: javascript-unsanitized-input-sendmail
  transporter.sendMail({
    from: 'welcome@example.com',
    to: 'recipient@example.com',
    subject: 'Welcome',
    html: template
  });
  
  res.send('Welcome email sent');
}
// {/fact}

// Case 8: User input in email with Promise-based sending
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_8(req, res) {
  const subject = req.query.subject;
  const content = req.body.content;
  
  // ruleid: javascript-unsanitized-input-sendmail
  transporter.sendMail({
    from: 'sender@example.com',
    to: 'recipient@example.com',
    subject: subject,
    html: content
  })
  .then(info => {
    res.send(`Email sent: ${info.messageId}`);
  })
  .catch(error => {
    res.status(500).send(`Error: ${error}`);
  });
}
// {/fact}

// Case 9: User input in email with async/await
// {fact rule=cross-site-scripting@v1.0 defects=1}
async function bad_case_9(req, res) {
  const { subject, message } = req.body;
  
  try {
    // ruleid: javascript-unsanitized-input-sendmail
    await transporter.sendMail({
      from: 'sender@example.com',
      to: 'recipient@example.com',
      subject: subject,
      html: `<p>${message}</p>`
    });
    res.send('Email sent successfully');
  } catch (error) {
    res.status(500).send('Failed to send email');
  }
}
// {/fact}

// Case 10: User input in email with conditional content
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_10(req, res) {
  const username = req.query.username;
  const isPremium = req.query.premium === 'true';
  
  let content = `<h1>Hello ${username}</h1>`;
  if (isPremium) {
    content += '<p>Thank you for being a premium member!</p>';
  } else {
    content += '<p>Consider upgrading to premium!</p>';
  }
  
  // ruleid: javascript-unsanitized-input-sendmail
  transporter.sendMail({
    from: 'sender@example.com',
    to: 'recipient@example.com',
    subject: 'Membership',
    html: content
  });
  
  res.send('Email sent');
}
// {/fact}

// Case 11: User input in email with attachments
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_11(req, res) {
  const subject = req.query.subject;
  const message = req.body.message;
  
  // ruleid: javascript-unsanitized-input-sendmail
  transporter.sendMail({
    from: 'sender@example.com',
    to: 'recipient@example.com',
    subject: subject,
    html: `<p>${message}</p>`,
    attachments: [
      {
        filename: 'report.pdf',
        path: './reports/report.pdf'
      }
    ]
  });
  
  res.send('Email with attachment sent');
}
// {/fact}

// Case 12: User input in email with CC and BCC
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_12(req, res) {
  const { subject, message, cc } = req.body;
  
  // ruleid: javascript-unsanitized-input-sendmail
  transporter.sendMail({
    from: 'sender@example.com',
    to: 'recipient@example.com',
    cc: cc,
    subject: subject,
    html: `<p>${message}</p>`
  });
  
  res.send('Email sent');
}
// {/fact}

// Case 13: User input in email with template literals in multiple places
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_13(req, res) {
  const { name, company, role } = req.body;
  
  // ruleid: javascript-unsanitized-input-sendmail
  transporter.sendMail({
    from: 'sender@example.com',
    to: 'recipient@example.com',
    subject: `New contact from ${name} at ${company}`,
    html: `
      <div>
        <h1>New Contact Request</h1>
        <p>Name: ${name}</p>
        <p>Company: ${company}</p>
        <p>Role: ${role}</p>
      </div>
    `
  });
  
  res.send('Contact email sent');
}
// {/fact}

// Case 14: User input in email with array of recipients
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_14(req, res) {
  const message = req.body.message;
  const recipients = req.body.recipients; // Array of email addresses
  
  // ruleid: javascript-unsanitized-input-sendmail
  transporter.sendMail({
    from: 'sender@example.com',
    to: recipients,
    subject: 'Announcement',
    html: `<p>${message}</p>`
  });
  
  res.send('Bulk email sent');
}
// {/fact}

// Case 15: User input in email with dynamic template generation
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_15(req, res) {
  const { title, content, footer } = req.body;
  
  const generateTemplate = (title, content, footer) => {
    return `
      <div>
        <h1>${title}</h1>
        <div>${content}</div>
        <footer>${footer}</footer>
      </div>
    `;
  };
  
  const emailTemplate = generateTemplate(title, content, footer);
  
  // ruleid: javascript-unsanitized-input-sendmail
  transporter.sendMail({
    from: 'sender@example.com',
    to: 'recipient@example.com',
    subject: title,
    html: emailTemplate
  });
  
  res.send('Email sent');
}
// {/fact}

// TRUE NEGATIVES (Safe Code)

// Case 1: Sanitizing user input in email subject
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_1(req, res) {
  const userSubject = req.query.subject;
  const sanitizedSubject = escape(userSubject);
  
  // ok: javascript-unsanitized-input-sendmail
  transporter.sendMail({
    from: 'sender@example.com',
    to: 'recipient@example.com',
    subject: sanitizedSubject,
    html: '<p>Email content</p>'
  });
  
  res.send('Email sent');
}
// {/fact}

// Case 2: Sanitizing user input in email HTML body
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_2(req, res) {
  const userMessage = req.body.message;
  const sanitizedMessage = sanitizeHtml(userMessage);
  
  // ok: javascript-unsanitized-input-sendmail
  transporter.sendMail({
    from: 'sender@example.com',
    to: 'recipient@example.com',
    subject: 'Hello',
    html: `<p>${sanitizedMessage}</p>`
  });
  
  res.send('Email sent');
}
// {/fact}

// Case 3: Sanitizing user input in both subject and body
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_3(req, res) {
  const { subject, message } = req.body;
  const sanitizedSubject = escape(subject);
  const sanitizedMessage = sanitizeHtml(message);
  
  // ok: javascript-unsanitized-input-sendmail
  transporter.sendMail({
    from: 'sender@example.com',
    to: 'recipient@example.com',
    subject: sanitizedSubject,
    html: `<div>
      <h1>${sanitizedSubject}</h1>
      <p>${sanitizedMessage}</p>
    </div>`
  });
  
  res.send('Email sent');
}
// {/fact}

// Case 4: Using DOMPurify for sanitization
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_4(req, res) {
  const message = req.body.message;
  const sanitizedMessage = purify.sanitize(message);
  
  // ok: javascript-unsanitized-input-sendmail
  transporter.sendMail({
    from: 'sender@example.com',
    to: 'recipient@example.com',
    subject: 'Message',
    html: sanitizedMessage
  });
  
  res.send('Email sent');
}
// {/fact}

// Case 5: Using text content instead of HTML
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_5(req, res) {
  const message = req.body.message;
  
  // ok: javascript-unsanitized-input-sendmail
  transporter.sendMail({
    from: 'sender@example.com',
    to: 'recipient@example.com',
    subject: 'Message',
    text: message // Using text instead of HTML avoids XSS
  });
  
  res.send('Email sent');
}
// {/fact}

// Case 6: Sanitizing user input in email with Promise-based sending
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_6(req, res) {
  const subject = req.query.subject;
  const content = req.body.content;
  
  const sanitizedSubject = escape(subject);
  const sanitizedContent = sanitizeHtml(content);
  
  // ok: javascript-unsanitized-input-sendmail
  transporter.sendMail({
    from: 'sender@example.com',
    to: 'recipient@example.com',
    subject: sanitizedSubject,
    html: sanitizedContent
  })
  .then(info => {
    res.send(`Email sent: ${info.messageId}`);
  })
  .catch(error => {
    res.status(500).send(`Error: ${error}`);
  });
}
// {/fact}

// Case 7: Sanitizing user input in email with async/await
// {fact rule=cross-site-scripting@v1.0 defects=0}
async function good_case_7(req, res) {
  const { subject, message } = req.body;
  
  const sanitizedSubject = escape(subject);
  const sanitizedMessage = sanitizeHtml(message);
  
  try {
    // ok: javascript-unsanitized-input-sendmail
    await transporter.sendMail({
      from: 'sender@example.com',
      to: 'recipient@example.com',
      subject: sanitizedSubject,
      html: `<p>${sanitizedMessage}</p>`
    });
    res.send('Email sent successfully');
  } catch (error) {
    res.status(500).send('Failed to send email');
  }
}
// {/fact}

// Case 8: Sanitizing user input in email template with variable substitution
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_8(req, res) {
  const username = req.query.username;
  const sanitizedUsername = escape(username);
  
  const template = `
    <div>
      <h1>Welcome ${sanitizedUsername}!</h1>
      <p>Thank you for registering.</p>
    </div>
  `;
  
  // ok: javascript-unsanitized-input-sendmail
  transporter.sendMail({
    from: 'welcome@example.com',
    to: 'recipient@example.com',
    subject: 'Welcome',
    html: template
  });
  
  res.send('Welcome email sent');
}
// {/fact}

// Case 9: Hardcoded content (no user input)
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_9(req, res) {
  // ok: javascript-unsanitized-input-sendmail
  transporter.sendMail({
    from: 'sender@example.com',
    to: 'recipient@example.com',
    subject: 'System Notification',
    html: '<p>This is a system generated message.</p>'
  });
  
  res.send('System notification sent');
}
// {/fact}

// Case 10: Sanitizing user input in email with conditional content
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_10(req, res) {
  const username = req.query.username;
  const isPremium = req.query.premium === 'true';
  
  const sanitizedUsername = escape(username);
  
  let content = `<h1>Hello ${sanitizedUsername}</h1>`;
  if (isPremium) {
    content += '<p>Thank you for being a premium member!</p>';
  } else {
    content += '<p>Consider upgrading to premium!</p>';
  }
  
  // ok: javascript-unsanitized-input-sendmail
  transporter.sendMail({
    from: 'sender@example.com',
    to: 'recipient@example.com',
    subject: 'Membership',
    html: content
  });
  
  res.send('Email sent');
}
// {/fact}

// Case 11: Sanitizing user input in email with attachments
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_11(req, res) {
  const subject = req.query.subject;
  const message = req.body.message;
  
  const sanitizedSubject = escape(subject);
  const sanitizedMessage = sanitizeHtml(message);
  
  // ok: javascript-unsanitized-input-sendmail
  transporter.sendMail({
    from: 'sender@example.com',
    to: 'recipient@example.com',
    subject: sanitizedSubject,
    html: `<p>${sanitizedMessage}</p>`,
    attachments: [
      {
        filename: 'report.pdf',
        path: './reports/report.pdf'
      }
    ]
  });
  
  res.send('Email with attachment sent');
}
// {/fact}

// Case 12: Using a template engine with auto-escaping
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_12(req, res) {
  const { name, message } = req.body;
  
  // Simulating a template engine with auto-escaping
  const renderTemplate = (template, data) => {
    // This simulates a template engine that automatically escapes values
    let result = template;
    for (const key in data) {
      const escapedValue = escape(data[key]);
      result = result.replace(new RegExp(`{{${key}}}`, 'g'), escapedValue);
    }
    return result;
  };
  
  const template = `
    <div>
      <h1>Message from {{name}}</h1>
      <p>{{message}}</p>
    </div>
  `;
  
  const htmlContent = renderTemplate(template, { name, message });
  
  // ok: javascript-unsanitized-input-sendmail
  transporter.sendMail({
    from: 'sender@example.com',
    to: 'recipient@example.com',
    subject: `Message from ${escape(name)}`,
    html: htmlContent
  });
  
  res.send('Email sent');
}
// {/fact}

// Case 13: Using a custom sanitization function
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_13(req, res) {
  const { subject, message } = req.body;
  
  const customSanitize = (input) => {
    // Custom sanitization logic
    return input
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  };
  
  const sanitizedSubject = customSanitize(subject);
  const sanitizedMessage = customSanitize(message);
  
  // ok: javascript-unsanitized-input-sendmail
  transporter.sendMail({
    from: 'sender@example.com',
    to: 'recipient@example.com',
    subject: sanitizedSubject,
    html: `<p>${sanitizedMessage}</p>`
  });
  
  res.send('Email sent');
}
// {/fact}

// Case 14: Using a validation function before sending
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_14(req, res) {
  const { subject, message } = req.body;
  
  // Validate input before using it
  const validateInput = (input) => {
    // Only allow alphanumeric characters and basic punctuation
    const regex = /^[a-zA-Z0-9 .,!?]*$/;
    return regex.test(input);
  };
  
  if (!validateInput(subject) || !validateInput(message)) {
    return res.status(400).send('Invalid input');
  }
  
  // Input is validated, but still sanitize for extra security
  const sanitizedSubject = escape(subject);
  const sanitizedMessage = escape(message);
  
  // ok: javascript-unsanitized-input-sendmail
  transporter.sendMail({
    from: 'sender@example.com',
    to: 'recipient@example.com',
    subject: sanitizedSubject,
    html: `<p>${sanitizedMessage}</p>`
  });
  
  res.send('Email sent');
}
// {/fact}

// Case 15: Using markdown instead of direct HTML
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_15(req, res) {
  const markdown = require('markdown-it')({
    html: false, // Disable HTML tags in input
    breaks: true,
    linkify: true
  });
  
  const { subject, markdownContent } = req.body;
  const sanitizedSubject = escape(subject);
  
  // Convert markdown to HTML (markdown-it sanitizes by default when html:false)
  const htmlContent = markdown.render(markdownContent);
  
  // ok: javascript-unsanitized-input-sendmail
  transporter.sendMail({
    from: 'sender@example.com',
    to: 'recipient@example.com',
    subject: sanitizedSubject,
    html: htmlContent
  });
  
  res.send('Email sent');
}
// {/fact}

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});