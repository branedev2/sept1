import * as express from 'express';
import * as nodemailer from 'nodemailer';
import * as sanitizeHtml from 'sanitize-html';
import * as validator from 'validator';
import * as DOMPurify from 'dompurify';
import { JSDOM } from 'jsdom';

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Initialize DOMPurify
const window = new JSDOM('').window;
const purify = DOMPurify(window);

// Configure nodemailer
const transporter = nodemailer.createTransport({
  host: 'smtp.example.com',
  port: 587,
  secure: false,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD
  }
});

// BAD CASES - Vulnerable code examples

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_1() {
  app.post('/send-email', (req, res) => {
    const userEmail = req.body.email;
    const userMessage = req.body.message;
    
    // ruleid: typescript-unsanitized-input-sendmail
    transporter.sendMail({
      from: 'system@example.com',
      to: 'admin@example.com',
      subject: 'User Message',
      html: `<p>Message from user ${userEmail}:</p><div>${userMessage}</div>`
    });
    
    res.send('Email sent!');
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_2() {
  app.get('/newsletter', (req, res) => {
    const subscriberName = req.query.name as string;
    const subscriberEmail = req.query.email as string;
    
    // ruleid: typescript-unsanitized-input-sendmail
    transporter.sendMail({
      from: 'newsletter@example.com',
      to: subscriberEmail,
      subject: 'Welcome to our Newsletter',
      html: `<h1>Welcome ${subscriberName}!</h1><p>Thank you for subscribing.</p>`
    });
    
    res.send('Welcome email sent!');
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_3() {
  app.post('/contact', (req, res) => {
    const name = req.body.name;
    const email = req.body.email;
    const message = req.body.message;
    
    let emailContent = `
      <h2>Contact Form Submission</h2>
      <p><strong>From:</strong> ${name} (${email})</p>
      <p><strong>Message:</strong></p>
      <div>${message}</div>
    `;
    
    // ruleid: typescript-unsanitized-input-sendmail
    transporter.sendMail({
      from: 'website@example.com',
      to: 'support@example.com',
      subject: `Contact from ${name}`,
      html: emailContent
    });
    
    res.json({ success: true });
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_4() {
  app.post('/feedback', (req, res) => {
    const userFeedback = req.body.feedback;
    const userRating = req.body.rating;
    const userBrowser = req.headers['user-agent'];
    
    // ruleid: typescript-unsanitized-input-sendmail
    transporter.sendMail({
      from: 'feedback@example.com',
      to: 'product@example.com',
      subject: `User Feedback: ${userRating}/5 stars`,
      html: `
        <h3>User Feedback</h3>
        <p>Rating: ${userRating}/5</p>
        <p>Browser: ${userBrowser}</p>
        <div class="feedback">${userFeedback}</div>
      `
    });
    
    res.send('Thank you for your feedback!');
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_5() {
  app.get('/invite', (req, res) => {
    const inviteeEmail = req.query.email as string;
    const inviterName = req.query.from as string;
    const customMessage = req.query.message as string;
    
    // ruleid: typescript-unsanitized-input-sendmail
    transporter.sendMail({
      from: 'invites@example.com',
      to: inviteeEmail,
      subject: `${inviterName} has invited you!`,
      html: `
        <h2>You've been invited!</h2>
        <p>${inviterName} has invited you to join our platform.</p>
        <p>Personal message: ${customMessage}</p>
        <a href="https://example.com/signup">Sign up now</a>
      `
    });
    
    res.send('Invitation sent!');
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_6() {
  app.post('/report', (req, res) => {
    const reportType = req.body.type;
    const reportDetails = req.body.details;
    const reporterEmail = req.body.email;
    
    // ruleid: typescript-unsanitized-input-sendmail
    transporter.sendMail({
      from: 'reports@example.com',
      to: 'security@example.com',
      subject: `New ${reportType} Report`,
      html: `
        <h2>${reportType} Report</h2>
        <p>Reported by: ${reporterEmail}</p>
        <div class="details">${reportDetails}</div>
      `
    });
    
    res.json({ status: 'Report submitted' });
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_7() {
  app.post('/subscribe', (req, res) => {
    const userName = req.body.name;
    const userEmail = req.body.email;
    const preferences = req.body.preferences;
    
    let preferencesHtml = '<ul>';
    for (const pref of preferences) {
      preferencesHtml += `<li>${pref}</li>`;
    }
    preferencesHtml += '</ul>';
    
    // ruleid: typescript-unsanitized-input-sendmail
    transporter.sendMail({
      from: 'subscriptions@example.com',
      to: userEmail,
      subject: 'Subscription Confirmation',
      html: `
        <h1>Hello ${userName}!</h1>
        <p>Your subscription preferences:</p>
        ${preferencesHtml}
      `
    });
    
    res.send('Subscribed successfully!');
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_8() {
  app.post('/order-confirmation', (req, res) => {
    const customerName = req.body.name;
    const orderItems = req.body.items;
    const customerEmail = req.body.email;
    
    let itemsHtml = '<table><tr><th>Item</th><th>Quantity</th><th>Price</th></tr>';
    for (const item of orderItems) {
      itemsHtml += `<tr><td>${item.name}</td><td>${item.quantity}</td><td>${item.price}</td></tr>`;
    }
    itemsHtml += '</table>';
    
    // ruleid: typescript-unsanitized-input-sendmail
    transporter.sendMail({
      from: 'orders@example.com',
      to: customerEmail,
      subject: 'Order Confirmation',
      html: `
        <h2>Thank you for your order, ${customerName}!</h2>
        <p>Order details:</p>
        ${itemsHtml}
      `
    });
    
    res.json({ success: true });
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_9() {
  app.post('/password-reset', (req, res) => {
    const userEmail = req.body.email;
    const resetToken = Math.random().toString(36).substring(2, 15);
    const userIp = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    
    // ruleid: typescript-unsanitized-input-sendmail
    transporter.sendMail({
      from: 'security@example.com',
      to: userEmail,
      subject: 'Password Reset Request',
      html: `
        <h2>Password Reset</h2>
        <p>We received a password reset request from IP: ${userIp}</p>
        <p>Click the link below to reset your password:</p>
        <a href="https://example.com/reset?token=${resetToken}">Reset Password</a>
      `
    });
    
    res.send('Password reset email sent');
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_10() {
  app.get('/event-reminder', (req, res) => {
    const eventName = req.query.event as string;
    const eventDate = req.query.date as string;
    const attendeeEmail = req.query.email as string;
    const attendeeName = req.query.name as string;
    
    // ruleid: typescript-unsanitized-input-sendmail
    transporter.sendMail({
      from: 'events@example.com',
      to: attendeeEmail,
      subject: `Reminder: ${eventName}`,
      html: `
        <h2>Event Reminder</h2>
        <p>Hello ${attendeeName},</p>
        <p>This is a reminder that ${eventName} is scheduled for ${eventDate}.</p>
        <p>We look forward to seeing you there!</p>
      `
    });
    
    res.send('Reminder sent');
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_11() {
  app.post('/support-ticket', (req, res) => {
    const ticketId = req.body.ticketId;
    const customerName = req.body.name;
    const customerEmail = req.body.email;
    const issueDescription = req.body.description;
    
    // ruleid: typescript-unsanitized-input-sendmail
    transporter.sendMail({
      from: 'support@example.com',
      to: customerEmail,
      cc: 'support-team@example.com',
      subject: `Support Ticket #${ticketId}`,
      html: `
        <h2>Support Ticket Created</h2>
        <p>Hello ${customerName},</p>
        <p>Your support ticket #${ticketId} has been created.</p>
        <h3>Issue Description:</h3>
        <div>${issueDescription}</div>
        <p>Our team will get back to you shortly.</p>
      `
    });
    
    res.json({ success: true, ticketId });
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_12() {
  app.post('/comment-notification', (req, res) => {
    const articleTitle = req.body.articleTitle;
    const commentAuthor = req.body.author;
    const commentContent = req.body.content;
    const authorEmail = req.body.email;
    
    // ruleid: typescript-unsanitized-input-sendmail
    transporter.sendMail({
      from: 'notifications@example.com',
      to: authorEmail,
      subject: `New comment on "${articleTitle}"`,
      html: `
        <h2>New Comment</h2>
        <p>Someone has commented on your article "${articleTitle}"</p>
        <div class="comment">
          <p><strong>${commentAuthor} wrote:</strong></p>
          <blockquote>${commentContent}</blockquote>
        </div>
        <a href="https://example.com/articles/comments">View all comments</a>
      `
    });
    
    res.send('Comment notification sent');
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_13() {
  app.post('/team-invitation', (req, res) => {
    const teamName = req.body.team;
    const inviteeEmail = req.body.email;
    const inviterName = req.body.inviter;
    const teamDescription = req.body.description;
    
    // ruleid: typescript-unsanitized-input-sendmail
    transporter.sendMail({
      from: 'teams@example.com',
      to: inviteeEmail,
      subject: `You're invited to join ${teamName}`,
      html: `
        <h2>Team Invitation</h2>
        <p>${inviterName} has invited you to join the team "${teamName}"</p>
        <h3>Team Description:</h3>
        <div>${teamDescription}</div>
        <a href="https://example.com/teams/join">Accept Invitation</a>
      `
    });
    
    res.json({ success: true });
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_14() {
  app.get('/custom-email', (req, res) => {
    const recipientEmail = req.query.to as string;
    const emailSubject = req.query.subject as string;
    const emailBody = req.query.body as string;
    
    // ruleid: typescript-unsanitized-input-sendmail
    transporter.sendMail({
      from: 'system@example.com',
      to: recipientEmail,
      subject: emailSubject,
      html: emailBody
    });
    
    res.send('Custom email sent');
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_15() {
  app.post('/survey-results', (req, res) => {
    const surveyName = req.body.surveyName;
    const userEmail = req.body.email;
    const answers = req.body.answers;
    
    let resultsHtml = '<h3>Your Responses:</h3><ul>';
    for (const [question, answer] of Object.entries(answers)) {
      resultsHtml += `<li><strong>${question}:</strong> ${answer}</li>`;
    }
    resultsHtml += '</ul>';
    
    // ruleid: typescript-unsanitized-input-sendmail
    transporter.sendMail({
      from: 'surveys@example.com',
      to: userEmail,
      subject: `Your ${surveyName} Survey Results`,
      html: `
        <h2>Thank you for completing our survey!</h2>
        <p>Survey: ${surveyName}</p>
        ${resultsHtml}
      `
    });
    
    res.json({ success: true });
  });
}
// {/fact}

// GOOD CASES - Secure code examples

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_1() {
  app.post('/send-email', (req, res) => {
    const userEmail = validator.escape(req.body.email);
    const userMessage = sanitizeHtml(req.body.message);
    
    // ok: typescript-unsanitized-input-sendmail
    transporter.sendMail({
      from: 'system@example.com',
      to: 'admin@example.com',
      subject: 'User Message',
      html: `<p>Message from user ${userEmail}:</p><div>${userMessage}</div>`
    });
    
    res.send('Email sent!');
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_2() {
  app.get('/newsletter', (req, res) => {
    const subscriberName = validator.escape(req.query.name as string);
    const subscriberEmail = validator.escape(req.query.email as string);
    
    // Validate email format
    if (!validator.isEmail(subscriberEmail)) {
      return res.status(400).send('Invalid email address');
    }
    
    // ok: typescript-unsanitized-input-sendmail
    transporter.sendMail({
      from: 'newsletter@example.com',
      to: subscriberEmail,
      subject: 'Welcome to our Newsletter',
      html: `<h1>Welcome ${subscriberName}!</h1><p>Thank you for subscribing.</p>`
    });
    
    res.send('Welcome email sent!');
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_3() {
  app.post('/contact', (req, res) => {
    const name = sanitizeHtml(req.body.name);
    const email = validator.escape(req.body.email);
    const message = sanitizeHtml(req.body.message, {
      allowedTags: ['b', 'i', 'em', 'strong', 'p', 'br'],
      allowedAttributes: {}
    });
    
    let emailContent = `
      <h2>Contact Form Submission</h2>
      <p><strong>From:</strong> ${name} (${email})</p>
      <p><strong>Message:</strong></p>
      <div>${message}</div>
    `;
    
    // ok: typescript-unsanitized-input-sendmail
    transporter.sendMail({
      from: 'website@example.com',
      to: 'support@example.com',
      subject: `Contact from ${name}`,
      html: emailContent
    });
    
    res.json({ success: true });
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_4() {
  app.post('/feedback', (req, res) => {
    const userFeedback = purify.sanitize(req.body.feedback);
    const userRating = parseInt(req.body.rating, 10);
    const userBrowser = validator.escape(req.headers['user-agent'] as string);
    
    // Validate rating
    if (isNaN(userRating) || userRating < 1 || userRating > 5) {
      return res.status(400).send('Invalid rating');
    }
    
    // ok: typescript-unsanitized-input-sendmail
    transporter.sendMail({
      from: 'feedback@example.com',
      to: 'product@example.com',
      subject: `User Feedback: ${userRating}/5 stars`,
      html: `
        <h3>User Feedback</h3>
        <p>Rating: ${userRating}/5</p>
        <p>Browser: ${userBrowser}</p>
        <div class="feedback">${userFeedback}</div>
      `
    });
    
    res.send('Thank you for your feedback!');
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_5() {
  app.get('/invite', (req, res) => {
    const inviteeEmail = validator.normalizeEmail(req.query.email as string);
    const inviterName = validator.escape(req.query.from as string);
    const customMessage = sanitizeHtml(req.query.message as string);
    
    // Validate email
    if (!inviteeEmail || !validator.isEmail(inviteeEmail as string)) {
      return res.status(400).send('Invalid email address');
    }
    
    // ok: typescript-unsanitized-input-sendmail
    transporter.sendMail({
      from: 'invites@example.com',
      to: inviteeEmail as string,
      subject: `${inviterName} has invited you!`,
      html: `
        <h2>You've been invited!</h2>
        <p>${inviterName} has invited you to join our platform.</p>
        <p>Personal message: ${customMessage}</p>
        <a href="https://example.com/signup">Sign up now</a>
      `
    });
    
    res.send('Invitation sent!');
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_6() {
  app.post('/report', (req, res) => {
    // Whitelist approach for report type
    const allowedReportTypes = ['bug', 'feature', 'security', 'other'];
    const reportType = allowedReportTypes.includes(req.body.type) ? req.body.type : 'other';
    
    const reportDetails = sanitizeHtml(req.body.details);
    const reporterEmail = validator.escape(req.body.email);
    
    // ok: typescript-unsanitized-input-sendmail
    transporter.sendMail({
      from: 'reports@example.com',
      to: 'security@example.com',
      subject: `New ${reportType} Report`,
      html: `
        <h2>${reportType} Report</h2>
        <p>Reported by: ${reporterEmail}</p>
        <div class="details">${reportDetails}</div>
      `
    });
    
    res.json({ status: 'Report submitted' });
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_7() {
  app.post('/subscribe', (req, res) => {
    const userName = validator.escape(req.body.name);
    const userEmail = validator.escape(req.body.email);
    const preferences = Array.isArray(req.body.preferences) ? req.body.preferences : [];
    
    // Whitelist allowed preferences
    const allowedPreferences = ['news', 'updates', 'promotions', 'events'];
    const sanitizedPreferences = preferences.filter(pref => 
      typeof pref === 'string' && allowedPreferences.includes(pref)
    );
    
    let preferencesHtml = '<ul>';
    for (const pref of sanitizedPreferences) {
      preferencesHtml += `<li>${pref}</li>`;
    }
    preferencesHtml += '</ul>';
    
    // ok: typescript-unsanitized-input-sendmail
    transporter.sendMail({
      from: 'subscriptions@example.com',
      to: userEmail,
      subject: 'Subscription Confirmation',
      html: `
        <h1>Hello ${userName}!</h1>
        <p>Your subscription preferences:</p>
        ${preferencesHtml}
      `
    });
    
    res.send('Subscribed successfully!');
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_8() {
  app.post('/order-confirmation', (req, res) => {
    const customerName = validator.escape(req.body.name);
    const customerEmail = validator.escape(req.body.email);
    const orderItems = Array.isArray(req.body.items) ? req.body.items : [];
    
    let itemsHtml = '<table><tr><th>Item</th><th>Quantity</th><th>Price</th></tr>';
    for (const item of orderItems) {
      // Sanitize each field individually
      const itemName = validator.escape(String(item.name || ''));
      const itemQuantity = parseInt(item.quantity, 10);
      const itemPrice = parseFloat(item.price);
      
      // Validate numeric values
      const safeQuantity = !isNaN(itemQuantity) && itemQuantity > 0 ? itemQuantity : 0;
      const safePrice = !isNaN(itemPrice) && itemPrice >= 0 ? itemPrice.toFixed(2) : '0.00';
      
      itemsHtml += `<tr><td>${itemName}</td><td>${safeQuantity}</td><td>$${safePrice}</td></tr>`;
    }
    itemsHtml += '</table>';
    
    // ok: typescript-unsanitized-input-sendmail
    transporter.sendMail({
      from: 'orders@example.com',
      to: customerEmail,
      subject: 'Order Confirmation',
      html: `
        <h2>Thank you for your order, ${customerName}!</h2>
        <p>Order details:</p>
        ${itemsHtml}
      `
    });
    
    res.json({ success: true });
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_9() {
  app.post('/password-reset', (req, res) => {
    const userEmail = validator.normalizeEmail(req.body.email);
    const resetToken = Math.random().toString(36).substring(2, 15);
    
    // Sanitize IP address
    let userIp = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    if (Array.isArray(userIp)) {
      userIp = userIp[0];
    }
    const safeUserIp = validator.escape(String(userIp));
    
    // ok: typescript-unsanitized-input-sendmail
    transporter.sendMail({
      from: 'security@example.com',
      to: userEmail as string,
      subject: 'Password Reset Request',
      html: `
        <h2>Password Reset</h2>
        <p>We received a password reset request from IP: ${safeUserIp}</p>
        <p>Click the link below to reset your password:</p>
        <a href="https://example.com/reset?token=${resetToken}">Reset Password</a>
      `
    });
    
    res.send('Password reset email sent');
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_10() {
  app.get('/event-reminder', (req, res) => {
    const eventName = validator.escape(req.query.event as string);
    const eventDate = validator.escape(req.query.date as string);
    const attendeeEmail = validator.normalizeEmail(req.query.email as string) as string;
    const attendeeName = validator.escape(req.query.name as string);
    
    // Validate date format
    if (!validator.isDate(eventDate)) {
      return res.status(400).send('Invalid date format');
    }
    
    // ok: typescript-unsanitized-input-sendmail
    transporter.sendMail({
      from: 'events@example.com',
      to: attendeeEmail,
      subject: `Reminder: ${eventName}`,
      html: `
        <h2>Event Reminder</h2>
        <p>Hello ${attendeeName},</p>
        <p>This is a reminder that ${eventName} is scheduled for ${eventDate}.</p>
        <p>We look forward to seeing you there!</p>
      `
    });
    
    res.send('Reminder sent');
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_11() {
  app.post('/support-ticket', (req, res) => {
    // Validate and sanitize ticket ID (assuming it should be numeric)
    const ticketId = parseInt(req.body.ticketId, 10);
    if (isNaN(ticketId) || ticketId <= 0) {
      return res.status(400).send('Invalid ticket ID');
    }
    
    const customerName = validator.escape(req.body.name);
    const customerEmail = validator.escape(req.body.email);
    const issueDescription = sanitizeHtml(req.body.description, {
      allowedTags: ['p', 'br', 'ul', 'ol', 'li', 'strong', 'em'],
      allowedAttributes: {}
    });
    
    // ok: typescript-unsanitized-input-sendmail
    transporter.sendMail({
      from: 'support@example.com',
      to: customerEmail,
      cc: 'support-team@example.com',
      subject: `Support Ticket #${ticketId}`,
      html: `
        <h2>Support Ticket Created</h2>
        <p>Hello ${customerName},</p>
        <p>Your support ticket #${ticketId} has been created.</p>
        <h3>Issue Description:</h3>
        <div>${issueDescription}</div>
        <p>Our team will get back to you shortly.</p>
      `
    });
    
    res.json({ success: true, ticketId });
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_12() {
  app.post('/comment-notification', (req, res) => {
    const articleTitle = validator.escape(req.body.articleTitle);
    const commentAuthor = validator.escape(req.body.author);
    const commentContent = sanitizeHtml(req.body.content, {
      allowedTags: ['p', 'br', 'b', 'i', 'em', 'strong'],
      allowedAttributes: {}
    });
    const authorEmail = validator.escape(req.body.email);
    
    // ok: typescript-unsanitized-input-sendmail
    transporter.sendMail({
      from: 'notifications@example.com',
      to: authorEmail,
      subject: `New comment on "${articleTitle}"`,
      html: `
        <h2>New Comment</h2>
        <p>Someone has commented on your article "${articleTitle}"</p>
        <div class="comment">
          <p><strong>${commentAuthor} wrote:</strong></p>
          <blockquote>${commentContent}</blockquote>
        </div>
        <a href="https://example.com/articles/comments">View all comments</a>
      `
    });
    
    res.send('Comment notification sent');
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_13() {
  app.post('/team-invitation', (req, res) => {
    const teamName = validator.escape(req.body.team);
    const inviteeEmail = validator.normalizeEmail(req.body.email) as string;
    const inviterName = validator.escape(req.body.inviter);
    const teamDescription = sanitizeHtml(req.body.description, {
      allowedTags: ['p', 'br', 'ul', 'ol', 'li'],
      allowedAttributes: {}
    });
    
    // Validate email
    if (!validator.isEmail(inviteeEmail)) {
      return res.status(400).send('Invalid email address');
    }
    
    // ok: typescript-unsanitized-input-sendmail
    transporter.sendMail({
      from: 'teams@example.com',
      to: inviteeEmail,
      subject: `You're invited to join ${teamName}`,
      html: `
        <h2>Team Invitation</h2>
        <p>${inviterName} has invited you to join the team "${teamName}"</p>
        <h3>Team Description:</h3>
        <div>${teamDescription}</div>
        <a href="https://example.com/teams/join">Accept Invitation</a>
      `
    });
    
    res.json({ success: true });
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_14() {
  app.get('/custom-email', (req, res) => {
    // This is a high-risk endpoint that should be restricted to authenticated admins
    // For demonstration purposes, we'll show proper sanitization
    
    const recipientEmail = validator.normalizeEmail(req.query.to as string) as string;
    const emailSubject = validator.escape(req.query.subject as string);
    const emailBody = sanitizeHtml(req.query.body as string, {
      allowedTags: sanitizeHtml.defaults.allowedTags.concat(['img']),
      allowedAttributes: {
        ...sanitizeHtml.defaults.allowedAttributes,
        img: ['src', 'alt', 'width', 'height']
      },
      allowedSchemes: ['http', 'https', 'mailto']
    });
    
    // Validate email
    if (!validator.isEmail(recipientEmail)) {
      return res.status(400).send('Invalid email address');
    }
    
    // ok: typescript-unsanitized-input-sendmail
    transporter.sendMail({
      from: 'system@example.com',
      to: recipientEmail,
      subject: emailSubject,
      html: emailBody
    });
    
    res.send('Custom email sent');
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_15() {
  app.post('/survey-results', (req, res) => {
    const surveyName = validator.escape(req.body.surveyName);
    const userEmail = validator.escape(req.body.email);
    const answers = req.body.answers || {};
    
    let resultsHtml = '<h3>Your Responses:</h3><ul>';
    
    // Safely process the answers object
    if (typeof answers === 'object' && answers !== null) {
      for (const [question, answer] of Object.entries(answers)) {
        const safeQuestion = validator.escape(String(question));
        const safeAnswer = validator.escape(String(answer));
        resultsHtml += `<li><strong>${safeQuestion}:</strong> ${safeAnswer}</li>`;
      }
    }
    
    resultsHtml += '</ul>';
    
    // ok: typescript-unsanitized-input-sendmail
    transporter.sendMail({
      from: 'surveys@example.com',
      to: userEmail,
      subject: `Your ${surveyName} Survey Results`,
      html: `
        <h2>Thank you for completing our survey!</h2>
        <p>Survey: ${surveyName}</p>
        ${resultsHtml}
      `
    });
    
    res.json({ success: true });
  });
}
// {/fact}

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});