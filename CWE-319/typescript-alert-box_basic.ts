// File: alert_box_examples.ts

import express from 'express';
import { Request, Response } from 'express';
import * as React from 'react';
import { sanitizeHtml } from 'some-sanitizer-library';
import DOMPurify from 'dompurify';

// True Positive Examples (Vulnerable Code)

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_1() {
  const app = express();
  
  app.get('/search', (req: Request, res: Response) => {
    const query = req.query.q as string;
    
    // Directly using user input in alert box
    // ruleid: typescript-alert-box
    const script = `<script>alert("${query}");</script>`;
    res.send(`Search results for: ${script}`);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_2() {
  const app = express();
  
  app.post('/comment', (req: Request, res: Response) => {
    const comment = req.body.comment;
    
    // Using template literals with user input
    // ruleid: typescript-alert-box
    const alertCode = `<script>alert(\`Comment received: ${comment}\`);</script>`;
    res.send(`Thank you for your comment! ${alertCode}`);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_3() {
  const app = express();
  
  app.get('/profile', (req: Request, res: Response) => {
    const username = req.query.username as string;
    
    // Using alert with user input in onclick attribute
    // ruleid: typescript-alert-box
    const dangerousButton = `<button onclick="alert('Hello, ${username}!')">Greet</button>`;
    res.send(`Welcome to your profile! ${dangerousButton}`);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_4() {
  const app = express();
  
  app.get('/error', (req: Request, res: Response) => {
    const errorMsg = req.query.error as string;
    
    // Using document.write with alert
    // ruleid: typescript-alert-box
    const errorScript = `<script>document.write('<div class="error" onclick="alert(\'${errorMsg}\')">Click for details</div>');</script>`;
    res.send(`An error occurred: ${errorScript}`);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_5() {
  const app = express();
  
  app.get('/welcome', (req: Request, res: Response) => {
    const name = req.query.name as string;
    
    // Using eval with alert
    // ruleid: typescript-alert-box
    const welcomeScript = `<script>eval("alert('Welcome, ${name}!')");</script>`;
    res.send(`${welcomeScript}`);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_6() {
  const app = express();
  
  app.get('/notification', (req: Request, res: Response) => {
    const message = req.query.message as string;
    const type = req.query.type as string;
    
    let alertType = 'info';
    if (type === 'error') alertType = 'error';
    
    // Using setTimeout with alert containing user input
    // ruleid: typescript-alert-box
    const notificationScript = `<script>setTimeout(() => { alert("${alertType}: ${message}") }, 1000);</script>`;
    res.send(`${notificationScript}Check your notifications.`);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_7() {
  const app = express();
  
  app.get('/confirm', (req: Request, res: Response) => {
    const action = req.query.action as string;
    
    // Using confirm dialog with user input
    // ruleid: typescript-alert-box
    const confirmScript = `<script>if(confirm("Do you want to ${action}?")) { 
      window.location.href = "/${action}"; 
    }</script>`;
    res.send(`${confirmScript}Processing your request...`);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_8() {
  const app = express();
  
  app.get('/prompt', (req: Request, res: Response) => {
    const defaultValue = req.query.default as string;
    
    // Using prompt dialog with user input
    // ruleid: typescript-alert-box
    const promptScript = `<script>const userInput = prompt("Enter your name:", "${defaultValue}");
    if(userInput) document.write("Hello, " + userInput);</script>`;
    res.send(`${promptScript}`);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_9() {
  const app = express();
  
  app.get('/redirect', (req: Request, res: Response) => {
    const destination = req.query.dest as string;
    
    // Using alert in a function with user input
    // ruleid: typescript-alert-box
    const redirectScript = `<script>
      function redirectWithAlert() {
        alert("Redirecting to ${destination}");
        window.location.href = "${destination}";
      }
      redirectWithAlert();
    </script>`;
    res.send(`${redirectScript}Redirecting...`);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_10() {
  const app = express();
  
  app.get('/debug', (req: Request, res: Response) => {
    const debugInfo = req.query.info as string;
    
    // Using alert in an IIFE with user input
    // ruleid: typescript-alert-box
    const debugScript = `<script>
      (function() {
        console.log("Debug info");
        alert("Debug: ${debugInfo}");
      })();
    </script>`;
    res.send(`Debug mode: ${debugScript}`);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_11() {
  const app = express();
  
  app.get('/timer', (req: Request, res: Response) => {
    const seconds = req.query.seconds as string;
    const message = req.query.message as string;
    
    // Using alert in setInterval with user input
    // ruleid: typescript-alert-box
    const timerScript = `<script>
      let count = ${seconds};
      const timer = setInterval(() => {
        if(count <= 0) {
          clearInterval(timer);
          alert("${message}");
        }
        document.getElementById("counter").textContent = count--;
      }, 1000);
    </script>`;
    res.send(`<div id="counter">${seconds}</div>${timerScript}`);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_12() {
  const app = express();
  
  app.get('/event', (req: Request, res: Response) => {
    const eventName = req.query.event as string;
    
    // Using alert in event listener with user input
    // ruleid: typescript-alert-box
    const eventScript = `<script>
      document.addEventListener("DOMContentLoaded", function() {
        document.body.addEventListener("click", function() {
          alert("Event triggered: ${eventName}");
        });
      });
    </script>`;
    res.send(`<div>Click anywhere to trigger event</div>${eventScript}`);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_13() {
  const app = express();
  
  app.get('/conditional-alert', (req: Request, res: Response) => {
    const condition = req.query.condition as string;
    const message = req.query.message as string;
    
    // Using alert in conditional statement with user input
    // ruleid: typescript-alert-box
    const conditionalScript = `<script>
      if(${condition}) {
        alert("${message}");
      }
    </script>`;
    res.send(`Conditional alert: ${conditionalScript}`);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_14() {
  const app = express();
  
  app.get('/dynamic-function', (req: Request, res: Response) => {
    const functionBody = req.query.func as string;
    
    // Using alert in dynamically created function with user input
    // ruleid: typescript-alert-box
    const dynamicScript = `<script>
      const dynamicFunction = new Function("alert('${functionBody}')");
      dynamicFunction();
    </script>`;
    res.send(`Dynamic function: ${dynamicScript}`);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_15() {
  const app = express();
  
  app.get('/custom-dialog', (req: Request, res: Response) => {
    const title = req.query.title as string;
    const content = req.query.content as string;
    
    // Using alert in custom dialog with user input
    // ruleid: typescript-alert-box
    const dialogScript = `<script>
      function showCustomDialog() {
        alert("${title}");
        document.getElementById("dialog-content").innerHTML = "${content}";
        document.getElementById("custom-dialog").style.display = "block";
      }
      showCustomDialog();
    </script>`;
    res.send(`<div id="custom-dialog" style="display:none;"><div id="dialog-content"></div></div>${dialogScript}`);
  });
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_1() {
  const app = express();
  
  app.get('/search', (req: Request, res: Response) => {
    const query = req.query.q as string;
    
    // Using sanitized user input
    // ok: typescript-alert-box
    const sanitizedQuery = DOMPurify.sanitize(query);
    const script = `<script>console.log("Search query: ${sanitizedQuery}");</script>`;
    res.send(`Search results for: ${sanitizedQuery}`);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_2() {
  const app = express();
  
  app.post('/comment', (req: Request, res: Response) => {
    const comment = req.body.comment;
    
    // Using HTML encoding for user input
    // ok: typescript-alert-box
    const encodedComment = comment.replace(/</g, '&lt;').replace(/>/g, '&gt;');
    res.send(`Thank you for your comment! ${encodedComment}`);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_3() {
  const app = express();
  
  app.get('/profile', (req: Request, res: Response) => {
    const username = req.query.username as string;
    
    // Using React to safely render user input
    // ok: typescript-alert-box
    const ProfileComponent = () => React.createElement('div', {}, `Welcome, ${username}`);
    const safeHtml = ReactDOMServer.renderToString(ProfileComponent());
    res.send(safeHtml);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_4() {
  const app = express();
  
  app.get('/error', (req: Request, res: Response) => {
    const errorMsg = req.query.error as string;
    
    // Using a safe notification system instead of alert
    // ok: typescript-alert-box
    const safeNotification = `
      <div class="notification error">
        ${errorMsg.replace(/</g, '&lt;').replace(/>/g, '&gt;')}
      </div>
      <script>
        // Safe way to show notification without using alert
        document.querySelector('.notification').style.display = 'block';
      </script>
    `;
    res.send(`An error occurred: ${safeNotification}`);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_5() {
  const app = express();
  
  app.get('/welcome', (req: Request, res: Response) => {
    const name = req.query.name as string;
    
    // Using content security policy to prevent inline scripts
    // ok: typescript-alert-box
    res.setHeader('Content-Security-Policy', "script-src 'self'");
    const welcomeMessage = `<div>Welcome, ${name.replace(/</g, '&lt;').replace(/>/g, '&gt;')}!</div>`;
    res.send(welcomeMessage);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_6() {
  const app = express();
  
  app.get('/notification', (req: Request, res: Response) => {
    const message = req.query.message as string;
    const type = req.query.type as string;
    
    // Using a custom notification component instead of alert
    // ok: typescript-alert-box
    const sanitizedMessage = DOMPurify.sanitize(message);
    const sanitizedType = ['info', 'error', 'warning'].includes(type) ? type : 'info';
    
    const notificationHtml = `
      <div id="notification" class="${sanitizedType}">${sanitizedMessage}</div>
      <script src="/static/notification.js"></script>
    `;
    res.send(`Check your notifications: ${notificationHtml}`);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_7() {
  const app = express();
  
  app.get('/confirm', (req: Request, res: Response) => {
    const action = req.query.action as string;
    
    // Using a modal dialog instead of confirm
    // ok: typescript-alert-box
    const allowedActions = ['save', 'delete', 'update'];
    const safeAction = allowedActions.includes(action) ? action : 'perform action';
    
    const confirmHtml = `
      <div id="confirm-modal" class="modal">
        <div class="modal-content">
          <p>Do you want to ${safeAction}?</p>
          <button id="confirm-yes">Yes</button>
          <button id="confirm-no">No</button>
        </div>
      </div>
      <script src="/static/modal.js"></script>
    `;
    res.send(`${confirmHtml}Processing your request...`);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_8() {
  const app = express();
  
  app.get('/prompt', (req: Request, res: Response) => {
    const defaultValue = req.query.default as string;
    
    // Using a form input instead of prompt
    // ok: typescript-alert-box
    const sanitizedDefault = defaultValue.replace(/</g, '&lt;').replace(/>/g, '&gt;');
    const promptHtml = `
      <form id="name-form">
        <label for="name">Enter your name:</label>
        <input type="text" id="name" name="name" value="${sanitizedDefault}">
        <button type="submit">Submit</button>
      </form>
    `;
    res.send(promptHtml);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_9() {
  const app = express();
  
  app.get('/redirect', (req: Request, res: Response) => {
    const destination = req.query.dest as string;
    
    // Validating URL before redirect
    // ok: typescript-alert-box
    const allowedDomains = ['example.com', 'trusted-site.org'];
    try {
      const url = new URL(destination);
      if (allowedDomains.includes(url.hostname)) {
        res.redirect(destination);
      } else {
        res.status(400).send("Invalid redirect destination");
      }
    } catch (e) {
      res.status(400).send("Invalid URL format");
    }
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_10() {
  const app = express();
  
  app.get('/debug', (req: Request, res: Response) => {
    const debugInfo = req.query.info as string;
    
    // Using server-side logging instead of client-side alerts
    // ok: typescript-alert-box
    console.log(`Debug info: ${debugInfo}`);
    res.send(`Debug information has been logged on the server.`);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_11() {
  const app = express();
  
  app.get('/timer', (req: Request, res: Response) => {
    const seconds = parseInt(req.query.seconds as string) || 10;
    const message = req.query.message as string;
    
    // Using a safe countdown timer with sanitized message
    // ok: typescript-alert-box
    const sanitizedMessage = DOMPurify.sanitize(message);
    const safeSeconds = Math.min(Math.max(1, seconds), 60); // Limit between 1-60 seconds
    
    const timerHtml = `
      <div id="timer-container">
        <div id="counter">${safeSeconds}</div>
        <div id="message" style="display:none;">${sanitizedMessage}</div>
      </div>
      <script src="/static/safe-timer.js"></script>
    `;
    res.send(timerHtml);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_12() {
  const app = express();
  
  app.get('/event', (req: Request, res: Response) => {
    const eventName = req.query.event as string;
    
    // Using a safe event system with sanitized event name
    // ok: typescript-alert-box
    const sanitizedEventName = DOMPurify.sanitize(eventName);
    const eventHtml = `
      <div id="event-container" data-event="${sanitizedEventName}">
        Click anywhere to trigger event
      </div>
      <script src="/static/event-handler.js"></script>
    `;
    res.send(eventHtml);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_13() {
  const app = express();
  
  app.get('/conditional-message', (req: Request, res: Response) => {
    const condition = req.query.condition as string;
    const message = req.query.message as string;
    
    // Using server-side evaluation of condition with sanitized output
    // ok: typescript-alert-box
    let showMessage = false;
    try {
      // Safely evaluate simple conditions
      if (condition === 'true' || condition === '1') {
        showMessage = true;
      }
    } catch (e) {
      // Default to false on error
    }
    
    const sanitizedMessage = DOMPurify.sanitize(message);
    const responseHtml = showMessage ? 
      `<div class="message">${sanitizedMessage}</div>` : 
      '<div>No message to display</div>';
    
    res.send(responseHtml);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_14() {
  const app = express();
  
  app.get('/function-execution', (req: Request, res: Response) => {
    const functionName = req.query.func as string;
    
    // Using a whitelist of allowed functions instead of dynamic execution
    // ok: typescript-alert-box
    const allowedFunctions = {
      'showWelcome': 'displayWelcomeMessage()',
      'showHelp': 'displayHelpContent()',
      'showContact': 'displayContactForm()'
    };
    
    const safeFunction = allowedFunctions[functionName] || 'console.log("Function not found")';
    const safeScript = `<script src="/static/safe-functions.js"></script>
                        <script>
                          document.addEventListener('DOMContentLoaded', function() {
                            ${safeFunction};
                          });
                        </script>`;
    
    res.send(`<div id="function-container"></div>${safeScript}`);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_15() {
  const app = express();
  
  app.get('/custom-dialog', (req: Request, res: Response) => {
    const title = req.query.title as string;
    const content = req.query.content as string;
    
    // Using a custom dialog component with sanitized content
    // ok: typescript-alert-box
    const sanitizedTitle = sanitizeHtml(title);
    const sanitizedContent = sanitizeHtml(content);
    
    const dialogHtml = `
      <div id="custom-dialog" class="dialog">
        <div class="dialog-header">${sanitizedTitle}</div>
        <div class="dialog-content">${sanitizedContent}</div>
        <div class="dialog-footer">
          <button id="dialog-close">Close</button>
        </div>
      </div>
      <script src="/static/dialog-component.js"></script>
    `;
    
    res.send(dialogHtml);
  });
}
// {/fact}

export {
  bad_case_1, bad_case_2, bad_case_3, bad_case_4, bad_case_5,
  bad_case_6, bad_case_7, bad_case_8, bad_case_9, bad_case_10,
  bad_case_11, bad_case_12, bad_case_13, bad_case_14, bad_case_15,
  good_case_1, good_case_2, good_case_3, good_case_4, good_case_5,
  good_case_6, good_case_7, good_case_8, good_case_9, good_case_10,
  good_case_11, good_case_12, good_case_13, good_case_14, good_case_15
};