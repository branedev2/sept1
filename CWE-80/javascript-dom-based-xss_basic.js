// DOM-based XSS Test Cases
// Rule ID: javascript-dom-based-xss

// True Positives (Vulnerable Code)

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_1() {
  // Get user input from URL parameter
  const urlParams = new URLSearchParams(window.location.search);
  const userInput = urlParams.get('name');
  
  // Vulnerable: Directly using innerHTML with user input
  const element = document.getElementById('greeting');
  // ruleid: javascript-dom-based-xss
  element.innerHTML = '<h1>Hello, ' + userInput + '!</h1>';
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_2() {
  // Get user input from hash fragment
  const hashValue = window.location.hash.substring(1);
  
  // Vulnerable: Using document.write with user input
  // ruleid: javascript-dom-based-xss
  document.write('<div class="user-content">' + hashValue + '</div>');
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_3() {
  // Get user input from localStorage (which could have been set by malicious script)
  const storedData = localStorage.getItem('userProfile');
  
  // Vulnerable: Using outerHTML with potentially unsafe data
  const profileSection = document.querySelector('.profile');
  // ruleid: javascript-dom-based-xss
  profileSection.outerHTML = '<section class="profile">' + storedData + '</section>';
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_4() {
  // Get user input from a cookie
  const username = document.cookie.split(';').find(cookie => cookie.trim().startsWith('username='));
  const userValue = username ? username.split('=')[1] : '';
  
  // Vulnerable: Using document.writeln with user input
  // ruleid: javascript-dom-based-xss
  document.writeln('<p>Welcome back, ' + userValue + '</p>');
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_5() {
  // Get user input from referrer
  const referrer = document.referrer;
  
  // Vulnerable: Using innerHTML with referrer data
  const refElement = document.getElementById('referrer-info');
  // ruleid: javascript-dom-based-xss
  refElement.innerHTML = 'You came from: ' + referrer;
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_6() {
  // Get user input from URL search params
  const urlParams = new URLSearchParams(window.location.search);
  const query = urlParams.get('q');
  
  // Vulnerable: Using innerHTML in a template literal
  const searchResults = document.getElementById('search-results');
  // ruleid: javascript-dom-based-xss
  searchResults.innerHTML = `<div class="results-header">Results for: ${query}</div>`;
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_7() {
  // Get user input from sessionStorage
  const savedComment = sessionStorage.getItem('pendingComment');
  
  // Vulnerable: Using innerHTML with a conditional
  const commentSection = document.getElementById('comments');
  if (savedComment && savedComment.length > 0) {
    // ruleid: javascript-dom-based-xss
    commentSection.innerHTML = '<div class="comment">' + savedComment + '</div>';
  }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_8() {
  // Get user input from URL fragment and decode it
  const fragment = decodeURIComponent(window.location.hash.substring(1));
  
  // Vulnerable: Using document.write with processed input
  if (fragment.startsWith('view=')) {
    const viewName = fragment.substring(5);
    // ruleid: javascript-dom-based-xss
    document.write('<h2>Current View: ' + viewName + '</h2>');
  }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_9() {
  // Get user input from POST message event
  window.addEventListener('message', function(event) {
    // Vulnerable: Using innerHTML with message data
    const messageContainer = document.getElementById('message-display');
    // ruleid: javascript-dom-based-xss
    messageContainer.innerHTML = '<div class="message">' + event.data + '</div>';
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_10() {
  // Get user input from IndexedDB
  const dbRequest = indexedDB.open('userNotes', 1);
  
  dbRequest.onsuccess = function(event) {
    const db = event.target.result;
    const transaction = db.transaction(['notes'], 'readonly');
    const objectStore = transaction.objectStore('notes');
    const request = objectStore.get(1);
    
    request.onsuccess = function(event) {
      if (request.result) {
        const noteContent = request.result.content;
        const noteElement = document.getElementById('note-display');
        // ruleid: javascript-dom-based-xss
        noteElement.innerHTML = noteContent;
      }
    };
  };
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_11() {
  // Get user input from WebSocket
  const socket = new WebSocket('wss://example.com/socket');
  
  socket.onmessage = function(event) {
    const message = JSON.parse(event.data);
    const chatWindow = document.getElementById('chat-window');
    // ruleid: javascript-dom-based-xss
    chatWindow.innerHTML += '<div class="message">' + message.text + '</div>';
  };
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_12() {
  // Get user input from form field
  document.getElementById('comment-form').addEventListener('submit', function(event) {
    event.preventDefault();
    const commentInput = document.getElementById('comment-input').value;
    
    // Vulnerable: Using innerHTML to display form input
    const commentsSection = document.getElementById('comments-section');
    // ruleid: javascript-dom-based-xss
    commentsSection.innerHTML += '<div class="comment">' + commentInput + '</div>';
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_13() {
  // Get user input from URL and process it
  const urlParams = new URLSearchParams(window.location.search);
  const theme = urlParams.get('theme') || 'default';
  const username = urlParams.get('user') || 'Guest';
  
  // Vulnerable: Using innerHTML with multiple inputs
  const header = document.querySelector('header');
  // ruleid: javascript-dom-based-xss
  header.innerHTML = `<div class="theme-${theme}">Welcome, ${username}!</div>`;
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_14() {
  // Get user input from drag and drop
  document.getElementById('drop-zone').addEventListener('drop', function(event) {
    event.preventDefault();
    
    const data = event.dataTransfer.getData('text/html');
    const dropTarget = document.getElementById('preview-area');
    
    // Vulnerable: Using innerHTML with drag and drop data
    // ruleid: javascript-dom-based-xss
    dropTarget.innerHTML = data;
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_15() {
  // Get user input from a custom data attribute
  const productElements = document.querySelectorAll('.product');
  
  productElements.forEach(element => {
    element.addEventListener('click', function() {
      const productDescription = this.getAttribute('data-description');
      const detailsPanel = document.getElementById('product-details');
      
      // Vulnerable: Using innerHTML with attribute data
      // ruleid: javascript-dom-based-xss
      detailsPanel.innerHTML = '<div class="description">' + productDescription + '</div>';
    });
  });
}
// {/fact}

// True Negatives (Safe Code)

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_1() {
  // Get user input from URL parameter
  const urlParams = new URLSearchParams(window.location.search);
  const userInput = urlParams.get('name');
  
  // Safe: Using textContent instead of innerHTML
  const element = document.getElementById('greeting');
  // ok: javascript-dom-based-xss
  element.textContent = 'Hello, ' + userInput + '!';
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_2() {
  // Get user input from hash fragment
  const hashValue = window.location.hash.substring(1);
  
  // Safe: Creating text node instead of using document.write
  const div = document.createElement('div');
  div.className = 'user-content';
  // ok: javascript-dom-based-xss
  div.textContent = hashValue;
  document.body.appendChild(div);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_3() {
  // Get user input from localStorage
  const storedData = localStorage.getItem('userProfile');
  
  // Safe: Using innerText and proper DOM manipulation
  const profileSection = document.querySelector('.profile');
  // ok: javascript-dom-based-xss
  profileSection.innerText = storedData;
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_4() {
  // Get user input from a cookie
  const username = document.cookie.split(';').find(cookie => cookie.trim().startsWith('username='));
  const userValue = username ? username.split('=')[1] : '';
  
  // Safe: Creating elements properly
  const paragraph = document.createElement('p');
  // ok: javascript-dom-based-xss
  paragraph.textContent = 'Welcome back, ' + userValue;
  document.body.appendChild(paragraph);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_5() {
  // Get user input from referrer
  const referrer = document.referrer;
  
  // Safe: Using DOMPurify to sanitize HTML
  const refElement = document.getElementById('referrer-info');
  // ok: javascript-dom-based-xss
  refElement.textContent = 'You came from: ' + referrer;
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_6() {
  // Get user input from URL search params
  const urlParams = new URLSearchParams(window.location.search);
  const query = urlParams.get('q');
  
  // Safe: Creating elements properly with textContent
  const searchResults = document.getElementById('search-results');
  const header = document.createElement('div');
  header.className = 'results-header';
  // ok: javascript-dom-based-xss
  header.textContent = 'Results for: ' + query;
  searchResults.appendChild(header);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_7() {
  // Get user input from sessionStorage
  const savedComment = sessionStorage.getItem('pendingComment');
  
  // Safe: Using proper DOM creation
  const commentSection = document.getElementById('comments');
  if (savedComment && savedComment.length > 0) {
    const commentDiv = document.createElement('div');
    commentDiv.className = 'comment';
    // ok: javascript-dom-based-xss
    commentDiv.textContent = savedComment;
    commentSection.appendChild(commentDiv);
  }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_8() {
  // Get user input from URL fragment and decode it
  const fragment = decodeURIComponent(window.location.hash.substring(1));
  
  // Safe: Using proper DOM creation instead of document.write
  if (fragment.startsWith('view=')) {
    const viewName = fragment.substring(5);
    const heading = document.createElement('h2');
    // ok: javascript-dom-based-xss
    heading.textContent = 'Current View: ' + viewName;
    document.body.appendChild(heading);
  }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_9() {
  // Get user input from POST message event
  window.addEventListener('message', function(event) {
    // Safe: Using textContent with message data
    const messageContainer = document.getElementById('message-display');
    const messageDiv = document.createElement('div');
    messageDiv.className = 'message';
    // ok: javascript-dom-based-xss
    messageDiv.textContent = event.data;
    messageContainer.appendChild(messageDiv);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_10() {
  // Get user input from IndexedDB
  const dbRequest = indexedDB.open('userNotes', 1);
  
  dbRequest.onsuccess = function(event) {
    const db = event.target.result;
    const transaction = db.transaction(['notes'], 'readonly');
    const objectStore = transaction.objectStore('notes');
    const request = objectStore.get(1);
    
    request.onsuccess = function(event) {
      if (request.result) {
        const noteContent = request.result.content;
        const noteElement = document.getElementById('note-display');
        // ok: javascript-dom-based-xss
        noteElement.textContent = noteContent;
      }
    };
  };
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_11() {
  // Get user input from WebSocket
  const socket = new WebSocket('wss://example.com/socket');
  
  socket.onmessage = function(event) {
    const message = JSON.parse(event.data);
    const chatWindow = document.getElementById('chat-window');
    
    const messageDiv = document.createElement('div');
    messageDiv.className = 'message';
    // ok: javascript-dom-based-xss
    messageDiv.textContent = message.text;
    chatWindow.appendChild(messageDiv);
  };
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_12() {
  // Get user input from form field
  document.getElementById('comment-form').addEventListener('submit', function(event) {
    event.preventDefault();
    const commentInput = document.getElementById('comment-input').value;
    
    // Safe: Using proper DOM creation
    const commentsSection = document.getElementById('comments-section');
    const commentDiv = document.createElement('div');
    commentDiv.className = 'comment';
    // ok: javascript-dom-based-xss
    commentDiv.textContent = commentInput;
    commentsSection.appendChild(commentDiv);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_13() {
  // Get user input from URL and process it
  const urlParams = new URLSearchParams(window.location.search);
  const theme = urlParams.get('theme') || 'default';
  const username = urlParams.get('user') || 'Guest';
  
  // Safe: Using proper DOM creation with multiple inputs
  const header = document.querySelector('header');
  const welcomeDiv = document.createElement('div');
  welcomeDiv.className = `theme-${theme.replace(/[^a-zA-Z0-9-_]/g, '')}`;  // Sanitize class name
  // ok: javascript-dom-based-xss
  welcomeDiv.textContent = `Welcome, ${username}!`;
  header.appendChild(welcomeDiv);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_14() {
  // Get user input from drag and drop
  document.getElementById('drop-zone').addEventListener('drop', function(event) {
    event.preventDefault();
    
    const data = event.dataTransfer.getData('text/plain');  // Get as plain text instead of HTML
    const dropTarget = document.getElementById('preview-area');
    
    // Safe: Using textContent with drag and drop data
    // ok: javascript-dom-based-xss
    dropTarget.textContent = data;
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_15() {
  // Get user input from a custom data attribute
  const productElements = document.querySelectorAll('.product');
  
  productElements.forEach(element => {
    element.addEventListener('click', function() {
      const productDescription = this.getAttribute('data-description');
      const detailsPanel = document.getElementById('product-details');
      
      // Safe: Using proper DOM creation
      const descDiv = document.createElement('div');
      descDiv.className = 'description';
      // ok: javascript-dom-based-xss
      descDiv.textContent = productDescription;
      
      // Clear previous content and add new content
      detailsPanel.innerHTML = '';  // Safe because we're not inserting user input
      detailsPanel.appendChild(descDiv);
    });
  });
}
// {/fact}