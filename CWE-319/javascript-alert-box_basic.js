// This file contains test cases for detecting alert box vulnerabilities
// that could lead to XSS attacks

// True Positive Cases (Vulnerable Code)

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_1() {
  // Direct use of alert with user input from URL
  const urlParams = new URLSearchParams(window.location.search);
  const userInput = urlParams.get('message');
  
  // ruleid: javascript-alert-box
  alert(userInput);
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_2() {
  // Using alert in an event handler with user input
  document.getElementById('myButton').onclick = function() {
    const userInput = document.getElementById('userInput').value;
    
    // ruleid: javascript-alert-box
    alert(userInput);
  };
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_3() {
  // Using alert with concatenated user input from URL hash
  const userInput = window.location.hash.substring(1);
  
  // ruleid: javascript-alert-box
  alert("Welcome " + userInput + "!");
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_4() {
  // Using alert with template literals containing user input
  const urlParams = new URLSearchParams(window.location.search);
  const userName = urlParams.get('name');
  
  // ruleid: javascript-alert-box
  alert(`Hello ${userName}, welcome to our site!`);
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_5() {
  // Using alert with user input from cookies
  const cookies = document.cookie.split(';');
  let userPreference;
  
  for (let i = 0; i < cookies.length; i++) {
    const cookie = cookies[i].trim();
    if (cookie.startsWith('userPreference=')) {
      userPreference = cookie.substring('userPreference='.length);
      break;
    }
  }
  
  // ruleid: javascript-alert-box
  alert("Your preference is: " + userPreference);
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_6() {
  // Using alert with user input from localStorage
  const savedMessage = localStorage.getItem('userMessage');
  
  if (savedMessage) {
    // ruleid: javascript-alert-box
    alert(savedMessage);
  }
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_7() {
  // Using alert with user input from a form submission
  document.getElementById('myForm').onsubmit = function(event) {
    event.preventDefault();
    const formData = new FormData(event.target);
    const userComment = formData.get('comment');
    
    // ruleid: javascript-alert-box
    alert("Thank you for your comment: " + userComment);
  };
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_8() {
  // Using alert with user input from URL in an AJAX callback
  const xhr = new XMLHttpRequest();
  xhr.open('GET', '/api/user?id=' + window.location.search.substring(1), true);
  
  xhr.onload = function() {
    if (xhr.status === 200) {
      const response = JSON.parse(xhr.responseText);
      
      // ruleid: javascript-alert-box
      alert("Welcome back, " + response.name);
    }
  };
  
  xhr.send();
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_9() {
  // Using alert with user input from sessionStorage
  window.addEventListener('load', function() {
    const userTheme = sessionStorage.getItem('theme');
    
    // ruleid: javascript-alert-box
    alert("Your current theme is: " + userTheme);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_10() {
  // Using alert with user input from a custom event
  document.addEventListener('customUserEvent', function(e) {
    const userData = e.detail;
    
    // ruleid: javascript-alert-box
    alert("Event received for user: " + userData.username);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_11() {
  // Using alert with user input from URL fragment processed through a function
  function processInput(input) {
    return input.toUpperCase();
  }
  
  const userInput = window.location.hash.substring(1);
  const processedInput = processInput(userInput);
  
  // ruleid: javascript-alert-box
  alert(processedInput);
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_12() {
  // Using alert with user input from postMessage API
  window.addEventListener('message', function(event) {
    if (event.origin === 'https://trusted-source.com') {
      const messageData = event.data;
      
      // ruleid: javascript-alert-box
      alert("Message received: " + messageData.content);
    }
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_13() {
  // Using alert with user input from IndexedDB
  const request = indexedDB.open('userDatabase', 1);
  
  request.onsuccess = function(event) {
    const db = event.target.result;
    const transaction = db.transaction(['userPreferences'], 'readonly');
    const objectStore = transaction.objectStore('userPreferences');
    const getRequest = objectStore.get('displayName');
    
    getRequest.onsuccess = function() {
      const displayName = getRequest.result;
      
      // ruleid: javascript-alert-box
      alert("Welcome back, " + displayName);
    };
  };
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_14() {
  // Using alert with user input from WebSocket
  const socket = new WebSocket('wss://example.com/socket');
  
  socket.onmessage = function(event) {
    const message = JSON.parse(event.data);
    
    // ruleid: javascript-alert-box
    alert("New notification: " + message.notification);
  };
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_15() {
  // Using alert with user input from Fetch API
  fetch('/api/user/profile')
    .then(response => response.json())
    .then(data => {
      // ruleid: javascript-alert-box
      alert("Profile loaded for: " + data.username);
    });
}
// {/fact}

// True Negative Cases (Safe Code)

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_1() {
  // Using alert with hardcoded string
  // ok: javascript-alert-box
  alert("Welcome to our website!");
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_2() {
  // Using alert with sanitized user input
  const urlParams = new URLSearchParams(window.location.search);
  const userInput = urlParams.get('message');
  
  function sanitizeInput(input) {
    if (!input) return '';
    return input.replace(/[<>&"']/g, function(match) {
      switch (match) {
        case '<': return '&lt;';
        case '>': return '&gt;';
        case '&': return '&amp;';
        case '"': return '&quot;';
        case "'": return '&#x27;';
      }
    });
  }
  
  const sanitizedInput = sanitizeInput(userInput);
  
  // ok: javascript-alert-box
  alert("Your message: " + sanitizedInput);
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_3() {
  // Using custom modal instead of alert
  const urlParams = new URLSearchParams(window.location.search);
  const userInput = urlParams.get('message');
  
  // ok: javascript-alert-box
  showCustomModal("Message", userInput);
  
  function showCustomModal(title, content) {
    const modal = document.createElement('div');
    modal.className = 'custom-modal';
    
    const titleElement = document.createElement('h2');
    titleElement.textContent = title;
    
    const contentElement = document.createElement('p');
    contentElement.textContent = content; // Safe as textContent doesn't interpret HTML
    
    modal.appendChild(titleElement);
    modal.appendChild(contentElement);
    document.body.appendChild(modal);
  }
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_4() {
  // Using alert with numeric values only
  const urlParams = new URLSearchParams(window.location.search);
  const userAge = parseInt(urlParams.get('age'), 10);
  
  if (!isNaN(userAge)) {
    // ok: javascript-alert-box
    alert("Your age is: " + userAge);
  }
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_5() {
  // Using alert with validated input from a predefined list
  const urlParams = new URLSearchParams(window.location.search);
  const userColor = urlParams.get('color');
  
  const allowedColors = ['red', 'green', 'blue', 'yellow'];
  
  if (allowedColors.includes(userColor)) {
    // ok: javascript-alert-box
    alert("You selected: " + userColor);
  } else {
    // ok: javascript-alert-box
    alert("Invalid color selection");
  }
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_6() {
  // Using console.log instead of alert for user input
  const urlParams = new URLSearchParams(window.location.search);
  const userInput = urlParams.get('debug');
  
  // ok: javascript-alert-box
  console.log("Debug info:", userInput);
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_7() {
  // Using alert with server-validated data
  fetch('/api/validate-input?text=' + encodeURIComponent(document.getElementById('userInput').value))
    .then(response => response.json())
    .then(data => {
      if (data.isValid) {
        // ok: javascript-alert-box
        alert("Valid input: " + data.sanitizedText);
      }
    });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_8() {
  // Using alert with DOMPurify sanitized input
  const userInput = document.getElementById('commentField').value;
  
  // Assuming DOMPurify is properly imported
  const sanitizedInput = DOMPurify.sanitize(userInput, {RETURN_DOM_FRAGMENT: false, RETURN_DOM: false});
  
  // ok: javascript-alert-box
  alert("Your comment: " + sanitizedInput);
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_9() {
  // Using alert with input limited to specific pattern
  const userInput = document.getElementById('zipCode').value;
  const zipRegex = /^\d{5}(-\d{4})?$/;
  
  if (zipRegex.test(userInput)) {
    // ok: javascript-alert-box
    alert("Zip code validated: " + userInput);
  } else {
    // ok: javascript-alert-box
    alert("Invalid zip code format");
  }
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_10() {
  // Using alert with boolean result of operation
  const urlParams = new URLSearchParams(window.location.search);
  const isSubscribed = urlParams.get('subscribed') === 'true';
  
  // ok: javascript-alert-box
  alert("Subscription status: " + (isSubscribed ? "Active" : "Inactive"));
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_11() {
  // Using custom notification system instead of alert
  const urlParams = new URLSearchParams(window.location.search);
  const message = urlParams.get('notification');
  
  // ok: javascript-alert-box
  showNotification({
    title: "System Message",
    message: message,
    type: "info"
  });
  
  function showNotification(config) {
    const notificationElement = document.createElement('div');
    notificationElement.className = 'notification ' + config.type;
    
    const titleElement = document.createElement('h3');
    titleElement.textContent = config.title;
    
    const messageElement = document.createElement('p');
    messageElement.textContent = config.message;
    
    notificationElement.appendChild(titleElement);
    notificationElement.appendChild(messageElement);
    
    document.getElementById('notificationArea').appendChild(notificationElement);
    
    setTimeout(() => {
      notificationElement.remove();
    }, 5000);
  }
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_12() {
  // Using alert with data that's been validated on the server side
  const sessionToken = localStorage.getItem('sessionToken');
  
  fetch('/api/user-profile', {
    headers: {
      'Authorization': 'Bearer ' + sessionToken
    }
  })
  .then(response => response.json())
  .then(data => {
    // This data is from a trusted source (our server)
    // ok: javascript-alert-box
    alert("Welcome back, " + data.displayName);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_13() {
  // Using alert with constant values selected from a map
  const urlParams = new URLSearchParams(window.location.search);
  const statusCode = urlParams.get('status');
  
  const statusMessages = {
    '200': 'Success',
    '404': 'Not Found',
    '500': 'Server Error'
  };
  
  const statusMessage = statusMessages[statusCode] || 'Unknown Status';
  
  // ok: javascript-alert-box
  alert("Operation result: " + statusMessage);
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_14() {
  // Using alert with calculated values
  const value1 = parseFloat(document.getElementById('value1').value);
  const value2 = parseFloat(document.getElementById('value2').value);
  
  if (!isNaN(value1) && !isNaN(value2)) {
    const sum = value1 + value2;
    
    // ok: javascript-alert-box
    alert("The sum is: " + sum);
  }
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_15() {
  // Using alert with timestamp
  document.getElementById('saveButton').addEventListener('click', function() {
    const now = new Date();
    const timestamp = now.toLocaleTimeString();
    
    // Save operation happens here
    
    // ok: javascript-alert-box
    alert("Data saved at " + timestamp);
  });
}
// {/fact}