// True Positive Examples (Vulnerable Code)

// Example 1: Simple direct assignment
// {fact rule=deprecated-method@v1.0 defects=1}
function bad_case_1() {
  // ruleid: javascript-document-domain
  document.domain = "example.com";
  
  // Rest of the function that relies on relaxed same-origin policy
  const iframe = document.getElementById("myframe");
  const iframeDoc = iframe.contentDocument;
  iframeDoc.body.innerHTML = "Modified from parent";
}
// {/fact}

// Example 2: Assignment within a function
// {fact rule=deprecated-method@v1.0 defects=1}
function bad_case_2() {
  function setupCrossDomainAccess() {
    // ruleid: javascript-document-domain
    document.domain = "example.org";
  }
  
  setupCrossDomainAccess();
  // Access iframe content from subdomain
  const frameContent = document.getElementById("subdomain-frame").contentWindow.document;
}
// {/fact}

// Example 3: Conditional assignment
// {fact rule=deprecated-method@v1.0 defects=1}
function bad_case_3() {
  const currentHost = window.location.hostname;
  
  if (currentHost.indexOf("example.com") !== -1) {
    // ruleid: javascript-document-domain
    document.domain = "example.com";
  }
  
  // Try to access iframe content
  try {
    const frameData = frames[0].document.getElementById("data").textContent;
    processData(frameData);
  } catch (e) {
    console.error("Cannot access frame data:", e);
  }
}
// {/fact}

// Example 4: Using with event listener
// {fact rule=deprecated-method@v1.0 defects=1}
function bad_case_4() {
  document.getElementById("enable-cross-domain").addEventListener("click", function() {
    // ruleid: javascript-document-domain
    document.domain = "company.net";
    alert("Cross-domain access enabled");
  });
  
  // Later in code, access iframe content
  function accessIframeContent() {
    return document.getElementById("subdomain-iframe").contentDocument.querySelector(".data").textContent;
  }
}
// {/fact}

// Example 5: Using in IIFE
// {fact rule=deprecated-method@v1.0 defects=1}
function bad_case_5() {
  (function() {
    // ruleid: javascript-document-domain
    document.domain = "myapp.io";
    
    // Setup cross-domain messaging
    window.addEventListener("message", function(event) {
      if (event.origin.endsWith("myapp.io")) {
        processMessage(event.data);
      }
    });
  })();
}
// {/fact}

// Example 6: Using with setTimeout
// {fact rule=deprecated-method@v1.0 defects=1}
function bad_case_6() {
  setTimeout(function() {
    // ruleid: javascript-document-domain
    document.domain = "webapp.com";
    console.log("Domain relaxed after timeout");
  }, 2000);
  
  // Later attempt to access iframe content
  function getIframeData() {
    try {
      return document.getElementById("cross-domain-frame").contentDocument.body.innerHTML;
    } catch (e) {
      return "Cannot access yet";
    }
  }
}
// {/fact}

// Example 7: Using with Promise
// {fact rule=deprecated-method@v1.0 defects=1}
function bad_case_7() {
  const domainSetupPromise = new Promise((resolve) => {
    // ruleid: javascript-document-domain
    document.domain = "service.app";
    resolve("Domain setup complete");
  });
  
  domainSetupPromise.then(message => {
    console.log(message);
    // Now try to access the iframe
    const iframeWindow = document.getElementById("api-frame").contentWindow;
    iframeWindow.postMessage("Ready", "*");
  });
}
// {/fact}

// Example 8: Using with try-catch
// {fact rule=deprecated-method@v1.0 defects=1}
function bad_case_8() {
  try {
    // ruleid: javascript-document-domain
    document.domain = "shared-domain.com";
    console.log("Domain relaxed successfully");
  } catch (error) {
    console.error("Failed to relax domain:", error);
  }
  
  // Attempt cross-frame access
  function accessFrameData() {
    const frame = window.frames[0];
    return frame.document.getElementById("shared-data").value;
  }
}
// {/fact}

// Example 9: Using with object destructuring
// {fact rule=deprecated-method@v1.0 defects=1}
function bad_case_9() {
  const config = {
    domain: "platform.app",
    allowSubdomains: true,
    timeout: 1000
  };
  
  const { domain } = config;
  
  if (config.allowSubdomains) {
    // ruleid: javascript-document-domain
    document.domain = domain;
  }
  
  // Later in code
  function shareDataWithParent() {
    window.parent.updateData(document.getElementById("local-data").value);
  }
}
// {/fact}

// Example 10: Using with template literals
// {fact rule=deprecated-method@v1.0 defects=1}
function bad_case_10() {
  const baseDomain = "secure";
  const tld = "net";
  
  // ruleid: javascript-document-domain
  document.domain = `${baseDomain}.${tld}`;
  
  // Setup cross-domain functionality
  window.addEventListener("load", function() {
    const parentData = window.parent.document.getElementById("parent-data");
    if (parentData) {
      document.getElementById("local-display").textContent = parentData.value;
    }
  });
}
// {/fact}

// Example 11: Using in a class method
// {fact rule=deprecated-method@v1.0 defects=1}
function bad_case_11() {
  class CrossDomainHelper {
    constructor(domain) {
      this.domain = domain;
    }
    
    enableCrossDomainAccess() {
      // ruleid: javascript-document-domain
      document.domain = this.domain;
      return true;
    }
    
    accessFrameContent(frameId) {
      return document.getElementById(frameId).contentDocument.body.innerHTML;
    }
  }
  
  const helper = new CrossDomainHelper("app-domain.com");
  helper.enableCrossDomainAccess();
  const content = helper.accessFrameContent("data-frame");
}
// {/fact}

// Example 12: Using with arrow function
// {fact rule=deprecated-method@v1.0 defects=1}
function bad_case_12() {
  const setupDomain = (domainName) => {
    // ruleid: javascript-document-domain
    document.domain = domainName;
    console.log(`Domain set to ${domainName}`);
  };
  
  setupDomain("shared-site.org");
  
  // Later in code
  const getFrameData = () => {
    const frame = document.querySelector("iframe").contentWindow;
    return frame.document.querySelector(".data-container").textContent;
  };
}
// {/fact}

// Example 13: Using with dynamic domain calculation
// {fact rule=deprecated-method@v1.0 defects=1}
function bad_case_13() {
  const hostname = window.location.hostname;
  const parts = hostname.split(".");
  
  if (parts.length > 2) {
    const baseDomain = parts.slice(-2).join(".");
    // ruleid: javascript-document-domain
    document.domain = baseDomain;
    
    // Now try to access parent frame
    try {
      const parentData = window.parent.document.getElementById("shared-config").textContent;
      initializeWithConfig(JSON.parse(parentData));
    } catch (e) {
      console.error("Failed to access parent frame:", e);
    }
  }
}
// {/fact}

// Example 14: Using with async/await
// {fact rule=deprecated-method@v1.0 defects=1}
function bad_case_14() {
  async function setupCrossDomainAccess() {
    // Simulate some async operation
    await new Promise(resolve => setTimeout(resolve, 100));
    
    // ruleid: javascript-document-domain
    document.domain = "multi-app.com";
    
    return "Cross-domain access enabled";
  }
  
  async function initializeApp() {
    const status = await setupCrossDomainAccess();
    console.log(status);
    
    // Now try to access iframe content
    const iframeDoc = document.getElementById("service-frame").contentDocument;
    const serviceData = iframeDoc.getElementById("api-data").textContent;
    processServiceData(serviceData);
  }
  
  initializeApp().catch(console.error);
}
// {/fact}

// Example 15: Using with ternary operator
// {fact rule=deprecated-method@v1.0 defects=1}
function bad_case_15() {
  const isProduction = window.location.hostname.includes("prod");
  
  // ruleid: javascript-document-domain
  document.domain = isProduction ? "product.com" : "product-staging.com";
  
  // Setup cross-domain communication
  function sendToParent(data) {
    try {
      window.parent.receiveData(data);
      return true;
    } catch (e) {
      console.error("Failed to send data to parent:", e);
      return false;
    }
  }
  
  document.getElementById("send-btn").addEventListener("click", function() {
    const result = sendToParent({ message: "Hello from iframe" });
    console.log("Send result:", result);
  });
}
// {/fact}

// True Negative Examples (Safe Code)

// Example 1: Using postMessage for cross-origin communication
// {fact rule=deprecated-method@v1.0 defects=0}
function good_case_1() {
  // ok: javascript-document-domain
  const iframe = document.getElementById("external-frame");
  iframe.contentWindow.postMessage({
    type: "request-data",
    id: "user-profile"
  }, "https://trusted-domain.com");
  
  window.addEventListener("message", function(event) {
    if (event.origin === "https://trusted-domain.com") {
      processData(event.data);
    }
  });
}
// {/fact}

// Example 2: Using CORS for API requests
// {fact rule=deprecated-method@v1.0 defects=0}
function good_case_2() {
  // ok: javascript-document-domain
  fetch("https://api.example.com/data", {
    method: "GET",
    credentials: "include",
    headers: {
      "Content-Type": "application/json"
    }
  })
  .then(response => response.json())
  .then(data => {
    document.getElementById("result").textContent = data.message;
  })
  .catch(error => console.error("Error fetching data:", error));
}
// {/fact}

// Example 3: Using iframe sandbox attribute
// {fact rule=deprecated-method@v1.0 defects=0}
function good_case_3() {
  // ok: javascript-document-domain
  const iframe = document.createElement("iframe");
  iframe.src = "https://external-service.com/widget";
  iframe.sandbox = "allow-scripts allow-same-origin";
  document.getElementById("widget-container").appendChild(iframe);
  
  // Listen for messages from the sandboxed iframe
  window.addEventListener("message", function(event) {
    if (event.origin === "https://external-service.com") {
      updateWidgetData(event.data);
    }
  });
}
// {/fact}

// Example 4: Using Content Security Policy
// {fact rule=deprecated-method@v1.0 defects=0}
function good_case_4() {
  // ok: javascript-document-domain
  const meta = document.createElement("meta");
  meta.httpEquiv = "Content-Security-Policy";
  meta.content = "default-src 'self'; frame-src https://trusted-frames.com";
  document.head.appendChild(meta);
  
  // Load iframe from allowed domain
  const iframe = document.createElement("iframe");
  iframe.src = "https://trusted-frames.com/widget";
  document.getElementById("frame-container").appendChild(iframe);
}
// {/fact}

// Example 5: Using window.open with specific features
// {fact rule=deprecated-method@v1.0 defects=0}
function good_case_5() {
  // ok: javascript-document-domain
  document.getElementById("open-popup").addEventListener("click", function() {
    const popup = window.open("https://related-service.com/auth", 
                             "auth_popup",
                             "width=600,height=400,resizable=yes");
    
    // Listen for messages from popup
    window.addEventListener("message", function(event) {
      if (event.origin === "https://related-service.com" && event.source === popup) {
        handleAuthResponse(event.data);
        popup.close();
      }
    });
  });
}
// {/fact}

// Example 6: Using Web Workers for isolated execution
// {fact rule=deprecated-method@v1.0 defects=0}
function good_case_6() {
  // ok: javascript-document-domain
  const worker = new Worker("data-processor.js");
  
  worker.onmessage = function(event) {
    document.getElementById("result").textContent = event.data.result;
  };
  
  document.getElementById("process-btn").addEventListener("click", function() {
    const data = document.getElementById("input-data").value;
    worker.postMessage({ action: "process", data: data });
  });
}
// {/fact}

// Example 7: Using Blob URLs for dynamic content
// {fact rule=deprecated-method@v1.0 defects=0}
function good_case_7() {
  // ok: javascript-document-domain
  const htmlContent = `
    <!DOCTYPE html>
    <html>
      <head><title>Dynamic Content</title></head>
      <body>
        <h1>Generated Content</h1>
        <div id="content">${generateSafeContent()}</div>
      </body>
    </html>
  `;
  
  const blob = new Blob([htmlContent], { type: "text/html" });
  const url = URL.createObjectURL(blob);
  
  const iframe = document.getElementById("content-frame");
  iframe.src = url;
  
  // Clean up when done
  iframe.onload = function() {
    setTimeout(() => URL.revokeObjectURL(url), 100);
  };
}
// {/fact}

// Example 8: Using fetch with mode: 'cors'
// {fact rule=deprecated-method@v1.0 defects=0}
function good_case_8() {
  // ok: javascript-document-domain
  fetch("https://api.external-service.com/data", {
    method: "GET",
    mode: "cors",
    headers: {
      "Authorization": `Bearer ${getAuthToken()}`
    }
  })
  .then(response => {
    if (!response.ok) {
      throw new Error(`HTTP error! Status: ${response.status}`);
    }
    return response.json();
  })
  .then(data => displayData(data))
  .catch(error => console.error("Fetch error:", error));
}
// {/fact}

// Example 9: Using window.parent safely with origin check
// {fact rule=deprecated-method@v1.0 defects=0}
function good_case_9() {
  // ok: javascript-document-domain
  function sendToParent(data) {
    // Check if we're in an iframe
    if (window.parent !== window) {
      // Send message to parent with origin specified
      window.parent.postMessage({
        type: "widget-data",
        payload: data
      }, "https://parent-domain.com");
    }
  }
  
  document.getElementById("submit-btn").addEventListener("click", function() {
    const formData = collectFormData();
    sendToParent(formData);
  });
}
// {/fact}

// Example 10: Using SharedArrayBuffer with proper isolation
// {fact rule=deprecated-method@v1.0 defects=0}
function good_case_10() {
  // ok: javascript-document-domain
  if (window.crossOriginIsolated) {
    const worker = new Worker("processor.js");
    
    // Create a shared buffer for fast communication
    const sharedBuffer = new SharedArrayBuffer(1024);
    const sharedArray = new Uint8Array(sharedBuffer);
    
    worker.postMessage({ buffer: sharedBuffer });
    
    // Monitor the shared array for results
    function checkResults() {
      if (Atomics.load(sharedArray, 0) === 1) {
        const result = extractResultFromBuffer(sharedArray);
        displayResult(result);
        return;
      }
      setTimeout(checkResults, 50);
    }
    
    checkResults();
  } else {
    console.error("Cross-origin isolation not enabled");
  }
}
// {/fact}

// Example 11: Using a service worker for cross-origin requests
// {fact rule=deprecated-method@v1.0 defects=0}
function good_case_11() {
  // ok: javascript-document-domain
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/service-worker.js')
      .then(registration => {
        console.log('Service Worker registered with scope:', registration.scope);
      })
      .catch(error => {
        console.error('Service Worker registration failed:', error);
      });
      
    // Send message to service worker to fetch cross-origin data
    navigator.serviceWorker.ready.then(registration => {
      navigator.serviceWorker.controller.postMessage({
        type: 'fetch-external',
        url: 'https://api.external-service.com/data'
      });
    });
    
    // Listen for response from service worker
    navigator.serviceWorker.addEventListener('message', event => {
      if (event.data.type === 'external-data') {
        displayData(event.data.payload);
      }
    });
  }
}
// {/fact}

// Example 12: Using iframe with srcdoc for controlled content
// {fact rule=deprecated-method@v1.0 defects=0}
function good_case_12() {
  // ok: javascript-document-domain
  const safeContent = createSanitizedHTML(userProvidedContent);
  
  const iframe = document.createElement('iframe');
  iframe.srcdoc = `
    <!DOCTYPE html>
    <html>
      <head>
        <style>
          body { font-family: sans-serif; margin: 0; padding: 10px; }
        </style>
      </head>
      <body>${safeContent}</body>
    </html>
  `;
  
  iframe.sandbox = 'allow-scripts';
  document.getElementById('content-container').appendChild(iframe);
}
// {/fact}

// Example 13: Using Cross-Origin Resource Policy header
// {fact rule=deprecated-method@v1.0 defects=0}
function good_case_13() {
  // ok: javascript-document-domain
  // This function sets up a fetch request with proper CORP awareness
  async function fetchWithCORP(url) {
    try {
      const response = await fetch(url, {
        method: 'GET',
        mode: 'cors',
        credentials: 'same-origin',
        headers: {
          'Cross-Origin-Resource-Policy': 'same-site'
        }
      });
      
      if (!response.ok) {
        throw new Error(`HTTP error! Status: ${response.status}`);
      }
      
      return await response.json();
    } catch (error) {
      console.error('Error fetching resource:', error);
      return null;
    }
  }
  
  // Use the function to fetch data
  fetchWithCORP('https://api.same-site-service.com/data')
    .then(data => {
      if (data) {
        updateDashboard(data);
      }
    });
}
// {/fact}

// Example 14: Using window.location instead of document.domain
// {fact rule=deprecated-method@v1.0 defects=0}
function good_case_14() {
  // ok: javascript-document-domain
  document.getElementById('switch-domain').addEventListener('click', function() {
    // Instead of modifying document.domain, redirect to the other domain
    const currentHost = window.location.hostname;
    
    if (currentHost === 'app.example.com') {
      window.location.href = 'https://admin.example.com/dashboard?from=app';
    } else {
      window.location.href = 'https://app.example.com/home?from=admin';
    }
  });
}
// {/fact}

// Example 15: Using cross-origin communication with Channel Messaging API
// {fact rule=deprecated-method@v1.0 defects=0}
function good_case_15() {
  // ok: javascript-document-domain
  // Create a message channel
  const channel = new MessageChannel();
  
  // Get reference to iframe
  const iframe = document.getElementById('partner-iframe');
  
  // Listen for messages on port1
  channel.port1.onmessage = function(event) {
    // Process the secure message from iframe
    const message = event.data;
    console.log('Received message:', message);
    document.getElementById('response-container').textContent = 
      `Received: ${message.text}`;
  };
  
  // Send the port to the iframe once it's loaded
  iframe.addEventListener('load', function() {
    // Transfer port2 to the iframe
    iframe.contentWindow.postMessage('init', 
      'https://trusted-partner.com', 
      [channel.port2]);
  });
}
// {/fact}