// JavaScript DOM-based Open Redirection Examples

// True Positives (Vulnerable Code)

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_1() {
  // Using location.search (query parameters) directly for redirection
  const urlParams = new URLSearchParams(location.search);
  const redirectUrl = urlParams.get('redirect');
  
  // ruleid: javascript-dom-based-open-redirection
  window.location.href = redirectUrl;
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_2() {
  // Using location.hash (URL fragment) directly for redirection
  const hash = location.hash.substring(1); // Remove the # character
  
  // ruleid: javascript-dom-based-open-redirection
  window.location = hash;
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_3() {
  // Using prompt() user input directly for redirection
  const userInput = prompt("Enter the URL you want to visit:");
  
  // ruleid: javascript-dom-based-open-redirection
  document.location = userInput;
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_4() {
  // Using jQuery val() from a form input for redirection
  $("#redirectButton").click(function() {
    const redirectUrl = $("#urlInput").val();
    
    // ruleid: javascript-dom-based-open-redirection
    window.location.replace(redirectUrl);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_5() {
  // Using data from an AJAX request for redirection
  $.ajax({
    url: "/get-redirect-url",
    success: function(data) {
      // ruleid: javascript-dom-based-open-redirection
      window.location.assign(data.url);
    }
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_6() {
  // Using URL parameters with template literals
  const params = new URLSearchParams(window.location.search);
  const nextPage = params.get('next');
  
  // ruleid: javascript-dom-based-open-redirection
  window.location.href = `${nextPage}?source=homepage`;
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_7() {
  // Using sessionStorage that could be set by other scripts
  const savedRedirect = sessionStorage.getItem('redirectAfterLogin');
  
  // ruleid: javascript-dom-based-open-redirection
  location.href = savedRedirect;
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_8() {
  // Using data from postMessage for redirection
  window.addEventListener('message', function(event) {
    if (event.origin === 'https://trusted-source.com') {
      // ruleid: javascript-dom-based-open-redirection
      window.location = event.data.redirectUrl;
    }
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_9() {
  // Using URL parameters with string concatenation
  const urlParams = new URLSearchParams(location.search);
  const redirectPath = urlParams.get('path') || '';
  
  // ruleid: javascript-dom-based-open-redirection
  window.location.href = 'https://example.com/' + redirectPath;
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_10() {
  // Using fetch API and redirecting based on response
  fetch('/api/get-redirect')
    .then(response => response.json())
    .then(data => {
      // ruleid: javascript-dom-based-open-redirection
      window.location = data.redirectUrl;
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_11() {
  // Using localStorage that could be manipulated
  document.getElementById('loginButton').addEventListener('click', function() {
    const redirectUrl = localStorage.getItem('lastVisitedPage');
    
    // ruleid: javascript-dom-based-open-redirection
    window.location.replace(redirectUrl);
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_12() {
  // Using URL parameters with conditional logic but still vulnerable
  const params = new URLSearchParams(window.location.search);
  let destination = params.get('to');
  
  if (!destination) {
    destination = '/default';
  }
  
  // ruleid: javascript-dom-based-open-redirection
  window.location = destination;
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_13() {
  // Using document.referrer for redirection
  const referrer = document.referrer;
  
  // ruleid: javascript-dom-based-open-redirection
  window.location.href = referrer;
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_14() {
  // Using multiple sources combined
  const urlParams = new URLSearchParams(location.search);
  const baseUrl = urlParams.get('domain') || 'example.com';
  const path = localStorage.getItem('lastPath') || '/home';
  
  // ruleid: javascript-dom-based-open-redirection
  window.location = `https://${baseUrl}${path}`;
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_15() {
  // Using data attributes from DOM elements that could be manipulated
  document.querySelectorAll('[data-redirect]').forEach(element => {
    element.addEventListener('click', function(e) {
      e.preventDefault();
      const redirectUrl = this.getAttribute('data-redirect');
      
      // ruleid: javascript-dom-based-open-redirection
      window.location.href = redirectUrl;
    });
  });
}
// {/fact}

// True Negatives (Safe Code)

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_1() {
  // Using a whitelist of allowed redirect URLs
  const urlParams = new URLSearchParams(location.search);
  const redirectUrl = urlParams.get('redirect');
  
  const allowedDomains = ['example.com', 'subdomain.example.com', 'trusted-site.org'];
  
  try {
    const urlObj = new URL(redirectUrl);
    // ok: javascript-dom-based-open-redirection
    if (allowedDomains.includes(urlObj.hostname)) {
      window.location.href = redirectUrl;
    } else {
      window.location.href = '/default';
    }
  } catch (e) {
    // Invalid URL, redirect to default
    window.location.href = '/default';
  }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_2() {
  // Using relative URLs only
  const urlParams = new URLSearchParams(location.search);
  let path = urlParams.get('path') || '/home';
  
  // Ensure it's a relative path by removing any protocol and domain parts
  if (path.includes('://') || path.startsWith('//')) {
    path = '/home';
  }
  
  // ok: javascript-dom-based-open-redirection
  window.location.href = path;
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_3() {
  // Using a URL validation function
  const userInput = prompt("Enter the page you want to visit:");
  
  function isValidInternalUrl(url) {
    // Only allow relative URLs or URLs to our domain
    if (url.startsWith('/') && !url.startsWith('//')) {
      return true;
    }
    try {
      const urlObj = new URL(url);
      return urlObj.hostname === 'example.com';
    } catch (e) {
      return false;
    }
  }
  
  // ok: javascript-dom-based-open-redirection
  if (isValidInternalUrl(userInput)) {
    window.location.href = userInput;
  } else {
    alert("Invalid URL");
    window.location.href = '/home';
  }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_4() {
  // Using jQuery with URL validation
  $("#redirectButton").click(function() {
    const redirectUrl = $("#urlInput").val();
    
    try {
      const url = new URL(redirectUrl, window.location.origin);
      // ok: javascript-dom-based-open-redirection
      if (url.hostname === window.location.hostname) {
        window.location.href = redirectUrl;
      } else {
        window.location.href = '/';
      }
    } catch (e) {
      window.location.href = '/';
    }
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_5() {
  // Using AJAX with response validation
  $.ajax({
    url: "/get-redirect-url",
    success: function(data) {
      const trustedDomains = ['example.com', 'sub.example.com'];
      
      try {
        const url = new URL(data.url);
        // ok: javascript-dom-based-open-redirection
        if (trustedDomains.includes(url.hostname)) {
          window.location.href = data.url;
        } else {
          console.error("Untrusted redirect URL");
          window.location.href = '/home';
        }
      } catch (e) {
        window.location.href = '/home';
      }
    }
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_6() {
  // Using hardcoded URLs in a mapping
  const urlParams = new URLSearchParams(window.location.search);
  const pageKey = urlParams.get('page');
  
  const safeRedirectMap = {
    'home': '/home',
    'about': '/about',
    'contact': '/contact',
    'products': '/products'
  };
  
  // ok: javascript-dom-based-open-redirection
  window.location.href = safeRedirectMap[pageKey] || '/home';
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_7() {
  // Using sessionStorage with validation
  const savedRedirect = sessionStorage.getItem('redirectAfterLogin');
  
  // Ensure it's a relative path
  const sanitizedUrl = savedRedirect && savedRedirect.startsWith('/') && !savedRedirect.startsWith('//') 
    ? savedRedirect 
    : '/dashboard';
  
  // ok: javascript-dom-based-open-redirection
  location.href = sanitizedUrl;
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_8() {
  // Using postMessage with proper origin and data validation
  window.addEventListener('message', function(event) {
    if (event.origin === 'https://trusted-source.com' && typeof event.data === 'object') {
      const redirectUrl = event.data.redirectUrl;
      
      // ok: javascript-dom-based-open-redirection
      if (redirectUrl && redirectUrl.startsWith('/') && !redirectUrl.startsWith('//')) {
        window.location.href = redirectUrl;
      } else {
        window.location.href = '/default';
      }
    }
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_9() {
  // Using URL parameters with path construction and validation
  const urlParams = new URLSearchParams(location.search);
  const section = urlParams.get('section');
  
  // Whitelist of allowed sections
  const allowedSections = ['products', 'services', 'about', 'contact'];
  
  // ok: javascript-dom-based-open-redirection
  if (section && allowedSections.includes(section)) {
    window.location.href = '/' + section;
  } else {
    window.location.href = '/home';
  }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_10() {
  // Using fetch API with response validation
  fetch('/api/get-redirect')
    .then(response => response.json())
    .then(data => {
      // ok: javascript-dom-based-open-redirection
      if (data.redirectUrl && data.redirectUrl.startsWith('/') && !data.redirectUrl.startsWith('//')) {
        window.location.href = data.redirectUrl;
      } else {
        window.location.href = '/dashboard';
      }
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_11() {
  // Using localStorage with strict validation
  document.getElementById('loginButton').addEventListener('click', function() {
    const redirectUrl = localStorage.getItem('lastVisitedPage');
    
    // Regular expression to ensure only relative paths without protocol exploitation
    const safeUrlRegex = /^\/(?!\/)[a-zA-Z0-9\/_-]*$/;
    
    // ok: javascript-dom-based-open-redirection
    if (redirectUrl && safeUrlRegex.test(redirectUrl)) {
      window.location.href = redirectUrl;
    } else {
      window.location.href = '/dashboard';
    }
  });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_12() {
  // Using URL parameters with path construction and sanitization
  const params = new URLSearchParams(window.location.search);
  let productId = params.get('productId');
  
  // Sanitize the productId to ensure it only contains alphanumeric characters
  if (productId && /^[a-zA-Z0-9-]+$/.test(productId)) {
    // ok: javascript-dom-based-open-redirection
    window.location.href = '/products/' + productId;
  } else {
    window.location.href = '/products';
  }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_13() {
  // Using document.referrer with validation
  const referrer = document.referrer;
  let safeReferrer = '/home';
  
  try {
    const referrerUrl = new URL(referrer);
    // Only allow referrers from our own domain
    // ok: javascript-dom-based-open-redirection
    if (referrerUrl.hostname === window.location.hostname) {
      safeReferrer = referrerUrl.pathname;
      window.location.href = safeReferrer;
    } else {
      window.location.href = '/home';
    }
  } catch (e) {
    window.location.href = '/home';
  }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_14() {
  // Using multiple sources with proper validation
  const urlParams = new URLSearchParams(location.search);
  const section = urlParams.get('section') || 'home';
  const subSection = localStorage.getItem('preferredSubSection') || 'overview';
  
  const validSections = ['home', 'products', 'services', 'about'];
  const validSubSections = ['overview', 'details', 'pricing', 'contact'];
  
  // ok: javascript-dom-based-open-redirection
  if (validSections.includes(section) && validSubSections.includes(subSection)) {
    window.location.href = `/${section}/${subSection}`;
  } else {
    window.location.href = '/home/overview';
  }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_15() {
  // Using data attributes with validation
  document.querySelectorAll('[data-redirect]').forEach(element => {
    element.addEventListener('click', function(e) {
      e.preventDefault();
      const redirectUrl = this.getAttribute('data-redirect');
      
      // Validate that it's a relative URL path
      // ok: javascript-dom-based-open-redirection
      if (redirectUrl && redirectUrl.startsWith('/') && !redirectUrl.startsWith('//')) {
        window.location.href = redirectUrl;
      } else {
        console.error("Invalid redirect URL");
        window.location.href = '/';
      }
    });
  });
}
// {/fact}