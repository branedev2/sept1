// typescript-dom-based-open-redirection test cases

// Import necessary modules
import { Request, Response } from 'express';

// True Positive Examples (Vulnerable Code)

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_1() {
  // Get URL from query parameter
  const urlParam = new URLSearchParams(window.location.search).get('url');
  
  if (urlParam) {
    // ruleid: typescript-dom-based-open-redirection
    window.location.href = urlParam;
  }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_2() {
  // Get redirect URL from hash fragment
  const redirectUrl = window.location.hash.substring(1);
  
  // ruleid: typescript-dom-based-open-redirection
  window.location.replace(redirectUrl);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_3() {
  // Extract URL from query parameter and use it for redirection
  const params = new URLSearchParams(window.location.search);
  const destination = params.get('redirect_to');
  
  // ruleid: typescript-dom-based-open-redirection
  window.location.assign(destination);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_4() {
  // Get URL from localStorage that was previously set from user input
  const savedRedirect = localStorage.getItem('userRedirect');
  
  if (savedRedirect) {
    // ruleid: typescript-dom-based-open-redirection
    document.location = savedRedirect;
  }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_5() {
  // Extract multiple parameters and construct a URL
  const params = new URLSearchParams(window.location.search);
  const site = params.get('site');
  const path = params.get('path');
  
  if (site && path) {
    const url = `${site}/${path}`;
    // ruleid: typescript-dom-based-open-redirection
    window.location = url;
  }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_6() {
  // Get URL from a cookie
  const cookies = document.cookie.split(';').reduce((acc, cookie) => {
    const [key, value] = cookie.trim().split('=');
    acc[key] = value;
    return acc;
  }, {} as Record<string, string>);
  
  const redirectUrl = cookies['redirect_url'];
  
  // ruleid: typescript-dom-based-open-redirection
  location.href = redirectUrl;
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_7() {
  // Extract URL from referrer and use it
  const referrer = document.referrer;
  const url = new URL(referrer);
  const redirectParam = url.searchParams.get('next');
  
  if (redirectParam) {
    // ruleid: typescript-dom-based-open-redirection
    self.location.href = redirectParam;
  }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_8() {
  // Using template literals with user input for redirection
  const userId = new URLSearchParams(window.location.search).get('id');
  const returnUrl = new URLSearchParams(window.location.search).get('return');
  
  // ruleid: typescript-dom-based-open-redirection
  window.location.href = `${returnUrl}?processed=true&user=${userId}`;
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_9() {
  // Process URL before redirection but still vulnerable
  let redirectUrl = new URLSearchParams(window.location.search).get('redirect');
  
  if (redirectUrl) {
    // Adding a parameter but still using user-provided base URL
    redirectUrl += (redirectUrl.includes('?') ? '&' : '?') + 'source=ourapp';
    
    // ruleid: typescript-dom-based-open-redirection
    location.assign(redirectUrl);
  }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_10() {
  // Using eval with location
  const nextPage = new URLSearchParams(window.location.search).get('next');
  
  if (nextPage) {
    // ruleid: typescript-dom-based-open-redirection
    eval(`window.location.href = '${nextPage}'`);
  }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_11() {
  // Redirection after timeout with user input
  const destination = new URLSearchParams(window.location.search).get('dest');
  
  if (destination) {
    setTimeout(() => {
      // ruleid: typescript-dom-based-open-redirection
      window.location = destination;
    }, 3000);
  }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_12() {
  // Using iframe for redirection
  const targetUrl = new URLSearchParams(window.location.search).get('frame_url');
  const iframe = document.createElement('iframe');
  
  // ruleid: typescript-dom-based-open-redirection
  iframe.src = targetUrl;
  document.body.appendChild(iframe);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_13() {
  // Redirection with concatenated URL parts
  const domain = new URLSearchParams(window.location.search).get('domain');
  const protocol = new URLSearchParams(window.location.search).get('protocol') || 'https';
  
  if (domain) {
    const url = `${protocol}://${domain}`;
    // ruleid: typescript-dom-based-open-redirection
    window.location.href = url;
  }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_14() {
  // Using window.open with user input
  const popupUrl = new URLSearchParams(window.location.search).get('popup');
  
  if (popupUrl) {
    // ruleid: typescript-dom-based-open-redirection
    window.open(popupUrl, '_blank');
  }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_15() {
  // Using a form's action attribute with user input
  const formAction = new URLSearchParams(window.location.search).get('form_action');
  const form = document.createElement('form');
  
  if (formAction) {
    // ruleid: typescript-dom-based-open-redirection
    form.action = formAction;
    form.method = 'post';
    document.body.appendChild(form);
    form.submit();
  }
}
// {/fact}

// True Negative Examples (Safe Code)

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_1() {
  // Using a whitelist of allowed redirect URLs
  const urlParam = new URLSearchParams(window.location.search).get('url');
  const allowedDomains = ['example.com', 'trusted-site.org', 'safe-domain.net'];
  
  if (urlParam) {
    try {
      const url = new URL(urlParam);
      if (allowedDomains.includes(url.hostname)) {
        // ok: typescript-dom-based-open-redirection
        window.location.href = urlParam;
      } else {
        // Default safe redirect
        window.location.href = '/home';
      }
    } catch (e) {
      // Invalid URL, redirect to default
      window.location.href = '/home';
    }
  }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_2() {
  // Using relative URLs only
  const path = new URLSearchParams(window.location.search).get('path');
  
  if (path) {
    // Ensure it's a relative path by removing any protocol and domain parts
    const safePath = path.replace(/^(?:\/\/|[^/]+)*\//, '/');
    
    // ok: typescript-dom-based-open-redirection
    window.location.href = safePath;
  }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_3() {
  // Using hardcoded URLs
  const action = new URLSearchParams(window.location.search).get('action');
  
  if (action === 'login') {
    // ok: typescript-dom-based-open-redirection
    window.location.href = '/login';
  } else if (action === 'logout') {
    // ok: typescript-dom-based-open-redirection
    window.location.href = '/logout';
  } else {
    // ok: typescript-dom-based-open-redirection
    window.location.href = '/home';
  }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_4() {
  // Using URL constructor to validate and only using the path component
  const redirectUrl = new URLSearchParams(window.location.search).get('redirect');
  
  if (redirectUrl) {
    try {
      const url = new URL(redirectUrl, window.location.origin);
      if (url.origin === window.location.origin) {
        // Only using the pathname + search from the same origin
        // ok: typescript-dom-based-open-redirection
        window.location.href = url.pathname + url.search;
      } else {
        window.location.href = '/';
      }
    } catch (e) {
      window.location.href = '/';
    }
  }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_5() {
  // Using a map of allowed redirect keys
  const redirectKey = new URLSearchParams(window.location.search).get('page');
  const redirectMap: Record<string, string> = {
    'home': '/home',
    'profile': '/user/profile',
    'settings': '/user/settings',
    'help': '/support/help'
  };
  
  if (redirectKey && redirectKey in redirectMap) {
    // ok: typescript-dom-based-open-redirection
    window.location.href = redirectMap[redirectKey];
  } else {
    window.location.href = '/home';
  }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_6() {
  // Hardcoded URL with appended user ID parameter
  const userId = new URLSearchParams(window.location.search).get('id');
  
  if (userId && /^\d+$/.test(userId)) {
    // ok: typescript-dom-based-open-redirection
    window.location.href = `/user/profile?id=${userId}`;
  }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_7() {
  // Using only hash navigation within the same page
  const section = new URLSearchParams(window.location.search).get('section');
  const allowedSections = ['intro', 'features', 'pricing', 'contact'];
  
  if (section && allowedSections.includes(section)) {
    // ok: typescript-dom-based-open-redirection
    window.location.hash = section;
  }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_8() {
  // Validate URL against a regex pattern for internal URLs
  const nextPage = new URLSearchParams(window.location.search).get('next');
  const internalUrlPattern = /^\/[a-zA-Z0-9\/_-]*$/;
  
  if (nextPage && internalUrlPattern.test(nextPage)) {
    // ok: typescript-dom-based-open-redirection
    window.location.href = nextPage;
  } else {
    window.location.href = '/';
  }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_9() {
  // Using a function to validate URLs
  const targetUrl = new URLSearchParams(window.location.search).get('target');
  
  function isValidInternalUrl(url: string): boolean {
    if (!url.startsWith('/')) return false;
    if (url.includes('//')) return false;
    return true;
  }
  
  if (targetUrl && isValidInternalUrl(targetUrl)) {
    // ok: typescript-dom-based-open-redirection
    window.location.href = targetUrl;
  }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_10() {
  // Using URL constructor to ensure same origin
  const returnTo = new URLSearchParams(window.location.search).get('returnTo');
  
  if (returnTo) {
    try {
      const url = new URL(returnTo, window.location.origin);
      if (url.origin === window.location.origin) {
        // ok: typescript-dom-based-open-redirection
        window.location.href = url.toString();
      } else {
        window.location.href = '/dashboard';
      }
    } catch (e) {
      window.location.href = '/dashboard';
    }
  }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_11() {
  // Using a fixed base URL with user parameters
  const productId = new URLSearchParams(window.location.search).get('product');
  const category = new URLSearchParams(window.location.search).get('category');
  
  if (productId && category) {
    // ok: typescript-dom-based-open-redirection
    window.location.href = `/shop/${category}/product/${productId}`;
  }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_12() {
  // Using a switch statement with fixed URLs
  const action = new URLSearchParams(window.location.search).get('action');
  
  switch (action) {
    case 'view':
      // ok: typescript-dom-based-open-redirection
      window.location.href = '/content/view';
      break;
    case 'edit':
      // ok: typescript-dom-based-open-redirection
      window.location.href = '/content/edit';
      break;
    case 'delete':
      // ok: typescript-dom-based-open-redirection
      window.location.href = '/content/delete';
      break;
    default:
      // ok: typescript-dom-based-open-redirection
      window.location.href = '/content/list';
  }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_13() {
  // Using URL parameters with a fixed base URL
  const params = new URLSearchParams(window.location.search);
  const page = params.get('page') || '1';
  const sort = params.get('sort') || 'name';
  const order = params.get('order') || 'asc';
  
  // Building a URL with only the query parameters from user input
  // ok: typescript-dom-based-open-redirection
  window.location.href = `/products?page=${page}&sort=${sort}&order=${order}`;
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_14() {
  // Using a data attribute from a DOM element with fixed URLs
  document.querySelectorAll('[data-redirect]').forEach(element => {
    element.addEventListener('click', (e) => {
      const action = element.getAttribute('data-redirect');
      e.preventDefault();
      
      if (action === 'login') {
        // ok: typescript-dom-based-open-redirection
        window.location.href = '/auth/login';
      } else if (action === 'register') {
        // ok: typescript-dom-based-open-redirection
        window.location.href = '/auth/register';
      }
    });
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_15() {
  // Using a secure redirect with signed URLs
  const signedUrl = new URLSearchParams(window.location.search).get('signed_url');
  const signature = new URLSearchParams(window.location.search).get('signature');
  
  // Verify the signature (simplified example)
  function verifySignature(url: string, sig: string): boolean {
    // In a real implementation, this would verify the signature cryptographically
    return sig === 'valid_signature_for_' + url;
  }
  
  if (signedUrl && signature && verifySignature(signedUrl, signature)) {
    // ok: typescript-dom-based-open-redirection
    window.location.href = signedUrl;
  } else {
    window.location.href = '/error';
  }
}
// {/fact}