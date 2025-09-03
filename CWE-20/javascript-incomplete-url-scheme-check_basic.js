// Test cases for javascript-incomplete-url-scheme-check
// This rule detects incomplete URL scheme validation that could lead to security vulnerabilities

// True Positives (Vulnerable Code)

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_1() {
  const url = document.location.href;
  // Only checks for javascript: but misses other dangerous schemes
  // ruleid: javascript-incomplete-url-scheme-check
  if (!url.startsWith('javascript:')) {
    window.location = url;
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_2() {
  const userInput = new URL(window.location.href).searchParams.get('redirect');
  // Only checks for one scheme variation
  // ruleid: javascript-incomplete-url-scheme-check
  if (userInput.indexOf('javascript:') === -1) {
    document.getElementById('link').href = userInput;
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_3() {
  const redirectUrl = document.getElementById('user-input').value;
  // Case-sensitive check that can be bypassed
  // ruleid: javascript-incomplete-url-scheme-check
  if (!redirectUrl.startsWith('javascript:')) {
    window.open(redirectUrl);
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_4() {
  const urlParam = new URLSearchParams(window.location.search).get('url');
  // Incomplete check - only looks for javascript: at the beginning
  // ruleid: javascript-incomplete-url-scheme-check
  if (!/^javascript:/i.test(urlParam)) {
    document.location = urlParam;
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_5() {
  const userProvidedUrl = document.cookie.split('redirect=')[1].split(';')[0];
  // Missing data: and vbscript: checks
  // ruleid: javascript-incomplete-url-scheme-check
  if (userProvidedUrl.toLowerCase().indexOf('javascript:') === -1) {
    window.location.href = userProvidedUrl;
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_6() {
  const url = document.referrer;
  // Only checks javascript: with regex but misses other schemes
  // ruleid: javascript-incomplete-url-scheme-check
  if (!url.match(/javascript:/i)) {
    document.getElementById('frame').src = url;
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_7() {
  const urlFromHash = window.location.hash.substring(1);
  // Checks only one scheme and uses weak string replacement
  // ruleid: javascript-incomplete-url-scheme-check
  const sanitizedUrl = urlFromHash.replace('javascript:', '');
  document.getElementById('content').innerHTML = `<a href="${sanitizedUrl}">Click here</a>`;
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_8() {
  const userInput = new URL(window.location.href).searchParams.get('link');
  // Only checks for javascript: but with insufficient regex
  // ruleid: javascript-incomplete-url-scheme-check
  if (!/javascript\s*:/i.test(userInput)) {
    document.write(`<iframe src="${userInput}"></iframe>`);
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_9() {
  const redirectUrl = sessionStorage.getItem('redirectUrl');
  // Checks only one scheme with simple string check
  // ruleid: javascript-incomplete-url-scheme-check
  if (redirectUrl.toLowerCase().indexOf('javascript:') === -1) {
    location.replace(redirectUrl);
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_10() {
  const url = localStorage.getItem('savedUrl');
  // Only checks one scheme and uses weak validation
  // ruleid: javascript-incomplete-url-scheme-check
  if (!url.includes('javascript:')) {
    document.querySelector('iframe').src = url;
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_11() {
  const userInput = document.getElementById('search').value;
  // Tries to sanitize but only removes one scheme
  // ruleid: javascript-incomplete-url-scheme-check
  const sanitized = userInput.replace(/javascript:/gi, '');
  document.getElementById('result').innerHTML = `<a href="${sanitized}">Result</a>`;
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_12() {
  const urlParam = new URLSearchParams(window.location.search).get('redirect');
  // Incomplete validation with regex that only checks one scheme
  // ruleid: javascript-incomplete-url-scheme-check
  if (urlParam && !urlParam.match(/^javascript:/)) {
    window.location.replace(urlParam);
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_13() {
  const message = JSON.parse(localStorage.getItem('message'));
  // Only checks for javascript: at the start
  // ruleid: javascript-incomplete-url-scheme-check
  if (!message.url.startsWith('javascript:')) {
    document.getElementById('message-link').href = message.url;
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_14() {
  const formData = new FormData(document.getElementById('user-form'));
  const userUrl = formData.get('website');
  // Only checks one scheme with case-sensitive check
  // ruleid: javascript-incomplete-url-scheme-check
  if (userUrl.indexOf('javascript:') === -1) {
    window.open(userUrl, '_blank');
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_15() {
  const urlFromPostMessage = event.data.url;
  // Checks only one scheme with insufficient validation
  // ruleid: javascript-incomplete-url-scheme-check
  if (!urlFromPostMessage.includes('javascript:')) {
    document.getElementById('external-content').src = urlFromPostMessage;
  }
}
// {/fact}

// True Negatives (Secure Code)

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_1() {
  const url = document.location.href;
  // Checks for multiple dangerous schemes
  // ok: javascript-incomplete-url-scheme-check
  if (!url.startsWith('javascript:') && !url.startsWith('data:') && !url.startsWith('vbscript:')) {
    window.location = url;
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_2() {
  const userInput = new URL(window.location.href).searchParams.get('redirect');
  // Uses regex to check for multiple dangerous schemes
  // ok: javascript-incomplete-url-scheme-check
  if (!/^(javascript|data|vbscript):/i.test(userInput)) {
    document.getElementById('link').href = userInput;
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_3() {
  const redirectUrl = document.getElementById('user-input').value;
  // Case-insensitive check for multiple schemes
  // ok: javascript-incomplete-url-scheme-check
  const lowerUrl = redirectUrl.toLowerCase();
  if (!lowerUrl.startsWith('javascript:') && !lowerUrl.startsWith('data:') && !lowerUrl.startsWith('vbscript:')) {
    window.open(redirectUrl);
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_4() {
  const urlParam = new URLSearchParams(window.location.search).get('url');
  // Whitelist approach - only allow specific schemes
  // ok: javascript-incomplete-url-scheme-check
  if (/^(http|https):\/\//i.test(urlParam)) {
    document.location = urlParam;
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_5() {
  const userProvidedUrl = document.cookie.split('redirect=')[1].split(';')[0];
  // Comprehensive check for multiple dangerous schemes
  // ok: javascript-incomplete-url-scheme-check
  if (!/^(javascript|data|vbscript|file):/i.test(userProvidedUrl)) {
    window.location.href = userProvidedUrl;
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_6() {
  const url = document.referrer;
  // Uses URL constructor to validate and restrict to http/https
  // ok: javascript-incomplete-url-scheme-check
  try {
    const parsedUrl = new URL(url);
    if (parsedUrl.protocol === 'http:' || parsedUrl.protocol === 'https:') {
      document.getElementById('frame').src = url;
    }
  } catch (e) {
    console.error('Invalid URL');
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_7() {
  const urlFromHash = window.location.hash.substring(1);
  // Uses a whitelist approach for allowed schemes
  // ok: javascript-incomplete-url-scheme-check
  const allowedSchemes = ['http:', 'https:'];
  try {
    const url = new URL(urlFromHash);
    if (allowedSchemes.includes(url.protocol)) {
      document.getElementById('content').innerHTML = `<a href="${urlFromHash}">Click here</a>`;
    }
  } catch (e) {
    console.error('Invalid URL');
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_8() {
  const userInput = new URL(window.location.href).searchParams.get('link');
  // Uses a comprehensive regex to check for multiple dangerous schemes
  // ok: javascript-incomplete-url-scheme-check
  if (!/^(?:javascript|data|vbscript|file):/i.test(userInput)) {
    document.write(`<iframe src="${userInput}"></iframe>`);
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_9() {
  const redirectUrl = sessionStorage.getItem('redirectUrl');
  // Uses URL API to validate and restrict protocols
  // ok: javascript-incomplete-url-scheme-check
  try {
    const url = new URL(redirectUrl);
    if (url.protocol === 'http:' || url.protocol === 'https:') {
      location.replace(redirectUrl);
    }
  } catch (e) {
    console.error('Invalid URL');
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_10() {
  const url = localStorage.getItem('savedUrl');
  // Uses a blacklist approach checking multiple dangerous schemes
  // ok: javascript-incomplete-url-scheme-check
  const dangerousSchemes = ['javascript:', 'data:', 'vbscript:', 'file:'];
  const isUrlSafe = !dangerousSchemes.some(scheme => url.toLowerCase().includes(scheme));
  if (isUrlSafe) {
    document.querySelector('iframe').src = url;
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_11() {
  const userInput = document.getElementById('search').value;
  // Uses URL constructor and validates protocol
  // ok: javascript-incomplete-url-scheme-check
  try {
    const url = new URL(userInput);
    if (['http:', 'https:'].includes(url.protocol)) {
      document.getElementById('result').innerHTML = `<a href="${url.href}">Result</a>`;
    }
  } catch (e) {
    console.error('Invalid URL');
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_12() {
  const urlParam = new URLSearchParams(window.location.search).get('redirect');
  // Comprehensive check for multiple dangerous schemes with regex
  // ok: javascript-incomplete-url-scheme-check
  if (urlParam && !/^(?:javascript|data|vbscript|file):/i.test(urlParam)) {
    window.location.replace(urlParam);
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_13() {
  const message = JSON.parse(localStorage.getItem('message'));
  // Uses a function to validate URL against multiple dangerous schemes
  // ok: javascript-incomplete-url-scheme-check
  function isUrlSafe(url) {
    const dangerousSchemes = ['javascript:', 'data:', 'vbscript:', 'file:'];
    return !dangerousSchemes.some(scheme => url.toLowerCase().startsWith(scheme));
  }
  
  if (message.url && isUrlSafe(message.url)) {
    document.getElementById('message-link').href = message.url;
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_14() {
  const formData = new FormData(document.getElementById('user-form'));
  const userUrl = formData.get('website');
  // Uses URL constructor and explicitly checks for safe protocols
  // ok: javascript-incomplete-url-scheme-check
  try {
    const url = new URL(userUrl);
    if (url.protocol === 'http:' || url.protocol === 'https:') {
      window.open(userUrl, '_blank');
    }
  } catch (e) {
    console.error('Invalid URL');
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_15() {
  const urlFromPostMessage = event.data.url;
  // Comprehensive check for all dangerous schemes
  // ok: javascript-incomplete-url-scheme-check
  const lowerUrl = urlFromPostMessage.toLowerCase();
  if (!lowerUrl.startsWith('javascript:') && 
      !lowerUrl.startsWith('data:') && 
      !lowerUrl.startsWith('vbscript:') &&
      !lowerUrl.startsWith('file:')) {
    document.getElementById('external-content').src = urlFromPostMessage;
  }
}
// {/fact}