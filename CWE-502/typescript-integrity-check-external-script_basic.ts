// Examples for typescript-integrity-check-external-script rule
import * as fs from 'fs';
import axios from 'axios';

// True Positive Examples (Vulnerable Code)

// Bad case 1: Creating a script element without integrity check
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_1() {
  const script = document.createElement('script');
  // ruleid: typescript-integrity-check-external-script
  script.src = 'https://cdn.example.com/library.js';
  document.head.appendChild(script);
}
// {/fact}

// Bad case 2: Loading external script with fetch without integrity check
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
async function bad_case_2() {
  try {
    // ruleid: typescript-integrity-check-external-script
    const response = await fetch('https://api.example.com/script.js');
    const scriptContent = await response.text();
    eval(scriptContent); // Executing the fetched script
  } catch (error) {
    console.error('Failed to load script:', error);
  }
}
// {/fact}

// Bad case 3: Using axios to load external script without integrity check
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
async function bad_case_3() {
  try {
    // ruleid: typescript-integrity-check-external-script
    const response = await axios.get('https://cdn.thirdparty.com/widget.js');
    const scriptContent = response.data;
    const script = document.createElement('script');
    script.textContent = scriptContent;
    document.body.appendChild(script);
  } catch (error) {
    console.error('Failed to load script:', error);
  }
}
// {/fact}

// Bad case 4: Dynamically loading multiple scripts without integrity checks
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_4() {
  const scriptUrls = [
    'https://cdn1.example.com/lib1.js',
    'https://cdn2.example.com/lib2.js',
    'https://cdn3.example.com/lib3.js'
  ];
  
  scriptUrls.forEach(url => {
    const script = document.createElement('script');
    // ruleid: typescript-integrity-check-external-script
    script.src = url;
    document.head.appendChild(script);
  });
}
// {/fact}

// Bad case 5: Loading external script in React component without integrity check
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_5() {
  class ExternalScriptComponent {
    componentDidMount() {
      const script = document.createElement('script');
      // ruleid: typescript-integrity-check-external-script
      script.src = 'https://analytics.example.com/tracker.js';
      script.async = true;
      document.body.appendChild(script);
    }
    
    render() {
      return <div>Component with external script</div>;
    }
  }
  
  return new ExternalScriptComponent();
}
// {/fact}

// Bad case 6: Using XMLHttpRequest to load script without integrity check
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_6() {
  const xhr = new XMLHttpRequest();
  // ruleid: typescript-integrity-check-external-script
  xhr.open('GET', 'https://cdn.example.com/library.js', true);
  xhr.onload = function() {
    if (xhr.status === 200) {
      const script = document.createElement('script');
      script.textContent = xhr.responseText;
      document.head.appendChild(script);
    }
  };
  xhr.send();
}
// {/fact}

// Bad case 7: Loading script via import statement without integrity check
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_7() {
  // ruleid: typescript-integrity-check-external-script
  import('https://cdn.example.com/module.js')
    .then(module => {
      module.initialize();
    })
    .catch(error => {
      console.error('Failed to load module:', error);
    });
}
// {/fact}

// Bad case 8: Creating script element with setAttribute without integrity
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_8() {
  const script = document.createElement('script');
  // ruleid: typescript-integrity-check-external-script
  script.setAttribute('src', 'https://cdn.example.com/framework.js');
  script.setAttribute('async', 'true');
  document.head.appendChild(script);
}
// {/fact}

// Bad case 9: Loading external script in Angular component without integrity check
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_9() {
  class AngularComponent {
    ngOnInit() {
      const script = document.createElement('script');
      // ruleid: typescript-integrity-check-external-script
      script.src = 'https://maps.example.com/api.js?key=YOUR_API_KEY';
      document.body.appendChild(script);
    }
  }
  
  return new AngularComponent();
}
// {/fact}

// Bad case 10: Loading script with dynamic URL without integrity check
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_10() {
  const version = '1.2.3';
  const script = document.createElement('script');
  // ruleid: typescript-integrity-check-external-script
  script.src = `https://cdn.example.com/library-${version}.js`;
  document.head.appendChild(script);
}
// {/fact}

// Bad case 11: Using jQuery to load external script without integrity check
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_11() {
  // Assuming jQuery is available
  // ruleid: typescript-integrity-check-external-script
  $.getScript('https://cdn.example.com/jquery-plugin.js', function() {
    console.log('Script loaded successfully');
  });
}
// {/fact}

// Bad case 12: Loading external script in Vue component without integrity check
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_12() {
  const VueComponent = {
    mounted() {
      const script = document.createElement('script');
      // ruleid: typescript-integrity-check-external-script
      script.src = 'https://cdn.example.com/vue-plugin.js';
      document.head.appendChild(script);
    }
  };
  
  return VueComponent;
}
// {/fact}

// Bad case 13: Loading external script based on environment without integrity check
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_13() {
  const isProduction = process.env.NODE_ENV === 'production';
  const scriptUrl = isProduction 
    ? 'https://cdn.example.com/prod.js' 
    : 'https://cdn.example.com/dev.js';
  
  const script = document.createElement('script');
  // ruleid: typescript-integrity-check-external-script
  script.src = scriptUrl;
  document.head.appendChild(script);
}
// {/fact}

// Bad case 14: Loading external script with error handling but no integrity check
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_14() {
  const script = document.createElement('script');
  // ruleid: typescript-integrity-check-external-script
  script.src = 'https://cdn.example.com/analytics.js';
  script.onerror = () => console.error('Failed to load analytics script');
  script.onload = () => console.log('Analytics script loaded successfully');
  document.head.appendChild(script);
}
// {/fact}

// Bad case 15: Loading external script with defer attribute but no integrity check
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_15() {
  const script = document.createElement('script');
  // ruleid: typescript-integrity-check-external-script
  script.src = 'https://cdn.example.com/deferred-script.js';
  script.defer = true;
  document.head.appendChild(script);
}
// {/fact}

// True Negative Examples (Secure Code)

// Good case 1: Creating a script element with integrity check
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_1() {
  const script = document.createElement('script');
  script.src = 'https://cdn.example.com/library.js';
  // ok: typescript-integrity-check-external-script
  script.integrity = 'sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC';
  script.crossOrigin = 'anonymous';
  document.head.appendChild(script);
}
// {/fact}

// Good case 2: Loading local script (no integrity needed for local resources)
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_2() {
  const script = document.createElement('script');
  // ok: typescript-integrity-check-external-script
  script.src = '/assets/js/local-script.js'; // Local script, not external
  document.head.appendChild(script);
}
// {/fact}

// Good case 3: Using fetch with integrity verification
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
async function good_case_3() {
  try {
    const expectedHash = 'sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC';
    const response = await fetch('https://api.example.com/script.js');
    const scriptContent = await response.text();
    
    // ok: typescript-integrity-check-external-script
    const calculatedHash = await calculateSha384(scriptContent);
    if (calculatedHash === expectedHash) {
      eval(scriptContent); // Execute only if integrity check passes
    } else {
      console.error('Integrity check failed');
    }
  } catch (error) {
    console.error('Failed to load script:', error);
  }
}
// {/fact}

// Helper function for SHA-384 calculation
async function calculateSha384(content: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(content);
  const hashBuffer = await crypto.subtle.digest('SHA-384', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  return `sha384-${hashHex}`;
}

// Good case 4: Using axios with integrity verification
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
async function good_case_4() {
  try {
    const expectedHash = 'sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC';
    const response = await axios.get('https://cdn.thirdparty.com/widget.js');
    const scriptContent = response.data;
    
    // ok: typescript-integrity-check-external-script
    const calculatedHash = await calculateSha384(scriptContent);
    if (calculatedHash === expectedHash) {
      const script = document.createElement('script');
      script.textContent = scriptContent;
      document.body.appendChild(script);
    } else {
      console.error('Integrity check failed');
    }
  } catch (error) {
    console.error('Failed to load script:', error);
  }
}
// {/fact}

// Good case 5: Dynamically loading multiple scripts with integrity checks
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_5() {
  const scripts = [
    {
      url: 'https://cdn1.example.com/lib1.js',
      integrity: 'sha384-1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef'
    },
    {
      url: 'https://cdn2.example.com/lib2.js',
      integrity: 'sha384-abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890'
    }
  ];
  
  scripts.forEach(scriptInfo => {
    const script = document.createElement('script');
    script.src = scriptInfo.url;
    // ok: typescript-integrity-check-external-script
    script.integrity = scriptInfo.integrity;
    script.crossOrigin = 'anonymous';
    document.head.appendChild(script);
  });
}
// {/fact}

// Good case 6: Loading external script in React component with integrity check
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_6() {
  class ExternalScriptComponent {
    componentDidMount() {
      const script = document.createElement('script');
      script.src = 'https://analytics.example.com/tracker.js';
      // ok: typescript-integrity-check-external-script
      script.integrity = 'sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC';
      script.crossOrigin = 'anonymous';
      script.async = true;
      document.body.appendChild(script);
    }
    
    render() {
      return <div>Component with external script</div>;
    }
  }
  
  return new ExternalScriptComponent();
}
// {/fact}

// Good case 7: Using XMLHttpRequest with integrity verification
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_7() {
  const xhr = new XMLHttpRequest();
  const expectedHash = 'sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC';
  
  xhr.open('GET', 'https://cdn.example.com/library.js', true);
  xhr.onload = async function() {
    if (xhr.status === 200) {
      // ok: typescript-integrity-check-external-script
      const calculatedHash = await calculateSha384(xhr.responseText);
      if (calculatedHash === expectedHash) {
        const script = document.createElement('script');
        script.textContent = xhr.responseText;
        document.head.appendChild(script);
      } else {
        console.error('Integrity check failed');
      }
    }
  };
  xhr.send();
}
// {/fact}

// Good case 8: Using a Content Security Policy instead of individual integrity attributes
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_8() {
  // ok: typescript-integrity-check-external-script
  const meta = document.createElement('meta');
  meta.httpEquiv = 'Content-Security-Policy';
  meta.content = "script-src 'self' https://cdn.example.com/ 'sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC'";
  document.head.appendChild(meta);
  
  const script = document.createElement('script');
  script.src = 'https://cdn.example.com/library.js';
  document.head.appendChild(script);
}
// {/fact}

// Good case 9: Loading script with setAttribute with integrity
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_9() {
  const script = document.createElement('script');
  script.setAttribute('src', 'https://cdn.example.com/framework.js');
  // ok: typescript-integrity-check-external-script
  script.setAttribute('integrity', 'sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC');
  script.setAttribute('crossorigin', 'anonymous');
  document.head.appendChild(script);
}
// {/fact}

// Good case 10: Loading external script in Angular component with integrity check
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_10() {
  class AngularComponent {
    ngOnInit() {
      const script = document.createElement('script');
      script.src = 'https://maps.example.com/api.js?key=YOUR_API_KEY';
      // ok: typescript-integrity-check-external-script
      script.integrity = 'sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC';
      script.crossOrigin = 'anonymous';
      document.body.appendChild(script);
    }
  }
  
  return new AngularComponent();
}
// {/fact}

// Good case 11: Loading script with dynamic URL but with integrity check
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_11() {
  const version = '1.2.3';
  const integrities = {
    '1.2.3': 'sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC',
    '1.2.2': 'sha384-abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890'
  };
  
  const script = document.createElement('script');
  script.src = `https://cdn.example.com/library-${version}.js`;
  // ok: typescript-integrity-check-external-script
  script.integrity = integrities[version];
  script.crossOrigin = 'anonymous';
  document.head.appendChild(script);
}
// {/fact}

// Good case 12: Using a script loader utility that enforces integrity checks
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_12() {
  // ok: typescript-integrity-check-external-script
  function loadScriptWithIntegrity(url: string, integrity: string): Promise<void> {
    return new Promise((resolve, reject) => {
      const script = document.createElement('script');
      script.src = url;
      script.integrity = integrity;
      script.crossOrigin = 'anonymous';
      script.onload = () => resolve();
      script.onerror = () => reject(new Error(`Failed to load script: ${url}`));
      document.head.appendChild(script);
    });
  }
  
  loadScriptWithIntegrity(
    'https://cdn.example.com/library.js',
    'sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC'
  ).catch(error => console.error(error));
}
// {/fact}

// Good case 13: Loading external script in Vue component with integrity check
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_13() {
  const VueComponent = {
    mounted() {
      const script = document.createElement('script');
      script.src = 'https://cdn.example.com/vue-plugin.js';
      // ok: typescript-integrity-check-external-script
      script.integrity = 'sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC';
      script.crossOrigin = 'anonymous';
      document.head.appendChild(script);
    }
  };
  
  return VueComponent;
}
// {/fact}

// Good case 14: Using inline script (no integrity needed for inline scripts)
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_14() {
  // ok: typescript-integrity-check-external-script
  const script = document.createElement('script');
  script.textContent = 'console.log("This is an inline script");'; // Inline script, not external
  document.head.appendChild(script);
}
// {/fact}

// Good case 15: Loading script from trusted domain with subresource integrity
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_15() {
  const script = document.createElement('script');
  script.src = 'https://cdn.example.com/deferred-script.js';
  // ok: typescript-integrity-check-external-script
  script.integrity = 'sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC';
  script.crossOrigin = 'anonymous';
  script.defer = true;
  document.head.appendChild(script);
}
// {/fact}