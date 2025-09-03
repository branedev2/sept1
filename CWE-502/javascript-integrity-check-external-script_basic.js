// This file demonstrates proper and improper use of integrity checks for external scripts
// Rule ID: javascript-integrity-check-external-script

// True Positives (Vulnerable Code Examples)

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_1() {
  // Creating a script element without integrity check
  const script = document.createElement('script');
  // ruleid: javascript-integrity-check-external-script
  script.src = 'https://cdn.example.com/library.js';
  document.head.appendChild(script);
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_2() {
  // Adding script with template literals but no integrity
  const cdnUrl = 'https://cdn.jsdelivr.net';
  const scriptPath = '/npm/jquery@3.6.0/dist/jquery.min.js';
  
  const script = document.createElement('script');
  // ruleid: javascript-integrity-check-external-script
  script.src = `${cdnUrl}${scriptPath}`;
  document.body.appendChild(script);
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_3() {
  // Using jQuery to add script without integrity
  const scriptUrl = 'https://unpkg.com/react@17/umd/react.production.min.js';
  
  // ruleid: javascript-integrity-check-external-script
  $('head').append(`<script src="${scriptUrl}"></script>`);
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_4() {
  // Dynamically loading multiple scripts without integrity
  const scripts = [
    'https://cdn.example.com/lib1.js',
    'https://cdn.example.com/lib2.js'
  ];
  
  scripts.forEach(url => {
    const script = document.createElement('script');
    // ruleid: javascript-integrity-check-external-script
    script.src = url;
    script.async = true;
    document.head.appendChild(script);
  });
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_5() {
  // Loading script based on environment without integrity
  const env = process.env.NODE_ENV || 'development';
  const scriptUrl = env === 'production' 
    ? 'https://cdn.example.com/prod.js' 
    : 'https://cdn.example.com/dev.js';
  
  const script = document.createElement('script');
  // ruleid: javascript-integrity-check-external-script
  script.src = scriptUrl;
  document.head.appendChild(script);
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_6() {
  // Using innerHTML to inject script without integrity
  const container = document.getElementById('scripts-container');
  // ruleid: javascript-integrity-check-external-script
  container.innerHTML = '<script src="https://cdn.example.com/analytics.js"></script>';
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_7() {
  // Using document.write to inject script without integrity
  const scriptUrl = 'https://cdn.example.com/tracking.js';
  // ruleid: javascript-integrity-check-external-script
  document.write(`<script src="${scriptUrl}"></script>`);
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_8() {
  // Using third-party loader without integrity
  const loadScript = (url, callback) => {
    const script = document.createElement('script');
    script.onload = callback;
    // ruleid: javascript-integrity-check-external-script
    script.src = url;
    document.head.appendChild(script);
  };
  
  loadScript('https://cdn.example.com/chart.js', () => {
    console.log('Chart.js loaded');
  });
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_9() {
  // Conditional script loading without integrity
  if (window.innerWidth > 768) {
    const script = document.createElement('script');
    // ruleid: javascript-integrity-check-external-script
    script.src = 'https://cdn.example.com/desktop-features.js';
    document.head.appendChild(script);
  } else {
    const script = document.createElement('script');
    // ruleid: javascript-integrity-check-external-script
    script.src = 'https://cdn.example.com/mobile-features.js';
    document.head.appendChild(script);
  }
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_10() {
  // Using setAttribute without integrity
  const script = document.createElement('script');
  // ruleid: javascript-integrity-check-external-script
  script.setAttribute('src', 'https://cdn.example.com/framework.js');
  document.head.appendChild(script);
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_11() {
  // Loading script with version parameter but no integrity
  const version = '1.2.3';
  const script = document.createElement('script');
  // ruleid: javascript-integrity-check-external-script
  script.src = `https://cdn.example.com/library.js?v=${version}`;
  document.head.appendChild(script);
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_12() {
  // Using async/defer without integrity
  const script = document.createElement('script');
  // ruleid: javascript-integrity-check-external-script
  script.src = 'https://cdn.example.com/async-script.js';
  script.async = true;
  script.defer = true;
  document.head.appendChild(script);
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_13() {
  // Using a function to determine script URL without integrity
  function getScriptUrl() {
    return 'https://cdn.example.com/dynamic-script.js';
  }
  
  const script = document.createElement('script');
  // ruleid: javascript-integrity-check-external-script
  script.src = getScriptUrl();
  document.head.appendChild(script);
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_14() {
  // Using a promise to load script without integrity
  const loadScript = (url) => {
    return new Promise((resolve, reject) => {
      const script = document.createElement('script');
      script.onload = resolve;
      script.onerror = reject;
      // ruleid: javascript-integrity-check-external-script
      script.src = url;
      document.head.appendChild(script);
    });
  };
  
  loadScript('https://cdn.example.com/promised-script.js')
    .then(() => console.log('Script loaded'))
    .catch(err => console.error('Script failed to load', err));
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_15() {
  // Using document fragment without integrity
  const fragment = document.createDocumentFragment();
  const script = document.createElement('script');
  // ruleid: javascript-integrity-check-external-script
  script.src = 'https://cdn.example.com/fragment-script.js';
  fragment.appendChild(script);
  document.head.appendChild(fragment);
}
// {/fact}

// True Negatives (Secure Code Examples)

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_1() {
  // Creating a script element with integrity check
  const script = document.createElement('script');
  script.src = 'https://cdn.example.com/library.js';
  // ok: javascript-integrity-check-external-script
  script.integrity = 'sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC';
  script.crossOrigin = 'anonymous';
  document.head.appendChild(script);
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_2() {
  // Adding script with template literals and integrity
  const cdnUrl = 'https://cdn.jsdelivr.net';
  const scriptPath = '/npm/jquery@3.6.0/dist/jquery.min.js';
  const integrity = 'sha384-vtXRMe3mGCbOeY7l30aIg8H9p3GdeSe4IFlP6G8JMa7o7lXvnz3GFKzPxzJdPfGK';
  
  const script = document.createElement('script');
  script.src = `${cdnUrl}${scriptPath}`;
  // ok: javascript-integrity-check-external-script
  script.integrity = integrity;
  script.crossOrigin = 'anonymous';
  document.body.appendChild(script);
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_3() {
  // Using jQuery to add script with integrity
  const scriptUrl = 'https://unpkg.com/react@17/umd/react.production.min.js';
  const integrity = 'sha384-7Er69WnAl0+tY1MYspqtqCMpXTqRYxR9LSrqJPAcnRuKu8RMp5B1K5eSgS5D5dqd';
  
  // ok: javascript-integrity-check-external-script
  $('head').append(`<script src="${scriptUrl}" integrity="${integrity}" crossorigin="anonymous"></script>`);
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_4() {
  // Dynamically loading multiple scripts with integrity
  const scripts = [
    {
      url: 'https://cdn.example.com/lib1.js',
      integrity: 'sha384-Q1/ZrxOAM5G7gJ2JLEaQXDHho3RXBGIFa7T/shrMcHHQbT9vJxbCQYrx8rkch1Wr'
    },
    {
      url: 'https://cdn.example.com/lib2.js',
      integrity: 'sha384-JZR6Spejh4U02d8jOt6vLEHfe/JQGiRRSQQxSfFWpi1MquVdAyjUar5+76PVCmYl'
    }
  ];
  
  scripts.forEach(script => {
    const el = document.createElement('script');
    el.src = script.url;
    // ok: javascript-integrity-check-external-script
    el.integrity = script.integrity;
    el.crossOrigin = 'anonymous';
    document.head.appendChild(el);
  });
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_5() {
  // Loading script based on environment with integrity
  const env = process.env.NODE_ENV || 'development';
  const scriptConfig = env === 'production' 
    ? {
        url: 'https://cdn.example.com/prod.js',
        integrity: 'sha384-7Er69WnAl0+tY1MYspqtqCMpXTqRYxR9LSrqJPAcnRuKu8RMp5B1K5eSgS5D5dqd'
      } 
    : {
        url: 'https://cdn.example.com/dev.js',
        integrity: 'sha384-JZR6Spejh4U02d8jOt6vLEHfe/JQGiRRSQQxSfFWpi1MquVdAyjUar5+76PVCmYl'
      };
  
  const script = document.createElement('script');
  script.src = scriptConfig.url;
  // ok: javascript-integrity-check-external-script
  script.integrity = scriptConfig.integrity;
  script.crossOrigin = 'anonymous';
  document.head.appendChild(script);
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_6() {
  // Using innerHTML with integrity
  const container = document.getElementById('scripts-container');
  const integrity = 'sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC';
  // ok: javascript-integrity-check-external-script
  container.innerHTML = `<script src="https://cdn.example.com/analytics.js" integrity="${integrity}" crossorigin="anonymous"></script>`;
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_7() {
  // Using document.write with integrity
  const scriptUrl = 'https://cdn.example.com/tracking.js';
  const integrity = 'sha384-Q1/ZrxOAM5G7gJ2JLEaQXDHho3RXBGIFa7T/shrMcHHQbT9vJxbCQYrx8rkch1Wr';
  // ok: javascript-integrity-check-external-script
  document.write(`<script src="${scriptUrl}" integrity="${integrity}" crossorigin="anonymous"></script>`);
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_8() {
  // Using third-party loader with integrity
  const loadScript = (url, integrity, callback) => {
    const script = document.createElement('script');
    script.onload = callback;
    script.src = url;
    // ok: javascript-integrity-check-external-script
    script.integrity = integrity;
    script.crossOrigin = 'anonymous';
    document.head.appendChild(script);
  };
  
  loadScript(
    'https://cdn.example.com/chart.js',
    'sha384-JZR6Spejh4U02d8jOt6vLEHfe/JQGiRRSQQxSfFWpi1MquVdAyjUar5+76PVCmYl',
    () => {
      console.log('Chart.js loaded');
    }
  );
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_9() {
  // Conditional script loading with integrity
  if (window.innerWidth > 768) {
    const script = document.createElement('script');
    script.src = 'https://cdn.example.com/desktop-features.js';
    // ok: javascript-integrity-check-external-script
    script.integrity = 'sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC';
    script.crossOrigin = 'anonymous';
    document.head.appendChild(script);
  } else {
    const script = document.createElement('script');
    script.src = 'https://cdn.example.com/mobile-features.js';
    // ok: javascript-integrity-check-external-script
    script.integrity = 'sha384-7Er69WnAl0+tY1MYspqtqCMpXTqRYxR9LSrqJPAcnRuKu8RMp5B1K5eSgS5D5dqd';
    script.crossOrigin = 'anonymous';
    document.head.appendChild(script);
  }
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_10() {
  // Using setAttribute with integrity
  const script = document.createElement('script');
  script.setAttribute('src', 'https://cdn.example.com/framework.js');
  // ok: javascript-integrity-check-external-script
  script.setAttribute('integrity', 'sha384-JZR6Spejh4U02d8jOt6vLEHfe/JQGiRRSQQxSfFWpi1MquVdAyjUar5+76PVCmYl');
  script.setAttribute('crossorigin', 'anonymous');
  document.head.appendChild(script);
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_11() {
  // Loading local script (no integrity needed)
  const script = document.createElement('script');
  // ok: javascript-integrity-check-external-script
  script.src = '/assets/js/local-script.js';
  document.head.appendChild(script);
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_12() {
  // Using async/defer with integrity
  const script = document.createElement('script');
  script.src = 'https://cdn.example.com/async-script.js';
  // ok: javascript-integrity-check-external-script
  script.integrity = 'sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC';
  script.crossOrigin = 'anonymous';
  script.async = true;
  script.defer = true;
  document.head.appendChild(script);
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_13() {
  // Using a function to determine script URL with integrity
  function getScriptConfig() {
    return {
      url: 'https://cdn.example.com/dynamic-script.js',
      integrity: 'sha384-JZR6Spejh4U02d8jOt6vLEHfe/JQGiRRSQQxSfFWpi1MquVdAyjUar5+76PVCmYl'
    };
  }
  
  const config = getScriptConfig();
  const script = document.createElement('script');
  script.src = config.url;
  // ok: javascript-integrity-check-external-script
  script.integrity = config.integrity;
  script.crossOrigin = 'anonymous';
  document.head.appendChild(script);
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_14() {
  // Using a promise to load script with integrity
  const loadScript = (url, integrity) => {
    return new Promise((resolve, reject) => {
      const script = document.createElement('script');
      script.onload = resolve;
      script.onerror = reject;
      script.src = url;
      // ok: javascript-integrity-check-external-script
      script.integrity = integrity;
      script.crossOrigin = 'anonymous';
      document.head.appendChild(script);
    });
  };
  
  loadScript(
    'https://cdn.example.com/promised-script.js',
    'sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC'
  )
    .then(() => console.log('Script loaded'))
    .catch(err => console.error('Script failed to load', err));
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_15() {
  // Using document fragment with integrity
  const fragment = document.createDocumentFragment();
  const script = document.createElement('script');
  script.src = 'https://cdn.example.com/fragment-script.js';
  // ok: javascript-integrity-check-external-script
  script.integrity = 'sha384-JZR6Spejh4U02d8jOt6vLEHfe/JQGiRRSQQxSfFWpi1MquVdAyjUar5+76PVCmYl';
  script.crossOrigin = 'anonymous';
  fragment.appendChild(script);
  document.head.appendChild(fragment);
}
// {/fact}