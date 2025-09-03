const { chromium, firefox, webkit } = require('playwright');
const http = require('http');
const express = require('express');

// True Positive Examples (Vulnerable Code)

// {fact rule=autoescape-disabled@v1.0 defects=1}
async function bad_case_1() {
  // Launching browser with exposed devtools on a public port
  const browser = await chromium.launch({
    // ruleid: javascript-playwright-exposed-chrome-devtools
    args: ['--remote-debugging-port=9222', '--remote-debugging-address=0.0.0.0']
  });
  
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
async function bad_case_2() {
  const debugPort = 9223;
  // Exposing devtools on a variable port
  // ruleid: javascript-playwright-exposed-chrome-devtools
  const browser = await chromium.launch({
    args: [`--remote-debugging-port=${debugPort}`, '--remote-debugging-address=0.0.0.0']
  });
  
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
async function bad_case_3() {
  // Using an environment variable but still exposing to all interfaces
  const port = process.env.DEBUG_PORT || 9224;
  // ruleid: javascript-playwright-exposed-chrome-devtools
  const browser = await chromium.launch({
    args: [`--remote-debugging-port=${port}`, '--remote-debugging-address=0.0.0.0']
  });
  
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
async function bad_case_4() {
  // Exposing devtools in a function that handles user requests
  const app = express();
  
  app.get('/run-browser', async (req, res) => {
    // ruleid: javascript-playwright-exposed-chrome-devtools
    const browser = await chromium.launch({
      args: ['--remote-debugging-port=9225', '--remote-debugging-address=0.0.0.0']
    });
    
    const page = await browser.newPage();
    await page.goto('https://example.com');
    res.send('Browser launched');
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
async function bad_case_5() {
  // Exposing devtools with additional insecure flags
  // ruleid: javascript-playwright-exposed-chrome-devtools
  const browser = await chromium.launch({
    args: [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--remote-debugging-port=9226',
      '--remote-debugging-address=0.0.0.0'
    ]
  });
  
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
async function bad_case_6() {
  // Using string concatenation to build args
  const debuggingArgs = '--remote-debugging-port=9227 --remote-debugging-address=0.0.0.0';
  const args = ['--no-sandbox', ...debuggingArgs.split(' ')];
  
  // ruleid: javascript-playwright-exposed-chrome-devtools
  const browser = await chromium.launch({ args });
  
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
async function bad_case_7() {
  // Using an array of arguments with exposed devtools
  const browserArgs = [];
  browserArgs.push('--no-sandbox');
  browserArgs.push('--remote-debugging-port=9228');
  browserArgs.push('--remote-debugging-address=0.0.0.0');
  
  // ruleid: javascript-playwright-exposed-chrome-devtools
  const browser = await chromium.launch({
    args: browserArgs
  });
  
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
async function bad_case_8() {
  // Using object spread to combine configurations
  const debugConfig = {
    args: ['--remote-debugging-port=9229', '--remote-debugging-address=0.0.0.0']
  };
  
  // ruleid: javascript-playwright-exposed-chrome-devtools
  const browser = await chromium.launch({
    ...debugConfig,
    headless: false
  });
  
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
async function bad_case_9() {
  // Using Firefox with exposed devtools
  // ruleid: javascript-playwright-exposed-chrome-devtools
  const browser = await firefox.launch({
    args: ['--remote-debugging-port=9230', '--remote-debugging-address=0.0.0.0']
  });
  
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
async function bad_case_10() {
  // Using WebKit with exposed devtools
  // ruleid: javascript-playwright-exposed-chrome-devtools
  const browser = await webkit.launch({
    args: ['--remote-debugging-port=9231', '--remote-debugging-address=0.0.0.0']
  });
  
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
async function bad_case_11() {
  // Using a function to generate args
  function getBrowserArgs() {
    return ['--remote-debugging-port=9232', '--remote-debugging-address=0.0.0.0'];
  }
  
  // ruleid: javascript-playwright-exposed-chrome-devtools
  const browser = await chromium.launch({
    args: getBrowserArgs()
  });
  
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
async function bad_case_12() {
  // Using conditional logic but still exposing devtools
  const isDebug = true;
  const args = ['--no-sandbox'];
  
  if (isDebug) {
    args.push('--remote-debugging-port=9233');
    args.push('--remote-debugging-address=0.0.0.0');
  }
  
  // ruleid: javascript-playwright-exposed-chrome-devtools
  const browser = await chromium.launch({ args });
  
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
async function bad_case_13() {
  // Using a map to generate args
  const debugOptions = new Map([
    ['port', '9234'],
    ['address', '0.0.0.0']
  ]);
  
  // ruleid: javascript-playwright-exposed-chrome-devtools
  const browser = await chromium.launch({
    args: [
      `--remote-debugging-port=${debugOptions.get('port')}`,
      `--remote-debugging-address=${debugOptions.get('address')}`
    ]
  });
  
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
async function bad_case_14() {
  // Using template literals
  const port = 9235;
  const address = '0.0.0.0';
  
  // ruleid: javascript-playwright-exposed-chrome-devtools
  const browser = await chromium.launch({
    args: [`--remote-debugging-port=${port}`, `--remote-debugging-address=${address}`]
  });
  
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
async function bad_case_15() {
  // Using a configuration object
  const config = {
    debugging: {
      enabled: true,
      port: 9236,
      address: '0.0.0.0'
    }
  };
  
  const args = [];
  if (config.debugging.enabled) {
    args.push(`--remote-debugging-port=${config.debugging.port}`);
    args.push(`--remote-debugging-address=${config.debugging.address}`);
  }
  
  // ruleid: javascript-playwright-exposed-chrome-devtools
  const browser = await chromium.launch({ args });
  
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// True Negative Examples (Safe Code)

// {fact rule=autoescape-disabled@v1.0 defects=0}
async function good_case_1() {
  // Launching browser without exposing devtools
  // ok: javascript-playwright-exposed-chrome-devtools
  const browser = await chromium.launch({
    headless: true
  });
  
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
async function good_case_2() {
  // Using args but not exposing devtools
  // ok: javascript-playwright-exposed-chrome-devtools
  const browser = await chromium.launch({
    args: ['--no-sandbox', '--disable-setuid-sandbox']
  });
  
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
async function good_case_3() {
  // Exposing devtools only to localhost (secure)
  // ok: javascript-playwright-exposed-chrome-devtools
  const browser = await chromium.launch({
    args: ['--remote-debugging-port=9222', '--remote-debugging-address=127.0.0.1']
  });
  
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
async function good_case_4() {
  // Using localhost explicitly for debugging
  const debugPort = 9223;
  
  // ok: javascript-playwright-exposed-chrome-devtools
  const browser = await chromium.launch({
    args: [`--remote-debugging-port=${debugPort}`, '--remote-debugging-address=localhost']
  });
  
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
async function good_case_5() {
  // Using Firefox without exposing devtools
  // ok: javascript-playwright-exposed-chrome-devtools
  const browser = await firefox.launch({
    headless: false
  });
  
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
async function good_case_6() {
  // Using WebKit without exposing devtools
  // ok: javascript-playwright-exposed-chrome-devtools
  const browser = await webkit.launch({
    args: ['--no-sandbox']
  });
  
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
async function good_case_7() {
  // Using a function to generate safe args
  function getSafeArgs() {
    return ['--no-sandbox', '--disable-gpu'];
  }
  
  // ok: javascript-playwright-exposed-chrome-devtools
  const browser = await chromium.launch({
    args: getSafeArgs()
  });
  
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
async function good_case_8() {
  // Using conditional logic with safe options
  const isDebug = true;
  const args = ['--no-sandbox'];
  
  if (isDebug) {
    // Only expose to localhost if debugging is enabled
    args.push('--remote-debugging-port=9224');
    args.push('--remote-debugging-address=127.0.0.1');
  }
  
  // ok: javascript-playwright-exposed-chrome-devtools
  const browser = await chromium.launch({ args });
  
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
async function good_case_9() {
  // Using object spread with safe configurations
  const safeConfig = {
    args: ['--no-sandbox']
  };
  
  // ok: javascript-playwright-exposed-chrome-devtools
  const browser = await chromium.launch({
    ...safeConfig,
    headless: true
  });
  
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
async function good_case_10() {
  // Using an array of safe arguments
  const browserArgs = [];
  browserArgs.push('--no-sandbox');
  browserArgs.push('--disable-gpu');
  
  // ok: javascript-playwright-exposed-chrome-devtools
  const browser = await chromium.launch({
    args: browserArgs
  });
  
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
async function good_case_11() {
  // Using environment variables for safe configuration
  const headless = process.env.HEADLESS === 'true';
  
  // ok: javascript-playwright-exposed-chrome-devtools
  const browser = await chromium.launch({
    headless,
    args: ['--no-sandbox']
  });
  
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
async function good_case_12() {
  // Using a map for safe configuration
  const browserOptions = new Map([
    ['headless', true],
    ['sandbox', false]
  ]);
  
  const args = [];
  if (!browserOptions.get('sandbox')) {
    args.push('--no-sandbox');
  }
  
  // ok: javascript-playwright-exposed-chrome-devtools
  const browser = await chromium.launch({
    headless: browserOptions.get('headless'),
    args
  });
  
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
async function good_case_13() {
  // Using template literals for safe configuration
  const noSandbox = true;
  
  // ok: javascript-playwright-exposed-chrome-devtools
  const browser = await chromium.launch({
    args: noSandbox ? ['--no-sandbox'] : []
  });
  
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
async function good_case_14() {
  // Using a configuration object with safe settings
  const config = {
    browser: {
      headless: true,
      args: ['--no-sandbox', '--disable-gpu']
    }
  };
  
  // ok: javascript-playwright-exposed-chrome-devtools
  const browser = await chromium.launch({
    headless: config.browser.headless,
    args: config.browser.args
  });
  
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
async function good_case_15() {
  // Using a secure debugging setup with proper access control
  // This example shows how to properly set up debugging if needed
  const isLocalDevelopment = process.env.NODE_ENV === 'development';
  
  let args = ['--no-sandbox'];
  if (isLocalDevelopment) {
    // Only enable debugging on localhost for development
    args.push('--remote-debugging-port=9225');
    args.push('--remote-debugging-address=127.0.0.1');
  }
  
  // ok: javascript-playwright-exposed-chrome-devtools
  const browser = await chromium.launch({ args });
  
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}