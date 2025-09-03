// File: puppeteer_security_examples.js
const puppeteer = require('puppeteer');
const express = require('express');
const http = require('http');
const fs = require('fs');
const path = require('path');
const dotenv = require('dotenv');

// True Positive Examples (Vulnerable Code)

// {fact rule=autoescape-disabled@v1.0 defects=1}
async function bad_case_1() {
  // Launching browser with remote debugging port exposed to all interfaces
  // ruleid: javascript-do-not-expose-puppeteer
  const browser = await puppeteer.launch({
    args: ['--remote-debugging-port=9222', '--remote-debugging-address=0.0.0.0']
  });
  
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
async function bad_case_2() {
  // Exposing remote debugging with no IP restriction
  // ruleid: javascript-do-not-expose-puppeteer
  const browser = await puppeteer.launch({
    args: ['--remote-debugging-port=9223']
  });
  
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
async function bad_case_3() {
  const debugPort = 9224;
  // Exposing remote debugging with variable port
  // ruleid: javascript-do-not-expose-puppeteer
  const browser = await puppeteer.launch({
    args: [`--remote-debugging-port=${debugPort}`, '--no-sandbox']
  });
  
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
async function bad_case_4() {
  const options = {
    args: ['--remote-debugging-port=9225', '--disable-gpu']
  };
  
  // Using options object to expose remote debugging
  // ruleid: javascript-do-not-expose-puppeteer
  const browser = await puppeteer.launch(options);
  
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
async function bad_case_5() {
  const args = [];
  args.push('--remote-debugging-port=9226');
  args.push('--no-sandbox');
  
  // Building args array dynamically to expose remote debugging
  // ruleid: javascript-do-not-expose-puppeteer
  const browser = await puppeteer.launch({ args });
  
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
async function bad_case_6() {
  const config = {
    port: 9227,
    args: [`--remote-debugging-port=9227`, '--remote-debugging-address=0.0.0.0']
  };
  
  // Using configuration object with nested args
  // ruleid: javascript-do-not-expose-puppeteer
  const browser = await puppeteer.launch(config);
  
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
async function bad_case_7() {
  // Using template literals to construct args with remote debugging
  const port = 9228;
  const address = '0.0.0.0';
  
  // ruleid: javascript-do-not-expose-puppeteer
  const browser = await puppeteer.launch({
    args: [`--remote-debugging-port=${port}`, `--remote-debugging-address=${address}`]
  });
  
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
async function bad_case_8() {
  // Using conditional to always enable remote debugging
  const isDebug = true;
  const args = ['--no-sandbox'];
  
  if (isDebug) {
    args.push('--remote-debugging-port=9229');
  }
  
  // ruleid: javascript-do-not-expose-puppeteer
  const browser = await puppeteer.launch({ args });
  
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
async function bad_case_9() {
  // Using spread operator with remote debugging args
  const debugArgs = ['--remote-debugging-port=9230'];
  const standardArgs = ['--no-sandbox', '--disable-gpu'];
  
  // ruleid: javascript-do-not-expose-puppeteer
  const browser = await puppeteer.launch({
    args: [...debugArgs, ...standardArgs]
  });
  
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
async function bad_case_10() {
  // Using object destructuring and remote debugging
  const options = {
    headless: true,
    args: ['--remote-debugging-port=9231']
  };
  
  const { headless, args } = options;
  
  // ruleid: javascript-do-not-expose-puppeteer
  const browser = await puppeteer.launch({ headless, args });
  
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
async function bad_case_11() {
  // Using a function to generate args with remote debugging
  function getArgs() {
    return ['--remote-debugging-port=9232', '--no-sandbox'];
  }
  
  // ruleid: javascript-do-not-expose-puppeteer
  const browser = await puppeteer.launch({
    args: getArgs()
  });
  
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
async function bad_case_12() {
  // Using array methods to add remote debugging
  const args = ['--no-sandbox'];
  args.unshift('--remote-debugging-port=9233');
  
  // ruleid: javascript-do-not-expose-puppeteer
  const browser = await puppeteer.launch({ args });
  
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
async function bad_case_13() {
  // Using environment variable but still exposing remote debugging
  const port = process.env.DEBUG_PORT || 9234;
  
  // ruleid: javascript-do-not-expose-puppeteer
  const browser = await puppeteer.launch({
    args: [`--remote-debugging-port=${port}`, '--remote-debugging-address=0.0.0.0']
  });
  
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
async function bad_case_14() {
  // Using multiple browser instances with remote debugging
  // ruleid: javascript-do-not-expose-puppeteer
  const browser1 = await puppeteer.launch({
    args: ['--remote-debugging-port=9235']
  });
  
  const browser2 = await puppeteer.launch({
    headless: false
  });
  
  const page = await browser1.newPage();
  await page.goto('https://example.com');
  await browser1.close();
  await browser2.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
async function bad_case_15() {
  // Using remote debugging with a try-catch block
  try {
    // ruleid: javascript-do-not-expose-puppeteer
    const browser = await puppeteer.launch({
      args: ['--remote-debugging-port=9236', '--remote-debugging-address=0.0.0.0']
    });
    
    const page = await browser.newPage();
    await page.goto('https://example.com');
    await browser.close();
  } catch (error) {
    console.error('Failed to launch browser:', error);
  }
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=autoescape-disabled@v1.0 defects=0}
async function good_case_1() {
  // Using puppeteer without exposing remote debugging
  // ok: javascript-do-not-expose-puppeteer
  const browser = await puppeteer.launch({
    headless: true
  });
  
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
async function good_case_2() {
  // Using puppeteer with safe arguments
  // ok: javascript-do-not-expose-puppeteer
  const browser = await puppeteer.launch({
    args: ['--no-sandbox', '--disable-gpu']
  });
  
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
async function good_case_3() {
  const options = {
    headless: true,
    defaultViewport: { width: 1280, height: 800 }
  };
  
  // Using options object without remote debugging
  // ok: javascript-do-not-expose-puppeteer
  const browser = await puppeteer.launch(options);
  
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
async function good_case_4() {
  const args = [];
  args.push('--no-sandbox');
  args.push('--disable-setuid-sandbox');
  
  // Building args array dynamically without remote debugging
  // ok: javascript-do-not-expose-puppeteer
  const browser = await puppeteer.launch({ args });
  
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
async function good_case_5() {
  // Using puppeteer with CDP but not exposing remote debugging port
  // ok: javascript-do-not-expose-puppeteer
  const browser = await puppeteer.launch();
  const page = await browser.newPage();
  
  // Using CDP directly through puppeteer's API instead of exposing port
  const client = await page.target().createCDPSession();
  await client.send('Network.enable');
  
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
async function good_case_6() {
  // Using environment variables for configuration without remote debugging
  const width = process.env.VIEWPORT_WIDTH || 1280;
  const height = process.env.VIEWPORT_HEIGHT || 800;
  
  // ok: javascript-do-not-expose-puppeteer
  const browser = await puppeteer.launch({
    defaultViewport: { width: parseInt(width), height: parseInt(height) }
  });
  
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
async function good_case_7() {
  // Using conditional to determine headless mode but not exposing debugging
  const isHeadless = process.env.NODE_ENV === 'production';
  
  // ok: javascript-do-not-expose-puppeteer
  const browser = await puppeteer.launch({
    headless: isHeadless,
    args: ['--no-sandbox']
  });
  
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
async function good_case_8() {
  // Using spread operator with safe args
  const standardArgs = ['--no-sandbox', '--disable-gpu'];
  const performanceArgs = ['--disable-dev-shm-usage', '--disable-accelerated-2d-canvas'];
  
  // ok: javascript-do-not-expose-puppeteer
  const browser = await puppeteer.launch({
    args: [...standardArgs, ...performanceArgs]
  });
  
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
async function good_case_9() {
  // Using object destructuring with safe options
  const options = {
    headless: true,
    defaultViewport: null,
    args: ['--no-sandbox']
  };
  
  const { headless, defaultViewport, args } = options;
  
  // ok: javascript-do-not-expose-puppeteer
  const browser = await puppeteer.launch({ headless, defaultViewport, args });
  
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
async function good_case_10() {
  // Using a function to generate safe args
  function getArgs() {
    return ['--no-sandbox', '--disable-setuid-sandbox'];
  }
  
  // ok: javascript-do-not-expose-puppeteer
  const browser = await puppeteer.launch({
    args: getArgs()
  });
  
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
async function good_case_11() {
  // Using array methods to add safe args
  const args = [];
  args.push('--no-sandbox');
  args.push('--disable-gpu');
  
  // ok: javascript-do-not-expose-puppeteer
  const browser = await puppeteer.launch({ args });
  
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
async function good_case_12() {
  // Using try-catch with safe configuration
  try {
    // ok: javascript-do-not-expose-puppeteer
    const browser = await puppeteer.launch({
      headless: true,
      args: ['--no-sandbox']
    });
    
    const page = await browser.newPage();
    await page.goto('https://example.com');
    await browser.close();
  } catch (error) {
    console.error('Failed to launch browser:', error);
  }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
async function good_case_13() {
  // Using puppeteer with custom user data dir but no remote debugging
  const userDataDir = path.join(__dirname, 'user_data');
  
  // ok: javascript-do-not-expose-puppeteer
  const browser = await puppeteer.launch({
    userDataDir,
    args: ['--no-sandbox']
  });
  
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
async function good_case_14() {
  // Using puppeteer with multiple browser instances, all secure
  // ok: javascript-do-not-expose-puppeteer
  const browser1 = await puppeteer.launch({
    headless: true,
    args: ['--no-sandbox']
  });
  
  const browser2 = await puppeteer.launch({
    headless: false,
    args: ['--disable-gpu']
  });
  
  const page = await browser1.newPage();
  await page.goto('https://example.com');
  await browser1.close();
  await browser2.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
async function good_case_15() {
  // Using puppeteer with a proxy but no remote debugging
  // ok: javascript-do-not-expose-puppeteer
  const browser = await puppeteer.launch({
    args: [
      '--no-sandbox',
      '--proxy-server=http://proxy.example.com:8080'
    ]
  });
  
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// Main execution
(async () => {
  console.log('Running Puppeteer security examples...');
  // Examples would be called here in a real application
})();