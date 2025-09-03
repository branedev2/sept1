const puppeteer = require('puppeteer');
const express = require('express');
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const url = require('url');

// True Positive Examples (Vulnerable Code)

// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_1() {
  // Launching browser with remote debugging enabled on all interfaces (0.0.0.0)
  // ruleid: exposed-puppeteer-chrome-devtools-ts-rule
  const browser = await puppeteer.launch({
    args: ['--remote-debugging-address=0.0.0.0', '--remote-debugging-port=9222']
  });
  
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_2() {
  // Exposing Chrome DevTools Protocol on a public IP
  // ruleid: exposed-puppeteer-chrome-devtools-ts-rule
  const browser = await puppeteer.launch({
    args: ['--remote-debugging-address=192.168.1.5', '--remote-debugging-port=9222']
  });
  
  await browser.newPage();
  console.log('Browser started with remote debugging');
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_3() {
  const options = {
    args: []
  };
  
  // Adding remote debugging flags dynamically
  options.args.push('--remote-debugging-address=0.0.0.0');
  options.args.push('--remote-debugging-port=9222');
  
  // ruleid: exposed-puppeteer-chrome-devtools-ts-rule
  const browser = await puppeteer.launch(options);
  
  const page = await browser.newPage();
  await page.goto('https://example.com');
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_4() {
  const debuggingPort = 9222;
  const debuggingAddress = '0.0.0.0';
  
  // Using template literals for arguments
  // ruleid: exposed-puppeteer-chrome-devtools-ts-rule
  const browser = await puppeteer.launch({
    args: [`--remote-debugging-address=${debuggingAddress}`, `--remote-debugging-port=${debuggingPort}`]
  });
  
  await browser.newPage();
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_5() {
  const config = {
    remoteDebugging: true,
    port: 9222,
    address: '0.0.0.0'
  };
  
  const args = [];
  if (config.remoteDebugging) {
    args.push(`--remote-debugging-address=${config.address}`);
    args.push(`--remote-debugging-port=${config.port}`);
  }
  
  // ruleid: exposed-puppeteer-chrome-devtools-ts-rule
  const browser = await puppeteer.launch({ args });
  
  const page = await browser.newPage();
  await page.goto('https://example.com');
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_6() {
  const userConfig = {
    debug: true,
    port: 9222
  };
  
  const launchOptions = {
    headless: true,
    args: []
  };
  
  if (userConfig.debug) {
    launchOptions.args.push('--remote-debugging-address=0.0.0.0');
    launchOptions.args.push(`--remote-debugging-port=${userConfig.port}`);
  }
  
  // ruleid: exposed-puppeteer-chrome-devtools-ts-rule
  const browser = await puppeteer.launch(launchOptions);
  
  await browser.newPage();
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_7() {
  const app = express();
  
  app.get('/start-browser', async (req, res) => {
    const port = req.query.port || 9222;
    
    // ruleid: exposed-puppeteer-chrome-devtools-ts-rule
    const browser = await puppeteer.launch({
      args: ['--remote-debugging-address=0.0.0.0', `--remote-debugging-port=${port}`]
    });
    
    res.send('Browser started with remote debugging');
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_8() {
  function getBrowserArgs() {
    return ['--remote-debugging-address=0.0.0.0', '--remote-debugging-port=9222'];
  }
  
  // ruleid: exposed-puppeteer-chrome-devtools-ts-rule
  const browser = await puppeteer.launch({
    args: getBrowserArgs()
  });
  
  const page = await browser.newPage();
  await page.goto('https://example.com');
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_9() {
  const debugOptions = {
    enabled: true,
    address: '0.0.0.0',
    port: 9222
  };
  
  const browserArgs = [];
  
  if (debugOptions.enabled) {
    browserArgs.push(`--remote-debugging-address=${debugOptions.address}`);
    browserArgs.push(`--remote-debugging-port=${debugOptions.port}`);
  }
  
  // ruleid: exposed-puppeteer-chrome-devtools-ts-rule
  const browser = await puppeteer.launch({
    headless: true,
    args: browserArgs
  });
  
  await browser.newPage();
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_10() {
  const environments = {
    development: {
      remoteDebugging: true,
      address: '0.0.0.0',
      port: 9222
    },
    production: {
      remoteDebugging: false
    }
  };
  
  const env = 'development';
  const config = environments[env];
  const args = [];
  
  if (config.remoteDebugging) {
    args.push(`--remote-debugging-address=${config.address}`);
    args.push(`--remote-debugging-port=${config.port}`);
  }
  
  // ruleid: exposed-puppeteer-chrome-devtools-ts-rule
  const browser = await puppeteer.launch({ args });
  
  await browser.newPage();
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_11() {
  // Using array spread to combine arguments
  const debugArgs = ['--remote-debugging-address=0.0.0.0', '--remote-debugging-port=9222'];
  const otherArgs = ['--no-sandbox', '--disable-setuid-sandbox'];
  
  // ruleid: exposed-puppeteer-chrome-devtools-ts-rule
  const browser = await puppeteer.launch({
    args: [...debugArgs, ...otherArgs]
  });
  
  await browser.newPage();
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_12() {
  const settings = {
    debug: {
      remote: true,
      address: '0.0.0.0',
      port: 9222
    }
  };
  
  const args = [];
  
  if (settings.debug.remote) {
    const { address, port } = settings.debug;
    args.push(`--remote-debugging-address=${address}`);
    args.push(`--remote-debugging-port=${port}`);
  }
  
  // ruleid: exposed-puppeteer-chrome-devtools-ts-rule
  const browser = await puppeteer.launch({ args });
  
  const page = await browser.newPage();
  await page.goto('https://example.com');
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_13() {
  // Using a function to configure browser launch options
  function configureBrowser(enableRemoteDebugging) {
    const options = {
      headless: true,
      args: ['--no-sandbox']
    };
    
    if (enableRemoteDebugging) {
      options.args.push('--remote-debugging-address=0.0.0.0');
      options.args.push('--remote-debugging-port=9222');
    }
    
    return options;
  }
  
  // ruleid: exposed-puppeteer-chrome-devtools-ts-rule
  const browser = await puppeteer.launch(configureBrowser(true));
  
  await browser.newPage();
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_14() {
  const app = express();
  
  app.post('/start-browser', async (req, res) => {
    const { enableDebugging } = req.body;
    const options = { args: [] };
    
    if (enableDebugging) {
      options.args.push('--remote-debugging-address=0.0.0.0');
      options.args.push('--remote-debugging-port=9222');
    }
    
    // ruleid: exposed-puppeteer-chrome-devtools-ts-rule
    const browser = await puppeteer.launch(options);
    
    res.send('Browser started');
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_15() {
  const remoteDebuggingConfig = {
    enabled: true,
    address: '0.0.0.0',
    port: 9222
  };
  
  const puppeteerConfig = {
    headless: false,
    defaultViewport: null,
    args: []
  };
  
  if (remoteDebuggingConfig.enabled) {
    puppeteerConfig.args.push(`--remote-debugging-address=${remoteDebuggingConfig.address}`);
    puppeteerConfig.args.push(`--remote-debugging-port=${remoteDebuggingConfig.port}`);
  }
  
  // ruleid: exposed-puppeteer-chrome-devtools-ts-rule
  const browser = await puppeteer.launch(puppeteerConfig);
  
  await browser.newPage();
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_1() {
  // Using localhost for remote debugging (not exposed externally)
  // ok: exposed-puppeteer-chrome-devtools-ts-rule
  const browser = await puppeteer.launch({
    args: ['--remote-debugging-address=127.0.0.1', '--remote-debugging-port=9222']
  });
  
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_2() {
  // Not using remote debugging at all
  // ok: exposed-puppeteer-chrome-devtools-ts-rule
  const browser = await puppeteer.launch({
    headless: true,
    args: ['--no-sandbox']
  });
  
  await browser.newPage();
  console.log('Browser started without remote debugging');
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_3() {
  const options = {
    args: []
  };
  
  // Adding only localhost debugging
  options.args.push('--remote-debugging-address=localhost');
  options.args.push('--remote-debugging-port=9222');
  
  // ok: exposed-puppeteer-chrome-devtools-ts-rule
  const browser = await puppeteer.launch(options);
  
  const page = await browser.newPage();
  await page.goto('https://example.com');
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_4() {
  const debuggingPort = 9222;
  
  // Using only port without exposing to all interfaces
  // ok: exposed-puppeteer-chrome-devtools-ts-rule
  const browser = await puppeteer.launch({
    args: [`--remote-debugging-port=${debuggingPort}`]
  });
  
  await browser.newPage();
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_5() {
  const config = {
    remoteDebugging: true,
    port: 9222,
    address: 'localhost'  // Using localhost instead of 0.0.0.0
  };
  
  const args = [];
  if (config.remoteDebugging) {
    args.push(`--remote-debugging-address=${config.address}`);
    args.push(`--remote-debugging-port=${config.port}`);
  }
  
  // ok: exposed-puppeteer-chrome-devtools-ts-rule
  const browser = await puppeteer.launch({ args });
  
  const page = await browser.newPage();
  await page.goto('https://example.com');
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_6() {
  const userConfig = {
    debug: true,
    port: 9222
  };
  
  const launchOptions = {
    headless: true,
    args: []
  };
  
  if (userConfig.debug) {
    launchOptions.args.push('--remote-debugging-address=127.0.0.1');
    launchOptions.args.push(`--remote-debugging-port=${userConfig.port}`);
  }
  
  // ok: exposed-puppeteer-chrome-devtools-ts-rule
  const browser = await puppeteer.launch(launchOptions);
  
  await browser.newPage();
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_7() {
  const app = express();
  
  app.get('/start-browser', async (req, res) => {
    const port = req.query.port || 9222;
    
    // ok: exposed-puppeteer-chrome-devtools-ts-rule
    const browser = await puppeteer.launch({
      args: ['--remote-debugging-address=localhost', `--remote-debugging-port=${port}`]
    });
    
    res.send('Browser started with secure remote debugging');
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_8() {
  function getBrowserArgs() {
    return ['--remote-debugging-address=127.0.0.1', '--remote-debugging-port=9222'];
  }
  
  // ok: exposed-puppeteer-chrome-devtools-ts-rule
  const browser = await puppeteer.launch({
    args: getBrowserArgs()
  });
  
  const page = await browser.newPage();
  await page.goto('https://example.com');
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_9() {
  // Using a secure tunnel for remote debugging
  // ok: exposed-puppeteer-chrome-devtools-ts-rule
  const browser = await puppeteer.launch({
    args: ['--remote-debugging-port=9222']  // Only specifying port, defaults to localhost
  });
  
  console.log('Set up SSH tunnel with: ssh -L 9222:localhost:9222 user@server');
  await browser.newPage();
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_10() {
  const environments = {
    development: {
      remoteDebugging: true,
      address: 'localhost',  // Using localhost instead of 0.0.0.0
      port: 9222
    },
    production: {
      remoteDebugging: false
    }
  };
  
  const env = 'development';
  const config = environments[env];
  const args = [];
  
  if (config.remoteDebugging) {
    args.push(`--remote-debugging-address=${config.address}`);
    args.push(`--remote-debugging-port=${config.port}`);
  }
  
  // ok: exposed-puppeteer-chrome-devtools-ts-rule
  const browser = await puppeteer.launch({ args });
  
  await browser.newPage();
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_11() {
  // Using a secure configuration with authentication proxy
  // ok: exposed-puppeteer-chrome-devtools-ts-rule
  const browser = await puppeteer.launch({
    args: ['--remote-debugging-address=127.0.0.1', '--remote-debugging-port=9222']
  });
  
  console.log('Browser started with debugging on localhost only');
  console.log('Access is secured through an authentication proxy');
  
  await browser.newPage();
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_12() {
  // Using environment variables for configuration with secure defaults
  const debugAddress = process.env.DEBUG_ADDRESS || 'localhost';
  const debugPort = process.env.DEBUG_PORT || '9222';
  
  // ok: exposed-puppeteer-chrome-devtools-ts-rule
  const browser = await puppeteer.launch({
    args: [
      `--remote-debugging-address=${debugAddress}`,
      `--remote-debugging-port=${debugPort}`
    ]
  });
  
  await browser.newPage();
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_13() {
  // Using a function to configure browser launch options with secure defaults
  function configureBrowser(enableRemoteDebugging) {
    const options = {
      headless: true,
      args: ['--no-sandbox']
    };
    
    if (enableRemoteDebugging) {
      options.args.push('--remote-debugging-address=127.0.0.1');
      options.args.push('--remote-debugging-port=9222');
    }
    
    return options;
  }
  
  // ok: exposed-puppeteer-chrome-devtools-ts-rule
  const browser = await puppeteer.launch(configureBrowser(true));
  
  await browser.newPage();
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_14() {
  // Using a firewall to restrict access
  // ok: exposed-puppeteer-chrome-devtools-ts-rule
  const browser = await puppeteer.launch({
    args: ['--remote-debugging-port=9222']  // Default to localhost
  });
  
  console.log('Browser started with debugging on localhost');
  console.log('Firewall is configured to restrict access to trusted IPs only');
  
  await browser.newPage();
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_15() {
  // Using a secure VPN for remote access
  // ok: exposed-puppeteer-chrome-devtools-ts-rule
  const browser = await puppeteer.launch({
    args: ['--remote-debugging-address=127.0.0.1', '--remote-debugging-port=9222']
  });
  
  console.log('Browser started with debugging on localhost');
  console.log('Access is restricted through VPN');
  
  await browser.newPage();
}
// {/fact}