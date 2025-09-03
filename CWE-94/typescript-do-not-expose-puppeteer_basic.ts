import * as puppeteer from 'puppeteer';
import { Browser, launch } from 'puppeteer';

// True Positive Examples (Vulnerable Code)

// {fact rule=autoescape-disabled@v1.0 defects=1}
async function bad_case_1() {
  // Exposing remote debugging protocol to all interfaces
  const browser = await puppeteer.launch({
    // ruleid: typescript-do-not-expose-puppeteer
    args: ['--remote-debugging-address=0.0.0.0', '--remote-debugging-port=9222']
  });
  
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
async function bad_case_2() {
  // Exposing remote debugging protocol with different IP but still public
  // ruleid: typescript-do-not-expose-puppeteer
  const browser = await launch({
    headless: true,
    args: ['--remote-debugging-address=0.0.0.0', '--remote-debugging-port=9223']
  });
  
  await browser.newPage();
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
async function bad_case_3() {
  const options = {
    headless: false,
    // ruleid: typescript-do-not-expose-puppeteer
    args: ['--no-sandbox', '--remote-debugging-address=0.0.0.0']
  };
  
  const browser = await puppeteer.launch(options);
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
async function bad_case_4() {
  const debuggingArgs = ['--remote-debugging-address=0.0.0.0', '--remote-debugging-port=9222'];
  
  // ruleid: typescript-do-not-expose-puppeteer
  const browser = await puppeteer.launch({
    args: debuggingArgs
  });
  
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
async function bad_case_5() {
  const port = 9222;
  
  // ruleid: typescript-do-not-expose-puppeteer
  const browser = await puppeteer.launch({
    args: [`--remote-debugging-address=0.0.0.0`, `--remote-debugging-port=${port}`]
  });
  
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
async function bad_case_6() {
  const config = {
    // ruleid: typescript-do-not-expose-puppeteer
    args: ['--remote-debugging-address=0.0.0.0', '--remote-debugging-port=9222', '--no-sandbox']
  };
  
  const browser = await puppeteer.launch(config);
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
async function bad_case_7() {
  const args = [];
  args.push('--no-sandbox');
  args.push('--remote-debugging-address=0.0.0.0');
  args.push('--remote-debugging-port=9222');
  
  // ruleid: typescript-do-not-expose-puppeteer
  const browser = await puppeteer.launch({ args });
  
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
async function bad_case_8() {
  function getBrowserArgs() {
    return ['--remote-debugging-address=0.0.0.0', '--remote-debugging-port=9222'];
  }
  
  // ruleid: typescript-do-not-expose-puppeteer
  const browser = await puppeteer.launch({
    args: getBrowserArgs()
  });
  
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
async function bad_case_9() {
  const remoteDebuggingAddress = '0.0.0.0';
  const remoteDebuggingPort = 9222;
  
  // ruleid: typescript-do-not-expose-puppeteer
  const browser = await puppeteer.launch({
    args: [
      `--remote-debugging-address=${remoteDebuggingAddress}`,
      `--remote-debugging-port=${remoteDebuggingPort}`
    ]
  });
  
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
async function bad_case_10() {
  // Using template literals
  const address = '0.0.0.0';
  
  // ruleid: typescript-do-not-expose-puppeteer
  const browser = await puppeteer.launch({
    args: [`--remote-debugging-address=${address}`, '--remote-debugging-port=9222']
  });
  
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
async function bad_case_11() {
  // Using array spread
  const baseArgs = ['--no-sandbox'];
  const debugArgs = ['--remote-debugging-address=0.0.0.0', '--remote-debugging-port=9222'];
  
  // ruleid: typescript-do-not-expose-puppeteer
  const browser = await puppeteer.launch({
    args: [...baseArgs, ...debugArgs]
  });
  
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
async function bad_case_12() {
  // Using object spread
  const baseOptions = { headless: true };
  const debugOptions = {
    args: ['--remote-debugging-address=0.0.0.0', '--remote-debugging-port=9222']
  };
  
  // ruleid: typescript-do-not-expose-puppeteer
  const browser = await puppeteer.launch({
    ...baseOptions,
    ...debugOptions
  });
  
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
async function bad_case_13() {
  // Using conditional arguments
  const isDebug = true;
  const args = ['--no-sandbox'];
  
  if (isDebug) {
    args.push('--remote-debugging-address=0.0.0.0');
    args.push('--remote-debugging-port=9222');
  }
  
  // ruleid: typescript-do-not-expose-puppeteer
  const browser = await puppeteer.launch({ args });
  
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
async function bad_case_14() {
  // Using a map to generate args
  const debugSettings = new Map<string, string>([
    ['remote-debugging-address', '0.0.0.0'],
    ['remote-debugging-port', '9222']
  ]);
  
  const args = Array.from(debugSettings.entries()).map(([key, value]) => `--${key}=${value}`);
  
  // ruleid: typescript-do-not-expose-puppeteer
  const browser = await puppeteer.launch({ args });
  
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
async function bad_case_15() {
  // Using object destructuring and default parameters
  const createBrowser = async ({ address = '0.0.0.0', port = 9222 } = {}) => {
    // ruleid: typescript-do-not-expose-puppeteer
    return await puppeteer.launch({
      args: [`--remote-debugging-address=${address}`, `--remote-debugging-port=${port}`]
    });
  };
  
  const browser = await createBrowser();
  await browser.close();
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=autoescape-disabled@v1.0 defects=0}
async function good_case_1() {
  // Using localhost for remote debugging (not exposed to external networks)
  // ok: typescript-do-not-expose-puppeteer
  const browser = await puppeteer.launch({
    args: ['--remote-debugging-address=127.0.0.1', '--remote-debugging-port=9222']
  });
  
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
async function good_case_2() {
  // Not using remote debugging at all
  // ok: typescript-do-not-expose-puppeteer
  const browser = await puppeteer.launch({
    args: ['--no-sandbox']
  });
  
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
async function good_case_3() {
  // Using localhost explicitly
  // ok: typescript-do-not-expose-puppeteer
  const browser = await puppeteer.launch({
    args: ['--remote-debugging-address=localhost', '--remote-debugging-port=9222']
  });
  
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
async function good_case_4() {
  // Using empty args array
  // ok: typescript-do-not-expose-puppeteer
  const browser = await puppeteer.launch({
    args: []
  });
  
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
async function good_case_5() {
  // Not specifying args at all
  // ok: typescript-do-not-expose-puppeteer
  const browser = await puppeteer.launch({
    headless: true
  });
  
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
async function good_case_6() {
  const safeArgs = ['--no-sandbox', '--disable-setuid-sandbox'];
  
  // ok: typescript-do-not-expose-puppeteer
  const browser = await puppeteer.launch({
    args: safeArgs
  });
  
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
async function good_case_7() {
  // Using loopback address for debugging
  // ok: typescript-do-not-expose-puppeteer
  const browser = await puppeteer.launch({
    args: ['--remote-debugging-address=127.0.0.1']
  });
  
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
async function good_case_8() {
  function getSafeArgs() {
    return ['--no-sandbox', '--disable-dev-shm-usage'];
  }
  
  // ok: typescript-do-not-expose-puppeteer
  const browser = await puppeteer.launch({
    args: getSafeArgs()
  });
  
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
async function good_case_9() {
  // Using conditional args but only with safe options
  const isDebug = true;
  const args = ['--no-sandbox'];
  
  if (isDebug) {
    args.push('--remote-debugging-address=localhost');
    args.push('--remote-debugging-port=9222');
  }
  
  // ok: typescript-do-not-expose-puppeteer
  const browser = await puppeteer.launch({ args });
  
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
async function good_case_10() {
  // Using object spread with safe options
  const baseOptions = { headless: true };
  const debugOptions = {
    args: ['--remote-debugging-address=127.0.0.1', '--remote-debugging-port=9222']
  };
  
  // ok: typescript-do-not-expose-puppeteer
  const browser = await puppeteer.launch({
    ...baseOptions,
    ...debugOptions
  });
  
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
async function good_case_11() {
  // Using array spread with safe options
  const baseArgs = ['--no-sandbox'];
  const debugArgs = ['--remote-debugging-address=localhost', '--remote-debugging-port=9222'];
  
  // ok: typescript-do-not-expose-puppeteer
  const browser = await puppeteer.launch({
    args: [...baseArgs, ...debugArgs]
  });
  
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
async function good_case_12() {
  // Using a map to generate safe args
  const debugSettings = new Map<string, string>([
    ['remote-debugging-address', '127.0.0.1'],
    ['remote-debugging-port', '9222']
  ]);
  
  const args = Array.from(debugSettings.entries()).map(([key, value]) => `--${key}=${value}`);
  
  // ok: typescript-do-not-expose-puppeteer
  const browser = await puppeteer.launch({ args });
  
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
async function good_case_13() {
  // Using object destructuring and default parameters with safe values
  const createBrowser = async ({ address = 'localhost', port = 9222 } = {}) => {
    // ok: typescript-do-not-expose-puppeteer
    return await puppeteer.launch({
      args: [`--remote-debugging-address=${address}`, `--remote-debugging-port=${port}`]
    });
  };
  
  const browser = await createBrowser();
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
async function good_case_14() {
  // Using a different port but still localhost
  // ok: typescript-do-not-expose-puppeteer
  const browser = await puppeteer.launch({
    args: ['--remote-debugging-address=127.0.0.1', '--remote-debugging-port=9223']
  });
  
  await browser.close();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
async function good_case_15() {
  // Using puppeteer with completely different arguments
  // ok: typescript-do-not-expose-puppeteer
  const browser = await puppeteer.launch({
    headless: true,
    args: [
      '--disable-gpu',
      '--disable-dev-shm-usage',
      '--disable-setuid-sandbox',
      '--no-first-run',
      '--no-sandbox',
      '--no-zygote'
    ]
  });
  
  await browser.close();
}
// {/fact}