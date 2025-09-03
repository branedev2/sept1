import { chromium, firefox, webkit, devices } from 'playwright';
import { test, expect } from '@playwright/test';

// True Positive Examples (Vulnerable Code)

// Example 1: Basic launch with exposed devtools
// {fact rule=autoescape-disabled@v1.0 defects=1}
async function bad_case_1() {
  // ruleid: typescript-playwright-exposed-chrome-devtools
  const browser = await chromium.launch({
    devtools: true,
    args: ['--remote-debugging-port=9222']
  });
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// Example 2: Using headless mode with exposed debugging port
// {fact rule=autoescape-disabled@v1.0 defects=1}
async function bad_case_2() {
  // ruleid: typescript-playwright-exposed-chrome-devtools
  const browser = await chromium.launch({
    headless: true,
    args: ['--remote-debugging-port=9223']
  });
  const context = await browser.newContext();
  const page = await context.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// Example 3: Exposing devtools on a specific address
// {fact rule=autoescape-disabled@v1.0 defects=1}
async function bad_case_3() {
  // ruleid: typescript-playwright-exposed-chrome-devtools
  const browser = await chromium.launch({
    args: ['--remote-debugging-address=0.0.0.0', '--remote-debugging-port=9224']
  });
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// Example 4: Using Firefox with exposed debugging port
// {fact rule=autoescape-disabled@v1.0 defects=1}
async function bad_case_4() {
  // ruleid: typescript-playwright-exposed-chrome-devtools
  const browser = await firefox.launch({
    args: ['-remote-debugging-port', '9225']
  });
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// Example 5: Using WebKit with exposed debugging port
// {fact rule=autoescape-disabled@v1.0 defects=1}
async function bad_case_5() {
  // ruleid: typescript-playwright-exposed-chrome-devtools
  const browser = await webkit.launch({
    args: ['--remote-debugging-port=9226']
  });
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// Example 6: Using environment variable but still exposing port
// {fact rule=autoescape-disabled@v1.0 defects=1}
async function bad_case_6() {
  const debugPort = process.env.DEBUG_PORT || '9227';
  // ruleid: typescript-playwright-exposed-chrome-devtools
  const browser = await chromium.launch({
    args: [`--remote-debugging-port=${debugPort}`]
  });
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// Example 7: Exposing devtools in a test
// {fact rule=autoescape-disabled@v1.0 defects=1}
async function bad_case_7() {
  test('Test with exposed devtools', async () => {
    // ruleid: typescript-playwright-exposed-chrome-devtools
    const browser = await chromium.launch({
      args: ['--remote-debugging-port=9228']
    });
    const page = await browser.newPage();
    await page.goto('https://example.com');
    await expect(page).toHaveTitle('Example Domain');
    await browser.close();
  });
}
// {/fact}

// Example 8: Using a variable for args but still exposing port
// {fact rule=autoescape-disabled@v1.0 defects=1}
async function bad_case_8() {
  const launchArgs = ['--no-sandbox', '--remote-debugging-port=9229'];
  // ruleid: typescript-playwright-exposed-chrome-devtools
  const browser = await chromium.launch({
    args: launchArgs
  });
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// Example 9: Using a function to generate args but still exposing port
// {fact rule=autoescape-disabled@v1.0 defects=1}
async function bad_case_9() {
  function getLaunchArgs() {
    return ['--disable-gpu', '--remote-debugging-port=9230'];
  }
  // ruleid: typescript-playwright-exposed-chrome-devtools
  const browser = await chromium.launch({
    args: getLaunchArgs()
  });
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// Example 10: Using a conditional to expose port
// {fact rule=autoescape-disabled@v1.0 defects=1}
async function bad_case_10() {
  const isDebug = true;
  const args = ['--no-sandbox'];
  if (isDebug) {
    args.push('--remote-debugging-port=9231');
  }
  // ruleid: typescript-playwright-exposed-chrome-devtools
  const browser = await chromium.launch({ args });
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// Example 11: Using template literals for args
// {fact rule=autoescape-disabled@v1.0 defects=1}
async function bad_case_11() {
  const port = 9232;
  // ruleid: typescript-playwright-exposed-chrome-devtools
  const browser = await chromium.launch({
    args: [`--remote-debugging-port=${port}`]
  });
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// Example 12: Using array spread for args
// {fact rule=autoescape-disabled@v1.0 defects=1}
async function bad_case_12() {
  const baseArgs = ['--no-sandbox'];
  const debugArgs = ['--remote-debugging-port=9233'];
  // ruleid: typescript-playwright-exposed-chrome-devtools
  const browser = await chromium.launch({
    args: [...baseArgs, ...debugArgs]
  });
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// Example 13: Using object spread for launch options
// {fact rule=autoescape-disabled@v1.0 defects=1}
async function bad_case_13() {
  const baseOptions = { headless: false };
  const debugOptions = { args: ['--remote-debugging-port=9234'] };
  // ruleid: typescript-playwright-exposed-chrome-devtools
  const browser = await chromium.launch({
    ...baseOptions,
    ...debugOptions
  });
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// Example 14: Using a config object
// {fact rule=autoescape-disabled@v1.0 defects=1}
async function bad_case_14() {
  const config = {
    browserType: chromium,
    options: {
      args: ['--remote-debugging-port=9235']
    }
  };
  // ruleid: typescript-playwright-exposed-chrome-devtools
  const browser = await config.browserType.launch(config.options);
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// Example 15: Using a helper function but still exposing port
// {fact rule=autoescape-disabled@v1.0 defects=1}
async function bad_case_15() {
  async function setupBrowser() {
    // ruleid: typescript-playwright-exposed-chrome-devtools
    return await chromium.launch({
      args: ['--remote-debugging-port=9236']
    });
  }
  
  const browser = await setupBrowser();
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// True Negative Examples (Safe Code)

// Example 1: Basic launch without exposed devtools
// {fact rule=autoescape-disabled@v1.0 defects=0}
async function good_case_1() {
  // ok: typescript-playwright-exposed-chrome-devtools
  const browser = await chromium.launch({
    headless: true
  });
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// Example 2: Using devtools locally but not exposing remote debugging
// {fact rule=autoescape-disabled@v1.0 defects=0}
async function good_case_2() {
  // ok: typescript-playwright-exposed-chrome-devtools
  const browser = await chromium.launch({
    devtools: true,
    headless: false
  });
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// Example 3: Using args but not exposing remote debugging
// {fact rule=autoescape-disabled@v1.0 defects=0}
async function good_case_3() {
  // ok: typescript-playwright-exposed-chrome-devtools
  const browser = await chromium.launch({
    args: ['--no-sandbox', '--disable-gpu']
  });
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// Example 4: Using Firefox without exposing debugging port
// {fact rule=autoescape-disabled@v1.0 defects=0}
async function good_case_4() {
  // ok: typescript-playwright-exposed-chrome-devtools
  const browser = await firefox.launch({
    headless: false
  });
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// Example 5: Using WebKit without exposing debugging port
// {fact rule=autoescape-disabled@v1.0 defects=0}
async function good_case_5() {
  // ok: typescript-playwright-exposed-chrome-devtools
  const browser = await webkit.launch({
    headless: true
  });
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// Example 6: Using environment variable for other settings
// {fact rule=autoescape-disabled@v1.0 defects=0}
async function good_case_6() {
  const headless = process.env.HEADLESS === 'true';
  // ok: typescript-playwright-exposed-chrome-devtools
  const browser = await chromium.launch({
    headless: headless
  });
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// Example 7: Using a test without exposing devtools
// {fact rule=autoescape-disabled@v1.0 defects=0}
async function good_case_7() {
  test('Test without exposed devtools', async () => {
    // ok: typescript-playwright-exposed-chrome-devtools
    const browser = await chromium.launch();
    const page = await browser.newPage();
    await page.goto('https://example.com');
    await expect(page).toHaveTitle('Example Domain');
    await browser.close();
  });
}
// {/fact}

// Example 8: Using a variable for args without exposing port
// {fact rule=autoescape-disabled@v1.0 defects=0}
async function good_case_8() {
  const launchArgs = ['--no-sandbox', '--disable-gpu'];
  // ok: typescript-playwright-exposed-chrome-devtools
  const browser = await chromium.launch({
    args: launchArgs
  });
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// Example 9: Using a function to generate args without exposing port
// {fact rule=autoescape-disabled@v1.0 defects=0}
async function good_case_9() {
  function getLaunchArgs() {
    return ['--disable-gpu', '--no-sandbox'];
  }
  // ok: typescript-playwright-exposed-chrome-devtools
  const browser = await chromium.launch({
    args: getLaunchArgs()
  });
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// Example 10: Using a conditional without exposing port
// {fact rule=autoescape-disabled@v1.0 defects=0}
async function good_case_10() {
  const isDebug = true;
  const options: any = { headless: !isDebug };
  if (isDebug) {
    options.devtools = true; // Local devtools only, not remote
  }
  // ok: typescript-playwright-exposed-chrome-devtools
  const browser = await chromium.launch(options);
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// Example 11: Using template literals for safe args
// {fact rule=autoescape-disabled@v1.0 defects=0}
async function good_case_11() {
  const userAgent = 'Mozilla/5.0 Custom User Agent';
  // ok: typescript-playwright-exposed-chrome-devtools
  const browser = await chromium.launch({
    args: [`--user-agent=${userAgent}`]
  });
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// Example 12: Using array spread for safe args
// {fact rule=autoescape-disabled@v1.0 defects=0}
async function good_case_12() {
  const baseArgs = ['--no-sandbox'];
  const extraArgs = ['--disable-gpu', '--disable-dev-shm-usage'];
  // ok: typescript-playwright-exposed-chrome-devtools
  const browser = await chromium.launch({
    args: [...baseArgs, ...extraArgs]
  });
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// Example 13: Using object spread for safe launch options
// {fact rule=autoescape-disabled@v1.0 defects=0}
async function good_case_13() {
  const baseOptions = { headless: false };
  const extraOptions = { slowMo: 100 };
  // ok: typescript-playwright-exposed-chrome-devtools
  const browser = await chromium.launch({
    ...baseOptions,
    ...extraOptions
  });
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// Example 14: Using a config object with safe options
// {fact rule=autoescape-disabled@v1.0 defects=0}
async function good_case_14() {
  const config = {
    browserType: chromium,
    options: {
      headless: true,
      args: ['--no-sandbox']
    }
  };
  // ok: typescript-playwright-exposed-chrome-devtools
  const browser = await config.browserType.launch(config.options);
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}

// Example 15: Using a helper function with safe options
// {fact rule=autoescape-disabled@v1.0 defects=0}
async function good_case_15() {
  async function setupBrowser() {
    // ok: typescript-playwright-exposed-chrome-devtools
    return await chromium.launch({
      headless: false,
      devtools: true // Local devtools only, not remote
    });
  }
  
  const browser = await setupBrowser();
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
}
// {/fact}