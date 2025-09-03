// File: process_env_undefined_examples.js

// This file contains examples of correct and incorrect ways to handle
// process.env variables in Node.js applications

// True Positive Examples (Vulnerable Code)

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_1() {
  // Setting an environment variable to undefined
  let configValue;
  // ruleid: javascript-process-env-undefined
  process.env.API_KEY = configValue; // configValue is undefined
  console.log(`API_KEY is now set to: ${process.env.API_KEY}`); // Will log "undefined" as a string
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_2() {
  const getConfig = () => undefined;
  // ruleid: javascript-process-env-undefined
  process.env.DATABASE_URL = getConfig();
  console.log(`Using database at: ${process.env.DATABASE_URL}`);
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_3() {
  function fetchSetting(key) {
    // This function doesn't return anything
    console.log(`Attempting to fetch setting: ${key}`);
  }
  // ruleid: javascript-process-env-undefined
  process.env.LOG_LEVEL = fetchSetting('logLevel');
  console.log(`Log level set to: ${process.env.LOG_LEVEL}`);
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_4() {
  const config = {};
  // ruleid: javascript-process-env-undefined
  process.env.DEBUG_MODE = config.debugMode;
  if (process.env.DEBUG_MODE === 'true') {
    console.log('Debug mode enabled');
  }
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_5() {
  let serverPort;
  if (Math.random() < 0) { // This condition is always false
    serverPort = 3000;
  }
  // ruleid: javascript-process-env-undefined
  process.env.PORT = serverPort;
  console.log(`Server will listen on port: ${process.env.PORT}`);
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_6() {
  const settings = { production: { apiUrl: 'https://api.example.com' } };
  const environment = 'development';
  // ruleid: javascript-process-env-undefined
  process.env.API_URL = settings[environment]?.apiUrl;
  console.log(`API URL: ${process.env.API_URL}`);
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_7() {
  function getOptionalSetting() {
    return undefined;
  }
  // ruleid: javascript-process-env-undefined
  process.env.CACHE_TTL = getOptionalSetting() || undefined;
  console.log(`Cache TTL: ${process.env.CACHE_TTL}`);
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_8() {
  const userSettings = new Map();
  // ruleid: javascript-process-env-undefined
  process.env.USER_LOCALE = userSettings.get('locale');
  console.log(`User locale: ${process.env.USER_LOCALE}`);
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_9() {
  const args = process.argv.slice(2);
  const configFile = args[1]; // Might be undefined if not provided
  // ruleid: javascript-process-env-undefined
  process.env.CONFIG_PATH = configFile;
  console.log(`Using config from: ${process.env.CONFIG_PATH}`);
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_10() {
  try {
    throw new Error('Configuration not found');
  } catch (error) {
    let fallbackConfig;
    // ruleid: javascript-process-env-undefined
    process.env.FALLBACK_MODE = fallbackConfig;
    console.log(`Fallback mode: ${process.env.FALLBACK_MODE}`);
  }
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_11() {
  const getServerConfig = async () => {
    // This function returns a Promise that resolves to undefined
    return undefined;
  };
  
  getServerConfig().then(config => {
    // ruleid: javascript-process-env-undefined
    process.env.SERVER_CONFIG = config;
    console.log(`Server config: ${process.env.SERVER_CONFIG}`);
  });
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_12() {
  const features = {};
  const featureName = 'darkMode';
  // ruleid: javascript-process-env-undefined
  process.env.FEATURE_ENABLED = features[featureName];
  if (process.env.FEATURE_ENABLED === 'true') {
    console.log('Feature is enabled');
  }
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_13() {
  let tempDir;
  if (process.platform === 'imaginary-os') { // This condition is always false
    tempDir = '/tmp';
  }
  // ruleid: javascript-process-env-undefined
  process.env.TEMP_DIRECTORY = tempDir;
  console.log(`Using temporary directory: ${process.env.TEMP_DIRECTORY}`);
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_14() {
  const [nodePath, scriptPath, ...args] = process.argv;
  const logFile = args.find(arg => arg.startsWith('--log='))?.split('=')[1];
  // ruleid: javascript-process-env-undefined
  process.env.LOG_FILE = logFile;
  console.log(`Logging to: ${process.env.LOG_FILE}`);
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_15() {
  const loadPlugin = name => {
    // This function doesn't return anything when plugin doesn't exist
    if (name === 'existing-plugin') {
      return 'plugin-data';
    }
  };
  // ruleid: javascript-process-env-undefined
  process.env.PLUGIN_DATA = loadPlugin('non-existing-plugin');
  console.log(`Plugin data: ${process.env.PLUGIN_DATA}`);
}
// {/fact}

// True Negative Examples (Safe Code)

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_1() {
  let configValue;
  // ok: javascript-process-env-undefined
  delete process.env.API_KEY; // Properly removing an environment variable
  console.log(`API_KEY is now: ${process.env.API_KEY}`);
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_2() {
  const getConfig = () => undefined;
  // ok: javascript-process-env-undefined
  if (getConfig() !== undefined) {
    process.env.DATABASE_URL = getConfig();
  } else {
    delete process.env.DATABASE_URL;
  }
  console.log(`Using database at: ${process.env.DATABASE_URL}`);
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_3() {
  function fetchSetting(key) {
    // This function doesn't return anything
    console.log(`Attempting to fetch setting: ${key}`);
  }
  const result = fetchSetting('logLevel');
  // ok: javascript-process-env-undefined
  if (result !== undefined) {
    process.env.LOG_LEVEL = result;
  } else {
    process.env.LOG_LEVEL = 'info'; // Default value
  }
  console.log(`Log level set to: ${process.env.LOG_LEVEL}`);
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_4() {
  const config = {};
  // ok: javascript-process-env-undefined
  process.env.DEBUG_MODE = config.debugMode || 'false';
  if (process.env.DEBUG_MODE === 'true') {
    console.log('Debug mode enabled');
  }
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_5() {
  let serverPort;
  if (Math.random() < 0) { // This condition is always false
    serverPort = 3000;
  }
  // ok: javascript-process-env-undefined
  if (serverPort === undefined) {
    delete process.env.PORT;
  } else {
    process.env.PORT = serverPort;
  }
  console.log(`Server will listen on port: ${process.env.PORT || '8080'}`);
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_6() {
  const settings = { production: { apiUrl: 'https://api.example.com' } };
  const environment = 'development';
  // ok: javascript-process-env-undefined
  process.env.API_URL = settings[environment]?.apiUrl || 'http://localhost:3000';
  console.log(`API URL: ${process.env.API_URL}`);
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_7() {
  function getOptionalSetting() {
    return undefined;
  }
  const setting = getOptionalSetting();
  // ok: javascript-process-env-undefined
  if (setting === undefined) {
    delete process.env.CACHE_TTL;
  } else {
    process.env.CACHE_TTL = setting;
  }
  console.log(`Cache TTL: ${process.env.CACHE_TTL}`);
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_8() {
  const userSettings = new Map();
  const locale = userSettings.get('locale');
  // ok: javascript-process-env-undefined
  if (locale !== undefined) {
    process.env.USER_LOCALE = locale;
  } else {
    process.env.USER_LOCALE = 'en-US'; // Default value
  }
  console.log(`User locale: ${process.env.USER_LOCALE}`);
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_9() {
  const args = process.argv.slice(2);
  const configFile = args[1]; // Might be undefined if not provided
  // ok: javascript-process-env-undefined
  process.env.CONFIG_PATH = configFile || './default-config.json';
  console.log(`Using config from: ${process.env.CONFIG_PATH}`);
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_10() {
  try {
    throw new Error('Configuration not found');
  } catch (error) {
    // ok: javascript-process-env-undefined
    process.env.FALLBACK_MODE = 'true'; // Explicitly setting a string value
    console.log(`Fallback mode: ${process.env.FALLBACK_MODE}`);
  }
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_11() {
  const getServerConfig = async () => {
    // This function returns a Promise that resolves to undefined
    return undefined;
  };
  
  getServerConfig().then(config => {
    // ok: javascript-process-env-undefined
    if (config === undefined) {
      delete process.env.SERVER_CONFIG;
    } else {
      process.env.SERVER_CONFIG = config;
    }
    console.log(`Server config: ${process.env.SERVER_CONFIG}`);
  });
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_12() {
  const features = {};
  const featureName = 'darkMode';
  const featureValue = features[featureName];
  // ok: javascript-process-env-undefined
  if (featureValue === undefined) {
    process.env.FEATURE_ENABLED = 'false'; // Default value
  } else {
    process.env.FEATURE_ENABLED = featureValue;
  }
  if (process.env.FEATURE_ENABLED === 'true') {
    console.log('Feature is enabled');
  }
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_13() {
  // ok: javascript-process-env-undefined
  process.env.TEMP_DIRECTORY = '/tmp'; // Explicitly setting a string value
  console.log(`Using temporary directory: ${process.env.TEMP_DIRECTORY}`);
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_14() {
  const [nodePath, scriptPath, ...args] = process.argv;
  const logFile = args.find(arg => arg.startsWith('--log='))?.split('=')[1];
  // ok: javascript-process-env-undefined
  if (typeof logFile === 'string') {
    process.env.LOG_FILE = logFile;
  } else {
    process.env.LOG_FILE = './app.log'; // Default value
  }
  console.log(`Logging to: ${process.env.LOG_FILE}`);
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_15() {
  // ok: javascript-process-env-undefined
  process.env.UNDEFINED_VALUE = "undefined"; // Explicitly setting to the string "undefined"
  console.log(`Explicitly set to string "undefined": ${process.env.UNDEFINED_VALUE}`);
}
// {/fact}