// Example file: process_env_undefined_examples.ts

// True Positives (Vulnerable Code)

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_1() {
  // Setting environment variable to undefined
  // ruleid: typescript-process-env-undefined
  process.env.API_KEY = undefined;
  
  console.log(`API key is: ${process.env.API_KEY}`); // Will log "API key is: undefined" as a string
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_2() {
  const config = {
    dbPassword: "password123",
    apiEndpoint: "https://api.example.com"
  };
  
  if (!config.dbPassword) {
    // ruleid: typescript-process-env-undefined
    process.env.DB_PASSWORD = undefined;
  }
  
  connectToDatabase(process.env.DB_PASSWORD);
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_3() {
  let apiKey: string | undefined = fetchApiKey();
  
  // ruleid: typescript-process-env-undefined
  process.env.API_KEY = apiKey; // If apiKey is undefined, this will set process.env.API_KEY to "undefined"
  
  makeApiRequest();
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_4() {
  const userSettings = getUserSettings();
  
  // ruleid: typescript-process-env-undefined
  process.env.USER_THEME = userSettings.theme; // If theme is undefined, this will set to "undefined"
  
  applyTheme();
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_5() {
  function resetEnvironment() {
    // ruleid: typescript-process-env-undefined
    process.env.DEBUG = undefined;
    console.log("Debug mode reset");
  }
  
  resetEnvironment();
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_6() {
  const configMap = new Map<string, string | undefined>();
  configMap.set("LOG_LEVEL", "info");
  configMap.set("CACHE_TTL", undefined);
  
  // ruleid: typescript-process-env-undefined
  process.env.CACHE_TTL = configMap.get("CACHE_TTL");
  
  initializeCache();
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_7() {
  let debugMode: any;
  
  try {
    debugMode = JSON.parse(fs.readFileSync('config.json', 'utf8')).debug;
  } catch (error) {
    // ruleid: typescript-process-env-undefined
    process.env.DEBUG_MODE = debugMode; // debugMode is undefined here
  }
  
  startApplication();
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_8() {
  const features = {
    darkMode: true,
    notifications: false
  };
  
  // ruleid: typescript-process-env-undefined
  process.env.EXPERIMENTAL_FEATURE = features.experimentalFeature; // This property doesn't exist
  
  checkFeatures();
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_9() {
  let credentials: {username: string, password?: string} = {username: "admin"};
  
  // ruleid: typescript-process-env-undefined
  process.env.PASSWORD = credentials.password; // password is undefined
  
  authenticate();
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_10() {
  const clearEnvironmentVars = (vars: string[]) => {
    vars.forEach(varName => {
      // ruleid: typescript-process-env-undefined
      process.env[varName] = undefined;
    });
  };
  
  clearEnvironmentVars(['API_KEY', 'SECRET_TOKEN', 'DEBUG_MODE']);
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_11() {
  interface Config {
    apiUrl?: string;
    timeout?: number;
  }
  
  const config: Config = {};
  
  // ruleid: typescript-process-env-undefined
  process.env.API_URL = config.apiUrl; // apiUrl is undefined
  
  initializeApi();
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_12() {
  const getOptionalSetting = (key: string): string | undefined => {
    // Some logic that might return undefined
    return Math.random() > 0.5 ? key.toUpperCase() : undefined;
  };
  
  // ruleid: typescript-process-env-undefined
  process.env.OPTIONAL_SETTING = getOptionalSetting("feature_flag");
  
  loadSettings();
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_13() {
  const userPreferences = {
    getTheme(): string | undefined {
      return undefined; // User has no theme preference
    }
  };
  
  // ruleid: typescript-process-env-undefined
  process.env.USER_THEME = userPreferences.getTheme();
  
  renderUI();
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_14() {
  let configValue: string | null | undefined;
  
  try {
    configValue = localStorage.getItem("appConfig");
  } catch (e) {
    configValue = undefined;
  }
  
  // ruleid: typescript-process-env-undefined
  process.env.APP_CONFIG = configValue;
  
  startApp();
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_15() {
  const resetConfig = () => {
    const configKeys = ["API_KEY", "DEBUG", "ENVIRONMENT"];
    
    for (const key of configKeys) {
      if (Math.random() > 0.8) {
        // ruleid: typescript-process-env-undefined
        process.env[key] = undefined;
      }
    }
  };
  
  resetConfig();
}
// {/fact}

// True Negatives (Safe Code)

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_1() {
  // ok: typescript-process-env-undefined
  delete process.env.API_KEY; // Properly removing an environment variable
  
  console.log(`API key is: ${process.env.API_KEY}`); // Will log "API key is: undefined" but the variable is actually unset
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_2() {
  // ok: typescript-process-env-undefined
  process.env.DEBUG_MODE = "false"; // Setting to a string value
  
  startDebugging();
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_3() {
  const apiKey = fetchApiKey();
  
  if (apiKey === undefined) {
    // ok: typescript-process-env-undefined
    delete process.env.API_KEY; // Properly removing when undefined
  } else {
    process.env.API_KEY = apiKey;
  }
  
  makeApiRequest();
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_4() {
  let theme = getUserTheme();
  
  // ok: typescript-process-env-undefined
  if (theme === undefined) {
    process.env.USER_THEME = "default"; // Setting a default value
  } else {
    process.env.USER_THEME = theme;
  }
  
  applyTheme();
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_5() {
  function resetEnvironment() {
    // ok: typescript-process-env-undefined
    delete process.env.DEBUG; // Properly removing environment variable
    console.log("Debug mode reset");
  }
  
  resetEnvironment();
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_6() {
  const configMap = new Map<string, string | undefined>();
  configMap.set("LOG_LEVEL", "info");
  configMap.set("CACHE_TTL", undefined);
  
  const cacheTtl = configMap.get("CACHE_TTL");
  // ok: typescript-process-env-undefined
  if (cacheTtl === undefined) {
    delete process.env.CACHE_TTL;
  } else {
    process.env.CACHE_TTL = cacheTtl;
  }
  
  initializeCache();
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_7() {
  let debugMode: any;
  
  try {
    debugMode = JSON.parse(fs.readFileSync('config.json', 'utf8')).debug;
  } catch (error) {
    // ok: typescript-process-env-undefined
    process.env.DEBUG_MODE = "false"; // Setting a default value instead of undefined
  }
  
  startApplication();
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_8() {
  const features = {
    darkMode: true,
    notifications: false
  };
  
  // ok: typescript-process-env-undefined
  process.env.EXPERIMENTAL_FEATURE = features.experimentalFeature ?? "false"; // Using nullish coalescing
  
  checkFeatures();
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_9() {
  let credentials: {username: string, password?: string} = {username: "admin"};
  
  // ok: typescript-process-env-undefined
  if (credentials.password === undefined) {
    delete process.env.PASSWORD;
  } else {
    process.env.PASSWORD = credentials.password;
  }
  
  authenticate();
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_10() {
  const clearEnvironmentVars = (vars: string[]) => {
    vars.forEach(varName => {
      // ok: typescript-process-env-undefined
      delete process.env[varName]; // Properly removing environment variables
    });
  };
  
  clearEnvironmentVars(['API_KEY', 'SECRET_TOKEN', 'DEBUG_MODE']);
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_11() {
  interface Config {
    apiUrl?: string;
    timeout?: number;
  }
  
  const config: Config = {};
  
  // ok: typescript-process-env-undefined
  if (config.apiUrl !== undefined) {
    process.env.API_URL = config.apiUrl;
  } else {
    process.env.API_URL = "https://default-api.example.com";
  }
  
  initializeApi();
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_12() {
  const getOptionalSetting = (key: string): string | undefined => {
    // Some logic that might return undefined
    return Math.random() > 0.5 ? key.toUpperCase() : undefined;
  };
  
  const setting = getOptionalSetting("feature_flag");
  // ok: typescript-process-env-undefined
  if (setting === undefined) {
    delete process.env.OPTIONAL_SETTING;
  } else {
    process.env.OPTIONAL_SETTING = setting;
  }
  
  loadSettings();
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_13() {
  // ok: typescript-process-env-undefined
  process.env.USER_THEME = "undefined"; // Explicitly setting to the string "undefined"
  
  renderUI();
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_14() {
  let configValue: string | null | undefined;
  
  try {
    configValue = localStorage.getItem("appConfig");
  } catch (e) {
    configValue = undefined;
  }
  
  // ok: typescript-process-env-undefined
  if (configValue === undefined || configValue === null) {
    delete process.env.APP_CONFIG;
  } else {
    process.env.APP_CONFIG = configValue;
  }
  
  startApp();
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_15() {
  const resetConfig = () => {
    const configKeys = ["API_KEY", "DEBUG", "ENVIRONMENT"];
    
    for (const key of configKeys) {
      if (Math.random() > 0.8) {
        // ok: typescript-process-env-undefined
        delete process.env[key]; // Properly removing environment variables
      }
    }
  };
  
  resetConfig();
}
// {/fact}

// Helper functions (not part of the test cases)
function fetchApiKey(): string | undefined { return "some-api-key"; }
function getUserSettings() { return { theme: "dark" }; }
function applyTheme() { /* Implementation */ }
function connectToDatabase(password: string) { /* Implementation */ }
function makeApiRequest() { /* Implementation */ }
function initializeCache() { /* Implementation */ }
function startApplication() { /* Implementation */ }
function checkFeatures() { /* Implementation */ }
function authenticate() { /* Implementation */ }
function initializeApi() { /* Implementation */ }
function loadSettings() { /* Implementation */ }
function renderUI() { /* Implementation */ }
function startApp() { /* Implementation */ }
function getUserTheme(): string | undefined { return "light"; }
function startDebugging() { /* Implementation */ }

// Mock fs module for examples
const fs = {
  readFileSync: (path: string, encoding: string) => '{"debug": true}'
};

// Mock localStorage for examples
const localStorage = {
  getItem: (key: string): string | null => null
};