// File: process_env_undefined_examples.ts

// This file contains examples of correct and incorrect ways to handle
// process.env variables in Node.js applications

// ==================== TRUE POSITIVES (VULNERABLE CODE) ====================

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_1() {
  // Setting environment variable to undefined (incorrect)
  const apiKey = getApiKey();
  if (!apiKey) {
    // ruleid: typescript-process-env-undefined
    process.env.API_KEY = undefined;
    console.log("API key not found, setting to undefined");
  } else {
    process.env.API_KEY = apiKey;
  }
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_2() {
  // Conditional assignment with undefined
  const dbConfig = loadDatabaseConfig();
  // ruleid: typescript-process-env-undefined
  process.env.DB_HOST = dbConfig.host || undefined;
  process.env.DB_PORT = dbConfig.port?.toString() || "5432";
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_3() {
  // Using undefined in a loop
  const configKeys = ["API_URL", "API_VERSION", "API_TIMEOUT"];
  const config: Record<string, string | undefined> = {
    API_URL: "https://api.example.com",
    API_VERSION: undefined,
    API_TIMEOUT: "30000"
  };
  
  for (const key of configKeys) {
    // ruleid: typescript-process-env-undefined
    process.env[key] = config[key];
  }
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_4() {
  // Using undefined with destructuring
  const { username, password, domain } = getUserCredentials();
  // ruleid: typescript-process-env-undefined
  process.env.AUTH_USERNAME = username || undefined;
  // ruleid: typescript-process-env-undefined
  process.env.AUTH_PASSWORD = password || undefined;
  process.env.AUTH_DOMAIN = domain || "default.com";
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_5() {
  // Using undefined with ternary operator
  const isDevelopment = checkEnvironment() === 'development';
  // ruleid: typescript-process-env-undefined
  process.env.DEBUG_MODE = isDevelopment ? undefined : "false";
  process.env.NODE_ENV = isDevelopment ? "development" : "production";
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_6() {
  // Using undefined with optional chaining
  const serverConfig = getServerConfig();
  // ruleid: typescript-process-env-undefined
  process.env.SERVER_HOST = serverConfig?.host;
  // ruleid: typescript-process-env-undefined
  process.env.SERVER_PORT = serverConfig?.port?.toString();
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_7() {
  // Using undefined with nullish coalescing
  const logConfig = getLoggingConfig();
  // ruleid: typescript-process-env-undefined
  process.env.LOG_LEVEL = logConfig.level ?? undefined;
  process.env.LOG_FORMAT = logConfig.format ?? "json";
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_8() {
  // Using undefined with array find
  const configs = getConfigurations();
  const securityConfig = configs.find(c => c.type === 'security');
  // ruleid: typescript-process-env-undefined
  process.env.SECURITY_TOKEN = securityConfig?.token;
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_9() {
  // Using undefined with async/await pattern
  async function setupEnv() {
    try {
      const config = await fetchRemoteConfig();
      // ruleid: typescript-process-env-undefined
      process.env.REMOTE_API_KEY = config.apiKey || undefined;
    } catch (error) {
      console.error("Failed to fetch remote config");
    }
  }
  setupEnv();
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_10() {
  // Using undefined with type assertion
  interface Config {
    timeout?: number;
    retries?: number;
  }
  
  const config = getConfig() as Config;
  // ruleid: typescript-process-env-undefined
  process.env.REQUEST_TIMEOUT = config.timeout?.toString();
  // ruleid: typescript-process-env-undefined
  process.env.REQUEST_RETRIES = config.retries?.toString();
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_11() {
  // Using undefined with object spread
  const defaultConfig = { host: "localhost", port: "8080" };
  const customConfig = getCustomConfig();
  const finalConfig = { ...defaultConfig, ...customConfig };
  
  // ruleid: typescript-process-env-undefined
  process.env.FINAL_HOST = finalConfig.host;
  // ruleid: typescript-process-env-undefined
  process.env.FINAL_PORT = finalConfig.port;
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_12() {
  // Using undefined with map function
  const features = getFeatureFlags();
  features.forEach(feature => {
    // ruleid: typescript-process-env-undefined
    process.env[`FEATURE_${feature.name.toUpperCase()}`] = feature.enabled?.toString();
  });
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_13() {
  // Using undefined with switch statement
  const mode = getApplicationMode();
  switch (mode) {
    case 'development':
      process.env.DEBUG = 'true';
      break;
    case 'production':
      process.env.DEBUG = 'false';
      break;
    default:
      // ruleid: typescript-process-env-undefined
      process.env.DEBUG = undefined;
  }
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_14() {
  // Using undefined with early return pattern
  function configureCache() {
    const cacheConfig = getCacheConfig();
    if (!cacheConfig) {
      // ruleid: typescript-process-env-undefined
      process.env.CACHE_TTL = undefined;
      return;
    }
    
    process.env.CACHE_TTL = cacheConfig.ttl.toString();
  }
  configureCache();
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=1}
function bad_case_15() {
  // Using undefined with try/catch
  try {
    const result = riskyOperation();
    process.env.OPERATION_RESULT = result;
  } catch (error) {
    // ruleid: typescript-process-env-undefined
    process.env.OPERATION_RESULT = undefined;
    console.error("Operation failed", error);
  }
}
// {/fact}

// ==================== TRUE NEGATIVES (SAFE CODE) ====================

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_1() {
  // Properly deleting environment variable
  const apiKey = getApiKey();
  if (!apiKey) {
    // ok: typescript-process-env-undefined
    delete process.env.API_KEY;
    console.log("API key not found, removing environment variable");
  } else {
    process.env.API_KEY = apiKey;
  }
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_2() {
  // Conditional assignment with proper fallback
  const dbConfig = loadDatabaseConfig();
  // ok: typescript-process-env-undefined
  process.env.DB_HOST = dbConfig.host || "localhost";
  process.env.DB_PORT = dbConfig.port?.toString() || "5432";
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_3() {
  // Properly handling undefined in a loop
  const configKeys = ["API_URL", "API_VERSION", "API_TIMEOUT"];
  const config: Record<string, string | undefined> = {
    API_URL: "https://api.example.com",
    API_VERSION: undefined,
    API_TIMEOUT: "30000"
  };
  
  for (const key of configKeys) {
    if (config[key] === undefined) {
      // ok: typescript-process-env-undefined
      delete process.env[key];
    } else {
      process.env[key] = config[key];
    }
  }
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_4() {
  // Properly handling undefined with destructuring
  const { username, password, domain } = getUserCredentials();
  
  if (username) {
    process.env.AUTH_USERNAME = username;
  } else {
    // ok: typescript-process-env-undefined
    delete process.env.AUTH_USERNAME;
  }
  
  if (password) {
    process.env.AUTH_PASSWORD = password;
  } else {
    // ok: typescript-process-env-undefined
    delete process.env.AUTH_PASSWORD;
  }
  
  process.env.AUTH_DOMAIN = domain || "default.com";
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_5() {
  // Properly handling undefined with ternary operator
  const isDevelopment = checkEnvironment() === 'development';
  
  if (isDevelopment) {
    // ok: typescript-process-env-undefined
    delete process.env.DEBUG_MODE;
  } else {
    process.env.DEBUG_MODE = "false";
  }
  
  process.env.NODE_ENV = isDevelopment ? "development" : "production";
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_6() {
  // Properly handling undefined with optional chaining
  const serverConfig = getServerConfig();
  
  if (serverConfig?.host) {
    process.env.SERVER_HOST = serverConfig.host;
  } else {
    // ok: typescript-process-env-undefined
    delete process.env.SERVER_HOST;
  }
  
  if (serverConfig?.port) {
    process.env.SERVER_PORT = serverConfig.port.toString();
  } else {
    // ok: typescript-process-env-undefined
    delete process.env.SERVER_PORT;
  }
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_7() {
  // Properly handling undefined with nullish coalescing
  const logConfig = getLoggingConfig();
  // ok: typescript-process-env-undefined
  process.env.LOG_LEVEL = logConfig.level ?? "info";
  process.env.LOG_FORMAT = logConfig.format ?? "json";
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_8() {
  // Properly handling undefined with array find
  const configs = getConfigurations();
  const securityConfig = configs.find(c => c.type === 'security');
  
  if (securityConfig?.token) {
    process.env.SECURITY_TOKEN = securityConfig.token;
  } else {
    // ok: typescript-process-env-undefined
    delete process.env.SECURITY_TOKEN;
  }
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_9() {
  // Properly handling undefined with async/await pattern
  async function setupEnv() {
    try {
      const config = await fetchRemoteConfig();
      if (config.apiKey) {
        process.env.REMOTE_API_KEY = config.apiKey;
      } else {
        // ok: typescript-process-env-undefined
        delete process.env.REMOTE_API_KEY;
      }
    } catch (error) {
      console.error("Failed to fetch remote config");
    }
  }
  setupEnv();
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_10() {
  // Properly handling undefined with type assertion
  interface Config {
    timeout?: number;
    retries?: number;
  }
  
  const config = getConfig() as Config;
  
  if (config.timeout !== undefined) {
    process.env.REQUEST_TIMEOUT = config.timeout.toString();
  } else {
    // ok: typescript-process-env-undefined
    delete process.env.REQUEST_TIMEOUT;
  }
  
  // ok: typescript-process-env-undefined
  process.env.REQUEST_RETRIES = config.retries?.toString() || "3";
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_11() {
  // Properly handling undefined with object spread
  const defaultConfig = { host: "localhost", port: "8080" };
  const customConfig = getCustomConfig();
  const finalConfig = { ...defaultConfig, ...customConfig };
  
  // ok: typescript-process-env-undefined
  if (finalConfig.host) {
    process.env.FINAL_HOST = finalConfig.host;
  } else {
    delete process.env.FINAL_HOST;
  }
  
  // ok: typescript-process-env-undefined
  if (finalConfig.port) {
    process.env.FINAL_PORT = finalConfig.port;
  } else {
    delete process.env.FINAL_PORT;
  }
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_12() {
  // Properly handling undefined with map function
  const features = getFeatureFlags();
  features.forEach(feature => {
    const envKey = `FEATURE_${feature.name.toUpperCase()}`;
    if (feature.enabled !== undefined) {
      process.env[envKey] = feature.enabled.toString();
    } else {
      // ok: typescript-process-env-undefined
      delete process.env[envKey];
    }
  });
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_13() {
  // Properly handling undefined with switch statement
  const mode = getApplicationMode();
  switch (mode) {
    case 'development':
      process.env.DEBUG = 'true';
      break;
    case 'production':
      process.env.DEBUG = 'false';
      break;
    default:
      // ok: typescript-process-env-undefined
      delete process.env.DEBUG;
  }
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_14() {
  // Properly handling undefined with early return pattern
  function configureCache() {
    const cacheConfig = getCacheConfig();
    if (!cacheConfig) {
      // ok: typescript-process-env-undefined
      delete process.env.CACHE_TTL;
      return;
    }
    
    process.env.CACHE_TTL = cacheConfig.ttl.toString();
  }
  configureCache();
}
// {/fact}

// {fact rule=improper-initialization@v1.0 defects=0}
function good_case_15() {
  // Properly handling undefined with try/catch
  try {
    const result = riskyOperation();
    process.env.OPERATION_RESULT = result;
  } catch (error) {
    // ok: typescript-process-env-undefined
    delete process.env.OPERATION_RESULT;
    console.error("Operation failed", error);
  }
}
// {/fact}

// Helper functions to make the examples work
function getApiKey(): string | undefined { return "sample-api-key"; }
function loadDatabaseConfig(): { host?: string, port?: number } { return { host: "localhost", port: 5432 }; }
function getUserCredentials(): { username?: string, password?: string, domain?: string } { return { username: "user", password: "pass", domain: "example.com" }; }
function checkEnvironment(): string { return "development"; }
function getServerConfig(): { host?: string, port?: number } | undefined { return { host: "localhost", port: 8080 }; }
function getLoggingConfig(): { level?: string, format?: string } { return { level: "info", format: "json" }; }
function getConfigurations(): Array<{ type: string, token?: string }> { return [{ type: "security", token: "secret-token" }]; }
async function fetchRemoteConfig(): Promise<{ apiKey?: string }> { return { apiKey: "remote-api-key" }; }
function getConfig(): unknown { return { timeout: 5000, retries: 3 }; }
function getCustomConfig(): { host?: string, port?: string } { return { host: "custom-host", port: "9090" }; }
function getFeatureFlags(): Array<{ name: string, enabled?: boolean }> { return [{ name: "darkMode", enabled: true }]; }
function getApplicationMode(): string { return "development"; }
function getCacheConfig(): { ttl: number } | null { return { ttl: 3600 }; }
function riskyOperation(): string { return "success"; }