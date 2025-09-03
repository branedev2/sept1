// Import required AWS SDK modules
const AWS = require('aws-sdk');
const { AppConfigData } = require('@aws-sdk/client-appconfigdata');
const { AppConfig } = require('@aws-sdk/client-appconfig');

// True Positive Examples (Deprecated API usage)

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_1() {
  // Using the deprecated GetConfiguration API directly
  const appConfig = new AWS.AppConfig();
  
  // ruleid: js-deprecated-get-configuration
  appConfig.getConfiguration({
    Application: 'MyApp',
    Environment: 'Production',
    Configuration: 'MyConfig',
    ClientId: 'client-1'
  }, (err, data) => {
    if (err) console.error(err);
    else console.log(data);
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_2() {
  // Using the deprecated GetConfiguration API with promises
  const appConfig = new AWS.AppConfig({ region: 'us-west-2' });
  
  // ruleid: js-deprecated-get-configuration
  appConfig.getConfiguration({
    Application: 'MyApp',
    Environment: 'Staging',
    Configuration: 'FeatureFlags',
    ClientId: 'client-2'
  }).promise()
    .then(data => console.log(data))
    .catch(err => console.error(err));
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_3() {
  // Using the deprecated GetConfiguration API in an async function
  async function fetchConfig() {
    const appConfig = new AWS.AppConfig({ region: 'eu-central-1' });
    try {
      // ruleid: js-deprecated-get-configuration
      const data = await appConfig.getConfiguration({
        Application: 'ServiceA',
        Environment: 'Dev',
        Configuration: 'ApiSettings',
        ClientId: 'client-3'
      }).promise();
      return data;
    } catch (err) {
      console.error(err);
      return null;
    }
  }
  
  fetchConfig();
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_4() {
  // Using the deprecated GetConfiguration API with variable parameters
  const appConfig = new AWS.AppConfig();
  const appName = 'PaymentService';
  const envName = process.env.NODE_ENV || 'Development';
  const configName = 'PaymentGateways';
  
  // ruleid: js-deprecated-get-configuration
  appConfig.getConfiguration({
    Application: appName,
    Environment: envName,
    Configuration: configName,
    ClientId: `client-${Date.now()}`
  }, function(err, data) {
    if (err) console.error('Failed to get config:', err);
    else console.log('Config retrieved:', data);
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_5() {
  // Using the deprecated GetConfiguration API in a class method
  class ConfigManager {
    constructor(region) {
      this.appConfig = new AWS.AppConfig({ region });
    }
    
    fetchConfiguration(app, env, config) {
      // ruleid: js-deprecated-get-configuration
      return this.appConfig.getConfiguration({
        Application: app,
        Environment: env,
        Configuration: config,
        ClientId: 'client-5'
      }).promise();
    }
  }
  
  const manager = new ConfigManager('us-east-1');
  manager.fetchConfiguration('AuthService', 'Production', 'AuthProviders')
    .then(data => console.log(data))
    .catch(err => console.error(err));
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_6() {
  // Using the deprecated GetConfiguration API with error handling
  const appConfig = new AWS.AppConfig();
  
  try {
    // ruleid: js-deprecated-get-configuration
    appConfig.getConfiguration({
      Application: 'LoggingService',
      Environment: 'Production',
      Configuration: 'LogLevels',
      ClientId: 'client-6'
    }, (err, data) => {
      if (err) throw new Error(`Config error: ${err.message}`);
      console.log('Log levels:', data);
    });
  } catch (error) {
    console.error('Failed to get configuration:', error);
  }
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_7() {
  // Using the deprecated GetConfiguration API with conditional logic
  const appConfig = new AWS.AppConfig();
  const isProduction = process.env.NODE_ENV === 'production';
  
  if (isProduction) {
    // ruleid: js-deprecated-get-configuration
    appConfig.getConfiguration({
      Application: 'WebApp',
      Environment: 'Production',
      Configuration: 'CacheSettings',
      ClientId: 'client-7'
    }, (err, data) => {
      if (!err) {
        initializeCache(data);
      }
    });
  } else {
    console.log('Using default cache settings for non-production');
  }
  
  function initializeCache(settings) {
    console.log('Initializing cache with settings:', settings);
  }
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_8() {
  // Using the deprecated GetConfiguration API in a loop
  const appConfig = new AWS.AppConfig();
  const services = ['Auth', 'Payment', 'Shipping', 'Notification'];
  
  for (const service of services) {
    // ruleid: js-deprecated-get-configuration
    appConfig.getConfiguration({
      Application: 'EcommerceApp',
      Environment: 'Production',
      Configuration: `${service}Config`,
      ClientId: `client-${service}`
    }, (err, data) => {
      if (err) console.error(`Failed to get ${service} config:`, err);
      else console.log(`${service} config:`, data);
    });
  }
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_9() {
  // Using the deprecated GetConfiguration API with destructuring
  const { AppConfig } = AWS;
  const appConfig = new AppConfig({ region: 'ap-southeast-1' });
  
  const params = {
    Application: 'MobileApp',
    Environment: 'Production',
    Configuration: 'UISettings',
    ClientId: 'client-9'
  };
  
  // ruleid: js-deprecated-get-configuration
  appConfig.getConfiguration(params)
    .promise()
    .then(({ Item }) => {
      if (Item && Item.settings) {
        applySettings(Item.settings);
      }
    })
    .catch(err => console.error('Config error:', err));
  
  function applySettings(settings) {
    console.log('Applying settings:', settings);
  }
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_10() {
  // Using the deprecated GetConfiguration API with a timeout
  const appConfig = new AWS.AppConfig();
  
  setTimeout(() => {
    // ruleid: js-deprecated-get-configuration
    appConfig.getConfiguration({
      Application: 'AnalyticsService',
      Environment: 'Production',
      Configuration: 'TrackingConfig',
      ClientId: 'client-10'
    }, (err, data) => {
      if (!err) {
        console.log('Tracking config loaded after delay');
      }
    });
  }, 1000);
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_11() {
  // Using the deprecated GetConfiguration API with event handling
  const appConfig = new AWS.AppConfig();
  const EventEmitter = require('events');
  const configEmitter = new EventEmitter();
  
  configEmitter.on('load-config', () => {
    // ruleid: js-deprecated-get-configuration
    appConfig.getConfiguration({
      Application: 'UserService',
      Environment: 'Production',
      Configuration: 'UserPreferences',
      ClientId: 'client-11'
    }, (err, data) => {
      if (err) configEmitter.emit('config-error', err);
      else configEmitter.emit('config-loaded', data);
    });
  });
  
  configEmitter.on('config-loaded', (data) => {
    console.log('Config loaded:', data);
  });
  
  configEmitter.emit('load-config');
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_12() {
  // Using the deprecated GetConfiguration API with a custom wrapper function
  const appConfig = new AWS.AppConfig({ region: 'us-west-1' });
  
  function getAppConfig(application, environment, configuration) {
    return new Promise((resolve, reject) => {
      // ruleid: js-deprecated-get-configuration
      appConfig.getConfiguration({
        Application: application,
        Environment: environment,
        Configuration: configuration,
        ClientId: `client-${application}`
      }, (err, data) => {
        if (err) reject(err);
        else resolve(data);
      });
    });
  }
  
  getAppConfig('NotificationService', 'Production', 'EmailTemplates')
    .then(templates => console.log('Email templates loaded'))
    .catch(err => console.error('Failed to load templates:', err));
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_13() {
  // Using the deprecated GetConfiguration API with multiple configurations
  const appConfig = new AWS.AppConfig();
  
  function loadAllConfigs() {
    const configs = [
      { app: 'Frontend', env: 'Production', config: 'Theme' },
      { app: 'Frontend', env: 'Production', config: 'Features' },
      { app: 'Frontend', env: 'Production', config: 'Localization' }
    ];
    
    return Promise.all(configs.map(({ app, env, config }) => {
      // ruleid: js-deprecated-get-configuration
      return appConfig.getConfiguration({
        Application: app,
        Environment: env,
        Configuration: config,
        ClientId: `client-${app}-${config}`
      }).promise();
    }));
  }
  
  loadAllConfigs()
    .then(results => console.log('All configs loaded'))
    .catch(err => console.error('Config loading failed:', err));
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_14() {
  // Using the deprecated GetConfiguration API with AWS SDK v2 import style
  const AppConfig = require('aws-sdk/clients/appconfig');
  const appConfig = new AppConfig({ region: 'eu-west-1' });
  
  // ruleid: js-deprecated-get-configuration
  appConfig.getConfiguration({
    Application: 'DataProcessingService',
    Environment: 'Production',
    Configuration: 'ProcessingRules',
    ClientId: 'client-14'
  }).promise()
    .then(data => {
      console.log('Processing rules loaded');
    })
    .catch(err => {
      console.error('Failed to load processing rules:', err);
    });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_15() {
  // Using the deprecated GetConfiguration API with custom AWS config
  const appConfig = new AWS.AppConfig({
    region: 'us-east-2',
    maxRetries: 3,
    httpOptions: {
      timeout: 5000
    }
  });
  
  // ruleid: js-deprecated-get-configuration
  appConfig.getConfiguration({
    Application: 'ReportingService',
    Environment: 'Production',
    Configuration: 'ReportFormats',
    ClientId: 'client-15'
  }, function(err, data) {
    if (err) {
      console.error('Error loading report formats:', err);
      return;
    }
    console.log('Report formats loaded successfully');
  });
}
// {/fact}

// True Negative Examples (Recommended API usage)

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_1() {
  // Using the recommended AppConfigData client with GetLatestConfiguration
  const appConfigData = new AppConfigData({ region: 'us-west-2' });
  
  async function getConfig() {
    // First get a configuration token
    const startSessionResponse = await appConfigData.startConfigurationSession({
      ApplicationIdentifier: 'MyApp',
      EnvironmentIdentifier: 'Production',
      ConfigurationProfileIdentifier: 'MyConfig'
    });
    
    // ok: js-deprecated-get-configuration
    const configResponse = await appConfigData.getLatestConfiguration({
      ConfigurationToken: startSessionResponse.InitialConfigurationToken
    });
    
    return configResponse;
  }
  
  getConfig()
    .then(data => console.log('Config retrieved'))
    .catch(err => console.error(err));
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_2() {
  // Using the recommended AppConfigData client with promise chaining
  const appConfigData = new AppConfigData({ region: 'us-east-1' });
  
  // ok: js-deprecated-get-configuration
  appConfigData.startConfigurationSession({
    ApplicationIdentifier: 'MyApp',
    EnvironmentIdentifier: 'Staging',
    ConfigurationProfileIdentifier: 'FeatureFlags'
  })
    .then(session => {
      return appConfigData.getLatestConfiguration({
        ConfigurationToken: session.InitialConfigurationToken
      });
    })
    .then(data => console.log('Feature flags retrieved'))
    .catch(err => console.error(err));
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_3() {
  // Using the AWS AppConfig Agent
  const { AppConfigAgent } = require('@aws-sdk/client-appconfig-agent');
  const agent = new AppConfigAgent({ region: 'us-west-2' });
  
  // ok: js-deprecated-get-configuration
  agent.getConfiguration({
    ApplicationIdentifier: 'ServiceA',
    ConfigurationIdentifier: 'ApiSettings',
    EnvironmentIdentifier: 'Dev'
  })
    .then(data => console.log('Config retrieved via agent'))
    .catch(err => console.error(err));
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_4() {
  // Using environment variables for configuration instead of AppConfig
  const dotenv = require('dotenv');
  
  // ok: js-deprecated-get-configuration
  dotenv.config();
  
  const config = {
    apiKey: process.env.API_KEY,
    endpoint: process.env.API_ENDPOINT,
    timeout: parseInt(process.env.API_TIMEOUT || '5000', 10)
  };
  
  console.log('Configuration loaded from environment variables');
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_5() {
  // Using a local configuration file
  const fs = require('fs');
  const path = require('path');
  
  function loadConfig() {
    try {
      // ok: js-deprecated-get-configuration
      const configPath = path.join(__dirname, 'config', `${process.env.NODE_ENV}.json`);
      const configData = fs.readFileSync(configPath, 'utf8');
      return JSON.parse(configData);
    } catch (err) {
      console.error('Failed to load config file:', err);
      return {};
    }
  }
  
  const config = loadConfig();
  console.log('Configuration loaded from file');
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_6() {
  // Using AWS Parameter Store instead of AppConfig
  const { SSMClient, GetParameterCommand } = require('@aws-sdk/client-ssm');
  const ssmClient = new SSMClient({ region: 'us-west-2' });
  
  async function getParameter(name) {
    const command = new GetParameterCommand({
      Name: name,
      WithDecryption: true
    });
    
    // ok: js-deprecated-get-configuration
    const response = await ssmClient.send(command);
    return response.Parameter.Value;
  }
  
  getParameter('/myapp/production/database-url')
    .then(value => console.log('Parameter retrieved'))
    .catch(err => console.error('Failed to get parameter:', err));
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_7() {
  // Using AWS Secrets Manager instead of AppConfig
  const { SecretsManagerClient, GetSecretValueCommand } = require('@aws-sdk/client-secrets-manager');
  const secretsClient = new SecretsManagerClient({ region: 'us-east-1' });
  
  async function getSecret(secretName) {
    const command = new GetSecretValueCommand({
      SecretId: secretName
    });
    
    // ok: js-deprecated-get-configuration
    const response = await secretsClient.send(command);
    return JSON.parse(response.SecretString);
  }
  
  getSecret('myapp/api-credentials')
    .then(secret => console.log('Secret retrieved'))
    .catch(err => console.error('Failed to get secret:', err));
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_8() {
  // Using a configuration service class with the recommended API
  class ConfigService {
    constructor(region) {
      this.appConfigData = new AppConfigData({ region });
    }
    
    async getConfig(app, env, config) {
      const session = await this.appConfigData.startConfigurationSession({
        ApplicationIdentifier: app,
        EnvironmentIdentifier: env,
        ConfigurationProfileIdentifier: config
      });
      
      // ok: js-deprecated-get-configuration
      return this.appConfigData.getLatestConfiguration({
        ConfigurationToken: session.InitialConfigurationToken
      });
    }
  }
  
  const configService = new ConfigService('us-west-2');
  configService.getConfig('AuthService', 'Production', 'AuthProviders')
    .then(data => console.log('Config retrieved'))
    .catch(err => console.error(err));
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_9() {
  // Using AWS SDK v3 modular imports for AppConfigData
  const { StartConfigurationSessionCommand, GetLatestConfigurationCommand } = require('@aws-sdk/client-appconfigdata');
  const appConfigData = new AppConfigData({ region: 'us-east-2' });
  
  async function getLatestConfig() {
    const startSessionCommand = new StartConfigurationSessionCommand({
      ApplicationIdentifier: 'WebApp',
      EnvironmentIdentifier: 'Production',
      ConfigurationProfileIdentifier: 'CacheSettings'
    });
    
    const session = await appConfigData.send(startSessionCommand);
    
    // ok: js-deprecated-get-configuration
    const getConfigCommand = new GetLatestConfigurationCommand({
      ConfigurationToken: session.InitialConfigurationToken
    });
    
    return appConfigData.send(getConfigCommand);
  }
  
  getLatestConfig()
    .then(data => console.log('Latest config retrieved'))
    .catch(err => console.error(err));
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_10() {
  // Using a custom configuration provider that doesn't use AppConfig at all
  class ConfigProvider {
    constructor() {
      this.configs = new Map();
    }
    
    set(key, value) {
      this.configs.set(key, value);
    }
    
    get(key) {
      // ok: js-deprecated-get-configuration
      return this.configs.get(key);
    }
  }
  
  const provider = new ConfigProvider();
  provider.set('database.url', 'mongodb://localhost:27017/myapp');
  provider.set('api.timeout', 5000);
  
  const dbUrl = provider.get('database.url');
  console.log('Using database URL:', dbUrl);
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_11() {
  // Using the AWS SDK v3 AppConfigData client with error handling
  const appConfigData = new AppConfigData({ region: 'ap-southeast-1' });
  
  async function fetchConfig() {
    try {
      const session = await appConfigData.startConfigurationSession({
        ApplicationIdentifier: 'MobileApp',
        EnvironmentIdentifier: 'Production',
        ConfigurationProfileIdentifier: 'UISettings'
      });
      
      // ok: js-deprecated-get-configuration
      const config = await appConfigData.getLatestConfiguration({
        ConfigurationToken: session.InitialConfigurationToken
      });
      
      return config;
    } catch (err) {
      console.error('Failed to fetch config:', err);
      return null;
    }
  }
  
  fetchConfig();
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_12() {
  // Using a configuration manager with caching that uses the recommended API
  class CachingConfigManager {
    constructor(region) {
      this.appConfigData = new AppConfigData({ region });
      this.cache = new Map();
      this.tokens = new Map();
    }
    
    async getConfig(app, env, profile) {
      const cacheKey = `${app}:${env}:${profile}`;
      
      if (!this.tokens.has(cacheKey)) {
        const session = await this.appConfigData.startConfigurationSession({
          ApplicationIdentifier: app,
          EnvironmentIdentifier: env,
          ConfigurationProfileIdentifier: profile
        });
        
        this.tokens.set(cacheKey, session.InitialConfigurationToken);
      }
      
      // ok: js-deprecated-get-configuration
      const config = await this.appConfigData.getLatestConfiguration({
        ConfigurationToken: this.tokens.get(cacheKey)
      });
      
      // Update token for next request
      if (config.NextPollConfigurationToken) {
        this.tokens.set(cacheKey, config.NextPollConfigurationToken);
      }
      
      return config;
    }
  }
  
  const manager = new CachingConfigManager('us-west-2');
  manager.getConfig('NotificationService', 'Production', 'EmailTemplates')
    .then(data => console.log('Config retrieved with caching'))
    .catch(err => console.error(err));
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_13() {
  // Using AWS AppConfig Data with polling for configuration updates
  const appConfigData = new AppConfigData({ region: 'us-east-1' });
  let configurationToken = null;
  
  async function pollForConfigurationUpdates() {
    try {
      if (!configurationToken) {
        const session = await appConfigData.startConfigurationSession({
          ApplicationIdentifier: 'DataProcessingService',
          EnvironmentIdentifier: 'Production',
          ConfigurationProfileIdentifier: 'ProcessingRules'
        });
        configurationToken = session.InitialConfigurationToken;
      }
      
      // ok: js-deprecated-get-configuration
      const result = await appConfigData.getLatestConfiguration({
        ConfigurationToken: configurationToken
      });
      
      // Update token for next poll
      configurationToken = result.NextPollConfigurationToken;
      
      // Process configuration if it changed
      if (result.Configuration && result.Configuration.length > 0) {
        console.log('Configuration updated');
      }
      
      // Schedule next poll
      setTimeout(pollForConfigurationUpdates, 30000);
    } catch (err) {
      console.error('Error polling for configuration updates:', err);
      // Reset token and try again later
      configurationToken = null;
      setTimeout(pollForConfigurationUpdates, 60000);
    }
  }
  
  // Start polling
  pollForConfigurationUpdates();
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_14() {
  // Using a configuration registry pattern with the recommended API
  class ConfigRegistry {
    constructor() {
      this.appConfigData = new AppConfigData({ region: 'us-west-2' });
      this.configs = {};
      this.sessions = {};
    }
    
    async registerConfig(name, app, env, profile) {
      const session = await this.appConfigData.startConfigurationSession({
        ApplicationIdentifier: app,
        EnvironmentIdentifier: env,
        ConfigurationProfileIdentifier: profile
      });
      
      this.sessions[name] = session.InitialConfigurationToken;
    }
    
    async getConfig(name) {
      if (!this.sessions[name]) {
        throw new Error(`Configuration ${name} not registered`);
      }
      
      // ok: js-deprecated-get-configuration
      const result = await this.appConfigData.getLatestConfiguration({
        ConfigurationToken: this.sessions[name]
      });
      
      // Update token for next request
      if (result.NextPollConfigurationToken) {
        this.sessions[name] = result.NextPollConfigurationToken;
      }
      
      return result;
    }
  }
  
  const registry = new ConfigRegistry();
  async function initializeRegistry() {
    await registry.registerConfig('reportFormats', 'ReportingService', 'Production', 'ReportFormats');
    const config = await registry.getConfig('reportFormats');
    console.log('Report formats config loaded');
  }
  
  initializeRegistry().catch(err => console.error(err));
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_15() {
  // Using AWS AppConfig Agent with retry logic
  const { AppConfigAgent } = require('@aws-sdk/client-appconfig-agent');
  const agent = new AppConfigAgent({ region: 'us-east-1' });
  
  async function getConfigWithRetry(app, env, config, maxRetries = 3) {
    let retries = 0;
    
    while (retries <= maxRetries) {
      try {
        // ok: js-deprecated-get-configuration
        const result = await agent.getConfiguration({
          ApplicationIdentifier: app,
          ConfigurationIdentifier: config,
          EnvironmentIdentifier: env
        });
        
        return result;
      } catch (err) {
        retries++;
        if (retries > maxRetries) {
          throw err;
        }
        
        // Exponential backoff
        const delay = Math.pow(2, retries) * 100;
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }
  }
  
  getConfigWithRetry('LoggingService', 'Production', 'LogLevels')
    .then(config => console.log('Log levels config retrieved with retry logic'))
    .catch(err => console.error('Failed to get config after retries:', err));
}
// {/fact}

module.exports = {
  // Export functions for testing
  bad_case_1, bad_case_2, bad_case_3, bad_case_4, bad_case_5,
  bad_case_6, bad_case_7, bad_case_8, bad_case_9, bad_case_10,
  bad_case_11, bad_case_12, bad_case_13, bad_case_14, bad_case_15,
  good_case_1, good_case_2, good_case_3, good_case_4, good_case_5,
  good_case_6, good_case_7, good_case_8, good_case_9, good_case_10,
  good_case_11, good_case_12, good_case_13, good_case_14, good_case_15
};