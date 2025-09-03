// Test cases for js-deprecated-get-configuration rule
// This rule detects usage of the deprecated AWS AppConfig GetConfiguration API

const AWS = require('aws-sdk');
const { AppConfigData } = require('@aws-sdk/client-appconfigdata');
const { AppConfig } = require('@aws-sdk/client-appconfig');
const axios = require('axios');
const fs = require('fs');

// True positive examples (vulnerable/insecure code that MUST be detected)

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
    }, function(err, data) {
        if (err) console.log(err, err.stack);
        else console.log(data);
    });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_2() {
    // Using the deprecated GetConfiguration API with promises
    const appConfig = new AWS.AppConfig();
    
    // ruleid: js-deprecated-get-configuration
    appConfig.getConfiguration({
        Application: 'MyApp',
        Environment: 'Development',
        Configuration: 'FeatureFlags',
        ClientId: 'client-2'
    }).promise()
      .then(data => console.log(data))
      .catch(err => console.error(err));
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_3() {
    // Using the deprecated GetConfiguration API with async/await
    async function fetchConfig() {
        const appConfig = new AWS.AppConfig();
        try {
            // ruleid: js-deprecated-get-configuration
            const data = await appConfig.getConfiguration({
                Application: 'ServiceA',
                Environment: 'Testing',
                Configuration: 'APISettings',
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
    const appName = process.env.APP_NAME || 'DefaultApp';
    const envName = process.env.ENV_NAME || 'Production';
    const configName = 'DatabaseSettings';
    
    // ruleid: js-deprecated-get-configuration
    appConfig.getConfiguration({
        Application: appName,
        Environment: envName,
        Configuration: configName,
        ClientId: 'client-4'
    }, function(err, data) {
        if (err) console.log(err, err.stack);
        else console.log(data);
    });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_5() {
    // Using the deprecated GetConfiguration API in a class method
    class ConfigManager {
        constructor() {
            this.appConfig = new AWS.AppConfig();
            this.clientId = 'client-5';
        }
        
        fetchConfiguration(appName, envName, configName) {
            // ruleid: js-deprecated-get-configuration
            return this.appConfig.getConfiguration({
                Application: appName,
                Environment: envName,
                Configuration: configName,
                ClientId: this.clientId
            }).promise();
        }
    }
    
    const manager = new ConfigManager();
    manager.fetchConfiguration('MyApp', 'Staging', 'LoggingConfig')
        .then(data => console.log(data))
        .catch(err => console.error(err));
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_6() {
    // Using the deprecated GetConfiguration API with destructuring
    const { AppConfig } = AWS;
    const appConfig = new AppConfig();
    
    // ruleid: js-deprecated-get-configuration
    appConfig.getConfiguration({
        Application: 'PaymentService',
        Environment: 'Production',
        Configuration: 'PaymentGateways',
        ClientId: 'client-6'
    }, (err, data) => {
        if (err) console.log(err);
        else console.log(data);
    });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_7() {
    // Using the deprecated GetConfiguration API with conditional execution
    const appConfig = new AWS.AppConfig();
    const shouldFetchConfig = true;
    
    if (shouldFetchConfig) {
        // ruleid: js-deprecated-get-configuration
        appConfig.getConfiguration({
            Application: 'NotificationService',
            Environment: 'Production',
            Configuration: 'EmailTemplates',
            ClientId: 'client-7'
        }, (err, data) => {
            if (!err) {
                processTemplates(data);
            }
        });
    }
    
    function processTemplates(data) {
        console.log('Processing templates:', data);
    }
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_8() {
    // Using the deprecated GetConfiguration API in a loop
    const appConfig = new AWS.AppConfig();
    const environments = ['Dev', 'Test', 'Staging', 'Production'];
    
    environments.forEach(env => {
        // ruleid: js-deprecated-get-configuration
        appConfig.getConfiguration({
            Application: 'MonitoringApp',
            Environment: env,
            Configuration: 'AlertSettings',
            ClientId: `client-8-${env}`
        }, (err, data) => {
            if (!err) {
                console.log(`Config for ${env}:`, data);
            }
        });
    });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_9() {
    // Using the deprecated GetConfiguration API with error handling
    const appConfig = new AWS.AppConfig();
    
    try {
        // ruleid: js-deprecated-get-configuration
        appConfig.getConfiguration({
            Application: 'AnalyticsService',
            Environment: 'Production',
            Configuration: 'TrackingConfig',
            ClientId: 'client-9'
        }, function(err, data) {
            if (err) {
                handleError(err);
            } else {
                initializeAnalytics(data);
            }
        });
    } catch (error) {
        console.error('Failed to fetch configuration:', error);
    }
    
    function handleError(err) {
        console.error('Configuration error:', err);
    }
    
    function initializeAnalytics(config) {
        console.log('Initializing analytics with config:', config);
    }
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_10() {
    // Using the deprecated GetConfiguration API with a custom client configuration
    const appConfig = new AWS.AppConfig({
        region: 'us-west-2',
        maxRetries: 3,
        httpOptions: {
            timeout: 5000
        }
    });
    
    // ruleid: js-deprecated-get-configuration
    appConfig.getConfiguration({
        Application: 'UserService',
        Environment: 'Production',
        Configuration: 'UserPreferences',
        ClientId: 'client-10'
    }).promise()
      .then(data => console.log(data))
      .catch(err => console.error(err));
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_11() {
    // Using the deprecated GetConfiguration API with dynamic configuration name
    const appConfig = new AWS.AppConfig();
    const configTypes = ['database', 'cache', 'api'];
    
    function loadConfiguration(configType) {
        const configName = `${configType}Config`;
        
        // ruleid: js-deprecated-get-configuration
        return appConfig.getConfiguration({
            Application: 'InfrastructureService',
            Environment: 'Production',
            Configuration: configName,
            ClientId: `client-11-${configType}`
        }).promise();
    }
    
    configTypes.forEach(type => {
        loadConfiguration(type)
            .then(config => console.log(`Loaded ${type} config:`, config))
            .catch(err => console.error(`Failed to load ${type} config:`, err));
    });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_12() {
    // Using the deprecated GetConfiguration API with a wrapper function
    const appConfig = new AWS.AppConfig();
    
    function fetchAppConfig(app, env, config) {
        // ruleid: js-deprecated-get-configuration
        return appConfig.getConfiguration({
            Application: app,
            Environment: env,
            Configuration: config,
            ClientId: 'client-12'
        }).promise();
    }
    
    fetchAppConfig('AuthService', 'Production', 'OAuthSettings')
        .then(data => {
            console.log('OAuth settings:', data);
        })
        .catch(err => {
            console.error('Failed to fetch OAuth settings:', err);
        });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_13() {
    // Using the deprecated GetConfiguration API with callback chaining
    const appConfig = new AWS.AppConfig();
    
    // ruleid: js-deprecated-get-configuration
    appConfig.getConfiguration({
        Application: 'LoggingService',
        Environment: 'Production',
        Configuration: 'LogLevels',
        ClientId: 'client-13'
    }, function(err, data) {
        if (err) {
            console.error(err);
            return;
        }
        
        // Process the first config and fetch another
        console.log('Log levels:', data);
        
        // ruleid: js-deprecated-get-configuration
        appConfig.getConfiguration({
            Application: 'LoggingService',
            Environment: 'Production',
            Configuration: 'LogDestinations',
            ClientId: 'client-13'
        }, function(err2, data2) {
            if (err2) {
                console.error(err2);
                return;
            }
            
            console.log('Log destinations:', data2);
        });
    });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_14() {
    // Using the deprecated GetConfiguration API with a timeout
    const appConfig = new AWS.AppConfig();
    
    const timeoutPromise = new Promise((_, reject) => {
        setTimeout(() => reject(new Error('Request timed out')), 3000);
    });
    
    // ruleid: js-deprecated-get-configuration
    const configPromise = appConfig.getConfiguration({
        Application: 'CacheService',
        Environment: 'Production',
        Configuration: 'CacheSettings',
        ClientId: 'client-14'
    }).promise();
    
    Promise.race([configPromise, timeoutPromise])
        .then(data => console.log('Cache settings:', data))
        .catch(err => console.error('Error:', err));
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_15() {
    // Using the deprecated GetConfiguration API with event handling
    const appConfig = new AWS.AppConfig();
    const EventEmitter = require('events');
    const configEmitter = new EventEmitter();
    
    configEmitter.on('fetch-config', ({ app, env, config }) => {
        // ruleid: js-deprecated-get-configuration
        appConfig.getConfiguration({
            Application: app,
            Environment: env,
            Configuration: config,
            ClientId: 'client-15'
        }, (err, data) => {
            if (err) {
                configEmitter.emit('config-error', err);
            } else {
                configEmitter.emit('config-loaded', data);
            }
        });
    });
    
    configEmitter.on('config-loaded', (data) => {
        console.log('Configuration loaded:', data);
    });
    
    configEmitter.on('config-error', (err) => {
        console.error('Configuration error:', err);
    });
    
    configEmitter.emit('fetch-config', {
        app: 'EventService',
        env: 'Production',
        config: 'EventHandlers'
    });
}
// {/fact}

// True negative examples (safe/secure code that MUST NOT be detected)

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_1() {
    // Using the recommended AWS AppConfig Agent and GetLatestConfiguration API
    const appConfigData = new AppConfigData({ region: 'us-west-2' });
    
    // ok: js-deprecated-get-configuration
    appConfigData.startConfigurationSession({
        ApplicationIdentifier: 'MyApp',
        EnvironmentIdentifier: 'Production',
        ConfigurationProfileIdentifier: 'MyConfig'
    }).then(session => {
        return appConfigData.getLatestConfiguration({
            ConfigurationToken: session.InitialConfigurationToken
        });
    }).then(data => {
        console.log('Configuration data:', data);
    }).catch(err => {
        console.error('Error:', err);
    });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_2() {
    // Using the recommended AWS AppConfig Agent and GetLatestConfiguration API with async/await
    async function fetchConfig() {
        const appConfigData = new AppConfigData({ region: 'us-west-2' });
        
        try {
            // ok: js-deprecated-get-configuration
            const session = await appConfigData.startConfigurationSession({
                ApplicationIdentifier: 'MyApp',
                EnvironmentIdentifier: 'Development',
                ConfigurationProfileIdentifier: 'FeatureFlags'
            });
            
            const configData = await appConfigData.getLatestConfiguration({
                ConfigurationToken: session.InitialConfigurationToken
            });
            
            return configData;
        } catch (err) {
            console.error('Error fetching configuration:', err);
            return null;
        }
    }
    
    fetchConfig();
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_3() {
    // Using a different AWS service that doesn't involve AppConfig
    const s3 = new AWS.S3();
    
    // ok: js-deprecated-get-configuration
    s3.getObject({
        Bucket: 'my-config-bucket',
        Key: 'configs/app-config.json'
    }, function(err, data) {
        if (err) console.log(err, err.stack);
        else console.log(data);
    });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_4() {
    // Using environment variables for configuration instead of AppConfig
    const dotenv = require('dotenv');
    dotenv.config();
    
    // ok: js-deprecated-get-configuration
    const config = {
        databaseUrl: process.env.DATABASE_URL,
        apiKey: process.env.API_KEY,
        logLevel: process.env.LOG_LEVEL || 'info'
    };
    
    console.log('Application configuration:', config);
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_5() {
    // Using a local configuration file instead of AppConfig
    
    // ok: js-deprecated-get-configuration
    const config = JSON.parse(fs.readFileSync('./config.json', 'utf8'));
    console.log('Configuration loaded from file:', config);
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_6() {
    // Using the AWS AppConfig service but not calling getConfiguration
    const appConfig = new AWS.AppConfig();
    
    // ok: js-deprecated-get-configuration
    appConfig.listApplications({}, function(err, data) {
        if (err) console.log(err, err.stack);
        else console.log('Available applications:', data);
    });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_7() {
    // Using the recommended AWS AppConfig Agent with polling
    const appConfigData = new AppConfigData({ region: 'us-west-2' });
    
    async function pollConfiguration() {
        try {
            // ok: js-deprecated-get-configuration
            const session = await appConfigData.startConfigurationSession({
                ApplicationIdentifier: 'MyApp',
                EnvironmentIdentifier: 'Production',
                ConfigurationProfileIdentifier: 'RuntimeConfig'
            });
            
            let token = session.InitialConfigurationToken;
            
            // Poll for configuration updates
            setInterval(async () => {
                try {
                    const result = await appConfigData.getLatestConfiguration({
                        ConfigurationToken: token
                    });
                    
                    // Update token for next poll
                    token = result.NextPollConfigurationToken;
                    
                    if (result.Configuration && result.Configuration.length > 0) {
                        console.log('New configuration received');
                        // Process new configuration
                    }
                } catch (err) {
                    console.error('Error polling configuration:', err);
                }
            }, 30000); // Poll every 30 seconds
        } catch (err) {
            console.error('Failed to start configuration session:', err);
        }
    }
    
    pollConfiguration();
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_8() {
    // Using the AWS SDK v3 AppConfig client without getConfiguration
    const appConfig = new AppConfig({ region: 'us-west-2' });
    
    // ok: js-deprecated-get-configuration
    appConfig.createApplication({
        Name: 'NewApplication',
        Description: 'A new application for configuration management'
    }).then(result => {
        console.log('Application created:', result);
    }).catch(err => {
        console.error('Failed to create application:', err);
    });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_9() {
    // Using a custom configuration service
    class ConfigService {
        constructor() {
            this.cache = {};
        }
        
        // ok: js-deprecated-get-configuration
        async getConfiguration(appName, envName, configName) {
            const cacheKey = `${appName}:${envName}:${configName}`;
            
            if (this.cache[cacheKey]) {
                return this.cache[cacheKey];
            }
            
            try {
                const response = await axios.get(`https://config-api.example.com/config/${appName}/${envName}/${configName}`);
                this.cache[cacheKey] = response.data;
                return response.data;
            } catch (err) {
                console.error('Failed to fetch configuration:', err);
                return null;
            }
        }
    }
    
    const configService = new ConfigService();
    configService.getConfiguration('MyApp', 'Production', 'ApiSettings')
        .then(config => console.log('API settings:', config));
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_10() {
    // Using AWS Parameter Store instead of AppConfig
    const ssm = new AWS.SSM();
    
    // ok: js-deprecated-get-configuration
    ssm.getParameter({
        Name: '/MyApp/Production/DatabaseConfig',
        WithDecryption: true
    }).promise()
      .then(result => {
          const config = JSON.parse(result.Parameter.Value);
          console.log('Database configuration:', config);
      })
      .catch(err => {
          console.error('Failed to fetch parameter:', err);
      });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_11() {
    // Using AWS Secrets Manager instead of AppConfig
    const secretsManager = new AWS.SecretsManager();
    
    // ok: js-deprecated-get-configuration
    secretsManager.getSecretValue({
        SecretId: 'MyApp/Production/ApiKeys'
    }).promise()
      .then(data => {
          const secrets = JSON.parse(data.SecretString);
          console.log('API keys loaded');
      })
      .catch(err => {
          console.error('Failed to load secrets:', err);
      });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_12() {
    // Using the AWS AppConfig Data client with a complete configuration polling implementation
    const appConfigData = new AppConfigData({ region: 'us-west-2' });
    
    class ConfigurationManager {
        constructor() {
            this.configToken = null;
            this.currentConfig = null;
        }
        
        // ok: js-deprecated-get-configuration
        async initialize(appId, envId, configId) {
            try {
                const session = await appConfigData.startConfigurationSession({
                    ApplicationIdentifier: appId,
                    EnvironmentIdentifier: envId,
                    ConfigurationProfileIdentifier: configId
                });
                
                this.configToken = session.InitialConfigurationToken;
                await this.refreshConfiguration();
                
                // Set up polling
                setInterval(() => this.refreshConfiguration(), 60000);
                
                return this.currentConfig;
            } catch (err) {
                console.error('Failed to initialize configuration:', err);
                throw err;
            }
        }
        
        async refreshConfiguration() {
            try {
                const result = await appConfigData.getLatestConfiguration({
                    ConfigurationToken: this.configToken
                });
                
                this.configToken = result.NextPollConfigurationToken;
                
                if (result.Configuration && result.Configuration.length > 0) {
                    this.currentConfig = JSON.parse(
                        new TextDecoder().decode(result.Configuration)
                    );
                    console.log('Configuration updated');
                }
                
                return this.currentConfig;
            } catch (err) {
                console.error('Failed to refresh configuration:', err);
                return this.currentConfig;
            }
        }
        
        getConfig() {
            return this.currentConfig;
        }
    }
    
    const manager = new ConfigurationManager();
    manager.initialize('MyApp', 'Production', 'AppSettings')
        .then(config => console.log('Initial configuration:', config))
        .catch(err => console.error('Initialization failed:', err));
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_13() {
    // Using a feature flag service instead of AppConfig
    const LaunchDarkly = require('launchdarkly-node-server-sdk');
    
    // ok: js-deprecated-get-configuration
    const ldClient = LaunchDarkly.init('sdk-key-123');
    
    ldClient.once('ready', () => {
        const showFeature = ldClient.variation('new-feature', { key: 'user-123' }, false);
        
        if (showFeature) {
            console.log('New feature is enabled');
        } else {
            console.log('New feature is disabled');
        }
    });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_14() {
    // Using a configuration file with watch for changes
    const chokidar = require('chokidar');
    
    let currentConfig = {};
    
    function loadConfig() {
        try {
            // ok: js-deprecated-get-configuration
            const configData = fs.readFileSync('./app-config.json', 'utf8');
            currentConfig = JSON.parse(configData);
            console.log('Configuration loaded');
        } catch (err) {
            console.error('Failed to load configuration:', err);
        }
    }
    
    // Initial load
    loadConfig();
    
    // Watch for changes
    chokidar.watch('./app-config.json').on('change', () => {
        console.log('Configuration file changed, reloading...');
        loadConfig();
    });
    
    function getConfig() {
        return currentConfig;
    }
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_15() {
    // Using AWS AppConfig Data client with error handling and retries
    const appConfigData = new AppConfigData({ 
        region: 'us-west-2',
        maxAttempts: 5
    });
    
    async function getAppConfiguration(appId, envId, configId) {
        let retries = 3;
        let delay = 1000;
        
        while (retries >= 0) {
            try {
                // ok: js-deprecated-get-configuration
                const session = await appConfigData.startConfigurationSession({
                    ApplicationIdentifier: appId,
                    EnvironmentIdentifier: envId,
                    ConfigurationProfileIdentifier: configId
                });
                
                const result = await appConfigData.getLatestConfiguration({
                    ConfigurationToken: session.InitialConfigurationToken
                });
                
                if (result.Configuration && result.Configuration.length > 0) {
                    return JSON.parse(new TextDecoder().decode(result.Configuration));
                }
                
                return {};
            } catch (err) {
                console.error(`Error fetching configuration (retries left: ${retries}):`, err);
                
                if (retries <= 0) {
                    throw err;
                }
                
                // Exponential backoff
                await new Promise(resolve => setTimeout(resolve, delay));
                delay *= 2;
                retries--;
            }
        }
    }
    
    getAppConfiguration('MyApp', 'Production', 'SystemSettings')
        .then(config => console.log('System settings:', config))
        .catch(err => console.error('Failed to load configuration:', err));
}
// {/fact}