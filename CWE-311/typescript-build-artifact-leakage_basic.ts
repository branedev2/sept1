import * as webpack from 'webpack';
import { DefinePlugin } from 'webpack';
import * as dotenv from 'dotenv';
import * as fs from 'fs';
import * as path from 'path';
import { EnvironmentPlugin } from 'webpack';
import { Configuration as WebpackConfiguration } from 'webpack';
import { Configuration as WebpackDevServerConfiguration } from 'webpack-dev-server';
import HtmlWebpackPlugin from 'html-webpack-plugin';
import TerserPlugin from 'terser-webpack-plugin';
import MiniCssExtractPlugin from 'mini-css-extract-plugin';

// True Positives (Vulnerable Code)

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_1() {
  // Directly exposing all environment variables in webpack configuration
  const config: webpack.Configuration = {
    // ... other webpack config
    plugins: [
      // ruleid: typescript-build-artifact-leakage
      new webpack.DefinePlugin({
        'process.env': JSON.stringify(process.env)
      })
    ]
  };
  return config;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_2() {
  // Using EnvironmentPlugin without specifying which variables to expose
  const webpackConfig = {
    // ... other config
    plugins: [
      // ruleid: typescript-build-artifact-leakage
      new webpack.EnvironmentPlugin(process.env)
    ]
  };
  return webpackConfig;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_3() {
  // Exposing all environment variables in a React app
  const config = {
    plugins: [
      // ruleid: typescript-build-artifact-leakage
      new DefinePlugin({
        'window.env': JSON.stringify(process.env)
      })
    ]
  };
  return config;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_4() {
  // Creating a global object with all environment variables
  const envKeys = Object.keys(process.env).reduce((prev, next) => {
    prev[`process.env.${next}`] = JSON.stringify(process.env[next]);
    return prev;
  }, {} as Record<string, string>);
  
  const config = {
    plugins: [
      // ruleid: typescript-build-artifact-leakage
      new DefinePlugin(envKeys)
    ]
  };
  return config;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_5() {
  // Exposing environment in HTML webpack plugin
  const config = {
    plugins: [
      new HtmlWebpackPlugin({
        template: './src/index.html',
        // ruleid: typescript-build-artifact-leakage
        templateParameters: {
          env: process.env
        }
      })
    ]
  };
  return config;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_6() {
  // Using a function that returns all environment variables
  const getAllEnv = () => process.env;
  
  const config = {
    plugins: [
      // ruleid: typescript-build-artifact-leakage
      new DefinePlugin({
        'process.env': JSON.stringify(getAllEnv())
      })
    ]
  };
  return config;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_7() {
  // Spreading environment variables into an object
  const envVars = {
    APP_VERSION: '1.0.0',
    ...process.env
  };
  
  const config = {
    plugins: [
      // ruleid: typescript-build-artifact-leakage
      new DefinePlugin({
        'process.env': JSON.stringify(envVars)
      })
    ]
  };
  return config;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_8() {
  // Using environment variables in a custom plugin
  class EnvExposingPlugin {
    apply(compiler: webpack.Compiler) {
      compiler.hooks.emit.tapAsync('EnvExposingPlugin', (compilation, callback) => {
        // ruleid: typescript-build-artifact-leakage
        const envData = JSON.stringify(process.env);
        compilation.assets['env-data.json'] = {
          source: () => envData,
          size: () => envData.length
        };
        callback();
      });
    }
  }
  
  const config = {
    plugins: [new EnvExposingPlugin()]
  };
  return config;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_9() {
  // Using environment in banner plugin
  const config = {
    plugins: [
      // ruleid: typescript-build-artifact-leakage
      new webpack.BannerPlugin({
        banner: `Environment: ${JSON.stringify(process.env)}`
      })
    ]
  };
  return config;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_10() {
  // Conditionally including all environment variables
  const isDev = process.env.NODE_ENV === 'development';
  
  const config = {
    plugins: [
      // ruleid: typescript-build-artifact-leakage
      new DefinePlugin({
        'process.env': isDev ? {} : JSON.stringify(process.env)
      })
    ]
  };
  return config;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_11() {
  // Using a utility function to process environment variables but still exposing all
  function processEnv(env: NodeJS.ProcessEnv) {
    return Object.entries(env).reduce((acc, [key, value]) => {
      acc[key] = JSON.stringify(value);
      return acc;
    }, {} as Record<string, string>);
  }
  
  const config = {
    plugins: [
      // ruleid: typescript-build-artifact-leakage
      new DefinePlugin({
        'process.env': processEnv(process.env)
      })
    ]
  };
  return config;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_12() {
  // Using environment variables in a loader
  const config = {
    module: {
      rules: [
        {
          test: /\.js$/,
          use: [
            {
              loader: 'string-replace-loader',
              options: {
                // ruleid: typescript-build-artifact-leakage
                search: 'ENV_PLACEHOLDER',
                replace: JSON.stringify(process.env)
              }
            }
          ]
        }
      ]
    }
  };
  return config;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_13() {
  // Creating a dynamic plugin that exposes environment
  function createEnvPlugin() {
    return new DefinePlugin({
      // ruleid: typescript-build-artifact-leakage
      'window.__ENV__': JSON.stringify(process.env)
    });
  }
  
  const config = {
    plugins: [createEnvPlugin()]
  };
  return config;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_14() {
  // Using environment in optimization settings
  const terserOptions = {
    terserOptions: {
      compress: {
        drop_console: true
      },
      format: {
        // ruleid: typescript-build-artifact-leakage
        comments: `Environment: ${JSON.stringify(process.env)}`
      }
    }
  };
  
  const config = {
    optimization: {
      minimizer: [new TerserPlugin(terserOptions)]
    }
  };
  return config;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_15() {
  // Using environment in CSS extraction
  const config = {
    plugins: [
      new MiniCssExtractPlugin({
        filename: '[name].css',
        chunkFilename: '[id].css',
        // ruleid: typescript-build-artifact-leakage
        ignoreOrder: process.env.NODE_ENV === 'production',
        attributes: {
          env: JSON.stringify(process.env)
        }
      })
    ]
  };
  return config;
}
// {/fact}

// True Negatives (Safe Code)

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_1() {
  // Only exposing specific environment variables
  const config: webpack.Configuration = {
    plugins: [
      // ok: typescript-build-artifact-leakage
      new webpack.DefinePlugin({
        'process.env.NODE_ENV': JSON.stringify(process.env.NODE_ENV),
        'process.env.PUBLIC_URL': JSON.stringify(process.env.PUBLIC_URL)
      })
    ]
  };
  return config;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_2() {
  // Using EnvironmentPlugin with specific variables
  const webpackConfig = {
    plugins: [
      // ok: typescript-build-artifact-leakage
      new webpack.EnvironmentPlugin(['NODE_ENV', 'PUBLIC_URL', 'REACT_APP_VERSION'])
    ]
  };
  return webpackConfig;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_3() {
  // Exposing only public environment variables with a prefix
  const publicEnvVars = Object.keys(process.env)
    .filter(key => key.startsWith('REACT_APP_'))
    .reduce((env, key) => {
      env[key] = process.env[key];
      return env;
    }, {} as Record<string, string | undefined>);
  
  const config = {
    plugins: [
      // ok: typescript-build-artifact-leakage
      new DefinePlugin({
        'process.env': JSON.stringify(publicEnvVars)
      })
    ]
  };
  return config;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_4() {
  // Manually specifying each environment variable
  const config = {
    plugins: [
      // ok: typescript-build-artifact-leakage
      new DefinePlugin({
        'process.env.NODE_ENV': JSON.stringify(process.env.NODE_ENV),
        'process.env.API_URL': JSON.stringify(process.env.API_URL),
        'process.env.APP_VERSION': JSON.stringify(process.env.APP_VERSION)
      })
    ]
  };
  return config;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_5() {
  // Using a whitelist approach for environment variables
  const allowedEnvVars = ['NODE_ENV', 'PUBLIC_URL', 'REACT_APP_API_ENDPOINT'];
  const safeEnv = allowedEnvVars.reduce((acc, key) => {
    if (process.env[key]) {
      acc[`process.env.${key}`] = JSON.stringify(process.env[key]);
    }
    return acc;
  }, {} as Record<string, string>);
  
  const config = {
    plugins: [
      // ok: typescript-build-artifact-leakage
      new DefinePlugin(safeEnv)
    ]
  };
  return config;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_6() {
  // Using dotenv to load environment variables and selecting specific ones
  dotenv.config();
  
  const config = {
    plugins: [
      // ok: typescript-build-artifact-leakage
      new DefinePlugin({
        'process.env.NODE_ENV': JSON.stringify(process.env.NODE_ENV),
        'process.env.API_URL': JSON.stringify(process.env.API_URL)
      })
    ]
  };
  return config;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_7() {
  // Using a configuration file to specify public environment variables
  const envConfig = {
    NODE_ENV: process.env.NODE_ENV,
    PUBLIC_URL: process.env.PUBLIC_URL,
    VERSION: process.env.VERSION
  };
  
  const config = {
    plugins: [
      // ok: typescript-build-artifact-leakage
      new DefinePlugin({
        'process.env': JSON.stringify(envConfig)
      })
    ]
  };
  return config;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_8() {
  // Creating a custom plugin that only exposes specific environment variables
  class SafeEnvPlugin {
    apply(compiler: webpack.Compiler) {
      compiler.hooks.emit.tapAsync('SafeEnvPlugin', (compilation, callback) => {
        // ok: typescript-build-artifact-leakage
        const safeEnv = {
          NODE_ENV: process.env.NODE_ENV,
          PUBLIC_URL: process.env.PUBLIC_URL
        };
        const envData = JSON.stringify(safeEnv);
        compilation.assets['env-data.json'] = {
          source: () => envData,
          size: () => envData.length
        };
        callback();
      });
    }
  }
  
  const config = {
    plugins: [new SafeEnvPlugin()]
  };
  return config;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_9() {
  // Using environment in banner plugin with specific variables
  const config = {
    plugins: [
      // ok: typescript-build-artifact-leakage
      new webpack.BannerPlugin({
        banner: `Version: ${process.env.VERSION}, Environment: ${process.env.NODE_ENV}`
      })
    ]
  };
  return config;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_10() {
  // Using a hardcoded configuration instead of environment variables
  const config = {
    plugins: [
      // ok: typescript-build-artifact-leakage
      new DefinePlugin({
        'process.env': JSON.stringify({
          NODE_ENV: 'production',
          API_URL: 'https://api.example.com'
        })
      })
    ]
  };
  return config;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_11() {
  // Loading environment variables from a file and selecting specific ones
  const envPath = path.resolve(process.cwd(), '.env');
  const envContent = fs.readFileSync(envPath, 'utf8');
  const parsedEnv = dotenv.parse(envContent);
  
  const safeEnv = {
    NODE_ENV: parsedEnv.NODE_ENV,
    PUBLIC_URL: parsedEnv.PUBLIC_URL
  };
  
  const config = {
    plugins: [
      // ok: typescript-build-artifact-leakage
      new DefinePlugin({
        'process.env': JSON.stringify(safeEnv)
      })
    ]
  };
  return config;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_12() {
  // Using environment variables in a loader with specific variables
  const config = {
    module: {
      rules: [
        {
          test: /\.js$/,
          use: [
            {
              loader: 'string-replace-loader',
              options: {
                // ok: typescript-build-artifact-leakage
                search: 'ENV_PLACEHOLDER',
                replace: JSON.stringify({
                  NODE_ENV: process.env.NODE_ENV,
                  PUBLIC_URL: process.env.PUBLIC_URL
                })
              }
            }
          ]
        }
      ]
    }
  };
  return config;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_13() {
  // Creating a dynamic plugin that exposes only specific environment variables
  function createSafeEnvPlugin() {
    return new DefinePlugin({
      // ok: typescript-build-artifact-leakage
      'window.__ENV__': JSON.stringify({
        NODE_ENV: process.env.NODE_ENV,
        API_URL: process.env.API_URL
      })
    });
  }
  
  const config = {
    plugins: [createSafeEnvPlugin()]
  };
  return config;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_14() {
  // Using a separate configuration file for environment variables
  interface EnvConfig {
    NODE_ENV: string;
    API_URL: string;
    VERSION: string;
  }
  
  const envConfig: EnvConfig = {
    NODE_ENV: process.env.NODE_ENV || 'development',
    API_URL: process.env.API_URL || 'http://localhost:3000',
    VERSION: process.env.VERSION || '1.0.0'
  };
  
  const config: WebpackConfiguration = {
    plugins: [
      // ok: typescript-build-artifact-leakage
      new DefinePlugin({
        'process.env': JSON.stringify(envConfig)
      })
    ]
  };
  return config;
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_15() {
  // Using a function to filter environment variables by a naming convention
  function getPublicEnvVars() {
    return Object.keys(process.env)
      .filter(key => key.startsWith('PUBLIC_') || key === 'NODE_ENV')
      .reduce((acc, key) => {
        acc[key] = process.env[key];
        return acc;
      }, {} as Record<string, string | undefined>);
  }
  
  const config = {
    plugins: [
      // ok: typescript-build-artifact-leakage
      new DefinePlugin({
        'process.env': JSON.stringify(getPublicEnvVars())
      })
    ]
  };
  return config;
}
// {/fact}