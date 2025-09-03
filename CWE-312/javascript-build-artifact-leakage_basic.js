// This file contains examples of secure and insecure usage of environment variables
// in build artifact plugins and configuration files

// True Positive Examples (Vulnerable Code)

// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_1() {
  const webpack = require('webpack');
  
  // ruleid: javascript-build-artifact-leakage
  const config = {
    plugins: [
      new webpack.DefinePlugin({
        'process.env': JSON.stringify(process.env)
      })
    ]
  };
  
  return config;
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_2() {
  const { DefinePlugin } = require('webpack');
  
  // ruleid: javascript-build-artifact-leakage
  module.exports = {
    plugins: [
      new DefinePlugin({
        ENV_VARS: JSON.stringify(process.env)
      })
    ]
  };
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_3() {
  const rollup = require('rollup');
  const replace = require('@rollup/plugin-replace');
  
  // ruleid: javascript-build-artifact-leakage
  const config = {
    plugins: [
      replace({
        'process.env': JSON.stringify(process.env)
      })
    ]
  };
  
  return rollup.rollup(config);
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_4() {
  const { EnvironmentPlugin } = require('webpack');
  
  // ruleid: javascript-build-artifact-leakage
  const config = {
    plugins: [
      new EnvironmentPlugin(Object.keys(process.env))
    ]
  };
  
  return config;
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_5() {
  const parcel = require('parcel-bundler');
  
  // ruleid: javascript-build-artifact-leakage
  const options = {
    env: process.env
  };
  
  const bundler = new parcel('./index.html', options);
  return bundler.bundle();
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_6() {
  const gulp = require('gulp');
  const template = require('gulp-template');
  
  // ruleid: javascript-build-artifact-leakage
  gulp.task('build', function() {
    return gulp.src('./src/*.js')
      .pipe(template({ env: process.env }))
      .pipe(gulp.dest('./dist'));
  });
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_7() {
  const esbuild = require('esbuild');
  
  // ruleid: javascript-build-artifact-leakage
  esbuild.build({
    entryPoints: ['app.js'],
    bundle: true,
    define: {
      'process.env': JSON.stringify(process.env)
    },
    outfile: 'out.js',
  });
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_8() {
  const vite = require('vite');
  
  // ruleid: javascript-build-artifact-leakage
  const config = {
    define: {
      'process.env': JSON.stringify(process.env)
    }
  };
  
  return vite.build(config);
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_9() {
  const { createApp } = require('vue');
  
  // ruleid: javascript-build-artifact-leakage
  const app = createApp({
    data() {
      return {
        environmentVariables: process.env
      }
    }
  });
  
  app.mount('#app');
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_10() {
  const nextConfig = {
    env: process.env,
    // ruleid: javascript-build-artifact-leakage
    webpack: (config) => {
      config.plugins.push(
        new require('webpack').DefinePlugin({
          'global.ENV': JSON.stringify(process.env)
        })
      );
      return config;
    }
  };
  
  module.exports = nextConfig;
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_11() {
  const { resolve } = require('path');
  const HtmlWebpackPlugin = require('html-webpack-plugin');
  
  // ruleid: javascript-build-artifact-leakage
  module.exports = {
    entry: './src/index.js',
    output: {
      path: resolve(__dirname, 'dist'),
      filename: 'bundle.js',
    },
    plugins: [
      new HtmlWebpackPlugin({
        template: './src/index.html',
        templateParameters: {
          env: process.env
        }
      })
    ]
  };
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_12() {
  const snowpack = require('snowpack');
  
  // ruleid: javascript-build-artifact-leakage
  const config = {
    buildOptions: {
      env: process.env
    }
  };
  
  snowpack.build(config);
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_13() {
  const browserify = require('browserify');
  const envify = require('envify/custom');
  
  // ruleid: javascript-build-artifact-leakage
  browserify('./main.js')
    .transform(envify(process.env))
    .bundle()
    .pipe(require('fs').createWriteStream('./bundle.js'));
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_14() {
  const { build } = require('@sveltejs/kit');
  
  // ruleid: javascript-build-artifact-leakage
  build({
    config: {
      kit: {
        env: {
          publicVars: process.env
        }
      }
    }
  });
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_15() {
  const { createStore } = require('redux');
  
  // ruleid: javascript-build-artifact-leakage
  const initialState = {
    environment: process.env
  };
  
  const store = createStore((state = initialState) => state);
  
  // This store might be serialized and included in the build
  window.__REDUX_STATE__ = store.getState();
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_1() {
  const webpack = require('webpack');
  
  // ok: javascript-build-artifact-leakage
  const config = {
    plugins: [
      new webpack.DefinePlugin({
        'process.env.NODE_ENV': JSON.stringify(process.env.NODE_ENV),
        'process.env.PUBLIC_URL': JSON.stringify(process.env.PUBLIC_URL)
      })
    ]
  };
  
  return config;
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_2() {
  const { DefinePlugin } = require('webpack');
  
  const publicEnvVars = {
    NODE_ENV: process.env.NODE_ENV,
    PUBLIC_URL: process.env.PUBLIC_URL
  };
  
  // ok: javascript-build-artifact-leakage
  module.exports = {
    plugins: [
      new DefinePlugin({
        'process.env': JSON.stringify(publicEnvVars)
      })
    ]
  };
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_3() {
  const rollup = require('rollup');
  const replace = require('@rollup/plugin-replace');
  
  // ok: javascript-build-artifact-leakage
  const config = {
    plugins: [
      replace({
        'process.env.NODE_ENV': JSON.stringify(process.env.NODE_ENV)
      })
    ]
  };
  
  return rollup.rollup(config);
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_4() {
  const { EnvironmentPlugin } = require('webpack');
  
  // ok: javascript-build-artifact-leakage
  const config = {
    plugins: [
      new EnvironmentPlugin(['NODE_ENV', 'PUBLIC_URL'])
    ]
  };
  
  return config;
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_5() {
  const parcel = require('parcel-bundler');
  
  // ok: javascript-build-artifact-leakage
  const options = {
    env: {
      NODE_ENV: process.env.NODE_ENV,
      PUBLIC_URL: process.env.PUBLIC_URL
    }
  };
  
  const bundler = new parcel('./index.html', options);
  return bundler.bundle();
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_6() {
  const gulp = require('gulp');
  const template = require('gulp-template');
  
  // ok: javascript-build-artifact-leakage
  gulp.task('build', function() {
    return gulp.src('./src/*.js')
      .pipe(template({ 
        nodeEnv: process.env.NODE_ENV,
        publicUrl: process.env.PUBLIC_URL
      }))
      .pipe(gulp.dest('./dist'));
  });
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_7() {
  const esbuild = require('esbuild');
  
  // ok: javascript-build-artifact-leakage
  esbuild.build({
    entryPoints: ['app.js'],
    bundle: true,
    define: {
      'process.env.NODE_ENV': JSON.stringify(process.env.NODE_ENV)
    },
    outfile: 'out.js',
  });
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_8() {
  const vite = require('vite');
  
  // ok: javascript-build-artifact-leakage
  const config = {
    define: {
      'process.env.NODE_ENV': JSON.stringify(process.env.NODE_ENV),
      'process.env.BASE_URL': JSON.stringify(process.env.BASE_URL)
    }
  };
  
  return vite.build(config);
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_9() {
  const { createApp } = require('vue');
  
  // ok: javascript-build-artifact-leakage
  const app = createApp({
    data() {
      return {
        nodeEnv: process.env.NODE_ENV,
        baseUrl: process.env.BASE_URL
      }
    }
  });
  
  app.mount('#app');
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_10() {
  const publicEnvVars = ['NODE_ENV', 'BASE_URL', 'PUBLIC_URL'];
  
  const filteredEnv = {};
  publicEnvVars.forEach(key => {
    if (process.env[key]) {
      filteredEnv[key] = process.env[key];
    }
  });
  
  // ok: javascript-build-artifact-leakage
  const nextConfig = {
    env: filteredEnv,
    webpack: (config) => {
      config.plugins.push(
        new require('webpack').DefinePlugin({
          'global.ENV': JSON.stringify(filteredEnv)
        })
      );
      return config;
    }
  };
  
  module.exports = nextConfig;
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_11() {
  const { resolve } = require('path');
  const HtmlWebpackPlugin = require('html-webpack-plugin');
  
  // ok: javascript-build-artifact-leakage
  module.exports = {
    entry: './src/index.js',
    output: {
      path: resolve(__dirname, 'dist'),
      filename: 'bundle.js',
    },
    plugins: [
      new HtmlWebpackPlugin({
        template: './src/index.html',
        templateParameters: {
          nodeEnv: process.env.NODE_ENV,
          publicUrl: process.env.PUBLIC_URL
        }
      })
    ]
  };
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_12() {
  const snowpack = require('snowpack');
  
  // ok: javascript-build-artifact-leakage
  const config = {
    buildOptions: {
      env: {
        NODE_ENV: process.env.NODE_ENV,
        PUBLIC_URL: process.env.PUBLIC_URL
      }
    }
  };
  
  snowpack.build(config);
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_13() {
  const browserify = require('browserify');
  const envify = require('envify/custom');
  
  const publicEnv = {
    NODE_ENV: process.env.NODE_ENV,
    PUBLIC_URL: process.env.PUBLIC_URL
  };
  
  // ok: javascript-build-artifact-leakage
  browserify('./main.js')
    .transform(envify(publicEnv))
    .bundle()
    .pipe(require('fs').createWriteStream('./bundle.js'));
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_14() {
  const { build } = require('@sveltejs/kit');
  
  // ok: javascript-build-artifact-leakage
  build({
    config: {
      kit: {
        env: {
          publicVars: {
            NODE_ENV: process.env.NODE_ENV,
            PUBLIC_URL: process.env.PUBLIC_URL
          }
        }
      }
    }
  });
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_15() {
  const { createStore } = require('redux');
  
  // ok: javascript-build-artifact-leakage
  const initialState = {
    environment: {
      nodeEnv: process.env.NODE_ENV,
      publicUrl: process.env.PUBLIC_URL
    }
  };
  
  const store = createStore((state = initialState) => state);
  
  // Only public environment variables are included in the serialized state
  window.__REDUX_STATE__ = store.getState();
}
// {/fact}