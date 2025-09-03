// File: electron_security_test_cases.js
const { app, BrowserWindow, BrowserView } = require('electron');
const path = require('path');
const url = require('url');

// TRUE POSITIVES - Insecure configurations that should be detected

// {fact rule=least-privilege-violation@v1.0 defects=1}
function bad_case_1() {
  // Creating a browser window with allowRunningInsecureContent set to true
  // This allows the execution of insecure code from secure pages
  const win = new BrowserWindow({
    width: 800,
    height: 600,
    webPreferences: {
      // ruleid: javascript-avoid-running-insecure-content-in-electron
      allowRunningInsecureContent: true
    }
  });
  win.loadURL('https://example.com');
}
// {/fact}

// {fact rule=least-privilege-violation@v1.0 defects=1}
function bad_case_2() {
  // Enabling nodeIntegration which gives web content access to Node.js APIs
  const win = new BrowserWindow({
    width: 800,
    height: 600,
    webPreferences: {
      // ruleid: javascript-avoid-running-insecure-content-in-electron
      nodeIntegration: true
    }
  });
  win.loadFile('index.html');
}
// {/fact}

// {fact rule=least-privilege-violation@v1.0 defects=1}
function bad_case_3() {
  // Enabling nodeIntegrationInWorker which gives web workers access to Node.js APIs
  const mainWindow = new BrowserWindow({
    webPreferences: {
      // ruleid: javascript-avoid-running-insecure-content-in-electron
      nodeIntegrationInWorker: true
    }
  });
  mainWindow.loadURL('https://example.com');
}
// {/fact}

// {fact rule=least-privilege-violation@v1.0 defects=1}
function bad_case_4() {
  // Enabling experimentalFeatures which may include unvetted or insecure features
  let win = new BrowserWindow({
    webPreferences: {
      // ruleid: javascript-avoid-running-insecure-content-in-electron
      experimentalFeatures: true
    }
  });
  win.loadURL('https://example.com');
}
// {/fact}

// {fact rule=least-privilege-violation@v1.0 defects=1}
function bad_case_5() {
  // Disabling webSecurity which removes protections like same-origin policy
  const window = new BrowserWindow({
    webPreferences: {
      // ruleid: javascript-avoid-running-insecure-content-in-electron
      webSecurity: false
    }
  });
  window.loadFile('index.html');
}
// {/fact}

// {fact rule=least-privilege-violation@v1.0 defects=1}
function bad_case_6() {
  // Disabling contextIsolation which is crucial for preventing prototype pollution attacks
  const win = new BrowserWindow({
    width: 800,
    height: 600,
    webPreferences: {
      // ruleid: javascript-avoid-running-insecure-content-in-electron
      contextIsolation: false
    }
  });
  win.loadURL('https://example.com');
}
// {/fact}

// {fact rule=least-privilege-violation@v1.0 defects=1}
function bad_case_7() {
  // Multiple insecure settings combined
  const win = new BrowserWindow({
    webPreferences: {
      // ruleid: javascript-avoid-running-insecure-content-in-electron
      nodeIntegration: true,
      webSecurity: false,
      contextIsolation: false
    }
  });
  win.loadURL('https://example.com');
}
// {/fact}

// {fact rule=least-privilege-violation@v1.0 defects=1}
function bad_case_8() {
  // Using BrowserView with insecure settings
  const view = new BrowserView({
    webPreferences: {
      // ruleid: javascript-avoid-running-insecure-content-in-electron
      allowRunningInsecureContent: true
    }
  });
  const win = new BrowserWindow({ width: 800, height: 600 });
  win.setBrowserView(view);
  view.setBounds({ x: 0, y: 0, width: 800, height: 600 });
  view.webContents.loadURL('https://example.com');
}
// {/fact}

// {fact rule=least-privilege-violation@v1.0 defects=1}
function bad_case_9() {
  // Using variable to set insecure configuration
  const enableNodeIntegration = true;
  const win = new BrowserWindow({
    webPreferences: {
      // ruleid: javascript-avoid-running-insecure-content-in-electron
      nodeIntegration: enableNodeIntegration
    }
  });
  win.loadURL('https://example.com');
}
// {/fact}

// {fact rule=least-privilege-violation@v1.0 defects=1}
function bad_case_10() {
  // Creating configuration object separately
  const webPrefs = {
    // ruleid: javascript-avoid-running-insecure-content-in-electron
    webSecurity: false,
    contextIsolation: false
  };
  
  const win = new BrowserWindow({
    width: 800,
    height: 600,
    webPreferences: webPrefs
  });
  win.loadURL('https://example.com');
}
// {/fact}

// {fact rule=least-privilege-violation@v1.0 defects=1}
function bad_case_11() {
  // Using destructuring and spread operator with insecure settings
  const basePrefs = { preload: path.join(__dirname, 'preload.js') };
  const insecurePrefs = { 
    // ruleid: javascript-avoid-running-insecure-content-in-electron
    nodeIntegration: true, 
    contextIsolation: false 
  };
  
  const win = new BrowserWindow({
    webPreferences: { ...basePrefs, ...insecurePrefs }
  });
  win.loadURL('https://example.com');
}
// {/fact}

// {fact rule=least-privilege-violation@v1.0 defects=1}
function bad_case_12() {
  // Conditional insecure settings
  const isDev = process.env.NODE_ENV === 'development';
  const win = new BrowserWindow({
    webPreferences: {
      // ruleid: javascript-avoid-running-insecure-content-in-electron
      webSecurity: !isDev, // Disables web security in development mode
      nodeIntegration: isDev // Enables node integration in development mode
    }
  });
  win.loadURL('https://example.com');
}
// {/fact}

// {fact rule=least-privilege-violation@v1.0 defects=1}
function bad_case_13() {
  // Using a function to create window with insecure settings
  function createWindow(url) {
    return new BrowserWindow({
      webPreferences: {
        // ruleid: javascript-avoid-running-insecure-content-in-electron
        nodeIntegration: true,
        contextIsolation: false
      }
    });
  }
  
  const win = createWindow();
  win.loadURL('https://example.com');
}
// {/fact}

// {fact rule=least-privilege-violation@v1.0 defects=1}
function bad_case_14() {
  // Using a class with insecure window creation
  class AppWindow {
    constructor(url) {
      this.window = new BrowserWindow({
        webPreferences: {
          // ruleid: javascript-avoid-running-insecure-content-in-electron
          allowRunningInsecureContent: true,
          webSecurity: false
        }
      });
      this.window.loadURL(url);
    }
  }
  
  const mainWindow = new AppWindow('https://example.com');
}
// {/fact}

// {fact rule=least-privilege-violation@v1.0 defects=1}
function bad_case_15() {
  // Using arrow function with insecure settings
  const createSecureWindow = (url) => {
    const win = new BrowserWindow({
      webPreferences: {
        // ruleid: javascript-avoid-running-insecure-content-in-electron
        experimentalFeatures: true,
        nodeIntegrationInWorker: true
      }
    });
    win.loadURL(url);
    return win;
  };
  
  const win = createSecureWindow('https://example.com');
}
// {/fact}

// TRUE NEGATIVES - Secure configurations that should not be detected

// {fact rule=least-privilege-violation@v1.0 defects=0}
function good_case_1() {
  // Using default security settings (not specifying insecure options)
  // ok: javascript-avoid-running-insecure-content-in-electron
  const win = new BrowserWindow({
    width: 800,
    height: 600
  });
  win.loadURL('https://example.com');
}
// {/fact}

// {fact rule=least-privilege-violation@v1.0 defects=0}
function good_case_2() {
  // Explicitly setting secure values
  // ok: javascript-avoid-running-insecure-content-in-electron
  const win = new BrowserWindow({
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true
    }
  });
  win.loadFile('index.html');
}
// {/fact}

// {fact rule=least-privilege-violation@v1.0 defects=0}
function good_case_3() {
  // Using preload script with secure settings
  // ok: javascript-avoid-running-insecure-content-in-electron
  const win = new BrowserWindow({
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false
    }
  });
  win.loadURL('https://example.com');
}
// {/fact}

// {fact rule=least-privilege-violation@v1.0 defects=0}
function good_case_4() {
  // Using BrowserView with secure settings
  // ok: javascript-avoid-running-insecure-content-in-electron
  const view = new BrowserView({
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true
    }
  });
  const win = new BrowserWindow({ width: 800, height: 600 });
  win.setBrowserView(view);
  view.setBounds({ x: 0, y: 0, width: 800, height: 600 });
  view.webContents.loadURL('https://example.com');
}
// {/fact}

// {fact rule=least-privilege-violation@v1.0 defects=0}
function good_case_5() {
  // Using secure defaults without specifying webPreferences
  // ok: javascript-avoid-running-insecure-content-in-electron
  const win = new BrowserWindow({
    width: 800,
    height: 600,
    title: 'Secure Window'
  });
  win.loadFile('index.html');
}
// {/fact}

// {fact rule=least-privilege-violation@v1.0 defects=0}
function good_case_6() {
  // Explicitly setting all security options to secure values
  // ok: javascript-avoid-running-insecure-content-in-electron
  const win = new BrowserWindow({
    webPreferences: {
      nodeIntegration: false,
      nodeIntegrationInWorker: false,
      contextIsolation: true,
      webSecurity: true,
      allowRunningInsecureContent: false,
      experimentalFeatures: false
    }
  });
  win.loadURL('https://example.com');
}
// {/fact}

// {fact rule=least-privilege-violation@v1.0 defects=0}
function good_case_7() {
  // Using a function to create window with secure settings
  function createSecureWindow(url) {
    // ok: javascript-avoid-running-insecure-content-in-electron
    return new BrowserWindow({
      webPreferences: {
        contextIsolation: true,
        nodeIntegration: false
      }
    });
  }
  
  const win = createSecureWindow();
  win.loadURL('https://example.com');
}
// {/fact}

// {fact rule=least-privilege-violation@v1.0 defects=0}
function good_case_8() {
  // Using a class with secure window creation
  class SecureAppWindow {
    constructor(url) {
      // ok: javascript-avoid-running-insecure-content-in-electron
      this.window = new BrowserWindow({
        webPreferences: {
          contextIsolation: true,
          webSecurity: true
        }
      });
      this.window.loadURL(url);
    }
  }
  
  const mainWindow = new SecureAppWindow('https://example.com');
}
// {/fact}

// {fact rule=least-privilege-violation@v1.0 defects=0}
function good_case_9() {
  // Using variable to set secure configuration
  const enableNodeIntegration = false;
  // ok: javascript-avoid-running-insecure-content-in-electron
  const win = new BrowserWindow({
    webPreferences: {
      nodeIntegration: enableNodeIntegration,
      contextIsolation: true
    }
  });
  win.loadURL('https://example.com');
}
// {/fact}

// {fact rule=least-privilege-violation@v1.0 defects=0}
function good_case_10() {
  // Creating configuration object separately with secure settings
  const webPrefs = {
    contextIsolation: true,
    nodeIntegration: false,
    webSecurity: true
  };
  
  // ok: javascript-avoid-running-insecure-content-in-electron
  const win = new BrowserWindow({
    width: 800,
    height: 600,
    webPreferences: webPrefs
  });
  win.loadURL('https://example.com');
}
// {/fact}

// {fact rule=least-privilege-violation@v1.0 defects=0}
function good_case_11() {
  // Using destructuring and spread operator with secure settings
  const basePrefs = { preload: path.join(__dirname, 'preload.js') };
  const securePrefs = { contextIsolation: true, nodeIntegration: false };
  
  // ok: javascript-avoid-running-insecure-content-in-electron
  const win = new BrowserWindow({
    webPreferences: { ...basePrefs, ...securePrefs }
  });
  win.loadURL('https://example.com');
}
// {/fact}

// {fact rule=least-privilege-violation@v1.0 defects=0}
function good_case_12() {
  // Conditional but always secure settings
  const isDev = process.env.NODE_ENV === 'development';
  // ok: javascript-avoid-running-insecure-content-in-electron
  const win = new BrowserWindow({
    webPreferences: {
      devTools: isDev, // Only enables dev tools in development mode
      contextIsolation: true, // Always enabled
      nodeIntegration: false // Always disabled
    }
  });
  win.loadURL('https://example.com');
}
// {/fact}

// {fact rule=least-privilege-violation@v1.0 defects=0}
function good_case_13() {
  // Using arrow function with secure settings
  const createSecureWindow = (url) => {
    // ok: javascript-avoid-running-insecure-content-in-electron
    const win = new BrowserWindow({
      webPreferences: {
        contextIsolation: true,
        nodeIntegration: false,
        webSecurity: true
      }
    });
    win.loadURL(url);
    return win;
  };
  
  const win = createSecureWindow('https://example.com');
}
// {/fact}

// {fact rule=least-privilege-violation@v1.0 defects=0}
function good_case_14() {
  // Using environment variables for configuration but maintaining security
  const enableDevTools = process.env.ENABLE_DEVTOOLS === 'true';
  // ok: javascript-avoid-running-insecure-content-in-electron
  const win = new BrowserWindow({
    webPreferences: {
      devTools: enableDevTools,
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false
    }
  });
  win.loadURL('https://example.com');
}
// {/fact}

// {fact rule=least-privilege-violation@v1.0 defects=0}
function good_case_15() {
  // Using a factory pattern with secure settings
  const windowFactory = {
    createMainWindow: function() {
      // ok: javascript-avoid-running-insecure-content-in-electron
      return new BrowserWindow({
        width: 800,
        height: 600,
        webPreferences: {
          preload: path.join(__dirname, 'preload.js'),
          contextIsolation: true
        }
      });
    }
  };
  
  const mainWindow = windowFactory.createMainWindow();
  mainWindow.loadFile('index.html');
}
// {/fact}

// Main application setup
app.whenReady().then(() => {
  // Example usage of one of the functions
  good_case_1();
  
  app.on('activate', function () {
    if (BrowserWindow.getAllWindows().length === 0) good_case_1();
  });
});

app.on('window-all-closed', function () {
  if (process.platform !== 'darwin') app.quit();
});