import { app, BrowserWindow, BrowserView } from 'electron';
import * as path from 'path';
import * as url from 'url';

// True Positive Examples (Insecure Configurations)

// {fact rule=least-privilege-violation@v1.0 defects=1}
function bad_case_1() {
  // Creating a BrowserWindow with allowRunningInsecureContent set to true
  // ruleid: typescript-avoid-running-insecure-content-in-electron
  const win = new BrowserWindow({
    width: 800,
    height: 600,
    webPreferences: {
      allowRunningInsecureContent: true
    }
  });
  
  win.loadURL('https://example.com');
}
// {/fact}

// {fact rule=least-privilege-violation@v1.0 defects=1}
function bad_case_2() {
  // Creating a BrowserWindow with nodeIntegration enabled
  // ruleid: typescript-avoid-running-insecure-content-in-electron
  const win = new BrowserWindow({
    width: 800,
    height: 600,
    webPreferences: {
      nodeIntegration: true
    }
  });
  
  win.loadFile('index.html');
}
// {/fact}

// {fact rule=least-privilege-violation@v1.0 defects=1}
function bad_case_3() {
  // Creating a BrowserWindow with nodeIntegrationInWorker enabled
  // ruleid: typescript-avoid-running-insecure-content-in-electron
  const win = new BrowserWindow({
    width: 800,
    height: 600,
    webPreferences: {
      nodeIntegrationInWorker: true
    }
  });
  
  win.loadURL('https://example.com');
}
// {/fact}

// {fact rule=least-privilege-violation@v1.0 defects=1}
function bad_case_4() {
  // Creating a BrowserWindow with experimentalFeatures enabled
  // ruleid: typescript-avoid-running-insecure-content-in-electron
  const win = new BrowserWindow({
    width: 800,
    height: 600,
    webPreferences: {
      experimentalFeatures: true
    }
  });
  
  win.loadURL('https://example.com');
}
// {/fact}

// {fact rule=least-privilege-violation@v1.0 defects=1}
function bad_case_5() {
  // Creating a BrowserWindow with webSecurity disabled
  // ruleid: typescript-avoid-running-insecure-content-in-electron
  const win = new BrowserWindow({
    width: 800,
    height: 600,
    webPreferences: {
      webSecurity: false
    }
  });
  
  win.loadURL('https://example.com');
}
// {/fact}

// {fact rule=least-privilege-violation@v1.0 defects=1}
function bad_case_6() {
  // Creating a BrowserWindow with contextIsolation disabled
  // ruleid: typescript-avoid-running-insecure-content-in-electron
  const win = new BrowserWindow({
    width: 800,
    height: 600,
    webPreferences: {
      contextIsolation: false
    }
  });
  
  win.loadURL('https://example.com');
}
// {/fact}

// {fact rule=least-privilege-violation@v1.0 defects=1}
function bad_case_7() {
  // Creating a BrowserWindow with multiple insecure settings
  // ruleid: typescript-avoid-running-insecure-content-in-electron
  const win = new BrowserWindow({
    width: 800,
    height: 600,
    webPreferences: {
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
  // Creating a BrowserView with allowRunningInsecureContent set to true
  // ruleid: typescript-avoid-running-insecure-content-in-electron
  const view = new BrowserView({
    webPreferences: {
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
  // Creating a BrowserView with nodeIntegration enabled
  // ruleid: typescript-avoid-running-insecure-content-in-electron
  const view = new BrowserView({
    webPreferences: {
      nodeIntegration: true
    }
  });
  
  const win = new BrowserWindow({ width: 800, height: 600 });
  win.setBrowserView(view);
  view.setBounds({ x: 0, y: 0, width: 800, height: 600 });
  view.webContents.loadURL('https://example.com');
}
// {/fact}

// {fact rule=least-privilege-violation@v1.0 defects=1}
function bad_case_10() {
  // Creating a BrowserView with webSecurity disabled
  // ruleid: typescript-avoid-running-insecure-content-in-electron
  const view = new BrowserView({
    webPreferences: {
      webSecurity: false
    }
  });
  
  const win = new BrowserWindow({ width: 800, height: 600 });
  win.setBrowserView(view);
  view.setBounds({ x: 0, y: 0, width: 800, height: 600 });
  view.webContents.loadURL('https://example.com');
}
// {/fact}

// {fact rule=least-privilege-violation@v1.0 defects=1}
function bad_case_11() {
  // Using a variable to set insecure configuration
  const enableNodeIntegration = true;
  
  // ruleid: typescript-avoid-running-insecure-content-in-electron
  const win = new BrowserWindow({
    width: 800,
    height: 600,
    webPreferences: {
      nodeIntegration: enableNodeIntegration
    }
  });
  
  win.loadURL('https://example.com');
}
// {/fact}

// {fact rule=least-privilege-violation@v1.0 defects=1}
function bad_case_12() {
  // Using an object to define webPreferences
  const webPrefs = {
    contextIsolation: false,
    webSecurity: false
  };
  
  // ruleid: typescript-avoid-running-insecure-content-in-electron
  const win = new BrowserWindow({
    width: 800,
    height: 600,
    webPreferences: webPrefs
  });
  
  win.loadURL('https://example.com');
}
// {/fact}

// {fact rule=least-privilege-violation@v1.0 defects=1}
function bad_case_13() {
  // Conditional insecure configuration
  const isDevMode = process.env.NODE_ENV === 'development';
  
  // ruleid: typescript-avoid-running-insecure-content-in-electron
  const win = new BrowserWindow({
    width: 800,
    height: 600,
    webPreferences: {
      nodeIntegration: isDevMode ? true : false,
      contextIsolation: !isDevMode
    }
  });
  
  win.loadURL('https://example.com');
}
// {/fact}

// {fact rule=least-privilege-violation@v1.0 defects=1}
function bad_case_14() {
  // Creating window with insecure settings in a function
  function createWindow(url: string) {
    // ruleid: typescript-avoid-running-insecure-content-in-electron
    const win = new BrowserWindow({
      width: 800,
      height: 600,
      webPreferences: {
        experimentalFeatures: true,
        nodeIntegrationInWorker: true
      }
    });
    
    win.loadURL(url);
    return win;
  }
  
  const mainWindow = createWindow('https://example.com');
}
// {/fact}

// {fact rule=least-privilege-violation@v1.0 defects=1}
function bad_case_15() {
  // Using spread operator with insecure settings
  const baseOptions = { width: 800, height: 600 };
  const insecureWebPrefs = { webPreferences: { webSecurity: false } };
  
  // ruleid: typescript-avoid-running-insecure-content-in-electron
  const win = new BrowserWindow({
    ...baseOptions,
    ...insecureWebPrefs
  });
  
  win.loadURL('https://example.com');
}
// {/fact}

// True Negative Examples (Secure Configurations)

// {fact rule=least-privilege-violation@v1.0 defects=0}
function good_case_1() {
  // Creating a BrowserWindow with default security settings
  // ok: typescript-avoid-running-insecure-content-in-electron
  const win = new BrowserWindow({
    width: 800,
    height: 600
  });
  
  win.loadURL('https://example.com');
}
// {/fact}

// {fact rule=least-privilege-violation@v1.0 defects=0}
function good_case_2() {
  // Creating a BrowserWindow with explicit secure settings
  // ok: typescript-avoid-running-insecure-content-in-electron
  const win = new BrowserWindow({
    width: 800,
    height: 600,
    webPreferences: {
      allowRunningInsecureContent: false,
      nodeIntegration: false,
      contextIsolation: true
    }
  });
  
  win.loadURL('https://example.com');
}
// {/fact}

// {fact rule=least-privilege-violation@v1.0 defects=0}
function good_case_3() {
  // Creating a BrowserWindow with only non-security related settings
  // ok: typescript-avoid-running-insecure-content-in-electron
  const win = new BrowserWindow({
    width: 800,
    height: 600,
    webPreferences: {
      devTools: false,
      zoomFactor: 1.0
    }
  });
  
  win.loadURL('https://example.com');
}
// {/fact}

// {fact rule=least-privilege-violation@v1.0 defects=0}
function good_case_4() {
  // Creating a BrowserView with default security settings
  // ok: typescript-avoid-running-insecure-content-in-electron
  const view = new BrowserView();
  
  const win = new BrowserWindow({ width: 800, height: 600 });
  win.setBrowserView(view);
  view.setBounds({ x: 0, y: 0, width: 800, height: 600 });
  view.webContents.loadURL('https://example.com');
}
// {/fact}

// {fact rule=least-privilege-violation@v1.0 defects=0}
function good_case_5() {
  // Creating a BrowserView with explicit secure settings
  // ok: typescript-avoid-running-insecure-content-in-electron
  const view = new BrowserView({
    webPreferences: {
      allowRunningInsecureContent: false,
      nodeIntegration: false,
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
function good_case_6() {
  // Using a variable to set secure configuration
  const enableNodeIntegration = false;
  
  // ok: typescript-avoid-running-insecure-content-in-electron
  const win = new BrowserWindow({
    width: 800,
    height: 600,
    webPreferences: {
      nodeIntegration: enableNodeIntegration,
      contextIsolation: true
    }
  });
  
  win.loadURL('https://example.com');
}
// {/fact}

// {fact rule=least-privilege-violation@v1.0 defects=0}
function good_case_7() {
  // Using an object to define secure webPreferences
  const webPrefs = {
    contextIsolation: true,
    webSecurity: true,
    nodeIntegration: false
  };
  
  // ok: typescript-avoid-running-insecure-content-in-electron
  const win = new BrowserWindow({
    width: 800,
    height: 600,
    webPreferences: webPrefs
  });
  
  win.loadURL('https://example.com');
}
// {/fact}

// {fact rule=least-privilege-violation@v1.0 defects=0}
function good_case_8() {
  // Creating window with secure settings in a function
  function createSecureWindow(url: string) {
    // ok: typescript-avoid-running-insecure-content-in-electron
    const win = new BrowserWindow({
      width: 800,
      height: 600,
      webPreferences: {
        contextIsolation: true,
        nodeIntegration: false,
        webSecurity: true
      }
    });
    
    win.loadURL(url);
    return win;
  }
  
  const mainWindow = createSecureWindow('https://example.com');
}
// {/fact}

// {fact rule=least-privilege-violation@v1.0 defects=0}
function good_case_9() {
  // Using spread operator with secure settings
  const baseOptions = { width: 800, height: 600 };
  const secureWebPrefs = { 
    webPreferences: { 
      contextIsolation: true,
      nodeIntegration: false
    } 
  };
  
  // ok: typescript-avoid-running-insecure-content-in-electron
  const win = new BrowserWindow({
    ...baseOptions,
    ...secureWebPrefs
  });
  
  win.loadURL('https://example.com');
}
// {/fact}

// {fact rule=least-privilege-violation@v1.0 defects=0}
function good_case_10() {
  // Creating a BrowserWindow with preload script (secure pattern)
  // ok: typescript-avoid-running-insecure-content-in-electron
  const win = new BrowserWindow({
    width: 800,
    height: 600,
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
function good_case_11() {
  // Creating a BrowserWindow with sandbox enabled
  // ok: typescript-avoid-running-insecure-content-in-electron
  const win = new BrowserWindow({
    width: 800,
    height: 600,
    webPreferences: {
      sandbox: true
    }
  });
  
  win.loadURL('https://example.com');
}
// {/fact}

// {fact rule=least-privilege-violation@v1.0 defects=0}
function good_case_12() {
  // Creating a BrowserWindow with secure content security policy
  // ok: typescript-avoid-running-insecure-content-in-electron
  const win = new BrowserWindow({
    width: 800,
    height: 600,
    webPreferences: {
      webSecurity: true
    }
  });
  
  win.webContents.session.webRequest.onHeadersReceived((details, callback) => {
    callback({
      responseHeaders: {
        ...details.responseHeaders,
        'Content-Security-Policy': ["default-src 'self'"]
      }
    });
  });
  
  win.loadURL('https://example.com');
}
// {/fact}

// {fact rule=least-privilege-violation@v1.0 defects=0}
function good_case_13() {
  // Creating a BrowserWindow with all default settings
  // ok: typescript-avoid-running-insecure-content-in-electron
  const win = new BrowserWindow();
  win.loadURL('https://example.com');
}
// {/fact}

// {fact rule=least-privilege-violation@v1.0 defects=0}
function good_case_14() {
  // Creating a BrowserWindow with only visual settings
  // ok: typescript-avoid-running-insecure-content-in-electron
  const win = new BrowserWindow({
    width: 800,
    height: 600,
    frame: false,
    transparent: true,
    titleBarStyle: 'hidden'
  });
  
  win.loadURL('https://example.com');
}
// {/fact}

// {fact rule=least-privilege-violation@v1.0 defects=0}
function good_case_15() {
  // Creating a BrowserWindow with secure settings for a specific environment
  const isDev = process.env.NODE_ENV === 'development';
  
  // ok: typescript-avoid-running-insecure-content-in-electron
  const win = new BrowserWindow({
    width: 800,
    height: 600,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      devTools: isDev
    }
  });
  
  win.loadURL('https://example.com');
}
// {/fact}