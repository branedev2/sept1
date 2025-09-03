import React, { useState, useEffect } from 'react';
import axios from 'axios';
import Cookies from 'js-cookie';
import { useHistory } from 'react-router-dom';

// TRUE POSITIVES (Vulnerable Code Examples)

// Example 1: Basic JWT storage in localStorage
// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_1() {
  const login = async (username: string, password: string) => {
    try {
      const response = await axios.post('/api/login', { username, password });
      const { token } = response.data;
      // ruleid: typescript-react-jwt-in-localstorage
      localStorage.setItem('jwt', token);
      console.log('Login successful');
    } catch (error) {
      console.error('Login failed', error);
    }
  };

  return (
    <button onClick={() => login('user', 'password')}>Login</button>
  );
}
// {/fact}

// Example 2: JWT token stored with different key name
// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_2() {
  const authenticateUser = async (credentials: { email: string, password: string }) => {
    const response = await axios.post('/api/auth', credentials);
    if (response.data.success) {
      // ruleid: typescript-react-jwt-in-localstorage
      localStorage.setItem('authToken', response.data.token);
      return true;
    }
    return false;
  };
  
  return <div>Authentication Component</div>;
}
// {/fact}

// Example 3: JWT stored in localStorage within useEffect
// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_3() {
  const [token, setToken] = useState<string | null>(null);
  
  useEffect(() => {
    const fetchToken = async () => {
      const response = await axios.get('/api/refresh-token');
      setToken(response.data.token);
      // ruleid: typescript-react-jwt-in-localstorage
      localStorage.setItem('userToken', response.data.token);
    };
    
    fetchToken();
  }, []);
  
  return <div>Token Management Component</div>;
}
// {/fact}

// Example 4: JWT stored in localStorage with additional data
// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_4() {
  const handleOAuthCallback = (code: string) => {
    axios.post('/api/oauth/callback', { code })
      .then(response => {
        const userData = {
          name: response.data.name,
          email: response.data.email,
          token: response.data.token
        };
        // ruleid: typescript-react-jwt-in-localstorage
        localStorage.setItem('userData', JSON.stringify(userData));
      })
      .catch(error => console.error(error));
  };
  
  return <div>OAuth Callback Handler</div>;
}
// {/fact}

// Example 5: JWT stored in localStorage with expiration handling
// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_5() {
  const loginWithExpiry = async (username: string, password: string) => {
    const response = await axios.post('/api/login', { username, password });
    const expiresIn = response.data.expiresIn || 3600; // 1 hour default
    const expiryTime = Date.now() + expiresIn * 1000;
    
    const tokenData = {
      token: response.data.token,
      expires: expiryTime
    };
    
    // ruleid: typescript-react-jwt-in-localstorage
    localStorage.setItem('sessionToken', JSON.stringify(tokenData));
  };
  
  return <div>Login With Expiry Component</div>;
}
// {/fact}

// Example 6: JWT stored in localStorage within a custom hook
// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_6() {
  const useAuth = () => {
    const [isAuthenticated, setIsAuthenticated] = useState(false);
    
    const login = async (credentials: any) => {
      try {
        const response = await axios.post('/api/login', credentials);
        // ruleid: typescript-react-jwt-in-localstorage
        localStorage.setItem('accessToken', response.data.accessToken);
        setIsAuthenticated(true);
        return true;
      } catch (error) {
        return false;
      }
    };
    
    return { isAuthenticated, login };
  };
  
  const { login } = useAuth();
  
  return (
    <button onClick={() => login({ username: 'user', password: 'pass' })}>
      Login
    </button>
  );
}
// {/fact}

// Example 7: JWT stored in localStorage with refresh token
// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_7() {
  const handleLogin = async (formData: FormData) => {
    const response = await axios.post('/api/auth/login', formData);
    
    if (response.data.success) {
      // ruleid: typescript-react-jwt-in-localstorage
      localStorage.setItem('accessToken', response.data.accessToken);
      // ruleid: typescript-react-jwt-in-localstorage
      localStorage.setItem('refreshToken', response.data.refreshToken);
    }
  };
  
  return <div>Login Form Component</div>;
}
// {/fact}

// Example 8: JWT stored in localStorage with error handling
// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_8() {
  const [error, setError] = useState<string | null>(null);
  
  const authenticate = async () => {
    try {
      const response = await axios.post('/api/authenticate');
      // ruleid: typescript-react-jwt-in-localstorage
      localStorage.setItem('jwt_token', response.data.token);
      setError(null);
    } catch (err) {
      setError('Authentication failed');
    }
  };
  
  return (
    <div>
      {error && <p>{error}</p>}
      <button onClick={authenticate}>Authenticate</button>
    </div>
  );
}
// {/fact}

// Example 9: JWT stored in localStorage within a class component
class bad_case_9 extends React.Component {
  async componentDidMount() {
    try {
      const response = await axios.get('/api/session');
      // ruleid: typescript-react-jwt-in-localstorage
      localStorage.setItem('session_token', response.data.token);
    } catch (error) {
      console.error('Failed to get session', error);
    }
  }
  
  render() {
    return <div>Class Component Example</div>;
  }
}

// Example 10: JWT stored in localStorage with redirect after login
// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_10() {
  const history = useHistory();
  
  const loginAndRedirect = async (credentials: any) => {
    const response = await axios.post('/api/login', credentials);
    
    if (response.data.token) {
      // ruleid: typescript-react-jwt-in-localstorage
      localStorage.setItem('auth_token', response.data.token);
      history.push('/dashboard');
    }
  };
  
  return <div>Login and Redirect Component</div>;
}
// {/fact}

// Example 11: JWT stored in localStorage with multiple tokens
// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_11() {
  const handleMultiAuth = async () => {
    const response = await axios.post('/api/multi-auth');
    
    // ruleid: typescript-react-jwt-in-localstorage
    localStorage.setItem('userToken', response.data.userToken);
    // ruleid: typescript-react-jwt-in-localstorage
    localStorage.setItem('apiToken', response.data.apiToken);
    // ruleid: typescript-react-jwt-in-localstorage
    localStorage.setItem('serviceToken', response.data.serviceToken);
  };
  
  return <button onClick={handleMultiAuth}>Authenticate Services</button>;
}
// {/fact}

// Example 12: JWT stored in localStorage with conditional logic
// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_12() {
  const [rememberMe, setRememberMe] = useState(false);
  
  const handleLogin = async (username: string, password: string) => {
    const response = await axios.post('/api/login', { username, password });
    
    if (rememberMe) {
      // ruleid: typescript-react-jwt-in-localstorage
      localStorage.setItem('persistentToken', response.data.token);
    } else {
      sessionStorage.setItem('tempToken', response.data.token);
    }
  };
  
  return (
    <div>
      <input 
        type="checkbox" 
        checked={rememberMe} 
        onChange={(e) => setRememberMe(e.target.checked)} 
      />
      <label>Remember me</label>
    </div>
  );
}
// {/fact}

// Example 13: JWT stored in localStorage with token prefix
// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_13() {
  const processAuthResponse = (response: any) => {
    const token = response.data.token;
    const tokenWithPrefix = `Bearer ${token}`;
    
    // ruleid: typescript-react-jwt-in-localstorage
    localStorage.setItem('bearerToken', tokenWithPrefix);
  };
  
  const login = async () => {
    const response = await axios.post('/api/login');
    processAuthResponse(response);
  };
  
  return <button onClick={login}>Login with Bearer</button>;
}
// {/fact}

// Example 14: JWT stored in localStorage with role-based tokens
// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_14() {
  const handleRoleBasedAuth = async (role: string) => {
    const response = await axios.post('/api/auth/role', { role });
    
    if (role === 'admin') {
      // ruleid: typescript-react-jwt-in-localstorage
      localStorage.setItem('adminToken', response.data.token);
    } else {
      // ruleid: typescript-react-jwt-in-localstorage
      localStorage.setItem('userToken', response.data.token);
    }
  };
  
  return (
    <div>
      <button onClick={() => handleRoleBasedAuth('admin')}>Login as Admin</button>
      <button onClick={() => handleRoleBasedAuth('user')}>Login as User</button>
    </div>
  );
}
// {/fact}

// Example 15: JWT stored in localStorage with dynamic key
// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_15() {
  const storeTokenForService = (serviceName: string, token: string) => {
    const storageKey = `${serviceName}_jwt`;
    // ruleid: typescript-react-jwt-in-localstorage
    localStorage.setItem(storageKey, token);
  };
  
  const authenticateService = async (service: string) => {
    const response = await axios.post(`/api/${service}/auth`);
    storeTokenForService(service, response.data.token);
  };
  
  return (
    <div>
      <button onClick={() => authenticateService('analytics')}>Auth Analytics</button>
      <button onClick={() => authenticateService('reporting')}>Auth Reporting</button>
    </div>
  );
}
// {/fact}

// TRUE NEGATIVES (Secure Code Examples)

// Example 1: Using HTTP-only cookies for JWT storage
// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_1() {
  const login = async (username: string, password: string) => {
    try {
      const response = await axios.post('/api/login', { username, password });
      // ok: typescript-react-jwt-in-localstorage
      // JWT is stored as HTTP-only cookie by the server
      console.log('Login successful, token stored in HTTP-only cookie');
    } catch (error) {
      console.error('Login failed', error);
    }
  };

  return (
    <button onClick={() => login('user', 'password')}>Login</button>
  );
}
// {/fact}

// Example 2: Using js-cookie with secure and httpOnly options
// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_2() {
  const authenticateUser = async (credentials: { email: string, password: string }) => {
    const response = await axios.post('/api/auth', credentials);
    if (response.data.success) {
      // ok: typescript-react-jwt-in-localstorage
      // Server sets the cookie, client just receives it
      document.cookie = `token=${response.data.token}; secure; SameSite=Strict; path=/`;
      return true;
    }
    return false;
  };
  
  return <div>Authentication Component</div>;
}
// {/fact}

// Example 3: Using sessionStorage for temporary session data (not JWT)
// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_3() {
  const [userPreferences, setUserPreferences] = useState<any>(null);
  
  useEffect(() => {
    const fetchUserPreferences = async () => {
      const response = await axios.get('/api/user/preferences');
      setUserPreferences(response.data);
      // ok: typescript-react-jwt-in-localstorage
      // Storing non-JWT data in sessionStorage is fine
      sessionStorage.setItem('userPreferences', JSON.stringify(response.data.preferences));
    };
    
    fetchUserPreferences();
  }, []);
  
  return <div>User Preferences Component</div>;
}
// {/fact}

// Example 4: Using in-memory state for JWT storage
// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_4() {
  const [authToken, setAuthToken] = useState<string | null>(null);
  
  const handleLogin = async (username: string, password: string) => {
    try {
      const response = await axios.post('/api/login', { username, password });
      // ok: typescript-react-jwt-in-localstorage
      // Storing JWT in memory state instead of localStorage
      setAuthToken(response.data.token);
      
      // Configure axios to use the token for future requests
      axios.defaults.headers.common['Authorization'] = `Bearer ${response.data.token}`;
    } catch (error) {
      console.error('Login failed', error);
    }
  };
  
  return <div>In-Memory Token Storage Component</div>;
}
// {/fact}

// Example 5: Using React Context for JWT storage
// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_5() {
  // This would typically be in a separate file
  const AuthContext = React.createContext<{
    token: string | null;
    login: (username: string, password: string) => Promise<void>;
  }>({
    token: null,
    login: async () => {},
  });
  
  const AuthProvider: React.FC<{children: React.ReactNode}> = ({ children }) => {
    const [token, setToken] = useState<string | null>(null);
    
    const login = async (username: string, password: string) => {
      try {
        const response = await axios.post('/api/login', { username, password });
        // ok: typescript-react-jwt-in-localstorage
        // Storing JWT in context state instead of localStorage
        setToken(response.data.token);
      } catch (error) {
        console.error('Login failed', error);
      }
    };
    
    return (
      <AuthContext.Provider value={{ token, login }}>
        {children}
      </AuthContext.Provider>
    );
  };
  
  return <AuthProvider>Auth Context Example</AuthProvider>;
}
// {/fact}

// Example 6: Using server-side authentication with sessions
// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_6() {
  const login = async (username: string, password: string) => {
    try {
      // ok: typescript-react-jwt-in-localstorage
      // Server handles session management with HTTP-only cookies
      await axios.post('/api/login', { username, password });
      window.location.href = '/dashboard';
    } catch (error) {
      console.error('Login failed', error);
    }
  };
  
  return <button onClick={() => login('user', 'pass')}>Login</button>;
}
// {/fact}

// Example 7: Using localStorage for non-sensitive data
// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_7() {
  const saveUserPreferences = (theme: string, language: string) => {
    const preferences = { theme, language };
    // ok: typescript-react-jwt-in-localstorage
    // Storing non-sensitive data in localStorage is fine
    localStorage.setItem('userPreferences', JSON.stringify(preferences));
  };
  
  return (
    <button onClick={() => saveUserPreferences('dark', 'en')}>
      Save Preferences
    </button>
  );
}
// {/fact}

// Example 8: Using a secure cookie library
// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_8() {
  const login = async (username: string, password: string) => {
    try {
      const response = await axios.post('/api/login', { username, password });
      // ok: typescript-react-jwt-in-localstorage
      // Using js-cookie library to set cookies with security options
      Cookies.set('auth', response.data.token, { 
        secure: true, 
        sameSite: 'strict',
        expires: 7 // 7 days
      });
    } catch (error) {
      console.error('Login failed', error);
    }
  };
  
  return <button onClick={() => login('user', 'pass')}>Login</button>;
}
// {/fact}

// Example 9: Using Redux state for JWT storage
// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_9() {
  // Simplified Redux implementation for example
  const [state, dispatch] = React.useReducer(
    (state: any, action: any) => {
      switch (action.type) {
        case 'SET_TOKEN':
          return { ...state, token: action.payload };
        default:
          return state;
      }
    },
    { token: null }
  );
  
  const login = async (username: string, password: string) => {
    try {
      const response = await axios.post('/api/login', { username, password });
      // ok: typescript-react-jwt-in-localstorage
      // Storing JWT in Redux state instead of localStorage
      dispatch({ type: 'SET_TOKEN', payload: response.data.token });
    } catch (error) {
      console.error('Login failed', error);
    }
  };
  
  return <div>Redux State Management Example</div>;
}
// {/fact}

// Example 10: Using localStorage for app settings (not JWT)
// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_10() {
  useEffect(() => {
    // ok: typescript-react-jwt-in-localstorage
    // Storing non-sensitive app settings in localStorage is fine
    localStorage.setItem('appSettings', JSON.stringify({
      notifications: true,
      darkMode: false,
      fontSize: 'medium'
    }));
  }, []);
  
  return <div>App Settings Component</div>;
}
// {/fact}

// Example 11: Using a token refresh approach with secure cookies
// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_11() {
  const refreshToken = async () => {
    try {
      // ok: typescript-react-jwt-in-localstorage
      // Token is refreshed server-side and set as HTTP-only cookie
      await axios.post('/api/refresh-token');
      console.log('Token refreshed successfully');
    } catch (error) {
      console.error('Token refresh failed', error);
    }
  };
  
  return <button onClick={refreshToken}>Refresh Token</button>;
}
// {/fact}

// Example 12: Using IndexedDB for non-sensitive data storage
// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_12() {
  const saveUserData = async (userData: any) => {
    // ok: typescript-react-jwt-in-localstorage
    // Using IndexedDB for non-sensitive user data, not JWT
    const request = indexedDB.open('UserDatabase', 1);
    
    request.onupgradeneeded = (event) => {
      const db = (event.target as IDBOpenDBRequest).result;
      db.createObjectStore('userData', { keyPath: 'id' });
    };
    
    request.onsuccess = (event) => {
      const db = (event.target as IDBOpenDBRequest).result;
      const transaction = db.transaction(['userData'], 'readwrite');
      const store = transaction.objectStore('userData');
      store.put({ id: 1, ...userData });
    };
  };
  
  return <div>IndexedDB Example</div>;
}
// {/fact}

// Example 13: Using memory state with axios interceptors
// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_13() {
  const [token, setToken] = useState<string | null>(null);
  
  useEffect(() => {
    // ok: typescript-react-jwt-in-localstorage
    // Setting up axios interceptor to use in-memory token
    const interceptor = axios.interceptors.request.use(config => {
      if (token) {
        config.headers.Authorization = `Bearer ${token}`;
      }
      return config;
    });
    
    return () => {
      axios.interceptors.request.eject(interceptor);
    };
  }, [token]);
  
  const login = async (username: string, password: string) => {
    const response = await axios.post('/api/login', { username, password });
    setToken(response.data.token);
  };
  
  return <div>Axios Interceptor Example</div>;
}
// {/fact}

// Example 14: Using server-side rendering with secure cookies
// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_14() {
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  
  useEffect(() => {
    // ok: typescript-react-jwt-in-localstorage
    // Check authentication status from server, which uses HTTP-only cookies
    const checkAuthStatus = async () => {
      try {
        const response = await axios.get('/api/auth/status');
        setIsLoggedIn(response.data.authenticated);
      } catch (error) {
        setIsLoggedIn(false);
      }
    };
    
    checkAuthStatus();
  }, []);
  
  return <div>{isLoggedIn ? 'Authenticated' : 'Not Authenticated'}</div>;
}
// {/fact}

// Example 15: Using Web Crypto API for secure client-side storage
// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_15() {
  const encryptAndStoreData = async (data: any) => {
    // ok: typescript-react-jwt-in-localstorage
    // Using Web Crypto API to encrypt non-sensitive data before storage
    // This is not storing JWT tokens in localStorage
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(JSON.stringify(data));
    
    const key = await window.crypto.subtle.generateKey(
      {
        name: 'AES-GCM',
        length: 256,
      },
      true,
      ['encrypt', 'decrypt']
    );
    
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encryptedData = await window.crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv,
      },
      key,
      dataBuffer
    );
    
    // Store encrypted data and IV (not JWT tokens)
    localStorage.setItem('encryptedData', JSON.stringify({
      data: Array.from(new Uint8Array(encryptedData)),
      iv: Array.from(iv)
    }));
  };
  
  return <div>Web Crypto API Example</div>;
}
// {/fact}