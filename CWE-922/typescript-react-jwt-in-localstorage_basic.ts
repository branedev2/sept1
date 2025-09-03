// File: jwt_storage_test_cases.tsx
import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import Cookies from 'js-cookie';
import { useCookies } from 'react-cookie';

// TRUE POSITIVES - Insecure JWT storage in localStorage

// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_1() {
  const login = async (username: string, password: string) => {
    try {
      const response = await axios.post('/api/login', { username, password });
      const token = response.data.token;
      // ruleid: typescript-react-jwt-in-localstorage
      localStorage.setItem('jwt', token);
      console.log('User logged in successfully');
    } catch (error) {
      console.error('Login failed:', error);
    }
  };
  
  return (
    <button onClick={() => login('user', 'password')}>Login</button>
  );
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_2() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const navigate = useNavigate();
  
  const handleLogin = async (formData: { email: string, password: string }) => {
    const response = await axios.post('/api/auth', formData);
    if (response.data.success) {
      // ruleid: typescript-react-jwt-in-localstorage
      localStorage.setItem('authToken', response.data.token);
      setIsAuthenticated(true);
      navigate('/dashboard');
    }
  };
  
  return (
    <div>
      <h1>Login Page</h1>
      {/* Form implementation omitted for brevity */}
    </div>
  );
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_3() {
  const AuthService = {
    storeUserToken: (token: string) => {
      // ruleid: typescript-react-jwt-in-localstorage
      window.localStorage.setItem('userJWT', token);
    },
    
    getToken: () => {
      return localStorage.getItem('userJWT');
    },
    
    logout: () => {
      localStorage.removeItem('userJWT');
    }
  };
  
  return (
    <div>
      <button onClick={() => AuthService.storeUserToken('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...')}>
        Set Token
      </button>
    </div>
  );
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_4() {
  useEffect(() => {
    const fetchUserData = async () => {
      try {
        const response = await axios.post('/api/refresh-token');
        const { accessToken, refreshToken } = response.data;
        // ruleid: typescript-react-jwt-in-localstorage
        localStorage.setItem('access_token', accessToken);
        // ruleid: typescript-react-jwt-in-localstorage
        localStorage.setItem('refresh_token', refreshToken);
      } catch (error) {
        console.error('Failed to refresh token:', error);
      }
    };
    
    fetchUserData();
  }, []);
  
  return <div>Token Refresh Component</div>;
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_5() {
  const [user, setUser] = useState(null);
  
  const registerUser = async (userData: any) => {
    const response = await axios.post('/api/register', userData);
    if (response.status === 201) {
      // ruleid: typescript-react-jwt-in-localstorage
      localStorage.setItem('jwtToken', response.data.token);
      setUser(response.data.user);
    }
  };
  
  return (
    <div>
      <h2>Register</h2>
      {/* Registration form would be here */}
    </div>
  );
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_6() {
  class AuthManager {
    static authenticate(token: string) {
      // ruleid: typescript-react-jwt-in-localstorage
      localStorage.setItem('auth_jwt', token);
    }
    
    static isAuthenticated() {
      return localStorage.getItem('auth_jwt') !== null;
    }
  }
  
  const handleApiResponse = (response: any) => {
    if (response.token) {
      AuthManager.authenticate(response.token);
    }
  };
  
  return <div>Auth Manager Component</div>;
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_7() {
  const [loginStatus, setLoginStatus] = useState('');
  
  const socialLogin = async (provider: string) => {
    try {
      const response = await axios.get(`/api/auth/${provider}`);
      // ruleid: typescript-react-jwt-in-localstorage
      localStorage['jwt_token'] = response.data.token; // Using bracket notation
      setLoginStatus('Logged in with ' + provider);
    } catch (error) {
      setLoginStatus('Login failed');
    }
  };
  
  return (
    <div>
      <button onClick={() => socialLogin('google')}>Login with Google</button>
      <button onClick={() => socialLogin('facebook')}>Login with Facebook</button>
      <p>{loginStatus}</p>
    </div>
  );
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_8() {
  const TokenStorage = {
    saveTokens: (accessToken: string, idToken: string) => {
      // ruleid: typescript-react-jwt-in-localstorage
      localStorage.setItem('access_jwt', accessToken);
      // ruleid: typescript-react-jwt-in-localstorage
      localStorage.setItem('id_jwt', idToken);
    }
  };
  
  const handleOAuthCallback = (urlParams: URLSearchParams) => {
    const accessToken = urlParams.get('access_token') || '';
    const idToken = urlParams.get('id_token') || '';
    TokenStorage.saveTokens(accessToken, idToken);
  };
  
  return <div>OAuth Callback Handler</div>;
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_9() {
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  
  useEffect(() => {
    const checkAuth = async () => {
      const token = await fetchAuthToken();
      if (token) {
        // ruleid: typescript-react-jwt-in-localstorage
        window.localStorage.setItem('session_jwt', token);
        setIsLoggedIn(true);
      }
    };
    
    checkAuth();
  }, []);
  
  const fetchAuthToken = async () => {
    const response = await axios.get('/api/token');
    return response.data.token;
  };
  
  return <div>{isLoggedIn ? 'Authenticated' : 'Not Authenticated'}</div>;
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_10() {
  const loginWithCredentials = (email: string, password: string) => {
    axios.post('/api/login', { email, password })
      .then(response => {
        if (response.data.success) {
          const { token } = response.data;
          // ruleid: typescript-react-jwt-in-localstorage
          localStorage.setItem('bearer_token', `Bearer ${token}`);
        }
      })
      .catch(error => console.error(error));
  };
  
  return (
    <form onSubmit={() => loginWithCredentials('user@example.com', 'password')}>
      {/* Form fields would be here */}
      <button type="submit">Login</button>
    </form>
  );
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_11() {
  const [authState, setAuthState] = useState({
    isAuthenticated: false,
    user: null
  });
  
  const handleSuccessfulAuth = (response: any) => {
    // ruleid: typescript-react-jwt-in-localstorage
    localStorage.setItem('jwt_auth_token', response.token);
    setAuthState({
      isAuthenticated: true,
      user: response.user
    });
  };
  
  return (
    <div className="auth-container">
      <h1>Authentication</h1>
      {/* Auth components would be here */}
    </div>
  );
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_12() {
  const storeMultipleTokens = (tokens: { access: string, refresh: string }) => {
    // ruleid: typescript-react-jwt-in-localstorage
    localStorage.setItem('jwt_access', tokens.access);
    // ruleid: typescript-react-jwt-in-localstorage
    localStorage.setItem('jwt_refresh', tokens.refresh);
  };
  
  const handleTokenResponse = (response: any) => {
    storeMultipleTokens({
      access: response.accessToken,
      refresh: response.refreshToken
    });
  };
  
  return <div>Token Handler Component</div>;
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_13() {
  const saveJwtToStorage = (jwt: string) => {
    const tokenData = {
      token: jwt,
      timestamp: new Date().getTime()
    };
    // ruleid: typescript-react-jwt-in-localstorage
    localStorage.setItem('jwt_data', JSON.stringify(tokenData));
  };
  
  const handleLogin = async () => {
    const response = await axios.post('/api/login');
    saveJwtToStorage(response.data.token);
  };
  
  return <button onClick={handleLogin}>Login</button>;
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_14() {
  interface AuthResponse {
    token: string;
    user: {
      id: string;
      name: string;
    };
  }
  
  const processAuthResponse = (response: AuthResponse) => {
    // ruleid: typescript-react-jwt-in-localstorage
    localStorage.setItem('user_jwt', response.token);
    console.log(`User ${response.user.name} authenticated`);
  };
  
  return <div>Auth Processor</div>;
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_15() {
  const [token, setToken] = useState<string | null>(null);
  
  useEffect(() => {
    if (token) {
      // ruleid: typescript-react-jwt-in-localstorage
      localStorage.setItem('react_app_jwt', token);
    }
  }, [token]);
  
  const authenticate = async () => {
    const response = await axios.post('/api/authenticate');
    setToken(response.data.token);
  };
  
  return <button onClick={authenticate}>Authenticate</button>;
}
// {/fact}

// TRUE NEGATIVES - Secure JWT storage alternatives

// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_1() {
  const login = async (username: string, password: string) => {
    try {
      const response = await axios.post('/api/login', { username, password });
      const token = response.data.token;
      // ok: typescript-react-jwt-in-localstorage
      document.cookie = `jwt=${token}; path=/; Secure; HttpOnly; SameSite=Strict`;
      console.log('User logged in successfully');
    } catch (error) {
      console.error('Login failed:', error);
    }
  };
  
  return (
    <button onClick={() => login('user', 'password')}>Login</button>
  );
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_2() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const navigate = useNavigate();
  
  const handleLogin = async (formData: { email: string, password: string }) => {
    const response = await axios.post('/api/auth', formData);
    if (response.data.success) {
      // ok: typescript-react-jwt-in-localstorage
      // Using js-cookie library for secure cookie management
      Cookies.set('authToken', response.data.token, { 
        secure: true, 
        sameSite: 'strict' 
      });
      setIsAuthenticated(true);
      navigate('/dashboard');
    }
  };
  
  return (
    <div>
      <h1>Login Page</h1>
      {/* Form implementation omitted for brevity */}
    </div>
  );
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_3() {
  // Using react-cookie hook for cookie management
  const [cookies, setCookie, removeCookie] = useCookies(['userJWT']);
  
  const AuthService = {
    storeUserToken: (token: string) => {
      // ok: typescript-react-jwt-in-localstorage
      setCookie('userJWT', token, { 
        path: '/',
        secure: true,
        sameSite: 'strict'
      });
    },
    
    getToken: () => {
      return cookies.userJWT;
    },
    
    logout: () => {
      removeCookie('userJWT');
    }
  };
  
  return (
    <div>
      <button onClick={() => AuthService.storeUserToken('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...')}>
        Set Token
      </button>
    </div>
  );
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_4() {
  // Using memory state for token storage during session
  const [accessToken, setAccessToken] = useState<string | null>(null);
  
  useEffect(() => {
    const fetchUserData = async () => {
      try {
        const response = await axios.post('/api/refresh-token');
        // ok: typescript-react-jwt-in-localstorage
        setAccessToken(response.data.accessToken);
        // Token is stored in memory state, not localStorage
      } catch (error) {
        console.error('Failed to refresh token:', error);
      }
    };
    
    fetchUserData();
  }, []);
  
  return <div>Token Refresh Component</div>;
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_5() {
  // Using sessionStorage instead of localStorage
  // While not as secure as cookies, it's better than localStorage as it's cleared when the tab is closed
  const [user, setUser] = useState(null);
  
  const registerUser = async (userData: any) => {
    const response = await axios.post('/api/register', userData);
    if (response.status === 201) {
      // ok: typescript-react-jwt-in-localstorage
      // Using sessionStorage which is cleared when the browser session ends
      sessionStorage.setItem('tempAuthData', response.data.token);
      setUser(response.data.user);
    }
  };
  
  return (
    <div>
      <h2>Register</h2>
      {/* Registration form would be here */}
    </div>
  );
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_6() {
  // Server-side authentication with secure cookies
  const authenticate = async (credentials: any) => {
    // ok: typescript-react-jwt-in-localstorage
    // Token is handled server-side, with HttpOnly cookies set by the server
    await axios.post('/api/login', credentials, {
      withCredentials: true // Allows the browser to handle cookies from the response
    });
    // The server sets HttpOnly cookies in its response
  };
  
  return <div>Server-side Auth Component</div>;
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_7() {
  // Using React Context for in-memory token storage
  const [authToken, setAuthToken] = useState<string | null>(null);
  
  const socialLogin = async (provider: string) => {
    try {
      const response = await axios.get(`/api/auth/${provider}`);
      // ok: typescript-react-jwt-in-localstorage
      setAuthToken(response.data.token); // Store in React state, not localStorage
    } catch (error) {
      console.error('Login failed:', error);
    }
  };
  
  return (
    <div>
      <button onClick={() => socialLogin('google')}>Login with Google</button>
      {authToken && <p>Authentication successful</p>}
    </div>
  );
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_8() {
  // Using a secure cookie with HttpOnly flag
  const handleOAuthCallback = async (code: string) => {
    const response = await axios.post('/api/oauth/token', { code });
    
    // ok: typescript-react-jwt-in-localstorage
    // Set secure HttpOnly cookie via document.cookie
    document.cookie = `auth_token=${response.data.token}; path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=3600`;
  };
  
  return <div>OAuth Handler</div>;
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_9() {
  // Using IndexedDB for token storage with encryption
  const storeTokenSecurely = async (token: string) => {
    // ok: typescript-react-jwt-in-localstorage
    // This example uses IndexedDB with encryption (simplified for brevity)
    const request = indexedDB.open('SecureTokenDB', 1);
    
    request.onupgradeneeded = (event) => {
      const db = request.result;
      db.createObjectStore('tokens', { keyPath: 'id' });
    };
    
    request.onsuccess = () => {
      const db = request.result;
      const tx = db.transaction('tokens', 'readwrite');
      const store = tx.objectStore('tokens');
      
      // In a real app, you would encrypt the token before storing
      store.put({ id: 'current', value: token });
    };
  };
  
  return <div>Secure Storage Component</div>;
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_10() {
  // Using a token service that communicates with a secure backend
  const tokenService = {
    requestToken: async (credentials: any) => {
      // ok: typescript-react-jwt-in-localstorage
      // The token is managed by the backend and only session ID is stored client-side
      const response = await axios.post('/api/token-service/authenticate', credentials, {
        withCredentials: true // Enables cookies
      });
      return response.data.sessionId;
    }
  };
  
  return <div>Token Service Component</div>;
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_11() {
  // Using memory state with automatic expiry
  const [token, setToken] = useState<string | null>(null);
  const [tokenExpiry, setTokenExpiry] = useState<number | null>(null);
  
  const login = async (credentials: any) => {
    const response = await axios.post('/api/login', credentials);
    
    // ok: typescript-react-jwt-in-localstorage
    // Store token in memory with expiration
    setToken(response.data.token);
    const expiryTime = Date.now() + (response.data.expiresIn * 1000);
    setTokenExpiry(expiryTime);
    
    // Set up automatic token expiry
    setTimeout(() => {
      setToken(null);
      setTokenExpiry(null);
    }, response.data.expiresIn * 1000);
  };
  
  return <div>Memory Token Component</div>;
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_12() {
  // Using a secure iframe for token storage
  const [iframeLoaded, setIframeLoaded] = useState(false);
  
  const storeTokenInIframe = (token: string) => {
    // ok: typescript-react-jwt-in-localstorage
    // Using a secure iframe in a different domain to store the token
    const iframe = document.getElementById('secure-token-iframe') as HTMLIFrameElement;
    if (iframe && iframe.contentWindow) {
      iframe.contentWindow.postMessage({ type: 'STORE_TOKEN', token }, 'https://secure-domain.com');
    }
  };
  
  return (
    <div>
      <iframe 
        id="secure-token-iframe" 
        src="https://secure-domain.com/token-storage.html"
        style={{ display: 'none' }}
        onLoad={() => setIframeLoaded(true)}
      />
      <button onClick={() => storeTokenInIframe('example-token')}>Store Token Securely</button>
    </div>
  );
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_13() {
  // Using Web Authentication API (WebAuthn)
  const authenticateWithWebAuthn = async () => {
    try {
      // ok: typescript-react-jwt-in-localstorage
      // Using WebAuthn for authentication instead of JWT tokens
      const publicKeyCredentialCreationOptions = {
        challenge: new Uint8Array([/* challenge would be here */]),
        rp: {
          name: "Example App",
          id: "example.com",
        },
        user: {
          id: new Uint8Array([1, 2, 3, 4]),
          name: "user@example.com",
          displayName: "Example User",
        },
        pubKeyCredParams: [{alg: -7, type: "public-key"}],
        timeout: 60000,
      };
      
      // This is a simplified example - actual WebAuthn implementation would be more complex
      const credential = await navigator.credentials.create({
        publicKey: publicKeyCredentialCreationOptions
      });
      
      // No JWT token is stored in localStorage
    } catch (error) {
      console.error('WebAuthn failed:', error);
    }
  };
  
  return <button onClick={authenticateWithWebAuthn}>Authenticate with WebAuthn</button>;
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_14() {
  // Using a secure backend session with CSRF protection
  const login = async (username: string, password: string) => {
    // ok: typescript-react-jwt-in-localstorage
    // Using server-side sessions instead of client-side JWT storage
    await axios.post('/api/login', { username, password }, {
      withCredentials: true,
      headers: {
        'X-CSRF-Token': document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || ''
      }
    });
    
    // The server handles session management with secure cookies
    // No token is stored in localStorage
  };
  
  return <button onClick={() => login('user', 'pass')}>Login with Server Session</button>;
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_15() {
  // Using Auth0 or similar authentication service
  const loginWithAuth0 = () => {
    // ok: typescript-react-jwt-in-localstorage
    // Using Auth0's secure authentication flow
    const auth0 = {
      authorize: () => {
        window.location.href = 'https://your-domain.auth0.com/authorize?' + 
          'response_type=code&' +
          'client_id=YOUR_CLIENT_ID&' +
          'redirect_uri=YOUR_CALLBACK_URL&' +
          'scope=openid profile email';
      }
    };
    
    auth0.authorize();
    // Auth0 handles token management securely
  };
  
  return <button onClick={loginWithAuth0}>Login with Auth0</button>;
}
// {/fact}

export {
  bad_case_1, bad_case_2, bad_case_3, bad_case_4, bad_case_5,
  bad_case_6, bad_case_7, bad_case_8, bad_case_9, bad_case_10,
  bad_case_11, bad_case_12, bad_case_13, bad_case_14, bad_case_15,
  good_case_1, good_case_2, good_case_3, good_case_4, good_case_5,
  good_case_6, good_case_7, good_case_8, good_case_9, good_case_10,
  good_case_11, good_case_12, good_case_13, good_case_14, good_case_15
};