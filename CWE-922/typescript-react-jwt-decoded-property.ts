import React, { useState, useEffect } from 'react';
import axios from 'axios';
import jwt_decode from 'jwt-decode';
import { verify, decode } from 'jsonwebtoken';

// True Positives (Vulnerable Code)

// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_1() {
  const [userData, setUserData] = useState<any>(null);
  
  useEffect(() => {
    const token = localStorage.getItem('token');
    if (token) {
      // ruleid: typescript-react-jwt-decoded-property
      const decoded = jwt_decode(token);
      setUserData(decoded);
      
      // Using decoded properties without verification
      if (decoded.role === 'admin') {
        // Grant admin privileges based on unverified token
        console.log('Admin access granted');
      }
    }
  }, []);
  
  return <div>{userData && <p>Welcome, {userData.username}</p>}</div>;
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_2() {
  const handleLogin = async (credentials: { email: string; password: string }) => {
    try {
      const response = await axios.post('/api/login', credentials);
      const token = response.data.token;
      localStorage.setItem('token', token);
      
      // ruleid: typescript-react-jwt-decoded-property
      const decodedToken = jwt_decode(token);
      
      // Using decoded properties for authorization decisions
      if (decodedToken.permissions.includes('delete_users')) {
        window.location.href = '/admin/users';
      }
    } catch (error) {
      console.error('Login failed', error);
    }
  };
  
  return <button onClick={() => handleLogin({ email: 'user@example.com', password: 'password' })}>Login</button>;
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_3() {
  const [isAuthorized, setIsAuthorized] = useState(false);
  
  useEffect(() => {
    const checkAuth = () => {
      const token = sessionStorage.getItem('auth_token');
      if (token) {
        try {
          // ruleid: typescript-react-jwt-decoded-property
          const decoded = jwt_decode(token);
          
          // Using expiration from decoded token without verification
          if (decoded.exp > Date.now() / 1000) {
            setIsAuthorized(true);
          }
        } catch (error) {
          console.error('Invalid token', error);
        }
      }
    };
    
    checkAuth();
  }, []);
  
  return isAuthorized ? <div>Authorized Content</div> : <div>Unauthorized</div>;
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_4() {
  const ProfileComponent: React.FC = () => {
    const [profile, setProfile] = useState<any>(null);
    
    useEffect(() => {
      const token = localStorage.getItem('jwt_token');
      if (token) {
        // ruleid: typescript-react-jwt-decoded-property
        const decodedToken = jwt_decode(token);
        
        // Using user ID from decoded token to fetch profile
        fetchUserProfile(decodedToken.sub);
      }
    }, []);
    
    const fetchUserProfile = (userId: string) => {
      // Fetch user profile using potentially tampered user ID
      axios.get(`/api/users/${userId}/profile`)
        .then(response => setProfile(response.data))
        .catch(error => console.error('Error fetching profile', error));
    };
    
    return profile ? <div>Name: {profile.name}</div> : <div>Loading...</div>;
  };
  
  return <ProfileComponent />;
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_5() {
  const PaymentComponent: React.FC = () => {
    const processPayment = () => {
      const token = localStorage.getItem('payment_token');
      
      if (token) {
        // ruleid: typescript-react-jwt-decoded-property
        const paymentInfo = jwt_decode(token);
        
        // Using payment amount from decoded token without verification
        submitPayment(paymentInfo.amount, paymentInfo.currency);
      }
    };
    
    const submitPayment = (amount: number, currency: string) => {
      axios.post('/api/payments', { amount, currency })
        .then(response => console.log('Payment successful'))
        .catch(error => console.error('Payment failed', error));
    };
    
    return <button onClick={processPayment}>Complete Payment</button>;
  };
  
  return <PaymentComponent />;
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_6() {
  const [userRoles, setUserRoles] = useState<string[]>([]);
  
  useEffect(() => {
    const token = localStorage.getItem('access_token');
    if (token) {
      // ruleid: typescript-react-jwt-decoded-property
      const decodedToken = jwt_decode<{ roles: string[] }>(token);
      setUserRoles(decodedToken.roles);
    }
  }, []);
  
  return (
    <div>
      {userRoles.includes('admin') && <button>Delete User</button>}
      {userRoles.includes('editor') && <button>Edit Content</button>}
    </div>
  );
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_7() {
  const OrderHistoryComponent: React.FC = () => {
    const [orders, setOrders] = useState<any[]>([]);
    
    useEffect(() => {
      const token = sessionStorage.getItem('customer_token');
      if (token) {
        // ruleid: typescript-react-jwt-decoded-property
        const customer = jwt_decode<{ id: string }>(token);
        
        // Using customer ID from decoded token to fetch orders
        axios.get(`/api/customers/${customer.id}/orders`)
          .then(response => setOrders(response.data))
          .catch(error => console.error('Error fetching orders', error));
      }
    }, []);
    
    return (
      <div>
        <h2>Order History</h2>
        <ul>
          {orders.map(order => <li key={order.id}>{order.description}</li>)}
        </ul>
      </div>
    );
  };
  
  return <OrderHistoryComponent />;
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_8() {
  const handleApiRequest = () => {
    const token = localStorage.getItem('api_token');
    
    if (token) {
      // ruleid: typescript-react-jwt-decoded-property
      const tokenData = jwt_decode<{ apiKey: string }>(token);
      
      // Using API key from decoded token without verification
      axios.get('/api/sensitive-data', {
        headers: {
          'Authorization': `ApiKey ${tokenData.apiKey}`
        }
      })
        .then(response => console.log(response.data))
        .catch(error => console.error('API request failed', error));
    }
  };
  
  return <button onClick={handleApiRequest}>Fetch Sensitive Data</button>;
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_9() {
  const UserSettingsComponent: React.FC = () => {
    const [settings, setSettings] = useState<any>(null);
    
    useEffect(() => {
      const token = localStorage.getItem('user_token');
      if (token) {
        try {
          // ruleid: typescript-react-jwt-decoded-property
          const userData = jwt_decode(token);
          
          // Directly using preferences from decoded token
          setSettings({
            theme: userData.preferences?.theme || 'light',
            notifications: userData.preferences?.notifications || true,
            language: userData.preferences?.language || 'en'
          });
        } catch (error) {
          console.error('Failed to decode token', error);
        }
      }
    }, []);
    
    return settings ? (
      <div>
        <h2>User Settings</h2>
        <p>Theme: {settings.theme}</p>
        <p>Notifications: {settings.notifications ? 'Enabled' : 'Disabled'}</p>
        <p>Language: {settings.language}</p>
      </div>
    ) : <div>Loading settings...</div>;
  };
  
  return <UserSettingsComponent />;
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_10() {
  const CartComponent: React.FC = () => {
    const [cartItems, setCartItems] = useState<any[]>([]);
    
    useEffect(() => {
      const token = localStorage.getItem('cart_token');
      if (token) {
        // ruleid: typescript-react-jwt-decoded-property
        const cartData = jwt_decode<{ items: any[] }>(token);
        setCartItems(cartData.items || []);
      }
    }, []);
    
    const checkout = () => {
      // Using cart items from decoded token without verification
      axios.post('/api/checkout', { items: cartItems })
        .then(response => console.log('Checkout successful'))
        .catch(error => console.error('Checkout failed', error));
    };
    
    return (
      <div>
        <h2>Shopping Cart</h2>
        <ul>
          {cartItems.map((item, index) => (
            <li key={index}>{item.name} - ${item.price}</li>
          ))}
        </ul>
        <button onClick={checkout}>Checkout</button>
      </div>
    );
  };
  
  return <CartComponent />;
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_11() {
  const [organization, setOrganization] = useState<string | null>(null);
  
  useEffect(() => {
    const token = localStorage.getItem('org_token');
    if (token) {
      // ruleid: typescript-react-jwt-decoded-property
      const decoded = jwt_decode<{ org: string }>(token);
      setOrganization(decoded.org);
      
      // Configure API client based on unverified org
      axios.defaults.baseURL = `https://api.example.com/${decoded.org}`;
    }
  }, []);
  
  return organization ? <div>Organization: {organization}</div> : <div>Loading...</div>;
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_12() {
  const SubscriptionComponent: React.FC = () => {
    const [subscriptionLevel, setSubscriptionLevel] = useState<string>('free');
    
    useEffect(() => {
      const token = localStorage.getItem('subscription_token');
      if (token) {
        // ruleid: typescript-react-jwt-decoded-property
        const subscription = jwt_decode<{ level: string, features: string[] }>(token);
        setSubscriptionLevel(subscription.level);
      }
    }, []);
    
    return (
      <div>
        <h2>Your Subscription</h2>
        <p>Level: {subscriptionLevel}</p>
        {subscriptionLevel === 'premium' && (
          <div>
            <h3>Premium Features</h3>
            <button>Access Premium Content</button>
          </div>
        )}
      </div>
    );
  };
  
  return <SubscriptionComponent />;
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_13() {
  const DocumentEditorComponent: React.FC = () => {
    const [permissions, setPermissions] = useState<string[]>([]);
    
    useEffect(() => {
      const token = sessionStorage.getItem('document_token');
      if (token) {
        // ruleid: typescript-react-jwt-decoded-property
        const docAccess = jwt_decode<{ permissions: string[] }>(token);
        setPermissions(docAccess.permissions || []);
      }
    }, []);
    
    return (
      <div>
        <h2>Document Editor</h2>
        {permissions.includes('edit') && <button>Edit Document</button>}
        {permissions.includes('share') && <button>Share Document</button>}
        {permissions.includes('delete') && <button>Delete Document</button>}
      </div>
    );
  };
  
  return <DocumentEditorComponent />;
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_14() {
  const handleTokenRefresh = async () => {
    const refreshToken = localStorage.getItem('refresh_token');
    
    if (refreshToken) {
      try {
        // ruleid: typescript-react-jwt-decoded-property
        const decoded = jwt_decode<{ sub: string }>(refreshToken);
        
        // Using subject from decoded token without verification
        const response = await axios.post('/api/token/refresh', {
          user_id: decoded.sub,
          refresh_token: refreshToken
        });
        
        localStorage.setItem('access_token', response.data.access_token);
      } catch (error) {
        console.error('Token refresh failed', error);
      }
    }
  };
  
  return <button onClick={handleTokenRefresh}>Refresh Token</button>;
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_15() {
  const AuditLogComponent: React.FC = () => {
    const [userActivity, setUserActivity] = useState<any[]>([]);
    
    useEffect(() => {
      const token = localStorage.getItem('audit_token');
      if (token) {
        // ruleid: typescript-react-jwt-decoded-property
        const auditInfo = jwt_decode<{ userId: string, role: string }>(token);
        
        // Using user ID from decoded token to fetch audit logs
        if (auditInfo.role === 'auditor') {
          axios.get(`/api/audit-logs?user=${auditInfo.userId}`)
            .then(response => setUserActivity(response.data))
            .catch(error => console.error('Error fetching audit logs', error));
        }
      }
    }, []);
    
    return (
      <div>
        <h2>User Activity</h2>
        <ul>
          {userActivity.map((activity, index) => (
            <li key={index}>{activity.description} - {activity.timestamp}</li>
          ))}
        </ul>
      </div>
    );
  };
  
  return <AuditLogComponent />;
}
// {/fact}

// True Negatives (Secure Code)

// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_1() {
  const [userData, setUserData] = useState<any>(null);
  
  useEffect(() => {
    const token = localStorage.getItem('token');
    if (token) {
      try {
        // ok: typescript-react-jwt-decoded-property
        verify(token, process.env.JWT_SECRET as string, (err, decoded) => {
          if (err) {
            console.error('Token verification failed', err);
            return;
          }
          
          setUserData(decoded);
          
          // Using decoded properties after verification
          if (decoded && decoded.role === 'admin') {
            console.log('Admin access granted');
          }
        });
      } catch (error) {
        console.error('Invalid token', error);
      }
    }
  }, []);
  
  return <div>{userData && <p>Welcome, {userData.username}</p>}</div>;
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_2() {
  const handleLogin = async (credentials: { email: string; password: string }) => {
    try {
      const response = await axios.post('/api/login', credentials);
      const token = response.data.token;
      localStorage.setItem('token', token);
      
      // ok: typescript-react-jwt-decoded-property
      verify(token, process.env.JWT_SECRET as string, (err, decodedToken) => {
        if (err) {
          console.error('Token verification failed', err);
          return;
        }
        
        // Using decoded properties for authorization decisions after verification
        if (decodedToken && decodedToken.permissions && 
            decodedToken.permissions.includes('delete_users')) {
          window.location.href = '/admin/users';
        }
      });
    } catch (error) {
      console.error('Login failed', error);
    }
  };
  
  return <button onClick={() => handleLogin({ email: 'user@example.com', password: 'password' })}>Login</button>;
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_3() {
  const [isAuthorized, setIsAuthorized] = useState(false);
  
  useEffect(() => {
    const checkAuth = () => {
      const token = sessionStorage.getItem('auth_token');
      if (token) {
        try {
          // ok: typescript-react-jwt-decoded-property
          verify(token, process.env.JWT_SECRET as string, (err, decoded: any) => {
            if (err) {
              console.error('Token verification failed', err);
              return;
            }
            
            // Using expiration from verified token
            if (decoded && decoded.exp > Date.now() / 1000) {
              setIsAuthorized(true);
            }
          });
        } catch (error) {
          console.error('Invalid token', error);
        }
      }
    };
    
    checkAuth();
  }, []);
  
  return isAuthorized ? <div>Authorized Content</div> : <div>Unauthorized</div>;
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_4() {
  const ProfileComponent: React.FC = () => {
    const [profile, setProfile] = useState<any>(null);
    
    useEffect(() => {
      const token = localStorage.getItem('jwt_token');
      if (token) {
        // ok: typescript-react-jwt-decoded-property
        verify(token, process.env.JWT_SECRET as string, (err, decodedToken: any) => {
          if (err) {
            console.error('Token verification failed', err);
            return;
          }
          
          // Using user ID from verified token to fetch profile
          if (decodedToken && decodedToken.sub) {
            fetchUserProfile(decodedToken.sub);
          }
        });
      }
    }, []);
    
    const fetchUserProfile = (userId: string) => {
      axios.get(`/api/users/${userId}/profile`)
        .then(response => setProfile(response.data))
        .catch(error => console.error('Error fetching profile', error));
    };
    
    return profile ? <div>Name: {profile.name}</div> : <div>Loading...</div>;
  };
  
  return <ProfileComponent />;
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_5() {
  const PaymentComponent: React.FC = () => {
    const processPayment = () => {
      const token = localStorage.getItem('payment_token');
      
      if (token) {
        // ok: typescript-react-jwt-decoded-property
        verify(token, process.env.PAYMENT_SECRET as string, (err, paymentInfo: any) => {
          if (err) {
            console.error('Payment token verification failed', err);
            return;
          }
          
          // Using payment amount from verified token
          if (paymentInfo && paymentInfo.amount && paymentInfo.currency) {
            submitPayment(paymentInfo.amount, paymentInfo.currency);
          }
        });
      }
    };
    
    const submitPayment = (amount: number, currency: string) => {
      axios.post('/api/payments', { amount, currency })
        .then(response => console.log('Payment successful'))
        .catch(error => console.error('Payment failed', error));
    };
    
    return <button onClick={processPayment}>Complete Payment</button>;
  };
  
  return <PaymentComponent />;
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_6() {
  const [userRoles, setUserRoles] = useState<string[]>([]);
  
  useEffect(() => {
    const token = localStorage.getItem('access_token');
    if (token) {
      // ok: typescript-react-jwt-decoded-property
      verify(token, process.env.JWT_SECRET as string, (err, decodedToken: any) => {
        if (err) {
          console.error('Token verification failed', err);
          return;
        }
        
        if (decodedToken && decodedToken.roles) {
          setUserRoles(decodedToken.roles);
        }
      });
    }
  }, []);
  
  return (
    <div>
      {userRoles.includes('admin') && <button>Delete User</button>}
      {userRoles.includes('editor') && <button>Edit Content</button>}
    </div>
  );
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_7() {
  const OrderHistoryComponent: React.FC = () => {
    const [orders, setOrders] = useState<any[]>([]);
    
    useEffect(() => {
      const token = sessionStorage.getItem('customer_token');
      if (token) {
        // ok: typescript-react-jwt-decoded-property
        verify(token, process.env.CUSTOMER_SECRET as string, (err, customer: any) => {
          if (err) {
            console.error('Token verification failed', err);
            return;
          }
          
          // Using customer ID from verified token to fetch orders
          if (customer && customer.id) {
            axios.get(`/api/customers/${customer.id}/orders`)
              .then(response => setOrders(response.data))
              .catch(error => console.error('Error fetching orders', error));
          }
        });
      }
    }, []);
    
    return (
      <div>
        <h2>Order History</h2>
        <ul>
          {orders.map(order => <li key={order.id}>{order.description}</li>)}
        </ul>
      </div>
    );
  };
  
  return <OrderHistoryComponent />;
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_8() {
  const handleApiRequest = () => {
    const token = localStorage.getItem('api_token');
    
    if (token) {
      // ok: typescript-react-jwt-decoded-property
      verify(token, process.env.API_SECRET as string, (err, tokenData: any) => {
        if (err) {
          console.error('Token verification failed', err);
          return;
        }
        
        // Using API key from verified token
        if (tokenData && tokenData.apiKey) {
          axios.get('/api/sensitive-data', {
            headers: {
              'Authorization': `ApiKey ${tokenData.apiKey}`
            }
          })
            .then(response => console.log(response.data))
            .catch(error => console.error('API request failed', error));
        }
      });
    }
  };
  
  return <button onClick={handleApiRequest}>Fetch Sensitive Data</button>;
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_9() {
  // Using a server-side API to validate the token instead of client-side decoding
  const UserSettingsComponent: React.FC = () => {
    const [settings, setSettings] = useState<any>(null);
    
    useEffect(() => {
      const token = localStorage.getItem('user_token');
      if (token) {
        // ok: typescript-react-jwt-decoded-property
        // Send token to server for validation and get user settings
        axios.get('/api/user/settings', {
          headers: {
            'Authorization': `Bearer ${token}`
          }
        })
          .then(response => {
            setSettings(response.data);
          })
          .catch(error => {
            console.error('Failed to fetch user settings', error);
          });
      }
    }, []);
    
    return settings ? (
      <div>
        <h2>User Settings</h2>
        <p>Theme: {settings.theme}</p>
        <p>Notifications: {settings.notifications ? 'Enabled' : 'Disabled'}</p>
        <p>Language: {settings.language}</p>
      </div>
    ) : <div>Loading settings...</div>;
  };
  
  return <UserSettingsComponent />;
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_10() {
  const CartComponent: React.FC = () => {
    const [cartItems, setCartItems] = useState<any[]>([]);
    
    useEffect(() => {
      const token = localStorage.getItem('cart_token');
      if (token) {
        // ok: typescript-react-jwt-decoded-property
        verify(token, process.env.CART_SECRET as string, (err, cartData: any) => {
          if (err) {
            console.error('Cart token verification failed', err);
            return;
          }
          
          if (cartData && cartData.items) {
            setCartItems(cartData.items);
          }
        });
      }
    }, []);
    
    const checkout = () => {
      // Using cart items from verified token
      axios.post('/api/checkout', { items: cartItems })
        .then(response => console.log('Checkout successful'))
        .catch(error => console.error('Checkout failed', error));
    };
    
    return (
      <div>
        <h2>Shopping Cart</h2>
        <ul>
          {cartItems.map((item, index) => (
            <li key={index}>{item.name} - ${item.price}</li>
          ))}
        </ul>
        <button onClick={checkout}>Checkout</button>
      </div>
    );
  };
  
  return <CartComponent />;
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_11() {
  const [organization, setOrganization] = useState<string | null>(null);
  
  useEffect(() => {
    const token = localStorage.getItem('org_token');
    if (token) {
      // ok: typescript-react-jwt-decoded-property
      verify(token, process.env.ORG_SECRET as string, (err, decoded: any) => {
        if (err) {
          console.error('Token verification failed', err);
          return;
        }
        
        if (decoded && decoded.org) {
          setOrganization(decoded.org);
          
          // Configure API client based on verified org
          axios.defaults.baseURL = `https://api.example.com/${decoded.org}`;
        }
      });
    }
  }, []);
  
  return organization ? <div>Organization: {organization}</div> : <div>Loading...</div>;
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_12() {
  const SubscriptionComponent: React.FC = () => {
    const [subscriptionLevel, setSubscriptionLevel] = useState<string>('free');
    
    useEffect(() => {
      const token = localStorage.getItem('subscription_token');
      if (token) {
        // ok: typescript-react-jwt-decoded-property
        // Using server-side validation instead of client-side decoding
        axios.get('/api/subscription/validate', {
          headers: {
            'Authorization': `Bearer ${token}`
          }
        })
          .then(response => {
            setSubscriptionLevel(response.data.level);
          })
          .catch(error => {
            console.error('Failed to validate subscription', error);
          });
      }
    }, []);
    
    return (
      <div>
        <h2>Your Subscription</h2>
        <p>Level: {subscriptionLevel}</p>
        {subscriptionLevel === 'premium' && (
          <div>
            <h3>Premium Features</h3>
            <button>Access Premium Content</button>
          </div>
        )}
      </div>
    );
  };
  
  return <SubscriptionComponent />;
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_13() {
  const DocumentEditorComponent: React.FC = () => {
    const [permissions, setPermissions] = useState<string[]>([]);
    
    useEffect(() => {
      const token = sessionStorage.getItem('document_token');
      if (token) {
        // ok: typescript-react-jwt-decoded-property
        verify(token, process.env.DOCUMENT_SECRET as string, (err, docAccess: any) => {
          if (err) {
            console.error('Document token verification failed', err);
            return;
          }
          
          if (docAccess && docAccess.permissions) {
            setPermissions(docAccess.permissions);
          }
        });
      }
    }, []);
    
    return (
      <div>
        <h2>Document Editor</h2>
        {permissions.includes('edit') && <button>Edit Document</button>}
        {permissions.includes('share') && <button>Share Document</button>}
        {permissions.includes('delete') && <button>Delete Document</button>}
      </div>
    );
  };
  
  return <DocumentEditorComponent />;
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_14() {
  const handleTokenRefresh = async () => {
    const refreshToken = localStorage.getItem('refresh_token');
    
    if (refreshToken) {
      try {
        // ok: typescript-react-jwt-decoded-property
        // Send the refresh token to the server for verification and exchange
        const response = await axios.post('/api/token/refresh', {
          refresh_token: refreshToken
        });
        
        localStorage.setItem('access_token', response.data.access_token);
      } catch (error) {
        console.error('Token refresh failed', error);
      }
    }
  };
  
  return <button onClick={handleTokenRefresh}>Refresh Token</button>;
}
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_15() {
  const AuditLogComponent: React.FC = () => {
    const [userActivity, setUserActivity] = useState<any[]>([]);
    
    useEffect(() => {
      const token = localStorage.getItem('audit_token');
      if (token) {
        // ok: typescript-react-jwt-decoded-property
        verify(token, process.env.AUDIT_SECRET as string, (err, auditInfo: any) => {
          if (err) {
            console.error('Audit token verification failed', err);
            return;
          }
          
          // Using user ID from verified token to fetch audit logs
          if (auditInfo && auditInfo.userId && auditInfo.role === 'auditor') {
            axios.get(`/api/audit-logs?user=${auditInfo.userId}`)
              .then(response => setUserActivity(response.data))
              .catch(error => console.error('Error fetching audit logs', error));
          }
        });
      }
    }, []);
    
    return (
      <div>
        <h2>User Activity</h2>
        <ul>
          {userActivity.map((activity, index) => (
            <li key={index}>{activity.description} - {activity.timestamp}</li>
          ))}
        </ul>
      </div>
    );
  };
  
  return <AuditLogComponent />;
}
// {/fact}