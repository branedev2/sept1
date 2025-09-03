import React, { useState, useEffect } from 'react';
import axios from 'axios';
import jwt_decode from 'jwt-decode';
import { verify, sign } from 'jsonwebtoken';

// True Positives (Vulnerable Code)

// Case 1: Directly using decoded JWT property without verification
// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_1() {
  const [userData, setUserData] = useState(null);
  
  useEffect(() => {
    const token = localStorage.getItem('auth_token');
    if (token) {
      // ruleid: typescript-react-jwt-decoded-property
      const decoded = jwt_decode(token);
      setUserData(decoded.user);
      
      // Using the decoded property directly
      if (decoded.role === 'admin') {
        // Grant admin privileges without verification
        enableAdminFeatures();
      }
    }
  }, []);
  
  const enableAdminFeatures = () => {
    console.log('Admin features enabled');
  };
  
  return (
    <div>
      {userData && <h1>Welcome, {userData.name}</h1>}
    </div>
  );
}
// {/fact}

// Case 2: Using decoded JWT for authorization decisions
// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_2() {
  const [isAuthorized, setIsAuthorized] = useState(false);
  
  useEffect(() => {
    const token = localStorage.getItem('jwt_token');
    if (token) {
      try {
        // ruleid: typescript-react-jwt-decoded-property
        const decodedToken = jwt_decode(token);
        
        // Making security decisions based on unverified token
        if (decodedToken.permissions.includes('delete_users')) {
          setIsAuthorized(true);
        }
      } catch (error) {
        console.error('Invalid token', error);
      }
    }
  }, []);
  
  return (
    <div>
      {isAuthorized ? 
        <button onClick={() => deleteUser(123)}>Delete User</button> : 
        <p>Unauthorized</p>
      }
    </div>
  );
  
  function deleteUser(id: number) {
    console.log(`Deleting user ${id}`);
  }
}
// {/fact}

// Case 3: Extracting sensitive information from decoded JWT
// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_3() {
  const [userEmail, setUserEmail] = useState('');
  
  useEffect(() => {
    const fetchUserData = async () => {
      const token = sessionStorage.getItem('access_token');
      if (token) {
        // ruleid: typescript-react-jwt-decoded-property
        const decoded = jwt_decode(token);
        setUserEmail(decoded.email);
        
        // Using sensitive information from decoded token
        await axios.get(`/api/user-data?email=${decoded.email}`);
      }
    };
    
    fetchUserData();
  }, []);
  
  return <div>User email: {userEmail}</div>;
}
// {/fact}

// Case 4: Using decoded JWT in component rendering
// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_4() {
  const [userProfile, setUserProfile] = useState(null);
  
  useEffect(() => {
    const token = localStorage.getItem('id_token');
    if (token) {
      try {
        // ruleid: typescript-react-jwt-decoded-property
        const decodedProfile = jwt_decode(token);
        setUserProfile(decodedProfile);
      } catch (error) {
        console.error('Failed to decode token', error);
      }
    }
  }, []);
  
  if (!userProfile) return <div>Loading...</div>;
  
  return (
    <div>
      <h1>{userProfile.name}</h1>
      <p>Role: {userProfile.role}</p>
      <p>Account ID: {userProfile.account_id}</p>
    </div>
  );
}
// {/fact}

// Case 5: Using decoded JWT for API requests
// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_5() {
  const [projectId, setProjectId] = useState(null);
  
  useEffect(() => {
    const token = localStorage.getItem('project_token');
    if (token) {
      // ruleid: typescript-react-jwt-decoded-property
      const decoded = jwt_decode(token);
      setProjectId(decoded.project_id);
      
      // Using the decoded property for API requests
      fetchProjectData(decoded.project_id);
    }
  }, []);
  
  const fetchProjectData = (id: string) => {
    axios.get(`/api/projects/${id}/data`);
  };
  
  return <div>Project ID: {projectId}</div>;
}
// {/fact}

// Case 6: Using decoded JWT in a custom hook
// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_6() {
  const useAuth = () => {
    const [user, setUser] = useState(null);
    
    useEffect(() => {
      const token = localStorage.getItem('auth_token');
      if (token) {
        // ruleid: typescript-react-jwt-decoded-property
        const decoded = jwt_decode(token);
        setUser({
          id: decoded.sub,
          name: decoded.name,
          permissions: decoded.permissions
        });
      }
    }, []);
    
    return { user };
  };
  
  const { user } = useAuth();
  
  return (
    <div>
      {user && (
        <div>
          <h2>Welcome, {user.name}</h2>
          <p>You have {user.permissions.length} permissions</p>
        </div>
      )}
    </div>
  );
}
// {/fact}

// Case 7: Using decoded JWT with async operations
// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_7() {
  const [organizationId, setOrganizationId] = useState('');
  
  useEffect(() => {
    const loadOrganizationData = async () => {
      const token = localStorage.getItem('org_token');
      if (token) {
        // ruleid: typescript-react-jwt-decoded-property
        const decoded = jwt_decode(token);
        setOrganizationId(decoded.org_id);
        
        // Using decoded property in async operation
        const response = await axios.get(`/api/organizations/${decoded.org_id}/members`);
        console.log(response.data);
      }
    };
    
    loadOrganizationData();
  }, []);
  
  return <div>Organization: {organizationId}</div>;
}
// {/fact}

// Case 8: Using decoded JWT in event handlers
// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_8() {
  const [token, setToken] = useState('');
  const [userData, setUserData] = useState(null);
  
  useEffect(() => {
    setToken(localStorage.getItem('user_token') || '');
  }, []);
  
  const handleButtonClick = () => {
    if (token) {
      // ruleid: typescript-react-jwt-decoded-property
      const decoded = jwt_decode(token);
      setUserData(decoded);
      
      // Using decoded property in event handler
      if (decoded.subscription_level === 'premium') {
        unlockPremiumFeatures();
      }
    }
  };
  
  const unlockPremiumFeatures = () => {
    console.log('Premium features unlocked');
  };
  
  return (
    <div>
      <button onClick={handleButtonClick}>Load User Data</button>
      {userData && <pre>{JSON.stringify(userData, null, 2)}</pre>}
    </div>
  );
}
// {/fact}

// Case 9: Using decoded JWT in a context provider
// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_9() {
  const AuthProvider = ({ children }: { children: React.ReactNode }) => {
    const [authState, setAuthState] = useState({
      isAuthenticated: false,
      user: null
    });
    
    useEffect(() => {
      const token = localStorage.getItem('auth_token');
      if (token) {
        try {
          // ruleid: typescript-react-jwt-decoded-property
          const decoded = jwt_decode(token);
          setAuthState({
            isAuthenticated: true,
            user: {
              id: decoded.sub,
              email: decoded.email,
              roles: decoded.roles
            }
          });
        } catch (error) {
          console.error('Invalid token', error);
        }
      }
    }, []);
    
    return (
      <div>
        {authState.isAuthenticated ? 
          <div>Authenticated as {authState.user?.email}</div> : 
          <div>Not authenticated</div>
        }
        {children}
      </div>
    );
  };
  
  return (
    <AuthProvider>
      <div>Protected Content</div>
    </AuthProvider>
  );
}
// {/fact}

// Case 10: Using decoded JWT with conditional rendering
// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_10() {
  const [hasAccess, setHasAccess] = useState(false);
  
  useEffect(() => {
    const token = localStorage.getItem('feature_token');
    if (token) {
      // ruleid: typescript-react-jwt-decoded-property
      const decoded = jwt_decode(token);
      
      // Using decoded property for conditional rendering
      if (decoded.features && decoded.features.includes('premium_dashboard')) {
        setHasAccess(true);
      }
    }
  }, []);
  
  return (
    <div>
      {hasAccess ? (
        <div>Premium Dashboard Content</div>
      ) : (
        <div>Basic Dashboard Content</div>
      )}
    </div>
  );
}
// {/fact}

// Case 11: Using decoded JWT in a form submission
// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_11() {
  const [formData, setFormData] = useState({ userId: '', teamId: '' });
  
  useEffect(() => {
    const token = localStorage.getItem('team_token');
    if (token) {
      // ruleid: typescript-react-jwt-decoded-property
      const decoded = jwt_decode(token);
      setFormData({
        userId: decoded.user_id,
        teamId: decoded.team_id
      });
    }
  }, []);
  
  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    // Using decoded properties in form submission
    axios.post('/api/team/update', formData);
  };
  
  return (
    <form onSubmit={handleSubmit}>
      <input
        type="text"
        value={formData.userId}
        readOnly
      />
      <input
        type="text"
        value={formData.teamId}
        readOnly
      />
      <button type="submit">Update Team</button>
    </form>
  );
}
// {/fact}

// Case 12: Using decoded JWT with localStorage updates
// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_12() {
  useEffect(() => {
    const token = localStorage.getItem('session_token');
    if (token) {
      // ruleid: typescript-react-jwt-decoded-property
      const decoded = jwt_decode(token);
      
      // Storing decoded JWT properties in localStorage
      localStorage.setItem('user_id', decoded.sub);
      localStorage.setItem('username', decoded.preferred_username);
      localStorage.setItem('email', decoded.email);
    }
  }, []);
  
  return <div>User data stored in localStorage</div>;
}
// {/fact}

// Case 13: Using decoded JWT with multiple tokens
// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_13() {
  const [accessData, setAccessData] = useState(null);
  const [profileData, setProfileData] = useState(null);
  
  useEffect(() => {
    const accessToken = localStorage.getItem('access_token');
    const idToken = localStorage.getItem('id_token');
    
    if (accessToken) {
      // ruleid: typescript-react-jwt-decoded-property
      const decodedAccess = jwt_decode(accessToken);
      setAccessData({
        scope: decodedAccess.scope,
        expires: decodedAccess.exp
      });
    }
    
    if (idToken) {
      // ruleid: typescript-react-jwt-decoded-property
      const decodedId = jwt_decode(idToken);
      setProfileData({
        name: decodedId.name,
        email: decodedId.email
      });
    }
  }, []);
  
  return (
    <div>
      {accessData && <div>Scope: {accessData.scope}</div>}
      {profileData && <div>Name: {profileData.name}</div>}
    </div>
  );
}
// {/fact}

// Case 14: Using decoded JWT with error handling but no verification
// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_14() {
  const [userData, setUserData] = useState(null);
  const [error, setError] = useState('');
  
  useEffect(() => {
    const token = localStorage.getItem('auth_token');
    if (token) {
      try {
        // ruleid: typescript-react-jwt-decoded-property
        const decoded = jwt_decode(token);
        setUserData({
          id: decoded.sub,
          roles: decoded.roles || []
        });
      } catch (err) {
        setError('Invalid token format');
        console.error(err);
      }
    } else {
      setError('No token found');
    }
  }, []);
  
  if (error) return <div>Error: {error}</div>;
  if (!userData) return <div>Loading...</div>;
  
  return (
    <div>
      <h2>User ID: {userData.id}</h2>
      <h3>Roles:</h3>
      <ul>
        {userData.roles.map((role: string, index: number) => (
          <li key={index}>{role}</li>
        ))}
      </ul>
    </div>
  );
}
// {/fact}

// Case 15: Using decoded JWT in a custom component
// {fact rule=insecure-connection@v1.0 defects=1}
function bad_case_15() {
  const UserBadge = () => {
    const [badge, setBadge] = useState({ level: '', color: '' });
    
    useEffect(() => {
      const token = localStorage.getItem('badge_token');
      if (token) {
        // ruleid: typescript-react-jwt-decoded-property
        const decoded = jwt_decode(token);
        setBadge({
          level: decoded.badge_level,
          color: decoded.badge_color
        });
      }
    }, []);
    
    return (
      <div style={{ backgroundColor: badge.color }}>
        User Level: {badge.level}
      </div>
    );
  };
  
  return (
    <div>
      <h1>User Profile</h1>
      <UserBadge />
    </div>
  );
}
// {/fact}

// True Negatives (Secure Code)

// Case 1: Properly verifying JWT before using decoded properties
// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_1() {
  const [userData, setUserData] = useState(null);
  
  useEffect(() => {
    const token = localStorage.getItem('auth_token');
    if (token) {
      try {
        // ok: typescript-react-jwt-decoded-property
        verify(token, process.env.JWT_SECRET as string, (err, decoded) => {
          if (err) {
            console.error('Token verification failed', err);
            return;
          }
          setUserData(decoded.user);
          
          if (decoded.role === 'admin') {
            enableAdminFeatures();
          }
        });
      } catch (error) {
        console.error('Invalid token', error);
      }
    }
  }, []);
  
  const enableAdminFeatures = () => {
    console.log('Admin features enabled');
  };
  
  return (
    <div>
      {userData && <h1>Welcome, {userData.name}</h1>}
    </div>
  );
}
// {/fact}

// Case 2: Using server-side verification for authorization decisions
// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_2() {
  const [isAuthorized, setIsAuthorized] = useState(false);
  
  useEffect(() => {
    const checkAuthorization = async () => {
      const token = localStorage.getItem('jwt_token');
      if (token) {
        try {
          // ok: typescript-react-jwt-decoded-property
          // Sending token to server for verification instead of client-side decoding
          const response = await axios.post('/api/verify-permission', {
            token,
            permission: 'delete_users'
          });
          
          setIsAuthorized(response.data.isAuthorized);
        } catch (error) {
          console.error('Authorization check failed', error);
        }
      }
    };
    
    checkAuthorization();
  }, []);
  
  return (
    <div>
      {isAuthorized ? 
        <button onClick={() => deleteUser(123)}>Delete User</button> : 
        <p>Unauthorized</p>
      }
    </div>
  );
  
  function deleteUser(id: number) {
    console.log(`Deleting user ${id}`);
  }
}
// {/fact}

// Case 3: Using JWT verification with a public key
// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_3() {
  const [userEmail, setUserEmail] = useState('');
  
  useEffect(() => {
    const fetchUserData = async () => {
      const token = sessionStorage.getItem('access_token');
      if (token) {
        try {
          // ok: typescript-react-jwt-decoded-property
          const publicKey = await fetchPublicKey(); // Fetch from JWKS endpoint
          const decoded = verify(token, publicKey);
          setUserEmail(decoded.email);
          
          await axios.get(`/api/user-data?email=${decoded.email}`);
        } catch (error) {
          console.error('Token verification failed', error);
        }
      }
    };
    
    fetchUserData();
  }, []);
  
  const fetchPublicKey = async () => {
    const response = await axios.get('/api/auth/keys');
    return response.data.publicKey;
  };
  
  return <div>User email: {userEmail}</div>;
}
// {/fact}

// Case 4: Using server API to get user profile instead of decoding JWT
// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_4() {
  const [userProfile, setUserProfile] = useState(null);
  
  useEffect(() => {
    const fetchUserProfile = async () => {
      const token = localStorage.getItem('id_token');
      if (token) {
        try {
          // ok: typescript-react-jwt-decoded-property
          // Using the token for authentication but getting profile from API
          const response = await axios.get('/api/user/profile', {
            headers: {
              Authorization: `Bearer ${token}`
            }
          });
          setUserProfile(response.data);
        } catch (error) {
          console.error('Failed to fetch profile', error);
        }
      }
    };
    
    fetchUserProfile();
  }, []);
  
  if (!userProfile) return <div>Loading...</div>;
  
  return (
    <div>
      <h1>{userProfile.name}</h1>
      <p>Role: {userProfile.role}</p>
      <p>Account ID: {userProfile.account_id}</p>
    </div>
  );
}
// {/fact}

// Case 5: Using JWT verification with proper error handling
// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_5() {
  const [projectId, setProjectId] = useState(null);
  const [error, setError] = useState('');
  
  useEffect(() => {
    const token = localStorage.getItem('project_token');
    if (token) {
      try {
        // ok: typescript-react-jwt-decoded-property
        verify(token, process.env.JWT_SECRET as string, (err, decoded) => {
          if (err) {
            setError('Invalid token');
            return;
          }
          
          setProjectId(decoded.project_id);
          fetchProjectData(decoded.project_id);
        });
      } catch (error) {
        setError('Token verification failed');
      }
    }
  }, []);
  
  const fetchProjectData = (id: string) => {
    axios.get(`/api/projects/${id}/data`);
  };
  
  if (error) return <div>Error: {error}</div>;
  
  return <div>Project ID: {projectId}</div>;
}
// {/fact}

// Case 6: Using a custom hook with proper JWT verification
// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_6() {
  const useAuth = () => {
    const [user, setUser] = useState(null);
    const [loading, setLoading] = useState(true);
    
    useEffect(() => {
      const verifyToken = async () => {
        const token = localStorage.getItem('auth_token');
        if (token) {
          try {
            // ok: typescript-react-jwt-decoded-property
            const decoded = await new Promise((resolve, reject) => {
              verify(token, process.env.JWT_SECRET as string, (err, decoded) => {
                if (err) reject(err);
                else resolve(decoded);
              });
            });
            
            setUser({
              id: decoded.sub,
              name: decoded.name,
              permissions: decoded.permissions
            });
          } catch (error) {
            console.error('Token verification failed', error);
          } finally {
            setLoading(false);
          }
        } else {
          setLoading(false);
        }
      };
      
      verifyToken();
    }, []);
    
    return { user, loading };
  };
  
  const { user, loading } = useAuth();
  
  if (loading) return <div>Loading...</div>;
  
  return (
    <div>
      {user ? (
        <div>
          <h2>Welcome, {user.name}</h2>
          <p>You have {user.permissions.length} permissions</p>
        </div>
      ) : (
        <div>Please log in</div>
      )}
    </div>
  );
}
// {/fact}

// Case 7: Using JWT verification with async/await
// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_7() {
  const [organizationId, setOrganizationId] = useState('');
  
  useEffect(() => {
    const loadOrganizationData = async () => {
      const token = localStorage.getItem('org_token');
      if (token) {
        try {
          // ok: typescript-react-jwt-decoded-property
          const decoded = await new Promise((resolve, reject) => {
            verify(token, process.env.JWT_SECRET as string, (err, decoded) => {
              if (err) reject(err);
              else resolve(decoded);
            });
          });
          
          setOrganizationId(decoded.org_id);
          
          const response = await axios.get(`/api/organizations/${decoded.org_id}/members`);
          console.log(response.data);
        } catch (error) {
          console.error('Token verification failed', error);
        }
      }
    };
    
    loadOrganizationData();
  }, []);
  
  return <div>Organization: {organizationId}</div>;
}
// {/fact}

// Case 8: Using server API for authentication status
// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_8() {
  const [token, setToken] = useState('');
  const [userData, setUserData] = useState(null);
  
  useEffect(() => {
    setToken(localStorage.getItem('user_token') || '');
  }, []);
  
  const handleButtonClick = async () => {
    if (token) {
      try {
        // ok: typescript-react-jwt-decoded-property
        // Using server API to verify token and get user data
        const response = await axios.get('/api/user/data', {
          headers: {
            Authorization: `Bearer ${token}`
          }
        });
        
        setUserData(response.data);
        
        if (response.data.subscription_level === 'premium') {
          unlockPremiumFeatures();
        }
      } catch (error) {
        console.error('Failed to get user data', error);
      }
    }
  };
  
  const unlockPremiumFeatures = () => {
    console.log('Premium features unlocked');
  };
  
  return (
    <div>
      <button onClick={handleButtonClick}>Load User Data</button>
      {userData && <pre>{JSON.stringify(userData, null, 2)}</pre>}
    </div>
  );
}
// {/fact}

// Case 9: Using a context provider with proper JWT verification
// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_9() {
  const AuthProvider = ({ children }: { children: React.ReactNode }) => {
    const [authState, setAuthState] = useState({
      isAuthenticated: false,
      user: null,
      loading: true
    });
    
    useEffect(() => {
      const verifyAuth = async () => {
        const token = localStorage.getItem('auth_token');
        if (token) {
          try {
            // ok: typescript-react-jwt-decoded-property
            const secret = process.env.JWT_SECRET as string;
            const decoded = await new Promise((resolve, reject) => {
              verify(token, secret, (err, decoded) => {
                if (err) reject(err);
                else resolve(decoded);
              });
            });
            
            setAuthState({
              isAuthenticated: true,
              user: {
                id: decoded.sub,
                email: decoded.email,
                roles: decoded.roles
              },
              loading: false
            });
          } catch (error) {
            console.error('Invalid token', error);
            setAuthState({
              isAuthenticated: false,
              user: null,
              loading: false
            });
          }
        } else {
          setAuthState({
            isAuthenticated: false,
            user: null,
            loading: false
          });
        }
      };
      
      verifyAuth();
    }, []);
    
    if (authState.loading) return <div>Loading authentication...</div>;
    
    return (
      <div>
        {authState.isAuthenticated ? 
          <div>Authenticated as {authState.user?.email}</div> : 
          <div>Not authenticated</div>
        }
        {children}
      </div>
    );
  };
  
  return (
    <AuthProvider>
      <div>Protected Content</div>
    </AuthProvider>
  );
}
// {/fact}

// Case 10: Using server API for feature access control
// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_10() {
  const [hasAccess, setHasAccess] = useState(false);
  const [loading, setLoading] = useState(true);
  
  useEffect(() => {
    const checkFeatureAccess = async () => {
      const token = localStorage.getItem('feature_token');
      if (token) {
        try {
          // ok: typescript-react-jwt-decoded-property
          // Using server API to check feature access
          const response = await axios.get('/api/features/premium-dashboard', {
            headers: {
              Authorization: `Bearer ${token}`
            }
          });
          
          setHasAccess(response.data.hasAccess);
        } catch (error) {
          console.error('Failed to check feature access', error);
        } finally {
          setLoading(false);
        }
      } else {
        setLoading(false);
      }
    };
    
    checkFeatureAccess();
  }, []);
  
  if (loading) return <div>Loading...</div>;
  
  return (
    <div>
      {hasAccess ? (
        <div>Premium Dashboard Content</div>
      ) : (
        <div>Basic Dashboard Content</div>
      )}
    </div>
  );
}
// {/fact}

// Case 11: Using JWT verification before form submission
// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_11() {
  const [formData, setFormData] = useState({ userId: '', teamId: '' });
  const [isValid, setIsValid] = useState(false);
  
  useEffect(() => {
    const verifyToken = async () => {
      const token = localStorage.getItem('team_token');
      if (token) {
        try {
          // ok: typescript-react-jwt-decoded-property
          const decoded = await new Promise((resolve, reject) => {
            verify(token, process.env.JWT_SECRET as string, (err, decoded) => {
              if (err) reject(err);
              else resolve(decoded);
            });
          });
          
          setFormData({
            userId: decoded.user_id,
            teamId: decoded.team_id
          });
          setIsValid(true);
        } catch (error) {
          console.error('Token verification failed', error);
        }
      }
    };
    
    verifyToken();
  }, []);
  
  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (isValid) {
      axios.post('/api/team/update', formData);
    }
  };
  
  return (
    <form onSubmit={handleSubmit}>
      <input
        type="text"
        value={formData.userId}
        readOnly
      />
      <input
        type="text"
        value={formData.teamId}
        readOnly
      />
      <button type="submit" disabled={!isValid}>Update Team</button>
    </form>
  );
}
// {/fact}

// Case 12: Using server API for user data instead of storing decoded JWT
// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_12() {
  useEffect(() => {
    const storeUserData = async () => {
      const token = localStorage.getItem('session_token');
      if (token) {
        try {
          // ok: typescript-react-jwt-decoded-property
          // Using server API to get user data instead of decoding JWT
          const response = await axios.get('/api/user/profile', {
            headers: {
              Authorization: `Bearer ${token}`
            }
          });
          
          // Storing data from verified API response
          localStorage.setItem('user_id', response.data.id);
          localStorage.setItem('username', response.data.username);
          localStorage.setItem('email', response.data.email);
        } catch (error) {
          console.error('Failed to get user data', error);
        }
      }
    };
    
    storeUserData();
  }, []);
  
  return <div>User data stored in localStorage</div>;
}
// {/fact}

// Case 13: Using JWT verification with multiple tokens
// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_13() {
  const [accessData, setAccessData] = useState(null);
  const [profileData, setProfileData] = useState(null);
  
  useEffect(() => {
    const verifyTokens = async () => {
      const accessToken = localStorage.getItem('access_token');
      const idToken = localStorage.getItem('id_token');
      const secret = process.env.JWT_SECRET as string;
      
      if (accessToken) {
        try {
          // ok: typescript-react-jwt-decoded-property
          const decodedAccess = await new Promise((resolve, reject) => {
            verify(accessToken, secret, (err, decoded) => {
              if (err) reject(err);
              else resolve(decoded);
            });
          });
          
          setAccessData({
            scope: decodedAccess.scope,
            expires: decodedAccess.exp
          });
        } catch (error) {
          console.error('Access token verification failed', error);
        }
      }
      
      if (idToken) {
        try {
          // ok: typescript-react-jwt-decoded-property
          const decodedId = await new Promise((resolve, reject) => {
            verify(idToken, secret, (err, decoded) => {
              if (err) reject(err);
              else resolve(decoded);
            });
          });
          
          setProfileData({
            name: decodedId.name,
            email: decodedId.email
          });
        } catch (error) {
          console.error('ID token verification failed', error);
        }
      }
    };
    
    verifyTokens();
  }, []);
  
  return (
    <div>
      {accessData && <div>Scope: {accessData.scope}</div>}
      {profileData && <div>Name: {profileData.name}</div>}
    </div>
  );
}
// {/fact}

// Case 14: Using JWT verification with comprehensive error handling
// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_14() {
  const [userData, setUserData] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  
  useEffect(() => {
    const verifyToken = async () => {
      const token = localStorage.getItem('auth_token');
      if (token) {
        try {
          // ok: typescript-react-jwt-decoded-property
          const secret = process.env.JWT_SECRET as string;
          const decoded = await new Promise((resolve, reject) => {
            verify(token, secret, { algorithms: ['HS256'] }, (err, decoded) => {
              if (err) reject(err);
              else resolve(decoded);
            });
          });
          
          setUserData({
            id: decoded.sub,
            roles: decoded.roles || []
          });
        } catch (err) {
          if (err.name === 'TokenExpiredError') {
            setError('Token has expired. Please log in again.');
          } else if (err.name === 'JsonWebTokenError') {
            setError('Invalid token. Please log in again.');
          } else {
            setError('Authentication error. Please try again.');
          }
          console.error(err);
        } finally {
          setLoading(false);
        }
      } else {
        setError('No token found');
        setLoading(false);
      }
    };
    
    verifyToken();
  }, []);
  
  if (loading) return <div>Loading...</div>;
  if (error) return <div>Error: {error}</div>;
  if (!userData) return <div>No user data available</div>;
  
  return (
    <div>
      <h2>User ID: {userData.id}</h2>
      <h3>Roles:</h3>
      <ul>
        {userData.roles.map((role: string, index: number) => (
          <li key={index}>{role}</li>
        ))}
      </ul>
    </div>
  );
}
// {/fact}

// Case 15: Using a custom component with proper JWT verification
// {fact rule=insecure-connection@v1.0 defects=0}
function good_case_15() {
  const UserBadge = () => {
    const [badge, setBadge] = useState({ level: '', color: '' });
    const [loading, setLoading] = useState(true);
    
    useEffect(() => {
      const verifyBadgeToken = async () => {
        const token = localStorage.getItem('badge_token');
        if (token) {
          try {
            // ok: typescript-react-jwt-decoded-property
            const secret = process.env.JWT_SECRET as string;
            const decoded = await new Promise((resolve, reject) => {
              verify(token, secret, (err, decoded) => {
                if (err) reject(err);
                else resolve(decoded);
              });
            });
            
            setBadge({
              level: decoded.badge_level,
              color: decoded.badge_color
            });
          } catch (error) {
            console.error('Badge token verification failed', error);
          } finally {
            setLoading(false);
          }
        } else {
          setLoading(false);
        }
      };
      
      verifyBadgeToken();
    }, []);
    
    if (loading) return <div>Loading badge...</div>;
    if (!badge.level) return <div>No badge available</div>;
    
    return (
      <div style={{ backgroundColor: badge.color }}>
        User Level: {badge.level}
      </div>
    );
  };
  
  return (
    <div>
      <h1>User Profile</h1>
      <UserBadge />
    </div>
  );
}
// {/fact}