// File: insecure_request_test_cases.tsx
import React, { useState, useEffect } from 'react';
import axios from 'axios';
import fetch from 'node-fetch';
import { XMLHttpRequest } from 'xmlhttprequest';

// TRUE POSITIVES (Vulnerable code examples)

// Example 1: Using fetch with HTTP URL
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_1() {
  useEffect(() => {
    const fetchData = async () => {
      try {
        // ruleid: typescript-react-insecure-request
        const response = await fetch('http://api.example.com/users');
        const data = await response.json();
        console.log(data);
      } catch (error) {
        console.error('Error fetching data:', error);
      }
    };
    
    fetchData();
  }, []);
  
  return <div>Loading data...</div>;
}
// {/fact}

// Example 2: Using axios with HTTP URL
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_2() {
  const [data, setData] = useState(null);
  
  useEffect(() => {
    // ruleid: typescript-react-insecure-request
    axios.get('http://api.example.com/products')
      .then(response => {
        setData(response.data);
      })
      .catch(error => {
        console.error('Error:', error);
      });
  }, []);
  
  return <div>{data ? JSON.stringify(data) : 'Loading...'}</div>;
}
// {/fact}

// Example 3: Using XMLHttpRequest with HTTP URL
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_3() {
  useEffect(() => {
    const xhr = new XMLHttpRequest();
    // ruleid: typescript-react-insecure-request
    xhr.open('GET', 'http://api.example.com/data', true);
    xhr.onload = () => {
      if (xhr.status === 200) {
        console.log(JSON.parse(xhr.responseText));
      }
    };
    xhr.send();
  }, []);
  
  return <div>Loading XMLHttpRequest data...</div>;
}
// {/fact}

// Example 4: Using fetch POST with HTTP URL and sensitive data
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_4() {
  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    const username = (document.getElementById('username') as HTMLInputElement).value;
    const password = (document.getElementById('password') as HTMLInputElement).value;
    
    try {
      // ruleid: typescript-react-insecure-request
      const response = await fetch('http://auth.example.com/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username, password }),
      });
      const data = await response.json();
      console.log(data);
    } catch (error) {
      console.error('Login failed:', error);
    }
  };
  
  return (
    <form onSubmit={handleSubmit}>
      <input id="username" type="text" placeholder="Username" />
      <input id="password" type="password" placeholder="Password" />
      <button type="submit">Login</button>
    </form>
  );
}
// {/fact}

// Example 5: Using axios PUT with HTTP URL
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_5() {
  const updateUser = async (userId: string, userData: any) => {
    try {
      // ruleid: typescript-react-insecure-request
      const response = await axios.put(`http://api.example.com/users/${userId}`, userData);
      return response.data;
    } catch (error) {
      console.error('Update failed:', error);
      return null;
    }
  };
  
  const handleUpdate = () => {
    updateUser('123', { name: 'John Doe', email: 'john@example.com' });
  };
  
  return <button onClick={handleUpdate}>Update User</button>;
}
// {/fact}

// Example 6: Using fetch with template literal HTTP URL
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_6() {
  const [userId, setUserId] = useState('123');
  
  useEffect(() => {
    const fetchUserData = async () => {
      // ruleid: typescript-react-insecure-request
      const response = await fetch(`http://api.example.com/users/${userId}`);
      const userData = await response.json();
      console.log(userData);
    };
    
    fetchUserData();
  }, [userId]);
  
  return <div>User ID: {userId}</div>;
}
// {/fact}

// Example 7: Using axios with HTTP URL in a custom hook
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_7() {
  const useDataFetching = (url: string) => {
    const [data, setData] = useState(null);
    const [loading, setLoading] = useState(true);
    
    useEffect(() => {
      const fetchData = async () => {
        try {
          // ruleid: typescript-react-insecure-request
          const response = await axios.get(url);
          setData(response.data);
        } catch (error) {
          console.error('Error fetching data:', error);
        } finally {
          setLoading(false);
        }
      };
      
      fetchData();
    }, [url]);
    
    return { data, loading };
  };
  
  const { data, loading } = useDataFetching('http://api.example.com/stats');
  
  return (
    <div>
      {loading ? 'Loading...' : JSON.stringify(data)}
    </div>
  );
}
// {/fact}

// Example 8: Using fetch with HTTP URL in an event handler
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_8() {
  const handleButtonClick = async () => {
    try {
      // ruleid: typescript-react-insecure-request
      const response = await fetch('http://api.example.com/trigger-action');
      const result = await response.json();
      alert(`Action result: ${result.status}`);
    } catch (error) {
      console.error('Action failed:', error);
    }
  };
  
  return <button onClick={handleButtonClick}>Trigger Action</button>;
}
// {/fact}

// Example 9: Using axios DELETE with HTTP URL
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_9() {
  const deleteResource = async (resourceId: string) => {
    try {
      // ruleid: typescript-react-insecure-request
      await axios.delete(`http://api.example.com/resources/${resourceId}`);
      return true;
    } catch (error) {
      console.error('Delete failed:', error);
      return false;
    }
  };
  
  const handleDelete = () => {
    deleteResource('resource-456');
  };
  
  return <button onClick={handleDelete}>Delete Resource</button>;
}
// {/fact}

// Example 10: Using fetch with HTTP URL and conditional logic
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_10() {
  const [shouldFetch, setShouldFetch] = useState(false);
  
  useEffect(() => {
    if (shouldFetch) {
      const fetchData = async () => {
        try {
          // ruleid: typescript-react-insecure-request
          const response = await fetch('http://api.example.com/conditional-data');
          const data = await response.json();
          console.log(data);
        } catch (error) {
          console.error('Fetch error:', error);
        }
      };
      
      fetchData();
    }
  }, [shouldFetch]);
  
  return <button onClick={() => setShouldFetch(true)}>Load Data</button>;
}
// {/fact}

// Example 11: Using axios with HTTP URL in a class component
class BadCase11 extends React.Component {
  componentDidMount() {
    // ruleid: typescript-react-insecure-request
    axios.get('http://api.example.com/class-component-data')
      .then(response => {
        this.setState({ data: response.data });
      })
      .catch(error => {
        console.error('Error in class component:', error);
      });
  }
  
  render() {
    return <div>Class Component Example</div>;
  }
}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_11() {
  return <BadCase11 />;
}
// {/fact}

// Example 12: Using fetch with HTTP URL and error boundary
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_12() {
  const fetchWithErrorHandling = async () => {
    try {
      // ruleid: typescript-react-insecure-request
      const response = await fetch('http://api.example.com/error-prone-endpoint');
      if (!response.ok) {
        throw new Error(`HTTP error! Status: ${response.status}`);
      }
      const data = await response.json();
      return data;
    } catch (error) {
      console.error('Advanced error handling:', error);
      throw error; // Re-throw for the error boundary
    }
  };
  
  useEffect(() => {
    fetchWithErrorHandling().catch(err => console.log('Caught by effect:', err));
  }, []);
  
  return <div>Error Boundary Example</div>;
}
// {/fact}

// Example 13: Using axios with HTTP URL and interceptors
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_13() {
  useEffect(() => {
    // Add request interceptor
    const requestInterceptor = axios.interceptors.request.use(
      config => {
        config.headers['Authorization'] = `Bearer token123`;
        return config;
      },
      error => {
        return Promise.reject(error);
      }
    );
    
    // Make the request
    // ruleid: typescript-react-insecure-request
    axios.get('http://api.example.com/protected-resource')
      .then(response => {
        console.log('Protected data:', response.data);
      })
      .catch(error => {
        console.error('Protected request failed:', error);
      });
    
    // Clean up
    return () => {
      axios.interceptors.request.eject(requestInterceptor);
    };
  }, []);
  
  return <div>Axios Interceptors Example</div>;
}
// {/fact}

// Example 14: Using fetch with HTTP URL in an async component
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_14() {
  const AsyncComponent = async () => {
    // ruleid: typescript-react-insecure-request
    const response = await fetch('http://api.example.com/async-data');
    const data = await response.json();
    return <div>{JSON.stringify(data)}</div>;
  };
  
  return <div>Async Component Wrapper</div>;
}
// {/fact}

// Example 15: Using axios with HTTP URL and query parameters
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_15() {
  const [searchTerm, setSearchTerm] = useState('');
  
  const handleSearch = async () => {
    try {
      // ruleid: typescript-react-insecure-request
      const response = await axios.get('http://api.example.com/search', {
        params: {
          q: searchTerm,
          limit: 10,
          sort: 'relevance'
        }
      });
      console.log('Search results:', response.data);
    } catch (error) {
      console.error('Search failed:', error);
    }
  };
  
  return (
    <div>
      <input 
        type="text" 
        value={searchTerm} 
        onChange={e => setSearchTerm(e.target.value)} 
      />
      <button onClick={handleSearch}>Search</button>
    </div>
  );
}
// {/fact}

// TRUE NEGATIVES (Secure code examples)

// Example 1: Using fetch with HTTPS URL
// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_1() {
  useEffect(() => {
    const fetchData = async () => {
      try {
        // ok: typescript-react-insecure-request
        const response = await fetch('https://api.example.com/users');
        const data = await response.json();
        console.log(data);
      } catch (error) {
        console.error('Error fetching data:', error);
      }
    };
    
    fetchData();
  }, []);
  
  return <div>Loading data securely...</div>;
}
// {/fact}

// Example 2: Using axios with HTTPS URL
// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_2() {
  const [data, setData] = useState(null);
  
  useEffect(() => {
    // ok: typescript-react-insecure-request
    axios.get('https://api.example.com/products')
      .then(response => {
        setData(response.data);
      })
      .catch(error => {
        console.error('Error:', error);
      });
  }, []);
  
  return <div>{data ? JSON.stringify(data) : 'Loading...'}</div>;
}
// {/fact}

// Example 3: Using XMLHttpRequest with HTTPS URL
// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_3() {
  useEffect(() => {
    const xhr = new XMLHttpRequest();
    // ok: typescript-react-insecure-request
    xhr.open('GET', 'https://api.example.com/data', true);
    xhr.onload = () => {
      if (xhr.status === 200) {
        console.log(JSON.parse(xhr.responseText));
      }
    };
    xhr.send();
  }, []);
  
  return <div>Loading XMLHttpRequest data securely...</div>;
}
// {/fact}

// Example 4: Using fetch POST with HTTPS URL and sensitive data
// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_4() {
  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    const username = (document.getElementById('username') as HTMLInputElement).value;
    const password = (document.getElementById('password') as HTMLInputElement).value;
    
    try {
      // ok: typescript-react-insecure-request
      const response = await fetch('https://auth.example.com/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username, password }),
      });
      const data = await response.json();
      console.log(data);
    } catch (error) {
      console.error('Login failed:', error);
    }
  };
  
  return (
    <form onSubmit={handleSubmit}>
      <input id="username" type="text" placeholder="Username" />
      <input id="password" type="password" placeholder="Password" />
      <button type="submit">Login</button>
    </form>
  );
}
// {/fact}

// Example 5: Using axios PUT with HTTPS URL
// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_5() {
  const updateUser = async (userId: string, userData: any) => {
    try {
      // ok: typescript-react-insecure-request
      const response = await axios.put(`https://api.example.com/users/${userId}`, userData);
      return response.data;
    } catch (error) {
      console.error('Update failed:', error);
      return null;
    }
  };
  
  const handleUpdate = () => {
    updateUser('123', { name: 'John Doe', email: 'john@example.com' });
  };
  
  return <button onClick={handleUpdate}>Update User</button>;
}
// {/fact}

// Example 6: Using fetch with relative URL (which inherits the protocol of the page)
// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_6() {
  useEffect(() => {
    const fetchData = async () => {
      try {
        // ok: typescript-react-insecure-request
        const response = await fetch('/api/data');
        const data = await response.json();
        console.log(data);
      } catch (error) {
        console.error('Error fetching data:', error);
      }
    };
    
    fetchData();
  }, []);
  
  return <div>Loading data with relative URL...</div>;
}
// {/fact}

// Example 7: Using axios with environment variable for base URL
// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_7() {
  const API_BASE_URL = process.env.REACT_APP_API_URL || 'https://api.example.com';
  
  useEffect(() => {
    const fetchData = async () => {
      try {
        // ok: typescript-react-insecure-request
        const response = await axios.get(`${API_BASE_URL}/data`);
        console.log(response.data);
      } catch (error) {
        console.error('Error:', error);
      }
    };
    
    fetchData();
  }, []);
  
  return <div>Loading with environment variable URL...</div>;
}
// {/fact}

// Example 8: Using fetch with HTTPS URL in an event handler
// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_8() {
  const handleButtonClick = async () => {
    try {
      // ok: typescript-react-insecure-request
      const response = await fetch('https://api.example.com/trigger-action');
      const result = await response.json();
      alert(`Action result: ${result.status}`);
    } catch (error) {
      console.error('Action failed:', error);
    }
  };
  
  return <button onClick={handleButtonClick}>Trigger Secure Action</button>;
}
// {/fact}

// Example 9: Using axios DELETE with HTTPS URL
// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_9() {
  const deleteResource = async (resourceId: string) => {
    try {
      // ok: typescript-react-insecure-request
      await axios.delete(`https://api.example.com/resources/${resourceId}`);
      return true;
    } catch (error) {
      console.error('Delete failed:', error);
      return false;
    }
  };
  
  const handleDelete = () => {
    deleteResource('resource-456');
  };
  
  return <button onClick={handleDelete}>Delete Resource Securely</button>;
}
// {/fact}

// Example 10: Using fetch with protocol-relative URL
// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_10() {
  useEffect(() => {
    const fetchData = async () => {
      try {
        // ok: typescript-react-insecure-request
        const response = await fetch('//api.example.com/data');
        const data = await response.json();
        console.log(data);
      } catch (error) {
        console.error('Error fetching data:', error);
      }
    };
    
    fetchData();
  }, []);
  
  return <div>Loading with protocol-relative URL...</div>;
}
// {/fact}

// Example 11: Using axios with HTTPS URL in a class component
class GoodCase11 extends React.Component {
  componentDidMount() {
    // ok: typescript-react-insecure-request
    axios.get('https://api.example.com/class-component-data')
      .then(response => {
        this.setState({ data: response.data });
      })
      .catch(error => {
        console.error('Error in class component:', error);
      });
  }
  
  render() {
    return <div>Secure Class Component Example</div>;
  }
}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_11() {
  return <GoodCase11 />;
}
// {/fact}

// Example 12: Using fetch with dynamic URL that enforces HTTPS
// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_12() {
  const [endpoint, setEndpoint] = useState('users');
  
  const getSecureUrl = (path: string) => {
    return `https://api.example.com/${path}`;
  };
  
  useEffect(() => {
    const fetchData = async () => {
      try {
        // ok: typescript-react-insecure-request
        const response = await fetch(getSecureUrl(endpoint));
        const data = await response.json();
        console.log(data);
      } catch (error) {
        console.error('Error fetching data:', error);
      }
    };
    
    fetchData();
  }, [endpoint]);
  
  return <div>Loading secure dynamic URL...</div>;
}
// {/fact}

// Example 13: Using axios with HTTPS URL and interceptors
// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_13() {
  useEffect(() => {
    // Add request interceptor
    const requestInterceptor = axios.interceptors.request.use(
      config => {
        config.headers['Authorization'] = `Bearer token123`;
        return config;
      },
      error => {
        return Promise.reject(error);
      }
    );
    
    // Make the request
    // ok: typescript-react-insecure-request
    axios.get('https://api.example.com/protected-resource')
      .then(response => {
        console.log('Protected data:', response.data);
      })
      .catch(error => {
        console.error('Protected request failed:', error);
      });
    
    // Clean up
    return () => {
      axios.interceptors.request.eject(requestInterceptor);
    };
  }, []);
  
  return <div>Secure Axios Interceptors Example</div>;
}
// {/fact}

// Example 14: Using fetch with URL object that enforces HTTPS
// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_14() {
  useEffect(() => {
    const fetchData = async () => {
      try {
        const url = new URL('/api/data', 'https://example.com');
        // ok: typescript-react-insecure-request
        const response = await fetch(url);
        const data = await response.json();
        console.log(data);
      } catch (error) {
        console.error('Error fetching data:', error);
      }
    };
    
    fetchData();
  }, []);
  
  return <div>Loading with URL object...</div>;
}
// {/fact}

// Example 15: Using axios with HTTPS URL and query parameters
// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_15() {
  const [searchTerm, setSearchTerm] = useState('');
  
  const handleSearch = async () => {
    try {
      // ok: typescript-react-insecure-request
      const response = await axios.get('https://api.example.com/search', {
        params: {
          q: searchTerm,
          limit: 10,
          sort: 'relevance'
        }
      });
      console.log('Search results:', response.data);
    } catch (error) {
      console.error('Search failed:', error);
    }
  };
  
  return (
    <div>
      <input 
        type="text" 
        value={searchTerm} 
        onChange={e => setSearchTerm(e.target.value)} 
      />
      <button onClick={handleSearch}>Secure Search</button>
    </div>
  );
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