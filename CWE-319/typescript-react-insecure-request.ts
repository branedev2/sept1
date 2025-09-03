import React, { useState, useEffect } from 'react';
import axios from 'axios';
import fetch from 'node-fetch';

// True Positive Examples (Insecure HTTP Requests)

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_1() {
  useEffect(() => {
    // ruleid: typescript-react-insecure-request
    fetch('http://api.example.com/users')
      .then(response => response.json())
      .then(data => console.log(data))
      .catch(error => console.error('Error fetching data:', error));
  }, []);

  return <div>User Data</div>;
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_2() {
  const [data, setData] = useState(null);
  
  useEffect(() => {
    const fetchData = async () => {
      try {
        // ruleid: typescript-react-insecure-request
        const response = await axios.get('http://api.example.com/sensitive-data');
        setData(response.data);
      } catch (error) {
        console.error('Error:', error);
      }
    };
    
    fetchData();
  }, []);
  
  return <div>{data ? JSON.stringify(data) : 'Loading...'}</div>;
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_3() {
  const submitForm = (formData: any) => {
    // ruleid: typescript-react-insecure-request
    fetch('http://api.example.com/submit', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(formData),
    })
      .then(response => response.json())
      .then(data => console.log('Success:', data))
      .catch(error => console.error('Error:', error));
  };
  
  return <button onClick={() => submitForm({ username: 'user', password: 'pass' })}>Submit</button>;
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_4() {
  const [userData, setUserData] = useState(null);
  
  const fetchUserData = (userId: string) => {
    // ruleid: typescript-react-insecure-request
    const xhr = new XMLHttpRequest();
    xhr.open('GET', `http://api.example.com/users/${userId}`, true);
    xhr.onload = function() {
      if (xhr.status === 200) {
        setUserData(JSON.parse(xhr.responseText));
      }
    };
    xhr.send();
  };
  
  return <button onClick={() => fetchUserData('123')}>Get User</button>;
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_5() {
  const uploadFile = (file: File) => {
    const formData = new FormData();
    formData.append('file', file);
    
    // ruleid: typescript-react-insecure-request
    axios.post('http://upload.example.com/files', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    })
      .then(response => console.log('Upload successful'))
      .catch(error => console.error('Upload failed:', error));
  };
  
  return <input type="file" onChange={(e) => uploadFile(e.target.files![0])} />;
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_6() {
  const [config, setConfig] = useState(null);
  
  useEffect(() => {
    // ruleid: typescript-react-insecure-request
    const apiUrl = 'http://config.example.com/app-settings';
    fetch(apiUrl)
      .then(response => response.json())
      .then(data => setConfig(data))
      .catch(error => console.error('Error loading config:', error));
  }, []);
  
  return <div>Configuration: {JSON.stringify(config)}</div>;
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_7() {
  const authenticateUser = (credentials: { username: string, password: string }) => {
    // ruleid: typescript-react-insecure-request
    return axios.post('http://auth.example.com/login', credentials)
      .then(response => {
        localStorage.setItem('token', response.data.token);
        return response.data;
      })
      .catch(error => {
        console.error('Authentication failed:', error);
        throw error;
      });
  };
  
  return <button onClick={() => authenticateUser({ username: 'user', password: 'pass' })}>Login</button>;
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_8() {
  const [products, setProducts] = useState([]);
  
  const searchProducts = (query: string) => {
    // ruleid: typescript-react-insecure-request
    fetch(`http://products.example.com/search?q=${query}`)
      .then(response => response.json())
      .then(data => setProducts(data))
      .catch(error => console.error('Search failed:', error));
  };
  
  return (
    <div>
      <input type="text" onChange={(e) => searchProducts(e.target.value)} />
      <div>{products.length} products found</div>
    </div>
  );
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_9() {
  const sendAnalytics = (event: string, metadata: any) => {
    // ruleid: typescript-react-insecure-request
    navigator.sendBeacon('http://analytics.example.com/track', JSON.stringify({
      event,
      metadata,
      timestamp: new Date().toISOString()
    }));
  };
  
  return <button onClick={() => sendAnalytics('button_click', { page: 'home' })}>Track Click</button>;
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_10() {
  const [weather, setWeather] = useState(null);
  
  const getWeatherByLocation = (lat: number, lon: number) => {
    // ruleid: typescript-react-insecure-request
    axios.get(`http://weather.example.com/forecast?lat=${lat}&lon=${lon}`)
      .then(response => setWeather(response.data))
      .catch(error => console.error('Weather data fetch failed:', error));
  };
  
  return <button onClick={() => getWeatherByLocation(40.7128, -74.0060)}>Get Weather</button>;
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_11() {
  const loadScript = (url: string) => {
    const script = document.createElement('script');
    // ruleid: typescript-react-insecure-request
    script.src = `http://cdn.example.com/scripts/${url}.js`;
    document.body.appendChild(script);
  };
  
  return <button onClick={() => loadScript('analytics')}>Load Script</button>;
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_12() {
  const [image, setImage] = useState('');
  
  useEffect(() => {
    // ruleid: typescript-react-insecure-request
    setImage('http://images.example.com/profile/default.jpg');
  }, []);
  
  return <img src={image} alt="Profile" />;
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_13() {
  const [videoUrl, setVideoUrl] = useState('');
  
  const loadVideo = (videoId: string) => {
    // ruleid: typescript-react-insecure-request
    setVideoUrl(`http://videos.example.com/watch/${videoId}`);
  };
  
  return (
    <div>
      <button onClick={() => loadVideo('abc123')}>Load Video</button>
      {videoUrl && <video src={videoUrl} controls />}
    </div>
  );
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_14() {
  const subscribeToNewsletter = (email: string) => {
    const data = new URLSearchParams();
    data.append('email', email);
    
    // ruleid: typescript-react-insecure-request
    fetch('http://newsletter.example.com/subscribe', {
      method: 'POST',
      body: data,
    })
      .then(response => response.json())
      .then(result => console.log('Subscription successful'))
      .catch(error => console.error('Subscription failed:', error));
  };
  
  return (
    <form onSubmit={(e) => {
      e.preventDefault();
      const email = (e.target as HTMLFormElement).email.value;
      subscribeToNewsletter(email);
    }}>
      <input type="email" name="email" required />
      <button type="submit">Subscribe</button>
    </form>
  );
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_15() {
  const [mapData, setMapData] = useState(null);
  
  const loadMapData = () => {
    // ruleid: typescript-react-insecure-request
    const mapUrl = 'http://maps.example.com/api/locations';
    axios.get(mapUrl)
      .then(response => setMapData(response.data))
      .catch(error => console.error('Map data loading failed:', error));
  };
  
  return <button onClick={loadMapData}>Load Map Data</button>;
}
// {/fact}

// True Negative Examples (Secure HTTPS Requests)

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_1() {
  useEffect(() => {
    // ok: typescript-react-insecure-request
    fetch('https://api.example.com/users')
      .then(response => response.json())
      .then(data => console.log(data))
      .catch(error => console.error('Error fetching data:', error));
  }, []);

  return <div>User Data</div>;
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_2() {
  const [data, setData] = useState(null);
  
  useEffect(() => {
    const fetchData = async () => {
      try {
        // ok: typescript-react-insecure-request
        const response = await axios.get('https://api.example.com/sensitive-data');
        setData(response.data);
      } catch (error) {
        console.error('Error:', error);
      }
    };
    
    fetchData();
  }, []);
  
  return <div>{data ? JSON.stringify(data) : 'Loading...'}</div>;
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_3() {
  const submitForm = (formData: any) => {
    // ok: typescript-react-insecure-request
    fetch('https://api.example.com/submit', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(formData),
    })
      .then(response => response.json())
      .then(data => console.log('Success:', data))
      .catch(error => console.error('Error:', error));
  };
  
  return <button onClick={() => submitForm({ username: 'user', password: 'pass' })}>Submit</button>;
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_4() {
  const [userData, setUserData] = useState(null);
  
  const fetchUserData = (userId: string) => {
    // ok: typescript-react-insecure-request
    const xhr = new XMLHttpRequest();
    xhr.open('GET', `https://api.example.com/users/${userId}`, true);
    xhr.onload = function() {
      if (xhr.status === 200) {
        setUserData(JSON.parse(xhr.responseText));
      }
    };
    xhr.send();
  };
  
  return <button onClick={() => fetchUserData('123')}>Get User</button>;
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_5() {
  const uploadFile = (file: File) => {
    const formData = new FormData();
    formData.append('file', file);
    
    // ok: typescript-react-insecure-request
    axios.post('https://upload.example.com/files', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    })
      .then(response => console.log('Upload successful'))
      .catch(error => console.error('Upload failed:', error));
  };
  
  return <input type="file" onChange={(e) => uploadFile(e.target.files![0])} />;
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_6() {
  const [config, setConfig] = useState(null);
  
  useEffect(() => {
    // ok: typescript-react-insecure-request
    const apiUrl = 'https://config.example.com/app-settings';
    fetch(apiUrl)
      .then(response => response.json())
      .then(data => setConfig(data))
      .catch(error => console.error('Error loading config:', error));
  }, []);
  
  return <div>Configuration: {JSON.stringify(config)}</div>;
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_7() {
  const authenticateUser = (credentials: { username: string, password: string }) => {
    // ok: typescript-react-insecure-request
    return axios.post('https://auth.example.com/login', credentials)
      .then(response => {
        localStorage.setItem('token', response.data.token);
        return response.data;
      })
      .catch(error => {
        console.error('Authentication failed:', error);
        throw error;
      });
  };
  
  return <button onClick={() => authenticateUser({ username: 'user', password: 'pass' })}>Login</button>;
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_8() {
  const [products, setProducts] = useState([]);
  
  const searchProducts = (query: string) => {
    // ok: typescript-react-insecure-request
    fetch(`https://products.example.com/search?q=${query}`)
      .then(response => response.json())
      .then(data => setProducts(data))
      .catch(error => console.error('Search failed:', error));
  };
  
  return (
    <div>
      <input type="text" onChange={(e) => searchProducts(e.target.value)} />
      <div>{products.length} products found</div>
    </div>
  );
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_9() {
  const sendAnalytics = (event: string, metadata: any) => {
    // ok: typescript-react-insecure-request
    navigator.sendBeacon('https://analytics.example.com/track', JSON.stringify({
      event,
      metadata,
      timestamp: new Date().toISOString()
    }));
  };
  
  return <button onClick={() => sendAnalytics('button_click', { page: 'home' })}>Track Click</button>;
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_10() {
  const [weather, setWeather] = useState(null);
  
  const getWeatherByLocation = (lat: number, lon: number) => {
    // ok: typescript-react-insecure-request
    axios.get(`https://weather.example.com/forecast?lat=${lat}&lon=${lon}`)
      .then(response => setWeather(response.data))
      .catch(error => console.error('Weather data fetch failed:', error));
  };
  
  return <button onClick={() => getWeatherByLocation(40.7128, -74.0060)}>Get Weather</button>;
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_11() {
  const loadScript = (url: string) => {
    const script = document.createElement('script');
    // ok: typescript-react-insecure-request
    script.src = `https://cdn.example.com/scripts/${url}.js`;
    document.body.appendChild(script);
  };
  
  return <button onClick={() => loadScript('analytics')}>Load Script</button>;
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_12() {
  const [image, setImage] = useState('');
  
  useEffect(() => {
    // ok: typescript-react-insecure-request
    setImage('https://images.example.com/profile/default.jpg');
  }, []);
  
  return <img src={image} alt="Profile" />;
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_13() {
  const [videoUrl, setVideoUrl] = useState('');
  
  const loadVideo = (videoId: string) => {
    // ok: typescript-react-insecure-request
    setVideoUrl(`https://videos.example.com/watch/${videoId}`);
  };
  
  return (
    <div>
      <button onClick={() => loadVideo('abc123')}>Load Video</button>
      {videoUrl && <video src={videoUrl} controls />}
    </div>
  );
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_14() {
  const subscribeToNewsletter = (email: string) => {
    const data = new URLSearchParams();
    data.append('email', email);
    
    // ok: typescript-react-insecure-request
    fetch('https://newsletter.example.com/subscribe', {
      method: 'POST',
      body: data,
    })
      .then(response => response.json())
      .then(result => console.log('Subscription successful'))
      .catch(error => console.error('Subscription failed:', error));
  };
  
  return (
    <form onSubmit={(e) => {
      e.preventDefault();
      const email = (e.target as HTMLFormElement).email.value;
      subscribeToNewsletter(email);
    }}>
      <input type="email" name="email" required />
      <button type="submit">Subscribe</button>
    </form>
  );
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_15() {
  const [mapData, setMapData] = useState(null);
  
  const loadMapData = () => {
    // ok: typescript-react-insecure-request
    const mapUrl = 'https://maps.example.com/api/locations';
    axios.get(mapUrl)
      .then(response => setMapData(response.data))
      .catch(error => console.error('Map data loading failed:', error));
  };
  
  return <button onClick={loadMapData}>Load Map Data</button>;
}
// {/fact}