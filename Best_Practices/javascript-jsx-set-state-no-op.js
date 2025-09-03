// React state setter no-op vulnerability examples
import React, { useState, useEffect } from 'react';

// True Positive Examples (Vulnerable Code)

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_1() {
  const [count, setCount] = useState(0);
  
  const handleClick = () => {
    // ruleid: javascript-jsx-set-state-no-op
    setCount(count); // Directly passing current state value, which is a no-op
  };
  
  return (
    <button onClick={handleClick}>Click me</button>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_2() {
  const [user, setUser] = useState({ name: 'John', age: 30 });
  
  const updateUser = () => {
    // ruleid: javascript-jsx-set-state-no-op
    setUser(user); // Directly passing current state object, which is a no-op
  };
  
  return (
    <div onClick={updateUser}>Update User</div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_3() {
  const [items, setItems] = useState([1, 2, 3]);
  
  useEffect(() => {
    // ruleid: javascript-jsx-set-state-no-op
    setItems(items); // Setting state to itself in useEffect, potential infinite loop
  }, [items]);
  
  return <div>{items.join(', ')}</div>;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_4() {
  const [isActive, setIsActive] = useState(false);
  
  const toggleActive = () => {
    const currentState = isActive;
    // ruleid: javascript-jsx-set-state-no-op
    setIsActive(currentState); // Using a variable that holds the current state value
  };
  
  return <div onClick={toggleActive}>Toggle</div>;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_5() {
  const [settings, setSettings] = useState({ theme: 'dark', notifications: true });
  
  const saveSettings = () => {
    const currentSettings = {...settings};
    // ruleid: javascript-jsx-set-state-no-op
    setSettings(settings); // Even though we created a copy, we're still setting to the same value
  };
  
  return <button onClick={saveSettings}>Save</button>;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_6() {
  const [counter, setCounter] = useState(0);
  
  const resetCounter = () => {
    // ruleid: javascript-jsx-set-state-no-op
    setCounter(counter); // Attempting to "reset" by setting to current value
  };
  
  return (
    <div>
      <p>Count: {counter}</p>
      <button onClick={resetCounter}>Reset</button>
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_7() {
  const [selectedId, setSelectedId] = useState(null);
  
  const handleSelection = (id) => {
    if (id === selectedId) {
      // ruleid: javascript-jsx-set-state-no-op
      setSelectedId(selectedId); // Redundant state update when id matches current selection
    } else {
      setSelectedId(id);
    }
  };
  
  return <div onClick={() => handleSelection(1)}>Select Item</div>;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_8() {
  const [formData, setFormData] = useState({ name: '', email: '' });
  
  const handleSubmit = () => {
    // Validate form
    if (formData.name && formData.email) {
      // Submit form
    } else {
      // ruleid: javascript-jsx-set-state-no-op
      setFormData(formData); // Setting state to itself as a no-op
    }
  };
  
  return <button onClick={handleSubmit}>Submit</button>;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_9() {
  const [list, setList] = useState([]);
  
  useEffect(() => {
    const fetchData = async () => {
      try {
        const data = await fetch('/api/items').then(res => res.json());
        if (data.length === 0) {
          // ruleid: javascript-jsx-set-state-no-op
          setList(list); // Setting to current value when API returns empty
        } else {
          setList(data);
        }
      } catch (error) {
        console.error(error);
      }
    };
    
    fetchData();
  }, []);
  
  return <ul>{list.map(item => <li key={item.id}>{item.name}</li>)}</ul>;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_10() {
  const [config, setConfig] = useState({ apiKey: 'abc123', endpoint: '/api' });
  
  const updateConfig = (newEndpoint) => {
    if (!newEndpoint) {
      // ruleid: javascript-jsx-set-state-no-op
      setConfig(config); // No-op when no new endpoint is provided
    } else {
      setConfig({ ...config, endpoint: newEndpoint });
    }
  };
  
  return <button onClick={() => updateConfig()}>Update Config</button>;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_11() {
  const [value, setValue] = useState('');
  
  const handleChange = (e) => {
    const newValue = e.target.value;
    if (newValue === value) {
      // ruleid: javascript-jsx-set-state-no-op
      setValue(value); // Setting to current value when input hasn't changed
    } else {
      setValue(newValue);
    }
  };
  
  return <input value={value} onChange={handleChange} />;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_12() {
  const [filters, setFilters] = useState({ category: 'all', sort: 'newest' });
  
  const resetFilters = () => {
    const defaultFilters = { category: 'all', sort: 'newest' };
    if (filters.category === defaultFilters.category && filters.sort === defaultFilters.sort) {
      // ruleid: javascript-jsx-set-state-no-op
      setFilters(filters); // Setting to current value when already at defaults
    } else {
      setFilters(defaultFilters);
    }
  };
  
  return <button onClick={resetFilters}>Reset Filters</button>;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_13() {
  const [position, setPosition] = useState({ x: 0, y: 0 });
  
  const moveItem = (dx, dy) => {
    if (dx === 0 && dy === 0) {
      // ruleid: javascript-jsx-set-state-no-op
      setPosition(position); // No-op when no movement
    } else {
      setPosition({ x: position.x + dx, y: position.y + dy });
    }
  };
  
  return <div onClick={() => moveItem(0, 0)}>Move</div>;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_14() {
  const [isExpanded, setIsExpanded] = useState(false);
  
  const toggleExpand = () => {
    const shouldExpand = !isExpanded;
    if (shouldExpand === isExpanded) {
      // ruleid: javascript-jsx-set-state-no-op
      setIsExpanded(isExpanded); // This condition shouldn't happen logically, but demonstrates the issue
    } else {
      setIsExpanded(shouldExpand);
    }
  };
  
  return <div onClick={toggleExpand}>Toggle</div>;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_15() {
  const [cart, setCart] = useState([]);
  
  const addToCart = (product) => {
    if (!product) {
      // ruleid: javascript-jsx-set-state-no-op
      setCart(cart); // No-op when no product is provided
    } else {
      setCart([...cart, product]);
    }
  };
  
  return <button onClick={() => addToCart()}>Add to Cart</button>;
}
// {/fact}

// True Negative Examples (Safe Code)

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_1() {
  const [count, setCount] = useState(0);
  
  const handleClick = () => {
    // ok: javascript-jsx-set-state-no-op
    setCount(prevCount => prevCount); // Using functional update form
  };
  
  return (
    <button onClick={handleClick}>Click me</button>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_2() {
  const [user, setUser] = useState({ name: 'John', age: 30 });
  
  const updateUser = () => {
    // ok: javascript-jsx-set-state-no-op
    setUser(prevUser => ({ ...prevUser, age: prevUser.age + 1 })); // Updating based on previous state
  };
  
  return (
    <div onClick={updateUser}>Update User</div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_3() {
  const [items, setItems] = useState([1, 2, 3]);
  
  useEffect(() => {
    // ok: javascript-jsx-set-state-no-op
    setItems(prevItems => [...prevItems, 4]); // Adding item based on previous state
  }, []);
  
  return <div>{items.join(', ')}</div>;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_4() {
  const [isActive, setIsActive] = useState(false);
  
  const toggleActive = () => {
    // ok: javascript-jsx-set-state-no-op
    setIsActive(prevState => !prevState); // Toggling based on previous state
  };
  
  return <div onClick={toggleActive}>Toggle</div>;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_5() {
  const [settings, setSettings] = useState({ theme: 'dark', notifications: true });
  
  const toggleTheme = () => {
    // ok: javascript-jsx-set-state-no-op
    setSettings(prevSettings => ({
      ...prevSettings,
      theme: prevSettings.theme === 'dark' ? 'light' : 'dark'
    }));
  };
  
  return <button onClick={toggleTheme}>Toggle Theme</button>;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_6() {
  const [counter, setCounter] = useState(0);
  
  const resetCounter = () => {
    // ok: javascript-jsx-set-state-no-op
    setCounter(0); // Setting to a literal value, not the current state
  };
  
  return (
    <div>
      <p>Count: {counter}</p>
      <button onClick={resetCounter}>Reset</button>
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_7() {
  const [selectedId, setSelectedId] = useState(null);
  
  const handleSelection = (id) => {
    // ok: javascript-jsx-set-state-no-op
    setSelectedId(prevId => id === prevId ? null : id); // Toggle selection based on previous state
  };
  
  return <div onClick={() => handleSelection(1)}>Select Item</div>;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_8() {
  const [formData, setFormData] = useState({ name: '', email: '' });
  
  const handleChange = (e) => {
    const { name, value } = e.target;
    // ok: javascript-jsx-set-state-no-op
    setFormData(prevData => ({
      ...prevData,
      [name]: value
    }));
  };
  
  return (
    <input 
      name="name" 
      value={formData.name} 
      onChange={handleChange} 
    />
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_9() {
  const [list, setList] = useState([]);
  
  useEffect(() => {
    const fetchData = async () => {
      try {
        const data = await fetch('/api/items').then(res => res.json());
        // ok: javascript-jsx-set-state-no-op
        setList(data); // Setting to new data from API, not current state
      } catch (error) {
        console.error(error);
      }
    };
    
    fetchData();
  }, []);
  
  return <ul>{list.map(item => <li key={item.id}>{item.name}</li>)}</ul>;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_10() {
  const [config, setConfig] = useState({ apiKey: 'abc123', endpoint: '/api' });
  
  const updateConfig = (newEndpoint) => {
    if (!newEndpoint) {
      return; // Early return instead of no-op state update
    }
    // ok: javascript-jsx-set-state-no-op
    setConfig(prevConfig => ({
      ...prevConfig,
      endpoint: newEndpoint
    }));
  };
  
  return <button onClick={() => updateConfig('/new-api')}>Update Config</button>;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_11() {
  const [value, setValue] = useState('');
  
  const handleChange = (e) => {
    const newValue = e.target.value;
    if (newValue === value) {
      return; // Early return instead of no-op state update
    }
    // ok: javascript-jsx-set-state-no-op
    setValue(newValue); // Setting to new value, not current state
  };
  
  return <input value={value} onChange={handleChange} />;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_12() {
  const [filters, setFilters] = useState({ category: 'all', sort: 'newest' });
  
  const resetFilters = () => {
    const defaultFilters = { category: 'all', sort: 'newest' };
    // ok: javascript-jsx-set-state-no-op
    setFilters(defaultFilters); // Setting to literal object, not current state
  };
  
  return <button onClick={resetFilters}>Reset Filters</button>;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_13() {
  const [position, setPosition] = useState({ x: 0, y: 0 });
  
  const moveItem = (dx, dy) => {
    if (dx === 0 && dy === 0) {
      return; // Early return instead of no-op state update
    }
    // ok: javascript-jsx-set-state-no-op
    setPosition(prevPos => ({
      x: prevPos.x + dx,
      y: prevPos.y + dy
    }));
  };
  
  return <div onClick={() => moveItem(10, 20)}>Move</div>;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_14() {
  const [isExpanded, setIsExpanded] = useState(false);
  
  const toggleExpand = () => {
    // ok: javascript-jsx-set-state-no-op
    setIsExpanded(prevState => !prevState); // Toggle based on previous state
  };
  
  return <div onClick={toggleExpand}>Toggle</div>;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_15() {
  const [cart, setCart] = useState([]);
  
  const addToCart = (product) => {
    if (!product) {
      return; // Early return instead of no-op state update
    }
    // ok: javascript-jsx-set-state-no-op
    setCart(prevCart => [...prevCart, product]); // Adding to cart based on previous state
  };
  
  return <button onClick={() => addToCart({ id: 1, name: 'Product' })}>Add to Cart</button>;
}
// {/fact}