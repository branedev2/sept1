// React performance test cases for bind and arrow functions in JSX attributes
import React, { useState, useEffect, Component } from 'react';
import ReactDOM from 'react-dom';

// BAD CASES - Using bind in JSX attributes

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_1() {
  class ClickCounter extends Component {
    constructor(props) {
      super(props);
      this.state = { count: 0 };
      this.handleClick = this.handleClick.bind(this);
    }
    
    handleClick() {
      this.setState({ count: this.state.count + 1 });
    }
    
    render() {
      return (
        // ruleid: javascript-jsx-disallow-bind
        <button onClick={this.handleClick.bind(this)}>
          Clicked {this.state.count} times
        </button>
      );
    }
  }
  
  return <ClickCounter />;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_2() {
  class TodoList extends Component {
    constructor(props) {
      super(props);
      this.state = { todos: ['Buy milk', 'Clean house'] };
    }
    
    deleteTodo(index) {
      const newTodos = [...this.state.todos];
      newTodos.splice(index, 1);
      this.setState({ todos: newTodos });
    }
    
    render() {
      return (
        <ul>
          {this.state.todos.map((todo, index) => (
            <li key={index}>
              {todo}
              {/* ruleid: javascript-jsx-disallow-bind */}
              <button onClick={this.deleteTodo.bind(this, index)}>Delete</button>
            </li>
          ))}
        </ul>
      );
    }
  }
  
  return <TodoList />;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_3() {
  const FormComponent = () => {
    const [value, setValue] = useState('');
    
    const handleChange = (event) => {
      setValue(event.target.value);
    };
    
    const handleSubmit = (event) => {
      event.preventDefault();
      console.log('Submitted:', value);
    };
    
    return (
      <form>
        {/* ruleid: javascript-jsx-disallow-bind */}
        <input type="text" value={value} onChange={handleChange.bind(this)} />
        {/* ruleid: javascript-jsx-disallow-bind */}
        <button onClick={handleSubmit.bind(this)}>Submit</button>
      </form>
    );
  };
  
  return <FormComponent />;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_4() {
  class DataTable extends Component {
    constructor(props) {
      super(props);
      this.state = {
        data: [
          { id: 1, name: 'John' },
          { id: 2, name: 'Jane' }
        ],
        sortOrder: 'asc'
      };
    }
    
    sortData(column) {
      const newOrder = this.state.sortOrder === 'asc' ? 'desc' : 'asc';
      this.setState({ sortOrder: newOrder });
    }
    
    render() {
      return (
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th 
                // ruleid: javascript-jsx-disallow-bind
                onClick={this.sortData.bind(this, 'id')}
              >
                Name
              </th>
            </tr>
          </thead>
          <tbody>
            {this.state.data.map(item => (
              <tr key={item.id}>
                <td>{item.id}</td>
                <td>{item.name}</td>
              </tr>
            ))}
          </tbody>
        </table>
      );
    }
  }
  
  return <DataTable />;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_5() {
  class Accordion extends Component {
    constructor(props) {
      super(props);
      this.state = { activePanel: null };
    }
    
    togglePanel(panelId) {
      this.setState({ 
        activePanel: this.state.activePanel === panelId ? null : panelId 
      });
    }
    
    render() {
      const panels = [
        { id: 1, title: 'Panel 1', content: 'Content 1' },
        { id: 2, title: 'Panel 2', content: 'Content 2' }
      ];
      
      return (
        <div className="accordion">
          {panels.map(panel => (
            <div key={panel.id}>
              <h3 
                // ruleid: javascript-jsx-disallow-bind
                onClick={this.togglePanel.bind(this, panel.id)}
              >
                {panel.title}
              </h3>
              {this.state.activePanel === panel.id && (
                <div>{panel.content}</div>
              )}
            </div>
          ))}
        </div>
      );
    }
  }
  
  return <Accordion />;
}
// {/fact}

// BAD CASES - Using arrow functions in JSX attributes

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_6() {
  const Counter = () => {
    const [count, setCount] = useState(0);
    
    return (
      // ruleid: javascript-jsx-disallow-bind
      <button onClick={() => setCount(count + 1)}>
        Clicked {count} times
      </button>
    );
  };
  
  return <Counter />;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_7() {
  const TodoList = () => {
    const [todos, setTodos] = useState(['Buy milk', 'Clean house']);
    
    return (
      <ul>
        {todos.map((todo, index) => (
          <li key={index}>
            {todo}
            {/* ruleid: javascript-jsx-disallow-bind */}
            <button onClick={() => {
              const newTodos = [...todos];
              newTodos.splice(index, 1);
              setTodos(newTodos);
            }}>
              Delete
            </button>
          </li>
        ))}
      </ul>
    );
  };
  
  return <TodoList />;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_8() {
  const FormComponent = () => {
    const [formData, setFormData] = useState({ name: '', email: '' });
    
    return (
      <form>
        <input
          type="text"
          value={formData.name}
          // ruleid: javascript-jsx-disallow-bind
          onChange={(e) => setFormData({...formData, name: e.target.value})}
        />
        <input
          type="email"
          value={formData.email}
          // ruleid: javascript-jsx-disallow-bind
          onChange={(e) => setFormData({...formData, email: e.target.value})}
        />
      </form>
    );
  };
  
  return <FormComponent />;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_9() {
  const TabPanel = () => {
    const [activeTab, setActiveTab] = useState(0);
    const tabs = ['Tab 1', 'Tab 2', 'Tab 3'];
    
    return (
      <div>
        <div className="tabs">
          {tabs.map((tab, index) => (
            <button
              key={index}
              // ruleid: javascript-jsx-disallow-bind
              onClick={() => setActiveTab(index)}
            >
              {tab}
            </button>
          ))}
        </div>
        <div className="content">
          Content for {tabs[activeTab]}
        </div>
      </div>
    );
  };
  
  return <TabPanel />;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_10() {
  const FilterableList = () => {
    const [filter, setFilter] = useState('');
    const items = ['Apple', 'Banana', 'Cherry', 'Date', 'Elderberry'];
    
    const filteredItems = items.filter(item => 
      item.toLowerCase().includes(filter.toLowerCase())
    );
    
    return (
      <div>
        <input
          type="text"
          placeholder="Filter items..."
          // ruleid: javascript-jsx-disallow-bind
          onChange={(e) => setFilter(e.target.value)}
        />
        <ul>
          {filteredItems.map((item, index) => (
            <li key={index}>{item}</li>
          ))}
        </ul>
      </div>
    );
  };
  
  return <FilterableList />;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_11() {
  class ModalComponent extends Component {
    constructor(props) {
      super(props);
      this.state = { isOpen: false };
    }
    
    render() {
      return (
        <div>
          {/* ruleid: javascript-jsx-disallow-bind */}
          <button onClick={() => this.setState({ isOpen: true })}>
            Open Modal
          </button>
          
          {this.state.isOpen && (
            <div className="modal">
              <h2>Modal Title</h2>
              <p>Modal content goes here</p>
              {/* ruleid: javascript-jsx-disallow-bind */}
              <button onClick={() => this.setState({ isOpen: false })}>
                Close
              </button>
            </div>
          )}
        </div>
      );
    }
  }
  
  return <ModalComponent />;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_12() {
  const ShoppingCart = () => {
    const [cart, setCart] = useState([
      { id: 1, name: 'Product 1', quantity: 1 },
      { id: 2, name: 'Product 2', quantity: 2 }
    ]);
    
    return (
      <div>
        <h2>Shopping Cart</h2>
        <ul>
          {cart.map(item => (
            <li key={item.id}>
              {item.name} - Quantity: {item.quantity}
              {/* ruleid: javascript-jsx-disallow-bind */}
              <button onClick={() => {
                setCart(cart.map(cartItem => 
                  cartItem.id === item.id 
                    ? { ...cartItem, quantity: cartItem.quantity + 1 } 
                    : cartItem
                ));
              }}>+</button>
              {/* ruleid: javascript-jsx-disallow-bind */}
              <button onClick={() => {
                setCart(cart.map(cartItem => 
                  cartItem.id === item.id 
                    ? { ...cartItem, quantity: Math.max(0, cartItem.quantity - 1) } 
                    : cartItem
                ));
              }}>-</button>
            </li>
          ))}
        </ul>
      </div>
    );
  };
  
  return <ShoppingCart />;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_13() {
  const ColorPicker = () => {
    const [selectedColor, setSelectedColor] = useState('#ff0000');
    const colors = ['#ff0000', '#00ff00', '#0000ff', '#ffff00', '#ff00ff'];
    
    return (
      <div>
        <div>
          {colors.map(color => (
            <div
              key={color}
              style={{ 
                backgroundColor: color, 
                width: '30px', 
                height: '30px', 
                display: 'inline-block',
                margin: '5px',
                border: color === selectedColor ? '2px solid black' : 'none'
              }}
              // ruleid: javascript-jsx-disallow-bind
              onClick={() => setSelectedColor(color)}
            />
          ))}
        </div>
        <div>Selected color: {selectedColor}</div>
      </div>
    );
  };
  
  return <ColorPicker />;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_14() {
  const SearchComponent = () => {
    const [query, setQuery] = useState('');
    const [results, setResults] = useState([]);
    
    useEffect(() => {
      if (query.length > 2) {
        // Simulate API call
        const mockResults = ['Result 1', 'Result 2', 'Result 3'].filter(
          r => r.toLowerCase().includes(query.toLowerCase())
        );
        setResults(mockResults);
      } else {
        setResults([]);
      }
    }, [query]);
    
    return (
      <div>
        <input
          type="text"
          placeholder="Search..."
          value={query}
          // ruleid: javascript-jsx-disallow-bind
          onChange={(e) => setQuery(e.target.value)}
        />
        <ul>
          {results.map((result, index) => (
            <li key={index}>{result}</li>
          ))}
        </ul>
      </div>
    );
  };
  
  return <SearchComponent />;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_15() {
  const RatingComponent = () => {
    const [rating, setRating] = useState(0);
    const maxStars = 5;
    
    return (
      <div>
        <div>
          {[...Array(maxStars)].map((_, index) => {
            const starValue = index + 1;
            return (
              <span
                key={index}
                style={{ cursor: 'pointer', fontSize: '24px' }}
                // ruleid: javascript-jsx-disallow-bind
                onClick={() => setRating(starValue)}
                // ruleid: javascript-jsx-disallow-bind
                onMouseEnter={() => console.log(`Hovering over ${starValue} stars`)}
              >
                {starValue <= rating ? '★' : '☆'}
              </span>
            );
          })}
        </div>
        <div>Your rating: {rating} stars</div>
      </div>
    );
  };
  
  return <RatingComponent />;
}
// {/fact}

// GOOD CASES - Properly handling function references in JSX

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_1() {
  class ClickCounter extends Component {
    constructor(props) {
      super(props);
      this.state = { count: 0 };
      this.handleClick = this.handleClick.bind(this);
    }
    
    handleClick() {
      this.setState({ count: this.state.count + 1 });
    }
    
    render() {
      return (
        // ok: javascript-jsx-disallow-bind
        <button onClick={this.handleClick}>
          Clicked {this.state.count} times
        </button>
      );
    }
  }
  
  return <ClickCounter />;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_2() {
  class TodoList extends Component {
    constructor(props) {
      super(props);
      this.state = { todos: ['Buy milk', 'Clean house'] };
      this.deleteTodo = this.deleteTodo.bind(this);
    }
    
    deleteTodo(index) {
      const newTodos = [...this.state.todos];
      newTodos.splice(index, 1);
      this.setState({ todos: newTodos });
    }
    
    renderTodoItem(todo, index) {
      // Create bound handler in constructor or component methods, not in render
      const deleteHandler = () => this.deleteTodo(index);
      
      return (
        <li key={index}>
          {todo}
          {/* ok: javascript-jsx-disallow-bind */}
          <button onClick={deleteHandler}>Delete</button>
        </li>
      );
    }
    
    render() {
      return (
        <ul>
          {this.state.todos.map((todo, index) => 
            this.renderTodoItem(todo, index)
          )}
        </ul>
      );
    }
  }
  
  return <TodoList />;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_3() {
  const FormComponent = () => {
    const [value, setValue] = useState('');
    
    // Define handlers outside of render
    const handleChange = (event) => {
      setValue(event.target.value);
    };
    
    const handleSubmit = (event) => {
      event.preventDefault();
      console.log('Submitted:', value);
    };
    
    return (
      <form>
        {/* ok: javascript-jsx-disallow-bind */}
        <input type="text" value={value} onChange={handleChange} />
        {/* ok: javascript-jsx-disallow-bind */}
        <button onClick={handleSubmit}>Submit</button>
      </form>
    );
  };
  
  return <FormComponent />;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_4() {
  class DataTable extends Component {
    constructor(props) {
      super(props);
      this.state = {
        data: [
          { id: 1, name: 'John' },
          { id: 2, name: 'Jane' }
        ],
        sortOrder: 'asc'
      };
      
      // Pre-bind methods in constructor
      this.sortById = this.sortData.bind(this, 'id');
      this.sortByName = this.sortData.bind(this, 'name');
    }
    
    sortData(column) {
      const newOrder = this.state.sortOrder === 'asc' ? 'desc' : 'asc';
      this.setState({ sortOrder: newOrder });
    }
    
    render() {
      return (
        <table>
          <thead>
            <tr>
              <th 
                // ok: javascript-jsx-disallow-bind
                onClick={this.sortById}
              >
                ID
              </th>
              <th 
                // ok: javascript-jsx-disallow-bind
                onClick={this.sortByName}
              >
                Name
              </th>
            </tr>
          </thead>
          <tbody>
            {this.state.data.map(item => (
              <tr key={item.id}>
                <td>{item.id}</td>
                <td>{item.name}</td>
              </tr>
            ))}
          </tbody>
        </table>
      );
    }
  }
  
  return <DataTable />;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_5() {
  class Accordion extends Component {
    constructor(props) {
      super(props);
      this.state = { activePanel: null };
      this.togglePanelFactory = this.togglePanelFactory.bind(this);
    }
    
    // Factory method to create panel toggler functions
    togglePanelFactory(panelId) {
      return () => {
        this.setState({ 
          activePanel: this.state.activePanel === panelId ? null : panelId 
        });
      };
    }
    
    render() {
      const panels = [
        { id: 1, title: 'Panel 1', content: 'Content 1' },
        { id: 2, title: 'Panel 2', content: 'Content 2' }
      ];
      
      return (
        <div className="accordion">
          {panels.map(panel => {
            // Create handler outside JSX
            const toggleHandler = this.togglePanelFactory(panel.id);
            
            return (
              <div key={panel.id}>
                <h3 
                  // ok: javascript-jsx-disallow-bind
                  onClick={toggleHandler}
                >
                  {panel.title}
                </h3>
                {this.state.activePanel === panel.id && (
                  <div>{panel.content}</div>
                )}
              </div>
            );
          })}
        </div>
      );
    }
  }
  
  return <Accordion />;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_6() {
  const Counter = () => {
    const [count, setCount] = useState(0);
    
    // Define handler outside of render
    const incrementCount = useCallback(() => {
      setCount(prevCount => prevCount + 1);
    }, []);
    
    return (
      // ok: javascript-jsx-disallow-bind
      <button onClick={incrementCount}>
        Clicked {count} times
      </button>
    );
  };
  
  return <Counter />;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_7() {
  const TodoList = () => {
    const [todos, setTodos] = useState(['Buy milk', 'Clean house']);
    
    // Create a memoized handler factory
    const createDeleteHandler = useCallback((index) => {
      return () => {
        const newTodos = [...todos];
        newTodos.splice(index, 1);
        setTodos(newTodos);
      };
    }, [todos]);
    
    return (
      <ul>
        {todos.map((todo, index) => {
          // Create handler outside JSX
          const deleteHandler = createDeleteHandler(index);
          
          return (
            <li key={index}>
              {todo}
              {/* ok: javascript-jsx-disallow-bind */}
              <button onClick={deleteHandler}>Delete</button>
            </li>
          );
        })}
      </ul>
    );
  };
  
  return <TodoList />;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_8() {
  const FormComponent = () => {
    const [formData, setFormData] = useState({ name: '', email: '' });
    
    // Create a single handler for all form fields
    const handleInputChange = useCallback((e) => {
      const { name, value } = e.target;
      setFormData(prev => ({...prev, [name]: value}));
    }, []);
    
    return (
      <form>
        <input
          type="text"
          name="name"
          value={formData.name}
          // ok: javascript-jsx-disallow-bind
          onChange={handleInputChange}
        />
        <input
          type="email"
          name="email"
          value={formData.email}
          // ok: javascript-jsx-disallow-bind
          onChange={handleInputChange}
        />
      </form>
    );
  };
  
  return <FormComponent />;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_9() {
  const TabPanel = () => {
    const [activeTab, setActiveTab] = useState(0);
    const tabs = ['Tab 1', 'Tab 2', 'Tab 3'];
    
    // Create a memoized handler factory
    const handleTabClick = useCallback((index) => () => {
      setActiveTab(index);
    }, []);
    
    return (
      <div>
        <div className="tabs">
          {tabs.map((tab, index) => {
            // Create handler outside JSX
            const clickHandler = handleTabClick(index);
            
            return (
              <button
                key={index}
                // ok: javascript-jsx-disallow-bind
                onClick={clickHandler}
              >
                {tab}
              </button>
            );
          })}
        </div>
        <div className="content">
          Content for {tabs[activeTab]}
        </div>
      </div>
    );
  };
  
  return <TabPanel />;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_10() {
  const FilterableList = () => {
    const [filter, setFilter] = useState('');
    const items = ['Apple', 'Banana', 'Cherry', 'Date', 'Elderberry'];
    
    // Define handler outside of render
    const handleFilterChange = useCallback((e) => {
      setFilter(e.target.value);
    }, []);
    
    const filteredItems = useMemo(() => {
      return items.filter(item => 
        item.toLowerCase().includes(filter.toLowerCase())
      );
    }, [filter, items]);
    
    return (
      <div>
        <input
          type="text"
          placeholder="Filter items..."
          // ok: javascript-jsx-disallow-bind
          onChange={handleFilterChange}
        />
        <ul>
          {filteredItems.map((item, index) => (
            <li key={index}>{item}</li>
          ))}
        </ul>
      </div>
    );
  };
  
  return <FilterableList />;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_11() {
  class ModalComponent extends Component {
    constructor(props) {
      super(props);
      this.state = { isOpen: false };
      this.openModal = this.openModal.bind(this);
      this.closeModal = this.closeModal.bind(this);
    }
    
    openModal() {
      this.setState({ isOpen: true });
    }
    
    closeModal() {
      this.setState({ isOpen: false });
    }
    
    render() {
      return (
        <div>
          {/* ok: javascript-jsx-disallow-bind */}
          <button onClick={this.openModal}>
            Open Modal
          </button>
          
          {this.state.isOpen && (
            <div className="modal">
              <h2>Modal Title</h2>
              <p>Modal content goes here</p>
              {/* ok: javascript-jsx-disallow-bind */}
              <button onClick={this.closeModal}>
                Close
              </button>
            </div>
          )}
        </div>
      );
    }
  }
  
  return <ModalComponent />;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_12() {
  const ShoppingCart = () => {
    const [cart, setCart] = useState([
      { id: 1, name: 'Product 1', quantity: 1 },
      { id: 2, name: 'Product 2', quantity: 2 }
    ]);
    
    // Create memoized handlers
    const increaseQuantity = useCallback((id) => () => {
      setCart(prevCart => prevCart.map(item => 
        item.id === id 
          ? { ...item, quantity: item.quantity + 1 } 
          : item
      ));
    }, []);
    
    const decreaseQuantity = useCallback((id) => () => {
      setCart(prevCart => prevCart.map(item => 
        item.id === id 
          ? { ...item, quantity: Math.max(0, item.quantity - 1) } 
          : item
      ));
    }, []);
    
    return (
      <div>
        <h2>Shopping Cart</h2>
        <ul>
          {cart.map(item => {
            // Create handlers outside JSX
            const handleIncrease = increaseQuantity(item.id);
            const handleDecrease = decreaseQuantity(item.id);
            
            return (
              <li key={item.id}>
                {item.name} - Quantity: {item.quantity}
                {/* ok: javascript-jsx-disallow-bind */}
                <button onClick={handleIncrease}>+</button>
                {/* ok: javascript-jsx-disallow-bind */}
                <button onClick={handleDecrease}>-</button>
              </li>
            );
          })}
        </ul>
      </div>
    );
  };
  
  return <ShoppingCart />;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_13() {
  const ColorPicker = () => {
    const [selectedColor, setSelectedColor] = useState('#ff0000');
    const colors = ['#ff0000', '#00ff00', '#0000ff', '#ffff00', '#ff00ff'];
    
    // Create a memoized handler factory
    const handleColorSelect = useCallback((color) => () => {
      setSelectedColor(color);
    }, []);
    
    return (
      <div>
        <div>
          {colors.map(color => {
            // Create handler outside JSX
            const selectHandler = handleColorSelect(color);
            
            return (
              <div
                key={color}
                style={{ 
                  backgroundColor: color, 
                  width: '30px', 
                  height: '30px', 
                  display: 'inline-block',
                  margin: '5px',
                  border: color === selectedColor ? '2px solid black' : 'none'
                }}
                // ok: javascript-jsx-disallow-bind
                onClick={selectHandler}
              />
            );
          })}
        </div>
        <div>Selected color: {selectedColor}</div>
      </div>
    );
  };
  
  return <ColorPicker />;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_14() {
  const SearchComponent = () => {
    const [query, setQuery] = useState('');
    const [results, setResults] = useState([]);
    
    // Define handler outside of render
    const handleQueryChange = useCallback((e) => {
      setQuery(e.target.value);
    }, []);
    
    useEffect(() => {
      if (query.length > 2) {
        // Simulate API call
        const mockResults = ['Result 1', 'Result 2', 'Result 3'].filter(
          r => r.toLowerCase().includes(query.toLowerCase())
        );
        setResults(mockResults);
      } else {
        setResults([]);
      }
    }, [query]);
    
    return (
      <div>
        <input
          type="text"
          placeholder="Search..."
          value={query}
          // ok: javascript-jsx-disallow-bind
          onChange={handleQueryChange}
        />
        <ul>
          {results.map((result, index) => (
            <li key={index}>{result}</li>
          ))}
        </ul>
      </div>
    );
  };
  
  return <SearchComponent />;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_15() {
  const RatingComponent = () => {
    const [rating, setRating] = useState(0);
    const maxStars = 5;
    
    // Create memoized handlers
    const handleStarClick = useCallback((value) => () => {
      setRating(value);
    }, []);
    
    const handleStarHover = useCallback((value) => () => {
      console.log(`Hovering over ${value} stars`);
    }, []);
    
    return (
      <div>
        <div>
          {[...Array(maxStars)].map((_, index) => {
            const starValue = index + 1;
            // Create handlers outside JSX
            const clickHandler = handleStarClick(starValue);
            const hoverHandler = handleStarHover(starValue);
            
            return (
              <span
                key={index}
                style={{ cursor: 'pointer', fontSize: '24px' }}
                // ok: javascript-jsx-disallow-bind
                onClick={clickHandler}
                // ok: javascript-jsx-disallow-bind
                onMouseEnter={hoverHandler}
              >
                {starValue <= rating ? '★' : '☆'}
              </span>
            );
          })}
        </div>
        <div>Your rating: {rating} stars</div>
      </div>
    );
  };
  
  return <RatingComponent />;
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