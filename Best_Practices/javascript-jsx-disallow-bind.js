// React performance test cases for javascript-jsx-disallow-bind rule

import React, { useState, useEffect, useCallback, useMemo } from 'react';

// TRUE POSITIVES (Bad cases that should be detected)

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_1() {
  class Button extends React.Component {
    render() {
      // ruleid: javascript-jsx-disallow-bind
      return <button onClick={this.handleClick.bind(this)}>Click me</button>;
    }
    
    handleClick() {
      console.log('Button clicked');
    }
  }
  
  return <Button />;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_2() {
  class TodoList extends React.Component {
    render() {
      return (
        <ul>
          {this.props.items.map((item) => (
            // ruleid: javascript-jsx-disallow-bind
            <li key={item.id} onClick={this.handleItemClick.bind(this, item.id)}>
              {item.text}
            </li>
          ))}
        </ul>
      );
    }
    
    handleItemClick(id) {
      console.log('Item clicked:', id);
    }
  }
  
  return <TodoList items={[{id: 1, text: 'Item 1'}, {id: 2, text: 'Item 2'}]} />;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_3() {
  function ParentComponent() {
    const [count, setCount] = useState(0);
    
    return (
      <div>
        <p>Count: {count}</p>
        {/* ruleid: javascript-jsx-disallow-bind */}
        <ChildComponent onIncrement={() => setCount(count + 1)} />
      </div>
    );
  }
  
  function ChildComponent({ onIncrement }) {
    return <button onClick={onIncrement}>Increment</button>;
  }
  
  return <ParentComponent />;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_4() {
  class Form extends React.Component {
    constructor(props) {
      super(props);
      this.state = { value: '' };
    }
    
    render() {
      return (
        <form>
          {/* ruleid: javascript-jsx-disallow-bind */}
          <input 
            type="text" 
            value={this.state.value} 
            onChange={(e) => this.setState({ value: e.target.value })} 
          />
        </form>
      );
    }
  }
  
  return <Form />;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_5() {
  function SearchComponent() {
    const [query, setQuery] = useState('');
    const [results, setResults] = useState([]);
    
    return (
      <div>
        {/* ruleid: javascript-jsx-disallow-bind */}
        <input 
          value={query} 
          onChange={(e) => {
            setQuery(e.target.value);
            fetchResults(e.target.value);
          }} 
        />
        <ul>
          {results.map(result => <li key={result.id}>{result.name}</li>)}
        </ul>
      </div>
    );
  }
  
  function fetchResults(query) {
    // Fetch logic here
  }
  
  return <SearchComponent />;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_6() {
  class Tabs extends React.Component {
    constructor(props) {
      super(props);
      this.state = { activeTab: 0 };
    }
    
    render() {
      return (
        <div>
          {this.props.tabs.map((tab, index) => (
            // ruleid: javascript-jsx-disallow-bind
            <button 
              key={index} 
              onClick={this.setActiveTab.bind(this, index)}
              className={this.state.activeTab === index ? 'active' : ''}
            >
              {tab.title}
            </button>
          ))}
        </div>
      );
    }
    
    setActiveTab(index) {
      this.setState({ activeTab: index });
    }
  }
  
  return <Tabs tabs={[{title: 'Tab 1'}, {title: 'Tab 2'}]} />;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_7() {
  function FilterableList() {
    const [filter, setFilter] = useState('');
    const items = ['Apple', 'Banana', 'Cherry', 'Date'];
    
    return (
      <div>
        {/* ruleid: javascript-jsx-disallow-bind */}
        <input type="text" onChange={(e) => setFilter(e.target.value)} />
        <ul>
          {items
            .filter(item => item.toLowerCase().includes(filter.toLowerCase()))
            .map(item => <li key={item}>{item}</li>)
          }
        </ul>
      </div>
    );
  }
  
  return <FilterableList />;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_8() {
  class Dropdown extends React.Component {
    constructor(props) {
      super(props);
      this.state = { isOpen: false };
    }
    
    render() {
      return (
        <div>
          {/* ruleid: javascript-jsx-disallow-bind */}
          <button onClick={() => this.setState(state => ({ isOpen: !state.isOpen }))}>
            Toggle
          </button>
          {this.state.isOpen && (
            <ul>
              {this.props.options.map(option => (
                <li key={option.value}>{option.label}</li>
              ))}
            </ul>
          )}
        </div>
      );
    }
  }
  
  return <Dropdown options={[{value: 1, label: 'Option 1'}, {value: 2, label: 'Option 2'}]} />;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_9() {
  function Counter() {
    const [count, setCount] = useState(0);
    
    return (
      <div>
        <p>Count: {count}</p>
        {/* ruleid: javascript-jsx-disallow-bind */}
        <button onClick={() => setCount(count + 1)}>Increment</button>
        {/* ruleid: javascript-jsx-disallow-bind */}
        <button onClick={() => setCount(count - 1)}>Decrement</button>
      </div>
    );
  }
  
  return <Counter />;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_10() {
  class DataTable extends React.Component {
    render() {
      return (
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {this.props.data.map(row => (
              <tr key={row.id}>
                <td>{row.name}</td>
                <td>
                  {/* ruleid: javascript-jsx-disallow-bind */}
                  <button onClick={this.handleEdit.bind(this, row.id)}>Edit</button>
                  {/* ruleid: javascript-jsx-disallow-bind */}
                  <button onClick={this.handleDelete.bind(this, row.id)}>Delete</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      );
    }
    
    handleEdit(id) {
      console.log('Edit', id);
    }
    
    handleDelete(id) {
      console.log('Delete', id);
    }
  }
  
  return <DataTable data={[{id: 1, name: 'Item 1'}, {id: 2, name: 'Item 2'}]} />;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_11() {
  function FormWithValidation() {
    const [email, setEmail] = useState('');
    const [error, setError] = useState('');
    
    return (
      <form>
        <div>
          <label>Email:</label>
          {/* ruleid: javascript-jsx-disallow-bind */}
          <input 
            type="email" 
            value={email} 
            onChange={(e) => {
              setEmail(e.target.value);
              if (!e.target.value.includes('@')) {
                setError('Invalid email');
              } else {
                setError('');
              }
            }} 
          />
          {error && <p className="error">{error}</p>}
        </div>
      </form>
    );
  }
  
  return <FormWithValidation />;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_12() {
  class Accordion extends React.Component {
    constructor(props) {
      super(props);
      this.state = { expandedIndex: null };
    }
    
    render() {
      return (
        <div>
          {this.props.items.map((item, index) => (
            <div key={index}>
              {/* ruleid: javascript-jsx-disallow-bind */}
              <h3 onClick={() => {
                this.setState(state => ({
                  expandedIndex: state.expandedIndex === index ? null : index
                }));
              }}>
                {item.title}
              </h3>
              {this.state.expandedIndex === index && (
                <div>{item.content}</div>
              )}
            </div>
          ))}
        </div>
      );
    }
  }
  
  return <Accordion items={[{title: 'Section 1', content: 'Content 1'}, {title: 'Section 2', content: 'Content 2'}]} />;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_13() {
  function ColorPicker() {
    const [color, setColor] = useState('#000000');
    const colors = ['#ff0000', '#00ff00', '#0000ff', '#ffff00', '#ff00ff'];
    
    return (
      <div>
        <div style={{ backgroundColor: color, width: 50, height: 50 }}></div>
        <div>
          {colors.map(c => (
            // ruleid: javascript-jsx-disallow-bind
            <button 
              key={c} 
              style={{ backgroundColor: c, width: 20, height: 20 }}
              onClick={() => setColor(c)}
            />
          ))}
        </div>
      </div>
    );
  }
  
  return <ColorPicker />;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_14() {
  class FileUploader extends React.Component {
    constructor(props) {
      super(props);
      this.state = { files: [] };
    }
    
    render() {
      return (
        <div>
          {/* ruleid: javascript-jsx-disallow-bind */}
          <input 
            type="file" 
            multiple 
            onChange={(e) => {
              this.setState({ files: Array.from(e.target.files) });
            }} 
          />
          <ul>
            {this.state.files.map((file, index) => (
              <li key={index}>{file.name}</li>
            ))}
          </ul>
        </div>
      );
    }
  }
  
  return <FileUploader />;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_15() {
  function Pagination() {
    const [currentPage, setCurrentPage] = useState(1);
    const totalPages = 10;
    
    const pages = [];
    for (let i = 1; i <= totalPages; i++) {
      pages.push(i);
    }
    
    return (
      <div>
        <ul className="pagination">
          {pages.map(page => (
            // ruleid: javascript-jsx-disallow-bind
            <li 
              key={page} 
              className={currentPage === page ? 'active' : ''}
              onClick={() => setCurrentPage(page)}
            >
              {page}
            </li>
          ))}
        </ul>
      </div>
    );
  }
  
  return <Pagination />;
}
// {/fact}

// TRUE NEGATIVES (Good cases that should not be detected)

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_1() {
  class Button extends React.Component {
    constructor(props) {
      super(props);
      this.handleClick = this.handleClick.bind(this);
    }
    
    render() {
      // ok: javascript-jsx-disallow-bind
      return <button onClick={this.handleClick}>Click me</button>;
    }
    
    handleClick() {
      console.log('Button clicked');
    }
  }
  
  return <Button />;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_2() {
  class TodoList extends React.Component {
    constructor(props) {
      super(props);
      this.handleItemClick = this.handleItemClick.bind(this);
    }
    
    render() {
      return (
        <ul>
          {this.props.items.map((item) => {
            // Create a bound function outside of render
            const handleClick = () => this.handleItemClick(item.id);
            
            // ok: javascript-jsx-disallow-bind
            return <li key={item.id} onClick={handleClick}>{item.text}</li>;
          })}
        </ul>
      );
    }
    
    handleItemClick(id) {
      console.log('Item clicked:', id);
    }
  }
  
  return <TodoList items={[{id: 1, text: 'Item 1'}, {id: 2, text: 'Item 2'}]} />;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_3() {
  function ParentComponent() {
    const [count, setCount] = useState(0);
    
    // Define the callback outside of render
    const handleIncrement = useCallback(() => {
      setCount(prevCount => prevCount + 1);
    }, []);
    
    return (
      <div>
        <p>Count: {count}</p>
        {/* ok: javascript-jsx-disallow-bind */}
        <ChildComponent onIncrement={handleIncrement} />
      </div>
    );
  }
  
  function ChildComponent({ onIncrement }) {
    return <button onClick={onIncrement}>Increment</button>;
  }
  
  return <ParentComponent />;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_4() {
  class Form extends React.Component {
    constructor(props) {
      super(props);
      this.state = { value: '' };
      this.handleChange = this.handleChange.bind(this);
    }
    
    handleChange(e) {
      this.setState({ value: e.target.value });
    }
    
    render() {
      return (
        <form>
          {/* ok: javascript-jsx-disallow-bind */}
          <input 
            type="text" 
            value={this.state.value} 
            onChange={this.handleChange} 
          />
        </form>
      );
    }
  }
  
  return <Form />;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_5() {
  function SearchComponent() {
    const [query, setQuery] = useState('');
    const [results, setResults] = useState([]);
    
    const handleQueryChange = useCallback((e) => {
      const newQuery = e.target.value;
      setQuery(newQuery);
      fetchResults(newQuery);
    }, []);
    
    return (
      <div>
        {/* ok: javascript-jsx-disallow-bind */}
        <input value={query} onChange={handleQueryChange} />
        <ul>
          {results.map(result => <li key={result.id}>{result.name}</li>)}
        </ul>
      </div>
    );
  }
  
  function fetchResults(query) {
    // Fetch logic here
  }
  
  return <SearchComponent />;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_6() {
  class Tabs extends React.Component {
    constructor(props) {
      super(props);
      this.state = { activeTab: 0 };
      this.renderTab = this.renderTab.bind(this);
    }
    
    setActiveTab(index) {
      this.setState({ activeTab: index });
    }
    
    renderTab(tab, index) {
      // Create a bound handler outside of render
      const handleClick = () => this.setActiveTab(index);
      
      // ok: javascript-jsx-disallow-bind
      return (
        <button 
          key={index} 
          onClick={handleClick}
          className={this.state.activeTab === index ? 'active' : ''}
        >
          {tab.title}
        </button>
      );
    }
    
    render() {
      return (
        <div>
          {this.props.tabs.map(this.renderTab)}
        </div>
      );
    }
  }
  
  return <Tabs tabs={[{title: 'Tab 1'}, {title: 'Tab 2'}]} />;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_7() {
  function FilterableList() {
    const [filter, setFilter] = useState('');
    const items = ['Apple', 'Banana', 'Cherry', 'Date'];
    
    const handleFilterChange = useCallback((e) => {
      setFilter(e.target.value);
    }, []);
    
    return (
      <div>
        {/* ok: javascript-jsx-disallow-bind */}
        <input type="text" onChange={handleFilterChange} />
        <ul>
          {items
            .filter(item => item.toLowerCase().includes(filter.toLowerCase()))
            .map(item => <li key={item}>{item}</li>)
          }
        </ul>
      </div>
    );
  }
  
  return <FilterableList />;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_8() {
  class Dropdown extends React.Component {
    constructor(props) {
      super(props);
      this.state = { isOpen: false };
      this.toggleDropdown = this.toggleDropdown.bind(this);
    }
    
    toggleDropdown() {
      this.setState(state => ({ isOpen: !state.isOpen }));
    }
    
    render() {
      return (
        <div>
          {/* ok: javascript-jsx-disallow-bind */}
          <button onClick={this.toggleDropdown}>
            Toggle
          </button>
          {this.state.isOpen && (
            <ul>
              {this.props.options.map(option => (
                <li key={option.value}>{option.label}</li>
              ))}
            </ul>
          )}
        </div>
      );
    }
  }
  
  return <Dropdown options={[{value: 1, label: 'Option 1'}, {value: 2, label: 'Option 2'}]} />;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_9() {
  function Counter() {
    const [count, setCount] = useState(0);
    
    const increment = useCallback(() => setCount(c => c + 1), []);
    const decrement = useCallback(() => setCount(c => c - 1), []);
    
    return (
      <div>
        <p>Count: {count}</p>
        {/* ok: javascript-jsx-disallow-bind */}
        <button onClick={increment}>Increment</button>
        {/* ok: javascript-jsx-disallow-bind */}
        <button onClick={decrement}>Decrement</button>
      </div>
    );
  }
  
  return <Counter />;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_10() {
  class DataTable extends React.Component {
    constructor(props) {
      super(props);
      this.handleEdit = this.handleEdit.bind(this);
      this.handleDelete = this.handleDelete.bind(this);
      this.renderRow = this.renderRow.bind(this);
    }
    
    handleEdit(id) {
      console.log('Edit', id);
    }
    
    handleDelete(id) {
      console.log('Delete', id);
    }
    
    renderRow(row) {
      // Create bound handlers outside of render
      const onEdit = () => this.handleEdit(row.id);
      const onDelete = () => this.handleDelete(row.id);
      
      return (
        <tr key={row.id}>
          <td>{row.name}</td>
          <td>
            {/* ok: javascript-jsx-disallow-bind */}
            <button onClick={onEdit}>Edit</button>
            {/* ok: javascript-jsx-disallow-bind */}
            <button onClick={onDelete}>Delete</button>
          </td>
        </tr>
      );
    }
    
    render() {
      return (
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {this.props.data.map(this.renderRow)}
          </tbody>
        </table>
      );
    }
  }
  
  return <DataTable data={[{id: 1, name: 'Item 1'}, {id: 2, name: 'Item 2'}]} />;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_11() {
  function FormWithValidation() {
    const [email, setEmail] = useState('');
    const [error, setError] = useState('');
    
    const validateEmail = useCallback((value) => {
      return value.includes('@') ? '' : 'Invalid email';
    }, []);
    
    const handleEmailChange = useCallback((e) => {
      const newEmail = e.target.value;
      setEmail(newEmail);
      setError(validateEmail(newEmail));
    }, [validateEmail]);
    
    return (
      <form>
        <div>
          <label>Email:</label>
          {/* ok: javascript-jsx-disallow-bind */}
          <input 
            type="email" 
            value={email} 
            onChange={handleEmailChange} 
          />
          {error && <p className="error">{error}</p>}
        </div>
      </form>
    );
  }
  
  return <FormWithValidation />;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_12() {
  class Accordion extends React.Component {
    constructor(props) {
      super(props);
      this.state = { expandedIndex: null };
      this.renderItem = this.renderItem.bind(this);
    }
    
    toggleItem(index) {
      this.setState(state => ({
        expandedIndex: state.expandedIndex === index ? null : index
      }));
    }
    
    renderItem(item, index) {
      // Create a bound handler outside of render
      const toggleThis = () => this.toggleItem(index);
      
      return (
        <div key={index}>
          {/* ok: javascript-jsx-disallow-bind */}
          <h3 onClick={toggleThis}>
            {item.title}
          </h3>
          {this.state.expandedIndex === index && (
            <div>{item.content}</div>
          )}
        </div>
      );
    }
    
    render() {
      return (
        <div>
          {this.props.items.map(this.renderItem)}
        </div>
      );
    }
  }
  
  return <Accordion items={[{title: 'Section 1', content: 'Content 1'}, {title: 'Section 2', content: 'Content 2'}]} />;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_13() {
  function ColorPicker() {
    const [color, setColor] = useState('#000000');
    const colors = ['#ff0000', '#00ff00', '#0000ff', '#ffff00', '#ff00ff'];
    
    // Create a memoized color selector factory
    const createColorSelector = useCallback(
      (c) => () => setColor(c),
      []
    );
    
    // Create button components with memoized handlers
    const colorButtons = useMemo(() => {
      return colors.map(c => {
        const handleClick = createColorSelector(c);
        
        return (
          // ok: javascript-jsx-disallow-bind
          <button 
            key={c} 
            style={{ backgroundColor: c, width: 20, height: 20 }}
            onClick={handleClick}
          />
        );
      });
    }, [colors, createColorSelector]);
    
    return (
      <div>
        <div style={{ backgroundColor: color, width: 50, height: 50 }}></div>
        <div>
          {colorButtons}
        </div>
      </div>
    );
  }
  
  return <ColorPicker />;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_14() {
  class FileUploader extends React.Component {
    constructor(props) {
      super(props);
      this.state = { files: [] };
      this.handleFileChange = this.handleFileChange.bind(this);
    }
    
    handleFileChange(e) {
      this.setState({ files: Array.from(e.target.files) });
    }
    
    render() {
      return (
        <div>
          {/* ok: javascript-jsx-disallow-bind */}
          <input 
            type="file" 
            multiple 
            onChange={this.handleFileChange} 
          />
          <ul>
            {this.state.files.map((file, index) => (
              <li key={index}>{file.name}</li>
            ))}
          </ul>
        </div>
      );
    }
  }
  
  return <FileUploader />;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_15() {
  function Pagination() {
    const [currentPage, setCurrentPage] = useState(1);
    const totalPages = 10;
    
    // Create a memoized page selector factory
    const createPageSelector = useCallback(
      (page) => () => setCurrentPage(page),
      []
    );
    
    // Generate an array of page numbers
    const pages = [];
    for (let i = 1; i <= totalPages; i++) {
      pages.push(i);
    }
    
    // Create pagination items with memoized handlers
    const paginationItems = useMemo(() => {
      return pages.map(page => {
        const handleClick = createPageSelector(page);
        
        return (
          // ok: javascript-jsx-disallow-bind
          <li 
            key={page} 
            className={currentPage === page ? 'active' : ''}
            onClick={handleClick}
          >
            {page}
          </li>
        );
      });
    }, [pages, currentPage, createPageSelector]);
    
    return (
      <div>
        <ul className="pagination">
          {paginationItems}
        </ul>
      </div>
    );
  }
  
  return <Pagination />;
}
// {/fact}