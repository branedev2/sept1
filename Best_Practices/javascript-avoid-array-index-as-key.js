// File: array_index_key_examples.js
import React, { useState, useEffect } from 'react';

// BAD EXAMPLES - Using array index as key

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_1() {
  const [users, setUsers] = useState([
    { name: 'John', id: 1 },
    { name: 'Mary', id: 2 },
    { name: 'Bob', id: 3 }
  ]);

  return (
    <div>
      <h2>User List</h2>
      <ul>
        {users.map((user, index) => (
          // ruleid: javascript-avoid-array-index-as-key
          <li key={index}>{user.name}</li>
        ))}
      </ul>
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_2() {
  const items = ['Apple', 'Banana', 'Cherry'];
  
  return (
    <div>
      {items.map((item, i) => (
        // ruleid: javascript-avoid-array-index-as-key
        <div key={i}>
          <span>{item}</span>
        </div>
      ))}
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_3() {
  const [data, setData] = useState([]);
  
  useEffect(() => {
    // Simulating API call
    setData(['Task 1', 'Task 2', 'Task 3']);
  }, []);
  
  return (
    <div>
      {data.map((task, idx) => (
        // ruleid: javascript-avoid-array-index-as-key
        <p key={idx}>{task}</p>
      ))}
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_4() {
  const products = [
    { name: 'Laptop', price: 999 },
    { name: 'Phone', price: 699 },
    { name: 'Tablet', price: 399 }
  ];
  
  return (
    <table>
      <tbody>
        {products.map((product, index) => (
          // ruleid: javascript-avoid-array-index-as-key
          <tr key={index}>
            <td>{product.name}</td>
            <td>${product.price}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_5() {
  const [comments, setComments] = useState([
    "Great article!",
    "Thanks for sharing",
    "I learned a lot"
  ]);
  
  return (
    <div className="comments-section">
      {comments.map((comment, i) => (
        // ruleid: javascript-avoid-array-index-as-key
        <div key={i} className="comment">
          {comment}
        </div>
      ))}
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_6() {
  const menuItems = ['Home', 'Products', 'About', 'Contact'];
  
  return (
    <nav>
      <ul>
        {menuItems.map((item, idx) => (
          // ruleid: javascript-avoid-array-index-as-key
          <li key={idx}>
            <a href={`/${item.toLowerCase()}`}>{item}</a>
          </li>
        ))}
      </ul>
    </nav>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_7() {
  const [notifications, setNotifications] = useState([
    "New message received",
    "Your order has shipped",
    "Payment successful"
  ]);
  
  return (
    <div className="notification-center">
      {notifications.map((notification, index) => (
        // ruleid: javascript-avoid-array-index-as-key
        <div key={`notification-${index}`} className="alert">
          {notification}
        </div>
      ))}
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_8() {
  const images = [
    'beach.jpg',
    'mountain.jpg',
    'forest.jpg'
  ];
  
  return (
    <div className="gallery">
      {images.map((src, i) => (
        // ruleid: javascript-avoid-array-index-as-key
        <img key={i} src={src} alt={`Image ${i+1}`} />
      ))}
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_9() {
  const tabs = ['Overview', 'Features', 'Pricing', 'Reviews'];
  
  return (
    <div className="tabs">
      {tabs.map((tab, idx) => (
        // ruleid: javascript-avoid-array-index-as-key
        <button key={idx} className="tab-button">
          {tab}
        </button>
      ))}
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_10() {
  const [formFields, setFormFields] = useState([
    { type: 'text', label: 'Name' },
    { type: 'email', label: 'Email' },
    { type: 'password', label: 'Password' }
  ]);
  
  return (
    <form>
      {formFields.map((field, index) => (
        // ruleid: javascript-avoid-array-index-as-key
        <div key={index} className="form-group">
          <label>{field.label}</label>
          <input type={field.type} />
        </div>
      ))}
    </form>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_11() {
  const [steps, setSteps] = useState([
    'Select product',
    'Add to cart',
    'Checkout',
    'Payment'
  ]);
  
  return (
    <div className="stepper">
      {steps.map((step, i) => (
        // ruleid: javascript-avoid-array-index-as-key
        <div key={i} className="step">
          <div className="step-number">{i + 1}</div>
          <div className="step-text">{step}</div>
        </div>
      ))}
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_12() {
  const [questions, setQuestions] = useState([
    "What is your name?",
    "What is your favorite color?",
    "What is your quest?"
  ]);
  
  return (
    <div className="quiz">
      {questions.map((question, index) => (
        // ruleid: javascript-avoid-array-index-as-key
        <div key={`q-${index}`} className="question-container">
          <p className="question">{question}</p>
          <input type="text" placeholder="Your answer" />
        </div>
      ))}
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_13() {
  const [cards, setCards] = useState([
    { title: 'Card 1', content: 'Content 1' },
    { title: 'Card 2', content: 'Content 2' },
    { title: 'Card 3', content: 'Content 3' }
  ]);
  
  return (
    <div className="card-grid">
      {cards.map((card, idx) => (
        // ruleid: javascript-avoid-array-index-as-key
        <div key={idx} className="card">
          <h3>{card.title}</h3>
          <p>{card.content}</p>
        </div>
      ))}
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_14() {
  const colors = ['red', 'green', 'blue', 'yellow', 'purple'];
  
  return (
    <div className="color-picker">
      {colors.map((color, i) => (
        // ruleid: javascript-avoid-array-index-as-key
        <div 
          key={i}
          className="color-swatch"
          style={{ backgroundColor: color }}
        />
      ))}
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_15() {
  const [todoItems, setTodoItems] = useState([
    { text: 'Buy groceries', completed: false },
    { text: 'Clean house', completed: true },
    { text: 'Walk dog', completed: false }
  ]);
  
  return (
    <ul className="todo-list">
      {todoItems.map((item, index) => (
        // ruleid: javascript-avoid-array-index-as-key
        <li key={index} className={item.completed ? 'completed' : ''}>
          <input type="checkbox" checked={item.completed} />
          <span>{item.text}</span>
        </li>
      ))}
    </ul>
  );
}
// {/fact}

// GOOD EXAMPLES - Using proper unique keys

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_1() {
  const [users, setUsers] = useState([
    { name: 'John', id: 1 },
    { name: 'Mary', id: 2 },
    { name: 'Bob', id: 3 }
  ]);

  return (
    <div>
      <h2>User List</h2>
      <ul>
        {users.map(user => (
          // ok: javascript-avoid-array-index-as-key
          <li key={user.id}>{user.name}</li>
        ))}
      </ul>
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_2() {
  const items = [
    { id: 'fruit-1', name: 'Apple' },
    { id: 'fruit-2', name: 'Banana' },
    { id: 'fruit-3', name: 'Cherry' }
  ];
  
  return (
    <div>
      {items.map(item => (
        // ok: javascript-avoid-array-index-as-key
        <div key={item.id}>
          <span>{item.name}</span>
        </div>
      ))}
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_3() {
  const [data, setData] = useState([]);
  
  useEffect(() => {
    // Simulating API call
    setData([
      { id: 't1', text: 'Task 1' },
      { id: 't2', text: 'Task 2' },
      { id: 't3', text: 'Task 3' }
    ]);
  }, []);
  
  return (
    <div>
      {data.map(task => (
        // ok: javascript-avoid-array-index-as-key
        <p key={task.id}>{task.text}</p>
      ))}
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_4() {
  const products = [
    { id: 'p1', name: 'Laptop', price: 999 },
    { id: 'p2', name: 'Phone', price: 699 },
    { id: 'p3', name: 'Tablet', price: 399 }
  ];
  
  return (
    <table>
      <tbody>
        {products.map(product => (
          // ok: javascript-avoid-array-index-as-key
          <tr key={product.id}>
            <td>{product.name}</td>
            <td>${product.price}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_5() {
  const [comments, setComments] = useState([
    { id: 'c1', text: "Great article!" },
    { id: 'c2', text: "Thanks for sharing" },
    { id: 'c3', text: "I learned a lot" }
  ]);
  
  return (
    <div className="comments-section">
      {comments.map(comment => (
        // ok: javascript-avoid-array-index-as-key
        <div key={comment.id} className="comment">
          {comment.text}
        </div>
      ))}
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_6() {
  const menuItems = [
    { id: 'menu-1', name: 'Home', path: '/home' },
    { id: 'menu-2', name: 'Products', path: '/products' },
    { id: 'menu-3', name: 'About', path: '/about' },
    { id: 'menu-4', name: 'Contact', path: '/contact' }
  ];
  
  return (
    <nav>
      <ul>
        {menuItems.map(item => (
          // ok: javascript-avoid-array-index-as-key
          <li key={item.id}>
            <a href={item.path}>{item.name}</a>
          </li>
        ))}
      </ul>
    </nav>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_7() {
  const [notifications, setNotifications] = useState([
    { id: 'n1', message: "New message received" },
    { id: 'n2', message: "Your order has shipped" },
    { id: 'n3', message: "Payment successful" }
  ]);
  
  return (
    <div className="notification-center">
      {notifications.map(notification => (
        // ok: javascript-avoid-array-index-as-key
        <div key={notification.id} className="alert">
          {notification.message}
        </div>
      ))}
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_8() {
  const images = [
    { id: 'img1', src: 'beach.jpg', alt: 'Beach scene' },
    { id: 'img2', src: 'mountain.jpg', alt: 'Mountain view' },
    { id: 'img3', src: 'forest.jpg', alt: 'Forest landscape' }
  ];
  
  return (
    <div className="gallery">
      {images.map(image => (
        // ok: javascript-avoid-array-index-as-key
        <img key={image.id} src={image.src} alt={image.alt} />
      ))}
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_9() {
  const tabs = [
    { id: 'tab1', label: 'Overview' },
    { id: 'tab2', label: 'Features' },
    { id: 'tab3', label: 'Pricing' },
    { id: 'tab4', label: 'Reviews' }
  ];
  
  return (
    <div className="tabs">
      {tabs.map(tab => (
        // ok: javascript-avoid-array-index-as-key
        <button key={tab.id} className="tab-button">
          {tab.label}
        </button>
      ))}
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_10() {
  const [formFields, setFormFields] = useState([
    { id: 'field1', type: 'text', label: 'Name' },
    { id: 'field2', type: 'email', label: 'Email' },
    { id: 'field3', type: 'password', label: 'Password' }
  ]);
  
  return (
    <form>
      {formFields.map(field => (
        // ok: javascript-avoid-array-index-as-key
        <div key={field.id} className="form-group">
          <label>{field.label}</label>
          <input type={field.type} />
        </div>
      ))}
    </form>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_11() {
  const [steps, setSteps] = useState([
    { id: 'step1', text: 'Select product' },
    { id: 'step2', text: 'Add to cart' },
    { id: 'step3', text: 'Checkout' },
    { id: 'step4', text: 'Payment' }
  ]);
  
  return (
    <div className="stepper">
      {steps.map((step, i) => (
        // ok: javascript-avoid-array-index-as-key
        <div key={step.id} className="step">
          <div className="step-number">{i + 1}</div>
          <div className="step-text">{step.text}</div>
        </div>
      ))}
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_12() {
  const [questions, setQuestions] = useState([
    { id: 'q1', text: "What is your name?" },
    { id: 'q2', text: "What is your favorite color?" },
    { id: 'q3', text: "What is your quest?" }
  ]);
  
  return (
    <div className="quiz">
      {questions.map(question => (
        // ok: javascript-avoid-array-index-as-key
        <div key={question.id} className="question-container">
          <p className="question">{question.text}</p>
          <input type="text" placeholder="Your answer" />
        </div>
      ))}
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_13() {
  const [cards, setCards] = useState([
    { id: 'card1', title: 'Card 1', content: 'Content 1' },
    { id: 'card2', title: 'Card 2', content: 'Content 2' },
    { id: 'card3', title: 'Card 3', content: 'Content 3' }
  ]);
  
  return (
    <div className="card-grid">
      {cards.map(card => (
        // ok: javascript-avoid-array-index-as-key
        <div key={card.id} className="card">
          <h3>{card.title}</h3>
          <p>{card.content}</p>
        </div>
      ))}
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_14() {
  const colors = [
    { id: 'color1', name: 'red' },
    { id: 'color2', name: 'green' },
    { id: 'color3', name: 'blue' },
    { id: 'color4', name: 'yellow' },
    { id: 'color5', name: 'purple' }
  ];
  
  return (
    <div className="color-picker">
      {colors.map(color => (
        // ok: javascript-avoid-array-index-as-key
        <div 
          key={color.id}
          className="color-swatch"
          style={{ backgroundColor: color.name }}
        />
      ))}
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_15() {
  const [todoItems, setTodoItems] = useState([
    { id: 'todo1', text: 'Buy groceries', completed: false },
    { id: 'todo2', text: 'Clean house', completed: true },
    { id: 'todo3', text: 'Walk dog', completed: false }
  ]);
  
  return (
    <ul className="todo-list">
      {todoItems.map(item => (
        // ok: javascript-avoid-array-index-as-key
        <li key={item.id} className={item.completed ? 'completed' : ''}>
          <input type="checkbox" checked={item.completed} />
          <span>{item.text}</span>
        </li>
      ))}
    </ul>
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