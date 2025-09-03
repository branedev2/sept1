// File: jsx_list_key_test_cases.js
import React from 'react';

// BAD CASES - Missing keys in JSX lists

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_1() {
  const items = ['apple', 'banana', 'cherry'];
  
  return (
    <div>
      <h1>Fruit List</h1>
      <ul>
        {items.map(item => (
          // ruleid: javascript-list-should-have-key
          <li>{item}</li>
        ))}
      </ul>
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_2() {
  const users = [
    { id: 1, name: 'John' },
    { id: 2, name: 'Jane' },
    { id: 3, name: 'Bob' }
  ];
  
  return (
    <div>
      {users.map(user => (
        // ruleid: javascript-list-should-have-key
        <div>
          <h2>{user.name}</h2>
          <p>ID: {user.id}</p>
        </div>
      ))}
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_3() {
  const products = [
    { name: 'Laptop', price: 999 },
    { name: 'Phone', price: 699 },
    { name: 'Tablet', price: 499 }
  ];
  
  return (
    <table>
      <tbody>
        {products.map((product, index) => (
          // ruleid: javascript-list-should-have-key
          <tr>
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
function bad_case_4() {
  const notifications = ['New message', 'Friend request', 'Update available'];
  
  const renderNotifications = () => {
    return notifications.map(notification => (
      // ruleid: javascript-list-should-have-key
      <div className="notification">{notification}</div>
    ));
  };
  
  return (
    <div className="notification-panel">
      {renderNotifications()}
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_5() {
  const tasks = ['Complete project', 'Send email', 'Schedule meeting'];
  
  return (
    <div>
      {tasks.map((task, i) => {
        return (
          // ruleid: javascript-list-should-have-key
          <div className="task-item">
            <span>{i + 1}. </span>
            <span>{task}</span>
          </div>
        );
      })}
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_6() {
  const comments = [
    { author: 'Alice', text: 'Great post!' },
    { author: 'Bob', text: 'Thanks for sharing.' }
  ];
  
  return (
    <div className="comments-section">
      {comments.map(comment => (
        // ruleid: javascript-list-should-have-key
        <article className="comment">
          <h4>{comment.author}</h4>
          <p>{comment.text}</p>
        </article>
      ))}
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_7() {
  const menuItems = ['Home', 'Products', 'About', 'Contact'];
  
  return (
    <nav>
      <ul>
        {menuItems.map(item => (
          // ruleid: javascript-list-should-have-key
          <li><a href={`/${item.toLowerCase()}`}>{item}</a></li>
        ))}
      </ul>
    </nav>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_8() {
  const colors = ['red', 'green', 'blue', 'yellow'];
  
  return (
    <div className="color-picker">
      {colors.map(color => (
        // ruleid: javascript-list-should-have-key
        <div 
          className="color-swatch" 
          style={{ backgroundColor: color }}
          onClick={() => console.log(`Selected ${color}`)}
        />
      ))}
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_9() {
  const steps = ['Mix ingredients', 'Bake for 20 minutes', 'Let cool'];
  
  return (
    <ol className="recipe-steps">
      {steps.map((step, idx) => (
        // ruleid: javascript-list-should-have-key
        <li className={idx === 0 ? 'first-step' : ''}>{step}</li>
      ))}
    </ol>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_10() {
  const images = [
    { src: 'image1.jpg', alt: 'Landscape' },
    { src: 'image2.jpg', alt: 'Portrait' },
    { src: 'image3.jpg', alt: 'Abstract' }
  ];
  
  return (
    <div className="gallery">
      {images.map(image => (
        // ruleid: javascript-list-should-have-key
        <figure>
          <img src={image.src} alt={image.alt} />
          <figcaption>{image.alt}</figcaption>
        </figure>
      ))}
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_11() {
  const data = [10, 20, 30, 40, 50];
  
  return (
    <div className="chart">
      {data.map(value => (
        // ruleid: javascript-list-should-have-key
        <div 
          className="bar" 
          style={{ height: `${value * 2}px` }} 
        />
      ))}
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_12() {
  const tags = ['JavaScript', 'React', 'Web Development'];
  
  const renderTags = () => {
    return tags.map(tag => (
      // ruleid: javascript-list-should-have-key
      <span className="tag">{tag}</span>
    ));
  };
  
  return (
    <div className="tag-container">
      {renderTags()}
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_13() {
  const options = ['Small', 'Medium', 'Large', 'X-Large'];
  
  return (
    <form>
      <div className="size-options">
        {options.map(option => (
          // ruleid: javascript-list-should-have-key
          <label>
            <input type="radio" name="size" value={option.toLowerCase()} />
            {option}
          </label>
        ))}
      </div>
    </form>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_14() {
  const events = [
    { title: 'Conference', date: '2023-06-15' },
    { title: 'Workshop', date: '2023-06-16' },
    { title: 'Meetup', date: '2023-06-17' }
  ];
  
  return (
    <div className="events-calendar">
      {events.map(event => (
        // ruleid: javascript-list-should-have-key
        <div className="event-card">
          <h3>{event.title}</h3>
          <time dateTime={event.date}>{event.date}</time>
        </div>
      ))}
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_15() {
  const features = ['Responsive design', 'Dark mode', 'Offline support'];
  
  return (
    <section className="features">
      {features.map((feature, i) => (
        // ruleid: javascript-list-should-have-key
        <div className="feature">
          <span className="feature-number">{i + 1}</span>
          <p>{feature}</p>
        </div>
      ))}
    </section>
  );
}
// {/fact}

// GOOD CASES - Properly using keys in JSX lists

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_1() {
  const items = ['apple', 'banana', 'cherry'];
  
  return (
    <div>
      <h1>Fruit List</h1>
      <ul>
        {items.map((item, index) => (
          // ok: javascript-list-should-have-key
          <li key={index}>{item}</li>
        ))}
      </ul>
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_2() {
  const users = [
    { id: 1, name: 'John' },
    { id: 2, name: 'Jane' },
    { id: 3, name: 'Bob' }
  ];
  
  return (
    <div>
      {users.map(user => (
        // ok: javascript-list-should-have-key
        <div key={user.id}>
          <h2>{user.name}</h2>
          <p>ID: {user.id}</p>
        </div>
      ))}
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_3() {
  const products = [
    { id: 'prod-1', name: 'Laptop', price: 999 },
    { id: 'prod-2', name: 'Phone', price: 699 },
    { id: 'prod-3', name: 'Tablet', price: 499 }
  ];
  
  return (
    <table>
      <tbody>
        {products.map(product => (
          // ok: javascript-list-should-have-key
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
function good_case_4() {
  const notifications = ['New message', 'Friend request', 'Update available'];
  
  const renderNotifications = () => {
    return notifications.map((notification, idx) => (
      // ok: javascript-list-should-have-key
      <div key={`notification-${idx}`} className="notification">
        {notification}
      </div>
    ));
  };
  
  return (
    <div className="notification-panel">
      {renderNotifications()}
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_5() {
  const tasks = ['Complete project', 'Send email', 'Schedule meeting'];
  
  return (
    <div>
      {tasks.map((task, i) => {
        const taskId = `task-${i}`;
        return (
          // ok: javascript-list-should-have-key
          <div key={taskId} className="task-item">
            <span>{i + 1}. </span>
            <span>{task}</span>
          </div>
        );
      })}
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_6() {
  const comments = [
    { id: 'c1', author: 'Alice', text: 'Great post!' },
    { id: 'c2', author: 'Bob', text: 'Thanks for sharing.' }
  ];
  
  return (
    <div className="comments-section">
      {comments.map(comment => (
        // ok: javascript-list-should-have-key
        <article key={comment.id} className="comment">
          <h4>{comment.author}</h4>
          <p>{comment.text}</p>
        </article>
      ))}
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_7() {
  const menuItems = ['Home', 'Products', 'About', 'Contact'];
  
  return (
    <nav>
      <ul>
        {menuItems.map((item, index) => (
          // ok: javascript-list-should-have-key
          <li key={`menu-${index}`}>
            <a href={`/${item.toLowerCase()}`}>{item}</a>
          </li>
        ))}
      </ul>
    </nav>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_8() {
  const colors = ['red', 'green', 'blue', 'yellow'];
  
  return (
    <div className="color-picker">
      {colors.map((color, idx) => (
        // ok: javascript-list-should-have-key
        <div 
          key={color}
          className="color-swatch" 
          style={{ backgroundColor: color }}
          onClick={() => console.log(`Selected ${color}`)}
        />
      ))}
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_9() {
  const steps = ['Mix ingredients', 'Bake for 20 minutes', 'Let cool'];
  
  return (
    <ol className="recipe-steps">
      {steps.map((step, idx) => (
        // ok: javascript-list-should-have-key
        <li key={`step-${idx}`} className={idx === 0 ? 'first-step' : ''}>
          {step}
        </li>
      ))}
    </ol>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_10() {
  const images = [
    { id: 'img1', src: 'image1.jpg', alt: 'Landscape' },
    { id: 'img2', src: 'image2.jpg', alt: 'Portrait' },
    { id: 'img3', src: 'image3.jpg', alt: 'Abstract' }
  ];
  
  return (
    <div className="gallery">
      {images.map(image => (
        // ok: javascript-list-should-have-key
        <figure key={image.id}>
          <img src={image.src} alt={image.alt} />
          <figcaption>{image.alt}</figcaption>
        </figure>
      ))}
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_11() {
  const data = [10, 20, 30, 40, 50];
  
  return (
    <div className="chart">
      {data.map((value, index) => (
        // ok: javascript-list-should-have-key
        <div 
          key={`bar-${index}`}
          className="bar" 
          style={{ height: `${value * 2}px` }} 
        />
      ))}
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_12() {
  const tags = ['JavaScript', 'React', 'Web Development'];
  
  const renderTags = () => {
    return tags.map((tag, idx) => (
      // ok: javascript-list-should-have-key
      <span key={`tag-${idx}`} className="tag">{tag}</span>
    ));
  };
  
  return (
    <div className="tag-container">
      {renderTags()}
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_13() {
  const options = ['Small', 'Medium', 'Large', 'X-Large'];
  
  return (
    <form>
      <div className="size-options">
        {options.map((option, idx) => (
          // ok: javascript-list-should-have-key
          <label key={option}>
            <input type="radio" name="size" value={option.toLowerCase()} />
            {option}
          </label>
        ))}
      </div>
    </form>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_14() {
  const events = [
    { id: 'evt1', title: 'Conference', date: '2023-06-15' },
    { id: 'evt2', title: 'Workshop', date: '2023-06-16' },
    { id: 'evt3', title: 'Meetup', date: '2023-06-17' }
  ];
  
  return (
    <div className="events-calendar">
      {events.map(event => (
        // ok: javascript-list-should-have-key
        <div key={event.id} className="event-card">
          <h3>{event.title}</h3>
          <time dateTime={event.date}>{event.date}</time>
        </div>
      ))}
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_15() {
  const features = ['Responsive design', 'Dark mode', 'Offline support'];
  
  return (
    <section className="features">
      {features.map((feature, i) => {
        const uniqueId = `feature-${i}-${feature.replace(/\s+/g, '-')}`;
        return (
          // ok: javascript-list-should-have-key
          <div key={uniqueId} className="feature">
            <span className="feature-number">{i + 1}</span>
            <p>{feature}</p>
          </div>
        );
      })}
    </section>
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