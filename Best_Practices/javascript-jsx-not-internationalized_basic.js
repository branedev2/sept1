import React from 'react';
import { useTranslation } from 'react-i18next';
import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';

// Initialize i18next for good examples
i18n
  .use(initReactI18next)
  .init({
    resources: {
      en: {
        translation: {
          welcome: "Welcome to our app",
          greeting: "Hello, {{name}}!",
          buttonText: "Click me",
          description: "This is a sample application",
          title: "My Application",
          menu: {
            home: "Home",
            about: "About",
            contact: "Contact"
          },
          footer: "© 2023 My Company",
          error: "An error occurred",
          loginForm: {
            username: "Username",
            password: "Password",
            submit: "Login"
          },
          products: {
            title: "Our Products",
            viewDetails: "View Details"
          },
          notification: "You have {{count}} new messages",
          settings: "Settings",
          logout: "Logout"
        }
      }
    },
    lng: "en",
    fallbackLng: "en",
    interpolation: {
      escapeValue: false
    }
  });

// BAD EXAMPLES - Not internationalized JSX

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_1() {
  return (
    <div>
      {/* ruleid: javascript-jsx-not-internationalized */}
      <h1>Welcome to our app</h1>
      <p>Please sign in to continue</p>
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_2() {
  const username = "John";
  return (
    <div>
      {/* ruleid: javascript-jsx-not-internationalized */}
      <p>Hello, {username}! How are you today?</p>
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_3() {
  return (
    <button>
      {/* ruleid: javascript-jsx-not-internationalized */}
      Click me
    </button>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_4() {
  const items = ["Apple", "Banana", "Orange"];
  return (
    <div>
      {/* ruleid: javascript-jsx-not-internationalized */}
      <h2>Available Fruits:</h2>
      <ul>
        {items.map(item => <li key={item}>{item}</li>)}
      </ul>
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_5() {
  const isLoggedIn = true;
  return (
    <nav>
      {/* ruleid: javascript-jsx-not-internationalized */}
      <ul>
        <li>Home</li>
        <li>About</li>
        <li>Contact</li>
        {isLoggedIn && <li>Logout</li>}
      </ul>
    </nav>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_6() {
  const handleSubmit = () => console.log('Form submitted');
  return (
    <form onSubmit={handleSubmit}>
      {/* ruleid: javascript-jsx-not-internationalized */}
      <label>Username:
        <input type="text" name="username" />
      </label>
      <label>Password:
        <input type="password" name="password" />
      </label>
      <button type="submit">Login</button>
    </form>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_7() {
  const count = 5;
  return (
    <div>
      {/* ruleid: javascript-jsx-not-internationalized */}
      <p>You have {count} new messages</p>
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_8() {
  const error = "Server connection failed";
  return (
    <div>
      {/* ruleid: javascript-jsx-not-internationalized */}
      <p className="error">Error: {error}</p>
      <button>Try Again</button>
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_9() {
  return (
    <footer>
      {/* ruleid: javascript-jsx-not-internationalized */}
      <p>© 2023 My Company. All rights reserved.</p>
    </footer>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_10() {
  const product = { name: "Smartphone", price: 599 };
  return (
    <div>
      {/* ruleid: javascript-jsx-not-internationalized */}
      <h3>{product.name}</h3>
      <p>Price: ${product.price}</p>
      <button>Add to Cart</button>
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_11() {
  return (
    <div>
      {/* ruleid: javascript-jsx-not-internationalized */}
      <h2>Contact Us</h2>
      <p>Please fill out the form below to get in touch with our team.</p>
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_12() {
  const isOpen = false;
  return (
    <div>
      {/* ruleid: javascript-jsx-not-internationalized */}
      <p>{isOpen ? "We're open!" : "Sorry, we're closed."}</p>
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_13() {
  const notifications = ["Payment received", "New message", "Friend request"];
  return (
    <div>
      {/* ruleid: javascript-jsx-not-internationalized */}
      <h3>Notifications ({notifications.length})</h3>
      <ul>
        {notifications.map((notification, index) => (
          <li key={index}>{notification}</li>
        ))}
      </ul>
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_14() {
  const handleClick = () => console.log('Settings clicked');
  return (
    <div>
      {/* ruleid: javascript-jsx-not-internationalized */}
      <button onClick={handleClick}>Settings</button>
      <button onClick={() => console.log('Logout')}>Logout</button>
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_15() {
  const steps = ["Select product", "Add to cart", "Checkout", "Payment"];
  return (
    <div>
      {/* ruleid: javascript-jsx-not-internationalized */}
      <h3>How to purchase:</h3>
      <ol>
        {steps.map((step, index) => (
          <li key={index}>{step}</li>
        ))}
      </ol>
    </div>
  );
}
// {/fact}

// GOOD EXAMPLES - Properly internationalized JSX

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_1() {
  const { t } = useTranslation();
  return (
    <div>
      {/* ok: javascript-jsx-not-internationalized */}
      <h1>{t('welcome')}</h1>
      <p>{t('description')}</p>
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_2() {
  const { t } = useTranslation();
  const username = "John";
  return (
    <div>
      {/* ok: javascript-jsx-not-internationalized */}
      <p>{t('greeting', { name: username })}</p>
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_3() {
  const { t } = useTranslation();
  return (
    <button>
      {/* ok: javascript-jsx-not-internationalized */}
      {t('buttonText')}
    </button>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_4() {
  const { t } = useTranslation();
  const items = ["Apple", "Banana", "Orange"];
  return (
    <div>
      {/* ok: javascript-jsx-not-internationalized */}
      <h2>{t('products.title')}</h2>
      <ul>
        {items.map(item => <li key={item}>{item}</li>)}
      </ul>
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_5() {
  const { t } = useTranslation();
  const isLoggedIn = true;
  return (
    <nav>
      {/* ok: javascript-jsx-not-internationalized */}
      <ul>
        <li>{t('menu.home')}</li>
        <li>{t('menu.about')}</li>
        <li>{t('menu.contact')}</li>
        {isLoggedIn && <li>{t('logout')}</li>}
      </ul>
    </nav>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_6() {
  const { t } = useTranslation();
  const handleSubmit = () => console.log('Form submitted');
  return (
    <form onSubmit={handleSubmit}>
      {/* ok: javascript-jsx-not-internationalized */}
      <label>{t('loginForm.username')}:
        <input type="text" name="username" />
      </label>
      <label>{t('loginForm.password')}:
        <input type="password" name="password" />
      </label>
      <button type="submit">{t('loginForm.submit')}</button>
    </form>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_7() {
  const { t } = useTranslation();
  const count = 5;
  return (
    <div>
      {/* ok: javascript-jsx-not-internationalized */}
      <p>{t('notification', { count })}</p>
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_8() {
  const { t } = useTranslation();
  const error = "Server connection failed";
  return (
    <div>
      {/* ok: javascript-jsx-not-internationalized */}
      <p className="error">{t('error')}: {error}</p>
      <button>{t('buttonText')}</button>
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_9() {
  const { t } = useTranslation();
  return (
    <footer>
      {/* ok: javascript-jsx-not-internationalized */}
      <p>{t('footer')}</p>
    </footer>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_10() {
  const { t } = useTranslation();
  const product = { name: "Smartphone", price: 599 };
  return (
    <div>
      {/* ok: javascript-jsx-not-internationalized */}
      <h3>{product.name}</h3>
      <p>Price: ${product.price}</p>
      <button>{t('products.viewDetails')}</button>
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_11() {
  // Using a different pattern with i18n directly
  return (
    <div>
      {/* ok: javascript-jsx-not-internationalized */}
      <h2>{i18n.t('title')}</h2>
      <p>{i18n.t('description')}</p>
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_12() {
  const { t } = useTranslation();
  const isOpen = false;
  // Using translation keys for conditional text
  const statusKey = isOpen ? 'openStatus' : 'closedStatus';
  return (
    <div>
      {/* ok: javascript-jsx-not-internationalized */}
      <p>{t(statusKey)}</p>
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_13() {
  const { t } = useTranslation();
  // Using a component that internally uses translation
  const TranslatedText = ({ textKey }) => <span>{t(textKey)}</span>;
  
  return (
    <div>
      {/* ok: javascript-jsx-not-internationalized */}
      <h3><TranslatedText textKey="title" /></h3>
      <p><TranslatedText textKey="description" /></p>
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_14() {
  const { t } = useTranslation();
  // Using translations with dynamic content
  const username = "John";
  const count = 3;
  
  return (
    <div>
      {/* ok: javascript-jsx-not-internationalized */}
      <p>{t('greeting', { name: username })}</p>
      <p>{t('notification', { count })}</p>
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_15() {
  // Using React.lazy and Suspense for loading translations
  const { t } = useTranslation();
  const menuItems = ['home', 'about', 'contact', 'settings'];
  
  return (
    <nav>
      {/* ok: javascript-jsx-not-internationalized */}
      <ul>
        {menuItems.map(item => (
          <li key={item}>{t(`menu.${item}`)}</li>
        ))}
      </ul>
    </nav>
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