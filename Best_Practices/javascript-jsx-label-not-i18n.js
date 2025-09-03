import React from 'react';
import { useTranslation } from 'react-i18next';
import { FormattedMessage } from 'react-intl';
import i18n from './i18n';

// True positives (vulnerable code that should be detected)

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_1() {
  return (
    <div>
      {/* ruleid: javascript-jsx-label-not-i18n */}
      <label htmlFor="username">Username:</label>
      <input id="username" type="text" />
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_2() {
  return (
    <form>
      {/* ruleid: javascript-jsx-label-not-i18n */}
      <label htmlFor="password">Enter your password:</label>
      <input id="password" type="password" />
    </form>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_3() {
  const submitForm = () => console.log('Form submitted');
  
  return (
    <div>
      <input type="text" id="email" />
      {/* ruleid: javascript-jsx-label-not-i18n */}
      <button onClick={submitForm}>Submit Form</button>
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_4() {
  return (
    <div>
      {/* ruleid: javascript-jsx-label-not-i18n */}
      <h1>Welcome to our application!</h1>
      <p>Please sign in to continue.</p>
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_5() {
  const items = ['Apple', 'Banana', 'Orange'];
  
  return (
    <div>
      {/* ruleid: javascript-jsx-label-not-i18n */}
      <h2>Available Fruits:</h2>
      <ul>
        {items.map(item => <li key={item}>{item}</li>)}
      </ul>
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_6() {
  return (
    <div>
      <input type="checkbox" id="terms" />
      {/* ruleid: javascript-jsx-label-not-i18n */}
      <label htmlFor="terms">I agree to the Terms and Conditions</label>
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_7() {
  const [value, setValue] = React.useState('');
  
  return (
    <div>
      {/* ruleid: javascript-jsx-label-not-i18n */}
      <p>Your current selection: {value || 'None'}</p>
      <input value={value} onChange={e => setValue(e.target.value)} />
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_8() {
  const errors = ['Invalid email', 'Password too short'];
  
  return (
    <div>
      {/* ruleid: javascript-jsx-label-not-i18n */}
      <h3>Please fix the following errors:</h3>
      <ul>
        {errors.map((error, index) => <li key={index}>{error}</li>)}
      </ul>
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_9() {
  return (
    <nav>
      <ul>
        {/* ruleid: javascript-jsx-label-not-i18n */}
        <li><a href="/home">Home</a></li>
        {/* ruleid: javascript-jsx-label-not-i18n */}
        <li><a href="/about">About</a></li>
        {/* ruleid: javascript-jsx-label-not-i18n */}
        <li><a href="/contact">Contact</a></li>
      </ul>
    </nav>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_10() {
  const [isOpen, setIsOpen] = React.useState(false);
  
  return (
    <div>
      {/* ruleid: javascript-jsx-label-not-i18n */}
      <button onClick={() => setIsOpen(!isOpen)}>
        {isOpen ? 'Hide Details' : 'Show Details'}
      </button>
      {isOpen && <div>Additional information here...</div>}
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_11() {
  const currentDate = new Date().toLocaleDateString();
  
  return (
    <footer>
      {/* ruleid: javascript-jsx-label-not-i18n */}
      <p>Today's date: {currentDate}</p>
      {/* ruleid: javascript-jsx-label-not-i18n */}
      <p>Copyright © 2023 My Company</p>
    </footer>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_12() {
  const handleSubmit = (e) => {
    e.preventDefault();
    // Form submission logic
  };
  
  return (
    <form onSubmit={handleSubmit}>
      <input type="text" required />
      {/* ruleid: javascript-jsx-label-not-i18n */}
      <span className="error-message">This field is required</span>
      {/* ruleid: javascript-jsx-label-not-i18n */}
      <button type="submit">Save Changes</button>
    </form>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_13() {
  const status = 'loading';
  
  return (
    <div>
      {status === 'loading' && (
        <div>
          {/* ruleid: javascript-jsx-label-not-i18n */}
          <p>Loading data, please wait...</p>
        </div>
      )}
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_14() {
  const items = [
    { id: 1, name: 'Item 1', price: 10 },
    { id: 2, name: 'Item 2', price: 20 }
  ];
  
  return (
    <table>
      <thead>
        <tr>
          {/* ruleid: javascript-jsx-label-not-i18n */}
          <th>ID</th>
          {/* ruleid: javascript-jsx-label-not-i18n */}
          <th>Name</th>
          {/* ruleid: javascript-jsx-label-not-i18n */}
          <th>Price</th>
        </tr>
      </thead>
      <tbody>
        {items.map(item => (
          <tr key={item.id}>
            <td>{item.id}</td>
            <td>{item.name}</td>
            <td>${item.price}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_15() {
  const [tab, setTab] = React.useState('profile');
  
  return (
    <div>
      <div className="tabs">
        {/* ruleid: javascript-jsx-label-not-i18n */}
        <button onClick={() => setTab('profile')} className={tab === 'profile' ? 'active' : ''}>Profile</button>
        {/* ruleid: javascript-jsx-label-not-i18n */}
        <button onClick={() => setTab('settings')} className={tab === 'settings' ? 'active' : ''}>Settings</button>
        {/* ruleid: javascript-jsx-label-not-i18n */}
        <button onClick={() => setTab('notifications')} className={tab === 'notifications' ? 'active' : ''}>Notifications</button>
      </div>
    </div>
  );
}
// {/fact}

// True negatives (safe code that should not be detected)

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_1() {
  const { t } = useTranslation();
  
  return (
    <div>
      {/* ok: javascript-jsx-label-not-i18n */}
      <label htmlFor="username">{t('form.username')}</label>
      <input id="username" type="text" />
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_2() {
  const { t } = useTranslation();
  
  return (
    <form>
      {/* ok: javascript-jsx-label-not-i18n */}
      <label htmlFor="password">{t('form.password.label')}</label>
      <input id="password" type="password" />
    </form>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_3() {
  const { t } = useTranslation();
  const submitForm = () => console.log('Form submitted');
  
  return (
    <div>
      <input type="text" id="email" />
      {/* ok: javascript-jsx-label-not-i18n */}
      <button onClick={submitForm}>{t('form.submit')}</button>
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_4() {
  return (
    <div>
      {/* ok: javascript-jsx-label-not-i18n */}
      <h1><FormattedMessage id="welcome.title" defaultMessage="Welcome to our application!" /></h1>
      {/* ok: javascript-jsx-label-not-i18n */}
      <p><FormattedMessage id="welcome.subtitle" defaultMessage="Please sign in to continue." /></p>
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_5() {
  const { t } = useTranslation();
  const items = ['Apple', 'Banana', 'Orange'];
  
  return (
    <div>
      {/* ok: javascript-jsx-label-not-i18n */}
      <h2>{t('fruits.title')}</h2>
      <ul>
        {items.map(item => (
          <li key={item}>{t(`fruits.${item.toLowerCase()}`)}</li>
        ))}
      </ul>
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_6() {
  const { t } = useTranslation();
  
  return (
    <div>
      <input type="checkbox" id="terms" />
      {/* ok: javascript-jsx-label-not-i18n */}
      <label htmlFor="terms">{t('terms.agreement')}</label>
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_7() {
  const { t } = useTranslation();
  const [value, setValue] = React.useState('');
  
  return (
    <div>
      {/* ok: javascript-jsx-label-not-i18n */}
      <p>{t('selection.current', { value: value || t('selection.none') })}</p>
      <input value={value} onChange={e => setValue(e.target.value)} />
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_8() {
  const { t } = useTranslation();
  const errorCodes = ['email.invalid', 'password.short'];
  
  return (
    <div>
      {/* ok: javascript-jsx-label-not-i18n */}
      <h3>{t('errors.title')}</h3>
      <ul>
        {errorCodes.map((errorCode, index) => (
          <li key={index}>{t(`errors.${errorCode}`)}</li>
        ))}
      </ul>
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_9() {
  const { t } = useTranslation();
  const menuItems = ['home', 'about', 'contact'];
  
  return (
    <nav>
      <ul>
        {menuItems.map(item => (
          <li key={item}>
            {/* ok: javascript-jsx-label-not-i18n */}
            <a href={`/${item}`}>{t(`nav.${item}`)}</a>
          </li>
        ))}
      </ul>
    </nav>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_10() {
  const { t } = useTranslation();
  const [isOpen, setIsOpen] = React.useState(false);
  
  return (
    <div>
      {/* ok: javascript-jsx-label-not-i18n */}
      <button onClick={() => setIsOpen(!isOpen)}>
        {isOpen ? t('details.hide') : t('details.show')}
      </button>
      {isOpen && <div>{t('details.content')}</div>}
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_11() {
  const { t } = useTranslation();
  const currentDate = new Date().toLocaleDateString();
  
  return (
    <footer>
      {/* ok: javascript-jsx-label-not-i18n */}
      <p>{t('footer.date', { date: currentDate })}</p>
      {/* ok: javascript-jsx-label-not-i18n */}
      <p>{t('footer.copyright', { year: new Date().getFullYear() })}</p>
    </footer>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_12() {
  const { t } = useTranslation();
  const handleSubmit = (e) => {
    e.preventDefault();
    // Form submission logic
  };
  
  return (
    <form onSubmit={handleSubmit}>
      <input type="text" required />
      {/* ok: javascript-jsx-label-not-i18n */}
      <span className="error-message">{t('validation.required')}</span>
      {/* ok: javascript-jsx-label-not-i18n */}
      <button type="submit">{t('form.save')}</button>
    </form>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_13() {
  const { t } = useTranslation();
  const status = 'loading';
  
  return (
    <div>
      {status === 'loading' && (
        <div>
          {/* ok: javascript-jsx-label-not-i18n */}
          <p>{t('status.loading')}</p>
        </div>
      )}
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_14() {
  const { t } = useTranslation();
  const items = [
    { id: 1, name: 'Item 1', price: 10 },
    { id: 2, name: 'Item 2', price: 20 }
  ];
  
  const tableHeaders = ['id', 'name', 'price'].map(header => (
    /* ok: javascript-jsx-label-not-i18n */
    <th key={header}>{t(`table.${header}`)}</th>
  ));
  
  return (
    <table>
      <thead>
        <tr>{tableHeaders}</tr>
      </thead>
      <tbody>
        {items.map(item => (
          <tr key={item.id}>
            <td>{item.id}</td>
            <td>{t(`items.${item.id}.name`)}</td>
            <td>${item.price}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_15() {
  const { t } = useTranslation();
  const [tab, setTab] = React.useState('profile');
  const tabs = ['profile', 'settings', 'notifications'];
  
  return (
    <div>
      <div className="tabs">
        {tabs.map(tabName => (
          /* ok: javascript-jsx-label-not-i18n */
          <button 
            key={tabName}
            onClick={() => setTab(tabName)} 
            className={tab === tabName ? 'active' : ''}
          >
            {t(`tabs.${tabName}`)}
          </button>
        ))}
      </div>
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