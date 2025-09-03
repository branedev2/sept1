// Example file: internationalization-examples.jsx
import React from 'react';
import { useTranslation } from 'react-i18next';
import { FormattedMessage } from 'react-intl';
import i18n from 'i18next';

// True Positive Examples (Non-internationalized labels)

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_1() {
  return (
    <div>
      {/* ruleid: javascript-jsx-label-not-i18n */}
      <button>Submit</button>
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_2() {
  return (
    <form>
      {/* ruleid: javascript-jsx-label-not-i18n */}
      <label>Username:</label>
      <input type="text" />
    </form>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_3() {
  return (
    <div>
      {/* ruleid: javascript-jsx-label-not-i18n */}
      <h1>Welcome to our website!</h1>
      <p>Please login to continue.</p>
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_4() {
  const errorMessage = "Invalid credentials";
  return (
    <div>
      {/* ruleid: javascript-jsx-label-not-i18n */}
      <span className="error">{errorMessage}</span>
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_5() {
  return (
    <nav>
      <ul>
        {/* ruleid: javascript-jsx-label-not-i18n */}
        <li><a href="/home">Home</a></li>
        <li><a href="/about">About</a></li>
        <li><a href="/contact">Contact</a></li>
      </ul>
    </nav>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_6() {
  const items = ["Apple", "Banana", "Orange"];
  return (
    <div>
      <h2>
        {/* ruleid: javascript-jsx-label-not-i18n */}
        Fruit List
      </h2>
      <ul>
        {items.map(item => (
          <li key={item}>{item}</li>
        ))}
      </ul>
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_7() {
  return (
    <div>
      {/* ruleid: javascript-jsx-label-not-i18n */}
      <p>Copyright © 2023 - All Rights Reserved</p>
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_8() {
  const isLoggedIn = false;
  return (
    <div>
      {isLoggedIn ? (
        <span>Welcome back!</span>
      ) : (
        /* ruleid: javascript-jsx-label-not-i18n */
        <button>Login</button>
      )}
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_9() {
  return (
    <form>
      {/* ruleid: javascript-jsx-label-not-i18n */}
      <legend>Personal Information</legend>
      <div>
        <label>First Name:</label>
        <input type="text" />
      </div>
    </form>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_10() {
  const notifications = 5;
  return (
    <div>
      {/* ruleid: javascript-jsx-label-not-i18n */}
      <span>You have {notifications} new messages</span>
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_11() {
  return (
    <div>
      {/* ruleid: javascript-jsx-label-not-i18n */}
      <button disabled>Loading...</button>
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_12() {
  const status = "pending";
  return (
    <div>
      {status === "pending" && (
        /* ruleid: javascript-jsx-label-not-i18n */
        <p>Your request is being processed...</p>
      )}
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_13() {
  return (
    <select>
      {/* ruleid: javascript-jsx-label-not-i18n */}
      <option value="">Select an option</option>
      <option value="1">Option 1</option>
      <option value="2">Option 2</option>
    </select>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_14() {
  const handleClick = () => alert("Clicked!");
  return (
    <div>
      {/* ruleid: javascript-jsx-label-not-i18n */}
      <button onClick={handleClick}>Click me</button>
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_15() {
  return (
    <table>
      <thead>
        <tr>
          {/* ruleid: javascript-jsx-label-not-i18n */}
          <th>Name</th>
          <th>Email</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>
        {/* Table content */}
      </tbody>
    </table>
  );
}
// {/fact}

// True Negative Examples (Properly internationalized labels)

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_1() {
  const { t } = useTranslation();
  return (
    <div>
      {/* ok: javascript-jsx-label-not-i18n */}
      <button>{t('submit')}</button>
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_2() {
  return (
    <form>
      {/* ok: javascript-jsx-label-not-i18n */}
      <label><FormattedMessage id="username.label" defaultMessage="Username:" /></label>
      <input type="text" />
    </form>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_3() {
  const { t } = useTranslation();
  return (
    <div>
      {/* ok: javascript-jsx-label-not-i18n */}
      <h1>{t('welcome.title')}</h1>
      <p>{t('login.prompt')}</p>
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_4() {
  const { t } = useTranslation();
  return (
    <div>
      {/* ok: javascript-jsx-label-not-i18n */}
      <span className="error">{t('error.invalid_credentials')}</span>
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_5() {
  const { t } = useTranslation();
  return (
    <nav>
      <ul>
        {/* ok: javascript-jsx-label-not-i18n */}
        <li><a href="/home">{t('nav.home')}</a></li>
        <li><a href="/about">{t('nav.about')}</a></li>
        <li><a href="/contact">{t('nav.contact')}</a></li>
      </ul>
    </nav>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_6() {
  const { t } = useTranslation();
  const items = [t('fruit.apple'), t('fruit.banana'), t('fruit.orange')];
  return (
    <div>
      {/* ok: javascript-jsx-label-not-i18n */}
      <h2>{t('fruit.list_title')}</h2>
      <ul>
        {items.map(item => (
          <li key={item}>{item}</li>
        ))}
      </ul>
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_7() {
  return (
    <div>
      {/* ok: javascript-jsx-label-not-i18n */}
      <p><FormattedMessage id="footer.copyright" defaultMessage="Copyright © 2023 - All Rights Reserved" /></p>
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_8() {
  const { t } = useTranslation();
  const isLoggedIn = false;
  return (
    <div>
      {isLoggedIn ? (
        /* ok: javascript-jsx-label-not-i18n */
        <span>{t('welcome.back')}</span>
      ) : (
        <button>{t('action.login')}</button>
      )}
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_9() {
  const { t } = useTranslation();
  return (
    <form>
      {/* ok: javascript-jsx-label-not-i18n */}
      <legend>{t('form.personal_info')}</legend>
      <div>
        <label>{t('form.first_name')}</label>
        <input type="text" />
      </div>
    </form>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_10() {
  const notifications = 5;
  return (
    <div>
      {/* ok: javascript-jsx-label-not-i18n */}
      <span>
        <FormattedMessage 
          id="notifications.count"
          defaultMessage="You have {count} new messages"
          values={{ count: notifications }}
        />
      </span>
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_11() {
  const { t } = useTranslation();
  return (
    <div>
      {/* ok: javascript-jsx-label-not-i18n */}
      <button disabled>{t('status.loading')}</button>
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_12() {
  const { t } = useTranslation();
  const status = "pending";
  return (
    <div>
      {status === "pending" && (
        /* ok: javascript-jsx-label-not-i18n */
        <p>{t('status.processing')}</p>
      )}
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_13() {
  const { t } = useTranslation();
  return (
    <select>
      {/* ok: javascript-jsx-label-not-i18n */}
      <option value="">{t('select.placeholder')}</option>
      <option value="1">{t('select.option1')}</option>
      <option value="2">{t('select.option2')}</option>
    </select>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_14() {
  const { t } = useTranslation();
  const handleClick = () => alert(t('alert.clicked'));
  return (
    <div>
      {/* ok: javascript-jsx-label-not-i18n */}
      <button onClick={handleClick}>{t('button.click_me')}</button>
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_15() {
  const { t } = useTranslation();
  return (
    <table>
      <thead>
        <tr>
          {/* ok: javascript-jsx-label-not-i18n */}
          <th>{t('table.name')}</th>
          <th>{t('table.email')}</th>
          <th>{t('table.actions')}</th>
        </tr>
      </thead>
      <tbody>
        {/* Table content */}
      </tbody>
    </table>
  );
}
// {/fact}