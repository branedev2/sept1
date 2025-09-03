import React from 'react';
import { useTranslation } from 'react-i18next';
import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';

// Initialize i18n for the good examples
i18n
  .use(initReactI18next)
  .init({
    resources: {
      en: {
        translation: {
          welcome: "Welcome to our application",
          greeting: "Hello, {{name}}!",
          submit: "Submit",
          cancel: "Cancel",
          errorMessage: "An error occurred",
          loginTitle: "Login to your account",
          signupPrompt: "Don't have an account? Sign up",
          forgotPassword: "Forgot password?",
          emailPlaceholder: "Enter your email",
          passwordPlaceholder: "Enter your password",
          searchPlaceholder: "Search...",
          loadingText: "Loading...",
          noResults: "No results found",
          successMessage: "Operation completed successfully",
          confirmDelete: "Are you sure you want to delete this item?",
          navigationHome: "Home",
          navigationAbout: "About",
          navigationContact: "Contact",
          footerText: "© 2023 Example Company. All rights reserved.",
          termsAndConditions: "Terms and Conditions"
        }
      }
    },
    lng: "en",
    fallbackLng: "en",
    interpolation: {
      escapeValue: false
    }
  });

// True positives (vulnerable/insecure code)

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_1() {
  return (
    // ruleid: javascript-jsx-not-internationalized
    <div>Welcome to our application</div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_2() {
  const name = "John";
  return (
    // ruleid: javascript-jsx-not-internationalized
    <h1>Hello, {name}!</h1>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_3() {
  return (
    <form>
      {/* ruleid: javascript-jsx-not-internationalized */}
      <button type="submit">Submit</button>
    </form>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_4() {
  return (
    <div>
      {/* ruleid: javascript-jsx-not-internationalized */}
      <button onClick={() => console.log('Cancelled')}>Cancel</button>
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_5() {
  const hasError = true;
  return (
    <div>
      {hasError && (
        // ruleid: javascript-jsx-not-internationalized
        <p className="error">An error occurred</p>
      )}
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_6() {
  return (
    <div className="login-container">
      {/* ruleid: javascript-jsx-not-internationalized */}
      <h2>Login to your account</h2>
      <form>{/* form fields */}</form>
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_7() {
  return (
    <div>
      <p>
        {/* ruleid: javascript-jsx-not-internationalized */}
        Don't have an account? <a href="/signup">Sign up</a>
      </p>
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_8() {
  return (
    <div>
      {/* ruleid: javascript-jsx-not-internationalized */}
      <a href="/reset-password">Forgot password?</a>
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_9() {
  return (
    <form>
      <input 
        type="email" 
        // ruleid: javascript-jsx-not-internationalized
        placeholder="Enter your email" 
      />
    </form>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_10() {
  return (
    <form>
      <input 
        type="password" 
        // ruleid: javascript-jsx-not-internationalized
        placeholder="Enter your password" 
      />
    </form>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_11() {
  return (
    <div>
      <input 
        type="search" 
        // ruleid: javascript-jsx-not-internationalized
        placeholder="Search..." 
      />
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_12() {
  const isLoading = true;
  return (
    <div>
      {isLoading && (
        // ruleid: javascript-jsx-not-internationalized
        <p>Loading...</p>
      )}
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_13() {
  const results = [];
  return (
    <div>
      {results.length === 0 && (
        // ruleid: javascript-jsx-not-internationalized
        <p>No results found</p>
      )}
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_14() {
  const isSuccess = true;
  return (
    <div>
      {isSuccess && (
        // ruleid: javascript-jsx-not-internationalized
        <div className="success-message">Operation completed successfully</div>
      )}
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_15() {
  return (
    <div className="confirmation-dialog">
      {/* ruleid: javascript-jsx-not-internationalized */}
      <p>Are you sure you want to delete this item?</p>
      <div className="buttons">
        {/* ruleid: javascript-jsx-not-internationalized */}
        <button className="confirm">Yes</button>
        {/* ruleid: javascript-jsx-not-internationalized */}
        <button className="cancel">No</button>
      </div>
    </div>
  );
}
// {/fact}

// True negatives (safe/secure code)

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_1() {
  const { t } = useTranslation();
  return (
    // ok: javascript-jsx-not-internationalized
    <div>{t('welcome')}</div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_2() {
  const { t } = useTranslation();
  const name = "John";
  return (
    // ok: javascript-jsx-not-internationalized
    <h1>{t('greeting', { name })}</h1>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_3() {
  const { t } = useTranslation();
  return (
    <form>
      {/* ok: javascript-jsx-not-internationalized */}
      <button type="submit">{t('submit')}</button>
    </form>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_4() {
  const { t } = useTranslation();
  return (
    <div>
      {/* ok: javascript-jsx-not-internationalized */}
      <button onClick={() => console.log('Cancelled')}>{t('cancel')}</button>
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_5() {
  const { t } = useTranslation();
  const hasError = true;
  return (
    <div>
      {hasError && (
        // ok: javascript-jsx-not-internationalized
        <p className="error">{t('errorMessage')}</p>
      )}
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_6() {
  const { t } = useTranslation();
  return (
    <div className="login-container">
      {/* ok: javascript-jsx-not-internationalized */}
      <h2>{t('loginTitle')}</h2>
      <form>{/* form fields */}</form>
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_7() {
  const { t } = useTranslation();
  return (
    <div>
      <p>
        {/* ok: javascript-jsx-not-internationalized */}
        {t('signupPrompt')} <a href="/signup">{t('signup')}</a>
      </p>
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_8() {
  const { t } = useTranslation();
  return (
    <div>
      {/* ok: javascript-jsx-not-internationalized */}
      <a href="/reset-password">{t('forgotPassword')}</a>
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_9() {
  const { t } = useTranslation();
  return (
    <form>
      <input 
        type="email" 
        // ok: javascript-jsx-not-internationalized
        placeholder={t('emailPlaceholder')} 
      />
    </form>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_10() {
  const { t } = useTranslation();
  return (
    <form>
      <input 
        type="password" 
        // ok: javascript-jsx-not-internationalized
        placeholder={t('passwordPlaceholder')} 
      />
    </form>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_11() {
  const { t } = useTranslation();
  return (
    <div>
      <input 
        type="search" 
        // ok: javascript-jsx-not-internationalized
        placeholder={t('searchPlaceholder')} 
      />
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_12() {
  const { t } = useTranslation();
  const isLoading = true;
  return (
    <div>
      {isLoading && (
        // ok: javascript-jsx-not-internationalized
        <p>{t('loadingText')}</p>
      )}
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_13() {
  const { t } = useTranslation();
  const results = [];
  return (
    <div>
      {results.length === 0 && (
        // ok: javascript-jsx-not-internationalized
        <p>{t('noResults')}</p>
      )}
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_14() {
  const { t } = useTranslation();
  const isSuccess = true;
  return (
    <div>
      {isSuccess && (
        // ok: javascript-jsx-not-internationalized
        <div className="success-message">{t('successMessage')}</div>
      )}
    </div>
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_15() {
  const { t } = useTranslation();
  return (
    <nav>
      <ul>
        {/* ok: javascript-jsx-not-internationalized */}
        <li><a href="/">{t('navigationHome')}</a></li>
        {/* ok: javascript-jsx-not-internationalized */}
        <li><a href="/about">{t('navigationAbout')}</a></li>
        {/* ok: javascript-jsx-not-internationalized */}
        <li><a href="/contact">{t('navigationContact')}</a></li>
      </ul>
    </nav>
  );
}
// {/fact}