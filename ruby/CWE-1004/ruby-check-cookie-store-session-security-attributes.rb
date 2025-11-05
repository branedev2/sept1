# Ruby Cookie Store Session Security Attributes Examples

# True Positives (Vulnerable Code)

# Example 1: Basic Rails cookie store configuration without security attributes
# {fact rule=insecure-file-permissions@v1.0 defects=1}
def bad_case_1
  # ruleid: ruby-check-cookie-store-session-security-attributes
  Rails.application.config.session_store :cookie_store, key: '_my_app_session'
end
# {/fact}

# Example 2: Cookie store with only one security attribute set
# {fact rule=insecure-file-permissions@v1.0 defects=1}
def bad_case_2
  # ruleid: ruby-check-cookie-store-session-security-attributes
  Rails.application.config.session_store :cookie_store, 
    key: '_my_app_session',
    secure: true
end
# {/fact}

# Example 3: Cookie store with httponly but not secure
# {fact rule=insecure-file-permissions@v1.0 defects=1}
def bad_case_3
  # ruleid: ruby-check-cookie-store-session-security-attributes
  Rails.application.config.session_store :cookie_store, 
    key: '_my_app_session',
    httponly: true
end
# {/fact}

# Example 4: Cookie store with explicitly disabled security attributes
# {fact rule=insecure-file-permissions@v1.0 defects=1}
def bad_case_4
  # ruleid: ruby-check-cookie-store-session-security-attributes
  Rails.application.config.session_store :cookie_store, 
    key: '_my_app_session',
    secure: false,
    httponly: false
end
# {/fact}

# Example 5: Cookie store with one attribute disabled
# {fact rule=insecure-file-permissions@v1.0 defects=1}
def bad_case_5
  # ruleid: ruby-check-cookie-store-session-security-attributes
  Rails.application.config.session_store :cookie_store, 
    key: '_my_app_session',
    secure: true,
    httponly: false
end
# {/fact}

# Example 6: Using cookies directly without security attributes
# {fact rule=insecure-file-permissions@v1.0 defects=1}
def bad_case_6
  # ruleid: ruby-check-cookie-store-session-security-attributes
  cookies[:user_id] = { value: "123", expires: 1.hour.from_now }
end
# {/fact}

# Example 7: Setting cookies with additional attributes but missing security ones
# {fact rule=insecure-file-permissions@v1.0 defects=1}
def bad_case_7
  # ruleid: ruby-check-cookie-store-session-security-attributes
  cookies[:auth_token] = { 
    value: "abc123", 
    expires: 30.days.from_now,
    path: "/",
    domain: ".example.com"
  }
end
# {/fact}

# Example 8: Using cookies.permanent without security attributes
# {fact rule=insecure-file-permissions@v1.0 defects=1}
def bad_case_8
  # ruleid: ruby-check-cookie-store-session-security-attributes
  cookies.permanent[:remember_me] = "yes"
end
# {/fact}

# Example 9: Using cookies.signed without security attributes
# {fact rule=insecure-file-permissions@v1.0 defects=1}
def bad_case_9
  # ruleid: ruby-check-cookie-store-session-security-attributes
  cookies.signed[:user_id] = user.id
end
# {/fact}

# Example 10: Using cookies.encrypted without security attributes
# {fact rule=insecure-file-permissions@v1.0 defects=1}
def bad_case_10
  # ruleid: ruby-check-cookie-store-session-security-attributes
  cookies.encrypted[:secret_data] = "sensitive information"
end
# {/fact}

# Example 11: Using ActionDispatch::Cookies::CookieJar without security attributes
# {fact rule=insecure-file-permissions@v1.0 defects=1}
def bad_case_11
  cookie_jar = ActionDispatch::Cookies::CookieJar.new
  # ruleid: ruby-check-cookie-store-session-security-attributes
  cookie_jar[:preference] = { value: "dark_mode" }
end
# {/fact}

# Example 12: Setting cookies with variable options hash without security attributes
# {fact rule=insecure-file-permissions@v1.0 defects=1}
def bad_case_12
  options = { value: "abc123", expires: 1.day.from_now }
  # ruleid: ruby-check-cookie-store-session-security-attributes
  cookies[:session_token] = options
end
# {/fact}

# Example 13: Using Rack::Session::Cookie without security attributes
# {fact rule=insecure-file-permissions@v1.0 defects=1}
def bad_case_13
  # ruleid: ruby-check-cookie-store-session-security-attributes
  use Rack::Session::Cookie, 
    key: 'rack.session',
    expire_after: 2592000
end
# {/fact}

# Example 14: Using ActionController::Session::CookieStore without security attributes
# {fact rule=insecure-file-permissions@v1.0 defects=1}
def bad_case_14
  # ruleid: ruby-check-cookie-store-session-security-attributes
  ActionController::Base.session = {
    key: '_app_session',
    secret: 'some_secret_string'
  }
end
# {/fact}

# Example 15: Using cookies.signed.permanent without security attributes
# {fact rule=insecure-file-permissions@v1.0 defects=1}
def bad_case_15
  # ruleid: ruby-check-cookie-store-session-security-attributes
  cookies.signed.permanent[:remember_token] = user.remember_token
end
# {/fact}

# True Negatives (Secure Code)

# Example 1: Basic Rails cookie store with both security attributes
# {fact rule=insecure-file-permissions@v1.0 defects=0}
def good_case_1
  # ok: ruby-check-cookie-store-session-security-attributes
  Rails.application.config.session_store :cookie_store, 
    key: '_my_app_session',
    secure: true,
    httponly: true
end
# {/fact}

# Example 2: Cookie store with additional attributes and security attributes
# {fact rule=insecure-file-permissions@v1.0 defects=0}
def good_case_2
  # ok: ruby-check-cookie-store-session-security-attributes
  Rails.application.config.session_store :cookie_store, 
    key: '_my_app_session',
    secure: true,
    httponly: true,
    expire_after: 2.weeks,
    same_site: :lax
end
# {/fact}

# Example 3: Using cookies directly with security attributes
# {fact rule=insecure-file-permissions@v1.0 defects=0}
def good_case_3
  # ok: ruby-check-cookie-store-session-security-attributes
  cookies[:user_id] = { 
    value: "123", 
    expires: 1.hour.from_now,
    secure: true,
    httponly: true
  }
end
# {/fact}

# Example 4: Using cookies.permanent with security attributes
# {fact rule=insecure-file-permissions@v1.0 defects=0}
def good_case_4
  # ok: ruby-check-cookie-store-session-security-attributes
  cookies.permanent[:remember_me] = { 
    value: "yes",
    secure: true,
    httponly: true
  }
end
# {/fact}

# Example 5: Using cookies.signed with security attributes
# {fact rule=insecure-file-permissions@v1.0 defects=0}
def good_case_5
  # ok: ruby-check-cookie-store-session-security-attributes
  cookies.signed[:user_id] = { 
    value: user.id,
    secure: true,
    httponly: true
  }
end
# {/fact}

# Example 6: Using cookies.encrypted with security attributes
# {fact rule=insecure-file-permissions@v1.0 defects=0}
def good_case_6
  # ok: ruby-check-cookie-store-session-security-attributes
  cookies.encrypted[:secret_data] = { 
    value: "sensitive information",
    secure: true,
    httponly: true
  }
end
# {/fact}

# Example 7: Using ActionDispatch::Cookies::CookieJar with security attributes
# {fact rule=insecure-file-permissions@v1.0 defects=0}
def good_case_7
  cookie_jar = ActionDispatch::Cookies::CookieJar.new
  # ok: ruby-check-cookie-store-session-security-attributes
  cookie_jar[:preference] = { 
    value: "dark_mode",
    secure: true,
    httponly: true
  }
end
# {/fact}

# Example 8: Setting cookies with variable options hash with security attributes
# {fact rule=insecure-file-permissions@v1.0 defects=0}
def good_case_8
  options = { 
    value: "abc123", 
    expires: 1.day.from_now,
    secure: true,
    httponly: true
  }
  # ok: ruby-check-cookie-store-session-security-attributes
  cookies[:session_token] = options
end
# {/fact}

# Example 9: Using Rack::Session::Cookie with security attributes
# {fact rule=insecure-file-permissions@v1.0 defects=0}
def good_case_9
  # ok: ruby-check-cookie-store-session-security-attributes
  use Rack::Session::Cookie, 
    key: 'rack.session',
    expire_after: 2592000,
    secure: true,
    httponly: true
end
# {/fact}

# Example 10: Using ActionController::Session::CookieStore with security attributes
# {fact rule=insecure-file-permissions@v1.0 defects=0}
def good_case_10
  # ok: ruby-check-cookie-store-session-security-attributes
  ActionController::Base.session = {
    key: '_app_session',
    secret: 'some_secret_string',
    secure: true,
    httponly: true
  }
end
# {/fact}

# Example 11: Using cookies.signed.permanent with security attributes
# {fact rule=insecure-file-permissions@v1.0 defects=0}
def good_case_11
  # ok: ruby-check-cookie-store-session-security-attributes
  cookies.signed.permanent[:remember_token] = {
    value: user.remember_token,
    secure: true,
    httponly: true
  }
end
# {/fact}

# Example 12: Using cookies with security attributes and SameSite
# {fact rule=insecure-file-permissions@v1.0 defects=0}
def good_case_12
  # ok: ruby-check-cookie-store-session-security-attributes
  cookies[:auth_token] = { 
    value: "abc123", 
    expires: 30.days.from_now,
    secure: true,
    httponly: true,
    same_site: :strict
  }
end
# {/fact}

# Example 13: Using cookies with security attributes and domain restriction
# {fact rule=insecure-file-permissions@v1.0 defects=0}
def good_case_13
  # ok: ruby-check-cookie-store-session-security-attributes
  cookies[:session_id] = { 
    value: "xyz789", 
    domain: ".example.com",
    path: "/",
    secure: true,
    httponly: true
  }
end
# {/fact}

# Example 14: Using cookies with security attributes in a controller action
# {fact rule=insecure-file-permissions@v1.0 defects=0}
def good_case_14
  def login
    user = User.find_by(email: params[:email])
    if user && user.authenticate(params[:password])
      # ok: ruby-check-cookie-store-session-security-attributes
      cookies[:auth_token] = { 
        value: user.generate_token,
        expires: params[:remember_me] ? 2.weeks.from_now : 24.hours.from_now,
        secure: true,
        httponly: true
      }
      redirect_to dashboard_path
    else
      render :login
    end
  end
end
# {/fact}

# Example 15: Using cookies with security attributes and conditional expiration
# {fact rule=insecure-file-permissions@v1.0 defects=0}
def good_case_15
  def set_preferences
    # ok: ruby-check-cookie-store-session-security-attributes
    cookies[:theme] = { 
      value: params[:theme] || "light",
      expires: params[:remember] ? 1.year.from_now : nil,
      secure: true,
      httponly: true
    }
    redirect_to root_path
  end
end
# {/fact}