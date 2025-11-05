# This file contains examples of secure and insecure configurations of force_ssl
# in Ruby on Rails applications

# True Positives (Vulnerable Code)

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_1
  # In config/environments/production.rb
  Rails.application.configure do
    # ruleid: ruby-force-ssl-false
    config.force_ssl = false
    
    # Other configurations
    config.cache_classes = true
    config.eager_load = true
  end
# {/fact}
end

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_2
  # In a Rails initializer file
  # ruleid: ruby-force-ssl-false
  Rails.application.config.force_ssl = false
end
# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_3
  class Application < Rails::Application
    # ruleid: ruby-force-ssl-false
    config.force_ssl = false
    
    config.load_defaults 6.1
    config.autoloader = :zeitwerk
  end
end
# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_4
  # In config/application.rb
  module MyApp
    class Application < Rails::Application
      # ruleid: ruby-force-ssl-false
      config.force_ssl = false if Rails.env.production?
    end
  end
end
# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_5
  # In an environment-specific configuration
  if Rails.env.staging?
    # ruleid: ruby-force-ssl-false
    Rails.application.configure do
      config.force_ssl = false
    end
  end
# {/fact}
end

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_6
  # Disabling SSL in development and test environments
  Rails.application.configure do
    if Rails.env.development? || Rails.env.test?
      # ruleid: ruby-force-ssl-false
      config.force_ssl = false
    end
  end
# {/fact}
end

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_7
  # Setting force_ssl based on an environment variable
  Rails.application.configure do
    # ruleid: ruby-force-ssl-false
    config.force_ssl = ENV['ENABLE_SSL'] == 'true' ? true : false
    
    # This is vulnerable when ENABLE_SSL is not 'true'
  end
# {/fact}
end

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_8
  # In a custom configuration method
  def configure_ssl(app)
    # ruleid: ruby-force-ssl-false
    app.config.force_ssl = false
  end
  
  configure_ssl(Rails.application)
end
# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_9
  # Using a constant to determine SSL configuration
  FORCE_SSL_ENABLED = false
  
  Rails.application.configure do
    # ruleid: ruby-force-ssl-false
    config.force_ssl = FORCE_SSL_ENABLED
  end
# {/fact}
end

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_10
  # In a Rails engine
  module MyEngine
    class Engine < ::Rails::Engine
      initializer "my_engine.configure_ssl" do |app|
        # ruleid: ruby-force-ssl-false
        app.config.force_ssl = false
      end
    end
  end
# {/fact}
end

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_11
  # Disabling SSL for specific environments
  environments = ['production', 'staging']
  
  environments.each do |env|
    if Rails.env == env
      # ruleid: ruby-force-ssl-false
      Rails.application.config.force_ssl = false
    end
  end
# {/fact}
end

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_12
  # Using a method to determine SSL configuration
  def ssl_enabled?
    false
  end
  
  Rails.application.configure do
    # ruleid: ruby-force-ssl-false
    config.force_ssl = ssl_enabled?
  end
# {/fact}
end

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_13
  # Setting force_ssl in a conditional block
  if ENV['ENVIRONMENT'] == 'internal'
    Rails.application.configure do
      # ruleid: ruby-force-ssl-false
      config.force_ssl = false
    end
  end
# {/fact}
end

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_14
  # Disabling SSL for a specific host
  Rails.application.configure do
    if ENV['HOSTNAME'] == 'internal-server'
      # ruleid: ruby-force-ssl-false
      config.force_ssl = false
    else
      config.force_ssl = true
    end
  end
# {/fact}
end

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_15
  # Disabling SSL based on a feature flag
  module SSLConfig
    def self.apply(config)
      # ruleid: ruby-force-ssl-false
      config.force_ssl = FeatureFlag.enabled?(:use_ssl)
      
      # Assuming FeatureFlag.enabled?(:use_ssl) returns false
    end
  end
  
  SSLConfig.apply(Rails.application.config)
end
# {/fact}

# True Negatives (Secure Code)

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_1
  # In config/environments/production.rb
  Rails.application.configure do
    # ok: ruby-force-ssl-false
    config.force_ssl = true
    
    # Other configurations
    config.cache_classes = true
    config.eager_load = true
  end
# {/fact}
end

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_2
  # In a Rails initializer file
  # ok: ruby-force-ssl-false
  Rails.application.config.force_ssl = true
end
# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_3
  class Application < Rails::Application
    # ok: ruby-force-ssl-false
    config.force_ssl = true
    
    config.load_defaults 6.1
    config.autoloader = :zeitwerk
  end
end
# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_4
  # In config/application.rb
  module MyApp
    class Application < Rails::Application
      # ok: ruby-force-ssl-false
      config.force_ssl = true if Rails.env.production?
    end
  end
end
# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_5
  # In an environment-specific configuration
  if Rails.env.staging? || Rails.env.production?
    # ok: ruby-force-ssl-false
    Rails.application.configure do
      config.force_ssl = true
    end
  end
# {/fact}
end

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_6
  # Setting SSL configuration for different environments
  Rails.application.configure do
    if Rails.env.development? || Rails.env.test?
      config.force_ssl = false
    else
      # ok: ruby-force-ssl-false
      config.force_ssl = true
    end
  end
# {/fact}
end

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_7
  # Setting force_ssl based on an environment variable with secure default
  Rails.application.configure do
    # ok: ruby-force-ssl-false
    config.force_ssl = ENV.fetch('DISABLE_SSL', 'false') != 'true'
  end
# {/fact}
end

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_8
  # In a custom configuration method
  def configure_ssl(app)
    # ok: ruby-force-ssl-false
    app.config.force_ssl = true
  end
  
  configure_ssl(Rails.application)
end
# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_9
  # Using a constant to determine SSL configuration
  FORCE_SSL_ENABLED = true
  
  Rails.application.configure do
    # ok: ruby-force-ssl-false
    config.force_ssl = FORCE_SSL_ENABLED
  end
# {/fact}
end

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_10
  # In a Rails engine
  module MyEngine
    class Engine < ::Rails::Engine
      initializer "my_engine.configure_ssl" do |app|
        # ok: ruby-force-ssl-false
        app.config.force_ssl = true
      end
    end
  end
# {/fact}
end

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_11
  # Enabling SSL for specific environments
  environments = ['production', 'staging']
  
  environments.each do |env|
    if Rails.env == env
      # ok: ruby-force-ssl-false
      Rails.application.config.force_ssl = true
    end
  end
# {/fact}
end

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_12
  # Using a method to determine SSL configuration
  def ssl_enabled?
    true
  end
  
  Rails.application.configure do
    # ok: ruby-force-ssl-false
    config.force_ssl = ssl_enabled?
  end
# {/fact}
end

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_13
  # Setting force_ssl in a conditional block
  if ENV['ENVIRONMENT'] == 'production'
    Rails.application.configure do
      # ok: ruby-force-ssl-false
      config.force_ssl = true
    end
  end
# {/fact}
end

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_14
  # Enabling SSL by default and only disabling for development
  Rails.application.configure do
    if Rails.env.development?
      config.force_ssl = false
    else
      # ok: ruby-force-ssl-false
      config.force_ssl = true
    end
  end
# {/fact}
end

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_15
  # Using a configuration service to determine SSL settings
  module SSLConfig
    def self.apply(config)
      # ok: ruby-force-ssl-false
      config.force_ssl = !development_mode?
    end
    
    def self.development_mode?
      Rails.env.development? || Rails.env.test?
    end
  end
  
  SSLConfig.apply(Rails.application.config)
end
# {/fact}