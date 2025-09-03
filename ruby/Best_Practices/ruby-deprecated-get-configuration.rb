# frozen_string_literal: true

require 'aws-sdk-appconfig'
require 'aws-sdk-appconfigdata'

# True Positive Examples (Using deprecated GetConfiguration API)

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_1
  client = Aws::AppConfig::Client.new(region: 'us-west-2')
  
  # ruleid: ruby-deprecated-get-configuration
  result = client.get_configuration({
    application: 'MyApp',
    environment: 'Production',
    configuration: 'MyConfig',
    client_id: 'my-client-id'
  })
  
  return result.content
end
# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_2
  client = Aws::AppConfig::Client.new
  params = {
    application: 'ServiceApp',
    environment: 'Staging',
    configuration: 'FeatureFlags',
    client_id: 'service-client'
  }
  
  # ruleid: ruby-deprecated-get-configuration
  response = client.get_configuration(params)
  
  puts "Retrieved configuration version: #{response.configuration_version}"
end
# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_3
  # Creating client with credentials
  client = Aws::AppConfig::Client.new(
    access_key_id: ENV['AWS_ACCESS_KEY_ID'],
    secret_access_key: ENV['AWS_SECRET_ACCESS_KEY'],
    region: 'us-east-1'
  )
  
  # ruleid: ruby-deprecated-get-configuration
  config = client.get_configuration(
    application: 'PaymentService',
    environment: 'Production',
    configuration: 'PaymentGateways',
    client_id: 'payment-service-client'
  )
  
  JSON.parse(config.content.read)
end
# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_4
  app_config = Aws::AppConfig::Client.new
  
  begin
    # ruleid: ruby-deprecated-get-configuration
    result = app_config.get_configuration({
      application: 'UserService',
      environment: 'Development',
      configuration: 'UserPreferences',
      client_id: 'user-service-dev'
    })
    
    config_data = JSON.parse(result.content.read)
    puts "Config loaded: #{config_data}"
  rescue Aws::AppConfig::Errors::ServiceError => e
    puts "Error retrieving configuration: #{e.message}"
  end
end
# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_5
  client = Aws::AppConfig::Client.new(region: ENV['AWS_REGION'])
  app_id = 'AuthService'
  env_id = 'Production'
  config_id = 'AuthSettings'
  
  # ruleid: ruby-deprecated-get-configuration
  response = client.get_configuration(
    application: app_id,
    environment: env_id,
    configuration: config_id,
    client_id: 'auth-service-client'
  )
  
  config_content = response.content.read
  return config_content
end
# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_6
  # Using the deprecated API with a different variable name
  appconfig_client = Aws::AppConfig::Client.new
  
  # ruleid: ruby-deprecated-get-configuration
  config_response = appconfig_client.get_configuration({
    application: 'LoggingService',
    environment: 'Production',
    configuration: 'LogLevels',
    client_id: 'logging-client-id'
  })
  
  log_levels = JSON.parse(config_response.content.read)
  configure_logging(log_levels)
end
# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_7
  # Using the deprecated API in a conditional block
  client = Aws::AppConfig::Client.new
  
  if ENV['LOAD_CONFIG'] == 'true'
    # ruleid: ruby-deprecated-get-configuration
    result = client.get_configuration({
      application: 'NotificationService',
      environment: 'Production',
      configuration: 'EmailTemplates',
      client_id: 'notification-client'
    })
    
    return result.content.read
  end
  
  return default_templates
end
# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_8
  # Using the deprecated API in a loop
  client = Aws::AppConfig::Client.new
  configs = ['DatabaseSettings', 'CacheSettings', 'ApiSettings']
  
  results = {}
  configs.each do |config|
    # ruleid: ruby-deprecated-get-configuration
    response = client.get_configuration({
      application: 'InfraService',
      environment: 'Production',
      configuration: config,
      client_id: "infra-service-#{config}"
    })
    
    results[config] = JSON.parse(response.content.read)
  end
# {/fact}
  
  return results
end

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_9
  # Using the deprecated API with method chaining
  # ruleid: ruby-deprecated-get-configuration
  content = Aws::AppConfig::Client.new.get_configuration({
    application: 'ReportingService',
    environment: 'Production',
    configuration: 'ReportFormats',
    client_id: 'reporting-client'
  }).content.read
  
  return JSON.parse(content)
end
# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_10
  # Using the deprecated API with a custom client configuration
  client = Aws::AppConfig::Client.new(
    region: 'us-west-2',
    http_read_timeout: 30,
    retry_limit: 5
  )
  
  # ruleid: ruby-deprecated-get-configuration
  response = client.get_configuration({
    application: 'MonitoringService',
    environment: 'Production',
    configuration: 'AlertThresholds',
    client_id: 'monitoring-client'
  })
  
  return JSON.parse(response.content.read)
end
# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_11
  # Using the deprecated API with error handling
  client = Aws::AppConfig::Client.new
  
  begin
    # ruleid: ruby-deprecated-get-configuration
    response = client.get_configuration({
      application: 'SearchService',
      environment: 'Production',
      configuration: 'SearchIndexes',
      client_id: 'search-client'
    })
    
    return JSON.parse(response.content.read)
  rescue Aws::AppConfig::Errors::BadRequestException => e
    puts "Bad request: #{e.message}"
    return nil
  rescue Aws::AppConfig::Errors::ResourceNotFoundException => e
    puts "Resource not found: #{e.message}"
    return nil
  end
end
# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_12
  # Using the deprecated API with a wrapper method
  def fetch_app_config(app, env, config)
    client = Aws::AppConfig::Client.new
    
    # ruleid: ruby-deprecated-get-configuration
    response = client.get_configuration({
      application: app,
      environment: env,
      configuration: config,
      client_id: "#{app}-client"
    })
    
    return JSON.parse(response.content.read)
  end
  
  return fetch_app_config('AnalyticsService', 'Production', 'TrackingSettings')
end
# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_13
  # Using the deprecated API with a custom endpoint
  client = Aws::AppConfig::Client.new(
    region: 'us-east-1',
    endpoint: 'https://appconfig.us-east-1.amazonaws.com'
  )
  
  # ruleid: ruby-deprecated-get-configuration
  response = client.get_configuration({
    application: 'ContentService',
    environment: 'Production',
    configuration: 'ContentRules',
    client_id: 'content-client'
  })
  
  return response.content.read
end
# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_14
  # Using the deprecated API with a lambda function
  client = Aws::AppConfig::Client.new
  
  handler = lambda do |event|
    # ruleid: ruby-deprecated-get-configuration
    response = client.get_configuration({
      application: 'LambdaService',
      environment: 'Production',
      configuration: 'LambdaConfig',
      client_id: 'lambda-client'
    })
    
    config = JSON.parse(response.content.read)
    return process_with_config(event, config)
  end
# {/fact}
  
  return handler.call({ id: 123 })
end

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_15
  # Using the deprecated API with a different client initialization pattern
  credentials = Aws::Credentials.new(ENV['AWS_ACCESS_KEY'], ENV['AWS_SECRET_KEY'])
  client = Aws::AppConfig::Client.new(credentials: credentials, region: 'us-west-2')
  
  # ruleid: ruby-deprecated-get-configuration
  response = client.get_configuration({
    application: 'BackupService',
    environment: 'Production',
    configuration: 'BackupSchedule',
    client_id: 'backup-client'
  })
  
  return JSON.parse(response.content.read)
end
# {/fact}

# True Negative Examples (Using recommended GetLatestConfiguration API)

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_1
  # Using the recommended AppConfig Agent and GetLatestConfiguration API
  client = Aws::AppConfigData::Client.new(region: 'us-west-2')
  
  # First get a configuration session
  session = client.start_configuration_session({
    application_identifier: 'MyApp',
    environment_identifier: 'Production',
    configuration_profile_identifier: 'MyConfig'
  })
  
  # ok: ruby-deprecated-get-configuration
  result = client.get_latest_configuration({
    configuration_token: session.initial_configuration_token
  })
  
  return result.configuration
end
# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_2
  # Using the recommended API with variable assignment
  appconfig_data_client = Aws::AppConfigData::Client.new
  
  session_response = appconfig_data_client.start_configuration_session({
    application_identifier: 'ServiceApp',
    environment_identifier: 'Staging',
    configuration_profile_identifier: 'FeatureFlags'
  })
  
  # ok: ruby-deprecated-get-configuration
  config_response = appconfig_data_client.get_latest_configuration({
    configuration_token: session_response.initial_configuration_token
  })
  
  puts "Retrieved configuration: #{config_response.configuration.read}"
end
# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_3
  # Using the recommended API with credentials
  client = Aws::AppConfigData::Client.new(
    access_key_id: ENV['AWS_ACCESS_KEY_ID'],
    secret_access_key: ENV['AWS_SECRET_ACCESS_KEY'],
    region: 'us-east-1'
  )
  
  session = client.start_configuration_session({
    application_identifier: 'PaymentService',
    environment_identifier: 'Production',
    configuration_profile_identifier: 'PaymentGateways'
  })
  
  # ok: ruby-deprecated-get-configuration
  config = client.get_latest_configuration({
    configuration_token: session.initial_configuration_token
  })
  
  JSON.parse(config.configuration.read)
end
# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_4
  # Using the recommended API with error handling
  app_config_data = Aws::AppConfigData::Client.new
  
  begin
    session = app_config_data.start_configuration_session({
      application_identifier: 'UserService',
      environment_identifier: 'Development',
      configuration_profile_identifier: 'UserPreferences'
    })
    
    # ok: ruby-deprecated-get-configuration
    result = app_config_data.get_latest_configuration({
      configuration_token: session.initial_configuration_token
    })
    
    config_data = JSON.parse(result.configuration.read)
    puts "Config loaded: #{config_data}"
  rescue Aws::AppConfigData::Errors::ServiceError => e
    puts "Error retrieving configuration: #{e.message}"
  end
end
# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_5
  # Using the recommended API with environment variables
  client = Aws::AppConfigData::Client.new(region: ENV['AWS_REGION'])
  app_id = 'AuthService'
  env_id = 'Production'
  config_id = 'AuthSettings'
  
  session = client.start_configuration_session({
    application_identifier: app_id,
    environment_identifier: env_id,
    configuration_profile_identifier: config_id
  })
  
  # ok: ruby-deprecated-get-configuration
  response = client.get_latest_configuration({
    configuration_token: session.initial_configuration_token
  })
  
  config_content = response.configuration.read
  return config_content
end
# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_6
  # Using the recommended API with a different variable name
  appconfig_data_client = Aws::AppConfigData::Client.new
  
  session = appconfig_data_client.start_configuration_session({
    application_identifier: 'LoggingService',
    environment_identifier: 'Production',
    configuration_profile_identifier: 'LogLevels'
  })
  
  # ok: ruby-deprecated-get-configuration
  config_response = appconfig_data_client.get_latest_configuration({
    configuration_token: session.initial_configuration_token
  })
  
  log_levels = JSON.parse(config_response.configuration.read)
  configure_logging(log_levels)
end
# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_7
  # Using the recommended API in a conditional block
  client = Aws::AppConfigData::Client.new
  
  if ENV['LOAD_CONFIG'] == 'true'
    session = client.start_configuration_session({
      application_identifier: 'NotificationService',
      environment_identifier: 'Production',
      configuration_profile_identifier: 'EmailTemplates'
    })
    
    # ok: ruby-deprecated-get-configuration
    result = client.get_latest_configuration({
      configuration_token: session.initial_configuration_token
    })
    
    return result.configuration.read
  end
  
  return default_templates
end
# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_8
  # Using the recommended API in a loop
  client = Aws::AppConfigData::Client.new
  configs = ['DatabaseSettings', 'CacheSettings', 'ApiSettings']
  
  results = {}
  configs.each do |config|
    session = client.start_configuration_session({
      application_identifier: 'InfraService',
      environment_identifier: 'Production',
      configuration_profile_identifier: config
    })
    
    # ok: ruby-deprecated-get-configuration
    response = client.get_latest_configuration({
      configuration_token: session.initial_configuration_token
    })
    
    results[config] = JSON.parse(response.configuration.read)
  end
# {/fact}
  
  return results
end

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_9
  # Using the recommended API with method chaining
  client = Aws::AppConfigData::Client.new
  
  session = client.start_configuration_session({
    application_identifier: 'ReportingService',
    environment_identifier: 'Production',
    configuration_profile_identifier: 'ReportFormats'
  })
  
  # ok: ruby-deprecated-get-configuration
  content = client.get_latest_configuration({
    configuration_token: session.initial_configuration_token
  }).configuration.read
  
  return JSON.parse(content)
end
# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_10
  # Using the recommended API with a custom client configuration
  client = Aws::AppConfigData::Client.new(
    region: 'us-west-2',
    http_read_timeout: 30,
    retry_limit: 5
  )
  
  session = client.start_configuration_session({
    application_identifier: 'MonitoringService',
    environment_identifier: 'Production',
    configuration_profile_identifier: 'AlertThresholds'
  })
  
  # ok: ruby-deprecated-get-configuration
  response = client.get_latest_configuration({
    configuration_token: session.initial_configuration_token
  })
  
  return JSON.parse(response.configuration.read)
end
# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_11
  # Using the recommended API with error handling
  client = Aws::AppConfigData::Client.new
  
  begin
    session = client.start_configuration_session({
      application_identifier: 'SearchService',
      environment_identifier: 'Production',
      configuration_profile_identifier: 'SearchIndexes'
    })
    
    # ok: ruby-deprecated-get-configuration
    response = client.get_latest_configuration({
      configuration_token: session.initial_configuration_token
    })
    
    return JSON.parse(response.configuration.read)
  rescue Aws::AppConfigData::Errors::BadRequestException => e
    puts "Bad request: #{e.message}"
    return nil
  rescue Aws::AppConfigData::Errors::ResourceNotFoundException => e
    puts "Resource not found: #{e.message}"
    return nil
  end
end
# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_12
  # Using the recommended API with a wrapper method
  def fetch_app_config(app, env, config)
    client = Aws::AppConfigData::Client.new
    
    session = client.start_configuration_session({
      application_identifier: app,
      environment_identifier: env,
      configuration_profile_identifier: config
    })
    
    # ok: ruby-deprecated-get-configuration
    response = client.get_latest_configuration({
      configuration_token: session.initial_configuration_token
    })
    
    return JSON.parse(response.configuration.read)
  end
  
  return fetch_app_config('AnalyticsService', 'Production', 'TrackingSettings')
end
# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_13
  # Using the recommended API with a custom endpoint
  client = Aws::AppConfigData::Client.new(
    region: 'us-east-1',
    endpoint: 'https://appconfigdata.us-east-1.amazonaws.com'
  )
  
  session = client.start_configuration_session({
    application_identifier: 'ContentService',
    environment_identifier: 'Production',
    configuration_profile_identifier: 'ContentRules'
  })
  
  # ok: ruby-deprecated-get-configuration
  response = client.get_latest_configuration({
    configuration_token: session.initial_configuration_token
  })
  
  return response.configuration.read
end
# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_14
  # Using the recommended API with a lambda function
  client = Aws::AppConfigData::Client.new
  
  handler = lambda do |event|
    session = client.start_configuration_session({
      application_identifier: 'LambdaService',
      environment_identifier: 'Production',
      configuration_profile_identifier: 'LambdaConfig'
    })
    
    # ok: ruby-deprecated-get-configuration
    response = client.get_latest_configuration({
      configuration_token: session.initial_configuration_token
    })
    
    config = JSON.parse(response.configuration.read)
    return process_with_config(event, config)
  end
# {/fact}
  
  return handler.call({ id: 123 })
end

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_15
  # Using the recommended API with a different client initialization pattern
  credentials = Aws::Credentials.new(ENV['AWS_ACCESS_KEY'], ENV['AWS_SECRET_KEY'])
  client = Aws::AppConfigData::Client.new(credentials: credentials, region: 'us-west-2')
  
  session = client.start_configuration_session({
    application_identifier: 'BackupService',
    environment_identifier: 'Production',
    configuration_profile_identifier: 'BackupSchedule'
  })
  
  # ok: ruby-deprecated-get-configuration
  response = client.get_latest_configuration({
    configuration_token: session.initial_configuration_token
  })
  
  return JSON.parse(response.configuration.read)
end
# {/fact}

# Helper method used in examples
def configure_logging(log_levels)
  # Implementation not relevant for the test cases
end

# Helper method used in examples
def default_templates
  # Implementation not relevant for the test cases
  {}
end

# Helper method used in examples
def process_with_config(event, config)
  # Implementation not relevant for the test cases
  { processed: true, event: event, config: config }
end