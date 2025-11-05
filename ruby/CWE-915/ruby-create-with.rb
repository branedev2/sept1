# frozen_string_literal: true
require 'rails'
require 'active_record'

# True Positive Examples (Vulnerable Code)

# {fact rule=mass-assignment@v1.0 defects=1}
def bad_case_1
  # Using create_with directly with user-supplied parameters
  params = ActionController::Parameters.new(JSON.parse(request.body.read))
  
  # ruleid: ruby-create-with
  User.create_with(params).find_or_create_by(email: params[:email])
end
# {/fact}

# {fact rule=mass-assignment@v1.0 defects=1}
def bad_case_2
  # Using create_with with request parameters without filtering
  user_params = params.to_unsafe_h
  
  # ruleid: ruby-create-with
  User.create_with(user_params).find_or_initialize_by(id: params[:id])
end
# {/fact}

# {fact rule=mass-assignment@v1.0 defects=1}
def bad_case_3
  # Using create_with with request parameters in a controller action
  def create
    input_data = request.GET
    
    # ruleid: ruby-create-with
    @user = User.create_with(input_data).find_or_create_by(username: input_data[:username])
    render json: @user
  end
end
# {/fact}

# {fact rule=mass-assignment@v1.0 defects=1}
def bad_case_4
  # Using create_with with form data without proper filtering
  form_data = params[:user]
  
  # ruleid: ruby-create-with
  User.create_with(form_data).find_or_create_by!(email: form_data[:email])
end
# {/fact}

# {fact rule=mass-assignment@v1.0 defects=1}
def bad_case_5
  # Using create_with with JSON data from request
  json_data = JSON.parse(request.body.read)
  
  # ruleid: ruby-create-with
  Admin.create_with(json_data).find_or_initialize_by(username: json_data['username'])
end
# {/fact}

# {fact rule=mass-assignment@v1.0 defects=1}
def bad_case_6
  # Using create_with with request parameters in a nested structure
  account_params = params[:account]
  
  # ruleid: ruby-create-with
  Account.create_with(account_params).find_or_create_by(name: account_params[:name])
end
# {/fact}

# {fact rule=mass-assignment@v1.0 defects=1}
def bad_case_7
  # Using create_with with headers as parameters
  header_data = request.headers.to_h
  
  # ruleid: ruby-create-with
  ApiKey.create_with(header_data).find_or_create_by(token: header_data['HTTP_AUTHORIZATION'])
end
# {/fact}

# {fact rule=mass-assignment@v1.0 defects=1}
def bad_case_8
  # Using create_with with cookies as parameters
  cookie_data = request.cookies
  
  # ruleid: ruby-create-with
  UserPreference.create_with(cookie_data).find_or_create_by(user_id: cookie_data[:user_id])
end
# {/fact}

# {fact rule=mass-assignment@v1.0 defects=1}
def bad_case_9
  # Using create_with with merged parameters
  user_input = params[:user].merge(params[:profile])
  
  # ruleid: ruby-create-with
  UserProfile.create_with(user_input).find_or_create_by(email: params[:user][:email])
end
# {/fact}

# {fact rule=mass-assignment@v1.0 defects=1}
def bad_case_10
  # Using create_with with parameters in a loop
  params[:users].each do |user_params|
    # ruleid: ruby-create-with
    User.create_with(user_params).find_or_create_by(email: user_params[:email])
  end
# {/fact}
end

# {fact rule=mass-assignment@v1.0 defects=1}
def bad_case_11
  # Using create_with with parameters from XML
  xml_data = Hash.from_xml(request.body.read)
  
  # ruleid: ruby-create-with
  Product.create_with(xml_data['product']).find_or_create_by(sku: xml_data['product']['sku'])
end
# {/fact}

# {fact rule=mass-assignment@v1.0 defects=1}
def bad_case_12
  # Using create_with with parameters in a conditional
  if params[:create_admin]
    admin_params = params[:admin]
    # ruleid: ruby-create-with
    Admin.create_with(admin_params).find_or_create_by(email: admin_params[:email])
  end
end
# {/fact}

# {fact rule=mass-assignment@v1.0 defects=1}
def bad_case_13
  # Using create_with with parameters in a transaction
  ActiveRecord::Base.transaction do
    # ruleid: ruby-create-with
    User.create_with(params[:user]).find_or_create_by(email: params[:user][:email])
  end
# {/fact}
end

# {fact rule=mass-assignment@v1.0 defects=1}
def bad_case_14
  # Using create_with with parameters from a different format
  yaml_data = YAML.safe_load(request.body.read)
  
  # ruleid: ruby-create-with
  Configuration.create_with(yaml_data).find_or_create_by(name: yaml_data['name'])
end
# {/fact}

# {fact rule=mass-assignment@v1.0 defects=1}
def bad_case_15
  # Using create_with with parameters and additional options
  user_input = params[:user]
  options = { validate: false }
  
  # ruleid: ruby-create-with
  User.create_with(user_input).find_or_create_by(email: user_input[:email], **options)
end
# {/fact}

# True Negative Examples (Safe Code)

# {fact rule=mass-assignment@v1.0 defects=0}
def good_case_1
  # Using create_with with strong parameters
  user_params = params.require(:user).permit(:name, :email)
  
  # ok: ruby-create-with
  User.create_with(user_params).find_or_create_by(email: params[:user][:email])
end
# {/fact}

# {fact rule=mass-assignment@v1.0 defects=0}
def good_case_2
  # Using create_with with explicitly defined attributes
  # ok: ruby-create-with
  User.create_with(name: params[:name], email: params[:email]).find_or_create_by(username: params[:username])
end
# {/fact}

# {fact rule=mass-assignment@v1.0 defects=0}
def good_case_3
  # Using create_with with filtered parameters
  allowed_params = params.slice(:name, :email)
  
  # ok: ruby-create-with
  User.create_with(allowed_params).find_or_create_by(email: params[:email])
end
# {/fact}

# {fact rule=mass-assignment@v1.0 defects=0}
def good_case_4
  # Using create_with with sanitized input
  sanitized_params = {
    name: ActionController::Base.helpers.sanitize(params[:name]),
    email: params[:email]&.downcase
  }
  
  # ok: ruby-create-with
  User.create_with(sanitized_params).find_or_create_by(email: sanitized_params[:email])
end
# {/fact}

# {fact rule=mass-assignment@v1.0 defects=0}
def good_case_5
  # Using create_with with hardcoded values
  # ok: ruby-create-with
  User.create_with(role: 'user', active: true).find_or_create_by(email: params[:email])
end
# {/fact}

# {fact rule=mass-assignment@v1.0 defects=0}
def good_case_6
  # Using create_with with validated parameters
  user_params = params.require(:user).permit(:name, :email)
  
  if valid_email?(user_params[:email])
    # ok: ruby-create-with
    User.create_with(user_params).find_or_create_by(email: user_params[:email])
  end
end
# {/fact}

# {fact rule=mass-assignment@v1.0 defects=0}
def good_case_7
  # Using create_with with non-sensitive attributes
  # ok: ruby-create-with
  UserPreference.create_with(theme: params[:theme], language: params[:language])
    .find_or_create_by(user_id: current_user.id)
end
# {/fact}

# {fact rule=mass-assignment@v1.0 defects=0}
def good_case_8
  # Using create_with with explicitly defined attributes from request
  # ok: ruby-create-with
  User.create_with(
    name: params[:name],
    email: params[:email],
    created_at: Time.now
  ).find_or_create_by(username: params[:username])
end
# {/fact}

# {fact rule=mass-assignment@v1.0 defects=0}
def good_case_9
  # Using create_with with attributes after validation
  email = params[:email]
  if email =~ /\A[\w+\-.]+@[a-z\d\-.]+\.[a-z]+\z/i
    # ok: ruby-create-with
    User.create_with(email: email, verified: false).find_or_create_by(username: params[:username])
  end
end
# {/fact}

# {fact rule=mass-assignment@v1.0 defects=0}
def good_case_10
  # Using create_with with transformed parameters
  transformed_params = {
    name: params[:name]&.titleize,
    email: params[:email]&.downcase
  }
  
  # ok: ruby-create-with
  User.create_with(transformed_params).find_or_create_by(email: transformed_params[:email])
end
# {/fact}

# {fact rule=mass-assignment@v1.0 defects=0}
def good_case_11
  # Using create_with with default values and only one user parameter
  # ok: ruby-create-with
  User.create_with(
    name: params[:name],
    active: true,
    role: 'standard',
    created_at: Time.now
  ).find_or_create_by(email: params[:email])
end
# {/fact}

# {fact rule=mass-assignment@v1.0 defects=0}
def good_case_12
  # Using create_with with parameters after authorization check
  if current_user.admin?
    admin_params = params.require(:admin).permit(:name, :email, :role)
    # ok: ruby-create-with
    Admin.create_with(admin_params).find_or_create_by(email: admin_params[:email])
  end
end
# {/fact}

# {fact rule=mass-assignment@v1.0 defects=0}
def good_case_13
  # Using create_with with non-request parameters
  config = { timeout: 30, retries: 3 }
  
  # ok: ruby-create-with
  ApiConfiguration.create_with(config).find_or_create_by(name: 'default')
end
# {/fact}

# {fact rule=mass-assignment@v1.0 defects=0}
def good_case_14
  # Using create_with with constant values
  # ok: ruby-create-with
  SystemSetting.create_with(
    value: 'enabled',
    updated_at: Time.now
  ).find_or_create_by(key: params[:setting_key])
end
# {/fact}

# {fact rule=mass-assignment@v1.0 defects=0}
def good_case_15
  # Using create_with with parameters after type checking
  if params[:age].is_a?(Integer) && params[:age] > 0 && params[:age] < 120
    # ok: ruby-create-with
    User.create_with(
      name: params[:name],
      age: params[:age]
    ).find_or_create_by(email: params[:email])
  end
end
# {/fact}

def valid_email?(email)
  email =~ /\A[\w+\-.]+@[a-z\d\-.]+\.[a-z]+\z/i
end