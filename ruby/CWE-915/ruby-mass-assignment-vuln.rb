# Required imports for Rails applications
require 'rails'
require 'active_record'

# Model definitions for examples
class User < ActiveRecord::Base
  # User model with sensitive attributes
  # Attributes: id, name, email, admin, role, api_key, password
end

class Product < ActiveRecord::Base
  # Product model
  # Attributes: id, name, price, description, owner_id
end

class Order < ActiveRecord::Base
  # Order model
  # Attributes: id, user_id, product_id, quantity, status
end

# TRUE POSITIVES - Vulnerable code examples

# {fact rule=mass-assignment@v1.0 defects=1}
def bad_case_1
  # Mass assignment vulnerability in controller action
  # Directly using params hash without filtering
  def create
    # ruleid: ruby-mass-assignment-vuln
    @user = User.new(params[:user])
    
    if @user.save
      redirect_to @user, notice: 'User was successfully created.'
    else
      render action: 'new'
    end
  end
end
# {/fact}

# {fact rule=mass-assignment@v1.0 defects=1}
def bad_case_2
  # Mass assignment vulnerability with update method
  def update
    @user = User.find(params[:id])
    
    # ruleid: ruby-mass-assignment-vuln
    if @user.update_attributes(params[:user])
      redirect_to @user, notice: 'User was successfully updated.'
    else
      render action: 'edit'
    end
  end
end
# {/fact}

# {fact rule=mass-assignment@v1.0 defects=1}
def bad_case_3
  # Mass assignment vulnerability with create method
  def create_product
    # ruleid: ruby-mass-assignment-vuln
    @product = Product.create(params[:product])
    
    redirect_to products_path
  end
end
# {/fact}

# {fact rule=mass-assignment@v1.0 defects=1}
def bad_case_4
  # Mass assignment vulnerability with nested attributes
  def update_order
    @order = Order.find(params[:id])
    
    # ruleid: ruby-mass-assignment-vuln
    @order.update(params[:order])
    
    redirect_to orders_path
  end
end
# {/fact}

# {fact rule=mass-assignment@v1.0 defects=1}
def bad_case_5
  # Mass assignment vulnerability with assign_attributes
  def update_profile
    @user = User.find(current_user.id)
    
    # ruleid: ruby-mass-assignment-vuln
    @user.assign_attributes(params[:user])
    @user.save
    
    redirect_to profile_path
  end
end
# {/fact}

# {fact rule=mass-assignment@v1.0 defects=1}
def bad_case_6
  # Mass assignment vulnerability with update_all
  def bulk_update
    # ruleid: ruby-mass-assignment-vuln
    User.where(id: params[:user_ids]).update_all(params[:user_attributes])
    
    redirect_to users_path, notice: 'Users updated successfully'
  end
end
# {/fact}

# {fact rule=mass-assignment@v1.0 defects=1}
def bad_case_7
  # Mass assignment vulnerability with attributes=
  def update_settings
    @user = User.find(current_user.id)
    
    # ruleid: ruby-mass-assignment-vuln
    @user.attributes = params[:user]
    @user.save
    
    redirect_to settings_path
  end
end
# {/fact}

# {fact rule=mass-assignment@v1.0 defects=1}
def bad_case_8
  # Mass assignment vulnerability with nested parameters
  def create_order_with_items
    # ruleid: ruby-mass-assignment-vuln
    @order = Order.new(params[:order])
    
    if @order.save
      redirect_to @order, notice: 'Order created successfully'
    else
      render :new
    end
  end
end
# {/fact}

# {fact rule=mass-assignment@v1.0 defects=1}
def bad_case_9
  # Mass assignment vulnerability with JSON parameters
  def api_update
    @user = User.find(params[:id])
    
    # ruleid: ruby-mass-assignment-vuln
    if @user.update(JSON.parse(request.body.read))
      render json: @user
    else
      render json: @user.errors, status: :unprocessable_entity
    end
  end
end
# {/fact}

# {fact rule=mass-assignment@v1.0 defects=1}
def bad_case_10
  # Mass assignment vulnerability with request parameters
  def create_from_api
    # ruleid: ruby-mass-assignment-vuln
    @product = Product.create(request.POST)
    
    render json: @product
  end
end
# {/fact}

# {fact rule=mass-assignment@v1.0 defects=1}
def bad_case_11
  # Mass assignment vulnerability with filtered but still unsafe params
  def update_admin
    @user = User.find(params[:id])
    filtered_params = params[:user].except(:some_field)
    
    # ruleid: ruby-mass-assignment-vuln
    @user.update(filtered_params)
    
    redirect_to admin_users_path
  end
end
# {/fact}

# {fact rule=mass-assignment@v1.0 defects=1}
def bad_case_12
  # Mass assignment vulnerability with dynamic attributes
  def update_dynamic
    @user = User.find(params[:id])
    
    # ruleid: ruby-mass-assignment-vuln
    @user.update(params[params[:entity_type]])
    
    redirect_to users_path
  end
end
# {/fact}

# {fact rule=mass-assignment@v1.0 defects=1}
def bad_case_13
  # Mass assignment vulnerability with conditional parameters
  def conditional_update
    @user = User.find(params[:id])
    update_params = params[:admin_mode] ? params[:user] : params[:user_limited]
    
    # ruleid: ruby-mass-assignment-vuln
    @user.update(update_params)
    
    redirect_to users_path
  end
end
# {/fact}

# {fact rule=mass-assignment@v1.0 defects=1}
def bad_case_14
  # Mass assignment vulnerability with parameter merging
  def create_with_defaults
    default_params = { active: true }
    merged_params = default_params.merge(params[:user])
    
    # ruleid: ruby-mass-assignment-vuln
    @user = User.create(merged_params)
    
    redirect_to users_path
  end
end
# {/fact}

# {fact rule=mass-assignment@v1.0 defects=1}
def bad_case_15
  # Mass assignment vulnerability with parameter transformation
  def create_with_transformation
    transformed_params = params[:user].transform_keys(&:to_sym)
    
    # ruleid: ruby-mass-assignment-vuln
    @user = User.create(transformed_params)
    
    redirect_to users_path
  end
end
# {/fact}

# TRUE NEGATIVES - Secure code examples

# {fact rule=mass-assignment@v1.0 defects=0}
def good_case_1
  # Using strong parameters to prevent mass assignment
  def create
    # ok: ruby-mass-assignment-vuln
    @user = User.new(user_params)
    
    if @user.save
      redirect_to @user, notice: 'User was successfully created.'
    else
      render action: 'new'
    end
  end
  
  private
  
  def user_params
    params.require(:user).permit(:name, :email)
  end
end
# {/fact}

# {fact rule=mass-assignment@v1.0 defects=0}
def good_case_2
  # Using strong parameters with update method
  def update
    @user = User.find(params[:id])
    
    # ok: ruby-mass-assignment-vuln
    if @user.update(user_params)
      redirect_to @user, notice: 'User was successfully updated.'
    else
      render action: 'edit'
    end
  end
  
  private
  
  def user_params
    params.require(:user).permit(:name, :email)
  end
end
# {/fact}

# {fact rule=mass-assignment@v1.0 defects=0}
def good_case_3
  # Using attr_accessible to whitelist attributes (Rails 3.x approach)
  class User < ActiveRecord::Base
    # ok: ruby-mass-assignment-vuln
    attr_accessible :name, :email
  end
  
  def create
    @user = User.new(params[:user])
    
    if @user.save
      redirect_to @user, notice: 'User was successfully created.'
    else
      render action: 'new'
    end
  end
end
# {/fact}

# {fact rule=mass-assignment@v1.0 defects=0}
def good_case_4
  # Using strong parameters with nested attributes
  def update_order
    @order = Order.find(params[:id])
    
    # ok: ruby-mass-assignment-vuln
    @order.update(order_params)
    
    redirect_to orders_path
  end
  
  private
  
  def order_params
    params.require(:order).permit(:status, :quantity, 
      line_items_attributes: [:id, :product_id, :quantity])
  end
end
# {/fact}

# {fact rule=mass-assignment@v1.0 defects=0}
def good_case_5
  # Using strong parameters with assign_attributes
  def update_profile
    @user = User.find(current_user.id)
    
    # ok: ruby-mass-assignment-vuln
    @user.assign_attributes(user_params)
    @user.save
    
    redirect_to profile_path
  end
  
  private
  
  def user_params
    params.require(:user).permit(:name, :email)
  end
end
# {/fact}

# {fact rule=mass-assignment@v1.0 defects=0}
def good_case_6
  # Manually assigning attributes instead of mass assignment
  def update_settings
    @user = User.find(current_user.id)
    
    # ok: ruby-mass-assignment-vuln
    @user.name = params[:user][:name]
    @user.email = params[:user][:email]
    @user.save
    
    redirect_to settings_path
  end
end
# {/fact}

# {fact rule=mass-assignment@v1.0 defects=0}
def good_case_7
  # Using config.active_record.whitelist_attributes
  # Application configuration in config/application.rb
  def application_config
    # ok: ruby-mass-assignment-vuln
    config.active_record.whitelist_attributes = true
  end
  
  def create
    @user = User.new(params[:user])
    
    if @user.save
      redirect_to @user, notice: 'User was successfully created.'
    else
      render action: 'new'
    end
  end
end
# {/fact}

# {fact rule=mass-assignment@v1.0 defects=0}
def good_case_8
  # Using strong parameters with conditional logic
  def update_user
    @user = User.find(params[:id])
    
    # ok: ruby-mass-assignment-vuln
    if @user.update(user_params)
      redirect_to @user, notice: 'User was successfully updated.'
    else
      render action: 'edit'
    end
  end
  
  private
  
  def user_params
    permitted_params = [:name, :email]
    permitted_params << :role if current_user.admin?
    params.require(:user).permit(permitted_params)
  end
end
# {/fact}

# {fact rule=mass-assignment@v1.0 defects=0}
def good_case_9
  # Using strong parameters with JSON API
  def api_update
    @user = User.find(params[:id])
    
    # ok: ruby-mass-assignment-vuln
    if @user.update(user_params)
      render json: @user
    else
      render json: @user.errors, status: :unprocessable_entity
    end
  end
  
  private
  
  def user_params
    params.require(:user).permit(:name, :email)
  end
end
# {/fact}

# {fact rule=mass-assignment@v1.0 defects=0}
def good_case_10
  # Using attr_protected to blacklist attributes (Rails 3.x approach)
  class User < ActiveRecord::Base
    # ok: ruby-mass-assignment-vuln
    attr_protected :admin, :role
  end
  
  def create
    @user = User.new(params[:user])
    
    if @user.save
      redirect_to @user, notice: 'User was successfully created.'
    else
      render action: 'new'
    end
  end
end
# {/fact}

# {fact rule=mass-assignment@v1.0 defects=0}
def good_case_11
  # Using strong parameters with nested resources
  def create_product_review
    @product = Product.find(params[:product_id])
    
    # ok: ruby-mass-assignment-vuln
    @review = @product.reviews.build(review_params)
    @review.user = current_user
    
    if @review.save
      redirect_to @product, notice: 'Review was successfully created.'
    else
      render action: 'new'
    end
  end
  
  private
  
  def review_params
    params.require(:review).permit(:title, :content, :rating)
  end
end
# {/fact}

# {fact rule=mass-assignment@v1.0 defects=0}
def good_case_12
  # Using strong parameters with arrays
  def bulk_update
    # ok: ruby-mass-assignment-vuln
    params[:products].each do |product_params|
      product = Product.find(product_params[:id])
      product.update(product_update_params(product_params))
    end
    
    redirect_to products_path, notice: 'Products updated successfully'
  end
# {/fact}
  
  private
  
  def product_update_params(product_params)
    ActionController::Parameters.new(product_params).permit(:name, :price)
  end
end

# {fact rule=mass-assignment@v1.0 defects=0}
def good_case_13
  # Using strong parameters with transformed data
  def create_with_transformation
    # ok: ruby-mass-assignment-vuln
    @user = User.create(user_params)
    
    redirect_to users_path
  end
  
  private
  
  def user_params
    transformed_data = params.require(:user).permit(:name, :email)
    transformed_data[:name] = transformed_data[:name].titleize if transformed_data[:name]
    transformed_data
  end
end
# {/fact}

# {fact rule=mass-assignment@v1.0 defects=0}
def good_case_14
  # Using strong parameters with default values
  def create_with_defaults
    # ok: ruby-mass-assignment-vuln
    @user = User.create(user_params)
    
    redirect_to users_path
  end
  
  private
  
  def user_params
    user_attributes = params.require(:user).permit(:name, :email)
    user_attributes.reverse_merge(active: true)
  end
end
# {/fact}

# {fact rule=mass-assignment@v1.0 defects=0}
def good_case_15
  # Using strong parameters with API versioning
  def api_v1_create
    # ok: ruby-mass-assignment-vuln
    @user = User.create(user_params)
    
    render json: @user
  end
  
  private
  
  def user_params
    case params[:api_version]
    when 'v1'
      params.require(:user).permit(:name, :email)
    when 'v2'
      params.require(:user).permit(:name, :email, :preferences)
    else
      params.require(:user).permit(:name)
    end
  end
end
# {/fact}