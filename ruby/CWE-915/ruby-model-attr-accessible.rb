# Mass Assignment Vulnerability Test Cases

class ApplicationController < ActionController::Base
  # Common base controller
end

# TRUE POSITIVES (Vulnerable Code)

class UsersController < ApplicationController
  # {fact rule=mass-assignment@v1.0 defects=1}
  def bad_case_1
    # ruleid: ruby-model-attr-accessible
    params.permit(:name, :email, :admin, :password)
    
    @user = User.new(params.permit(:name, :email, :admin, :password))
    @user.save
  end
  # {/fact}

  # {fact rule=mass-assignment@v1.0 defects=1}
  def bad_case_2
    # ruleid: ruby-model-attr-accessible
    @user = User.create(params.permit(:username, :email, :token, :role))
    
    if @user.save
      redirect_to @user
    else
      render 'new'
    end
  end
  # {/fact}

  # {fact rule=mass-assignment@v1.0 defects=1}
  def bad_case_3
    # ruleid: ruby-model-attr-accessible
    user_params = params.require(:user).permit(:name, :email, :account_id, :password)
    
    @user = User.find(params[:id])
    @user.update(user_params)
    redirect_to @user
  end
  # {/fact}

  # {fact rule=mass-assignment@v1.0 defects=1}
  def bad_case_4
    # ruleid: ruby-model-attr-accessible
    @user = User.find(params[:id])
    
    if @user.update(params.require(:user).permit(:name, :email, :banned, :role))
      redirect_to users_path, notice: 'User was successfully updated.'
    else
      render :edit
    end
  end
  # {/fact}

  # {fact rule=mass-assignment@v1.0 defects=1}
  def bad_case_5
    # ruleid: ruby-model-attr-accessible
    permitted = params.permit(:name, :email, :admin, :token, :password)
    
    @user = User.new(permitted)
    @user.save
    redirect_to @user
  end
  # {/fact}
end

class AccountsController < ApplicationController
  # {fact rule=mass-assignment@v1.0 defects=1}
  def bad_case_6
    # ruleid: ruby-model-attr-accessible
    account_params = params.require(:account).permit(:name, :description, :token, :owner_id)
    
    @account = Account.new(account_params)
    @account.save
    redirect_to @account
  end
  # {/fact}

  # {fact rule=mass-assignment@v1.0 defects=1}
  def bad_case_7
    # ruleid: ruby-model-attr-accessible
    @account = Account.find(params[:id])
    
    if @account.update(params.require(:account).permit(:name, :description, :account_id, :active))
      redirect_to @account, notice: 'Account updated successfully'
    else
      render :edit
    end
  end
  # {/fact}
end

class AdminController < ApplicationController
  # {fact rule=mass-assignment@v1.0 defects=1}
  def bad_case_8
    # ruleid: ruby-model-attr-accessible
    # Using permit! is extremely dangerous as it allows all parameters
    @user = User.find(params[:id])
    @user.update(params.require(:user).permit!)
    
    redirect_to admin_users_path
  end
  # {/fact}
end

class ProductsController < ApplicationController
  # {fact rule=mass-assignment@v1.0 defects=1}
  def bad_case_9
    # ruleid: ruby-model-attr-accessible
    # Allowing sensitive attributes in nested parameters
    product_params = params.require(:product).permit(
      :name, 
      :price, 
      :description, 
      category_attributes: [:name, :admin_only]
    )
    
    @product = Product.new(product_params)
    @product.save
  end
  # {/fact}
end

class OrdersController < ApplicationController
  # {fact rule=mass-assignment@v1.0 defects=1}
  def bad_case_10
    # ruleid: ruby-model-attr-accessible
    # Allowing sensitive attributes in an array of permitted parameters
    permitted_attrs = [:customer_name, :amount, :admin_override, :token]
    
    @order = Order.new(params.require(:order).permit(*permitted_attrs))
    @order.save
  end
  # {/fact}
end

class SettingsController < ApplicationController
  # {fact rule=mass-assignment@v1.0 defects=1}
  def bad_case_11
    # ruleid: ruby-model-attr-accessible
    # Dynamically building permitted parameters with sensitive attributes
    permitted_params = [:name, :email]
    permitted_params << :admin if params[:include_admin]
    permitted_params << :account_id
    
    @settings = Settings.new(params.require(:settings).permit(*permitted_params))
    @settings.save
  end
  # {/fact}
end

class ProfilesController < ApplicationController
  # {fact rule=mass-assignment@v1.0 defects=1}
  def bad_case_12
    # ruleid: ruby-model-attr-accessible
    # Using a method to define permitted parameters including sensitive ones
    @profile = Profile.find(params[:id])
    @profile.update(profile_params)
    
    redirect_to @profile
  end
  # {/fact}
  
  private
  
  def profile_params
    params.require(:profile).permit(:name, :bio, :banned, :admin_notes)
  end
end

class RolesController < ApplicationController
  # {fact rule=mass-assignment@v1.0 defects=1}
  def bad_case_13
    # ruleid: ruby-model-attr-accessible
    # Multiple sensitive attributes in different contexts
    role_params = params.require(:role).permit(
      :name, 
      :description, 
      :admin,
      permissions: [:read, :write, :delete, :token]
    )
    
    @role = Role.create(role_params)
    redirect_to @role
  end
  # {/fact}
end

class ApiKeysController < ApplicationController
  # {fact rule=mass-assignment@v1.0 defects=1}
  def bad_case_14
    # ruleid: ruby-model-attr-accessible
    # Sensitive attributes in nested arrays
    key_params = params.require(:api_key).permit(
      :name,
      :expires_at,
      scopes: [],
      metadata: [:created_by, :token, :admin_generated]
    )
    
    @api_key = ApiKey.new(key_params)
    @api_key.save
  end
  # {/fact}
end

class SessionsController < ApplicationController
  # {fact rule=mass-assignment@v1.0 defects=1}
  def bad_case_15
    # ruleid: ruby-model-attr-accessible
    # Conditionally permitting sensitive attributes
    if current_user.super_admin?
      session_params = params.require(:session).permit(:user_id, :token, :admin_session)
    else
      session_params = params.require(:session).permit(:user_id)
    end
    
    @session = Session.create(session_params)
  end
  # {/fact}
end

# TRUE NEGATIVES (Safe Code)

class SafeUsersController < ApplicationController
  # {fact rule=mass-assignment@v1.0 defects=0}
  def good_case_1
    # ok: ruby-model-attr-accessible
    # Only permitting safe attributes
    @user = User.new(params.require(:user).permit(:name, :email, :bio))
    @user.save
  end
  # {/fact}

  # {fact rule=mass-assignment@v1.0 defects=0}
  def good_case_2
    # ok: ruby-model-attr-accessible
    # Explicitly setting sensitive attributes separately with validation
    user_params = params.require(:user).permit(:name, :email, :password)
    
    @user = User.new(user_params)
    @user.admin = false # Explicitly set, not mass-assigned
    @user.save
  end
  # {/fact}

  # {fact rule=mass-assignment@v1.0 defects=0}
  def good_case_3
    # ok: ruby-model-attr-accessible
    # Using role-based attribute filtering
    @user = User.find(params[:id])
    
    permitted_attrs = [:name, :email]
    # Adding admin attribute only if current user is an admin and with explicit check
    if current_user.admin? && params[:user][:make_admin].present?
      @user.admin = true
    end
    
    @user.update(params.require(:user).permit(*permitted_attrs))
  end
  # {/fact}
end

class SafeAccountsController < ApplicationController
  # {fact rule=mass-assignment@v1.0 defects=0}
  def good_case_4
    # ok: ruby-model-attr-accessible
    # Safe attributes only
    @account = Account.new(params.require(:account).permit(:name, :description, :public))
    
    # Set sensitive attributes explicitly after validation
    @account.account_id = generate_unique_account_id
    @account.save
  end
  # {/fact}

  # {fact rule=mass-assignment@v1.0 defects=0}
  def good_case_5
    # ok: ruby-model-attr-accessible
    # Using virtual attributes instead of sensitive ones
    account_params = params.require(:account).permit(:name, :description, :visibility)
    
    @account = Account.new(account_params)
    # Process virtual attribute safely
    @account.public = (account_params[:visibility] == 'public')
    @account.save
  end
  # {/fact}
end

class SafeProductsController < ApplicationController
  # {fact rule=mass-assignment@v1.0 defects=0}
  def good_case_6
    # ok: ruby-model-attr-accessible
    # Safe nested attributes
    product_params = params.require(:product).permit(
      :name, 
      :price, 
      :description,
      category_attributes: [:name, :description]
    )
    
    @product = Product.new(product_params)
    # Set sensitive attributes explicitly
    if current_user.admin?
      @product.category.admin_only = params[:product][:category][:admin_only] == '1'
    end
    @product.save
  end
  # {/fact}
end

class SafeOrdersController < ApplicationController
  # {fact rule=mass-assignment@v1.0 defects=0}
  def good_case_7
    # ok: ruby-model-attr-accessible
    # Using service objects for sensitive operations
    order_params = params.require(:order).permit(:customer_name, :amount)
    
    @order = Order.new(order_params)
    
    # Handle sensitive operations separately
    if current_user.admin? && params[:admin_override].present?
      AdminOrderService.apply_override(@order, params[:admin_override])
    end
    
    @order.save
  end
  # {/fact}
end

class SafeSettingsController < ApplicationController
  # {fact rule=mass-assignment@v1.0 defects=0}
  def good_case_8
    # ok: ruby-model-attr-accessible
    # Safe dynamic parameters
    permitted_params = [:name, :email, :theme, :language]
    
    @settings = Settings.new(params.require(:settings).permit(*permitted_params))
    @settings.save
  end
  # {/fact}
end

class SafeProfilesController < ApplicationController
  # {fact rule=mass-assignment@v1.0 defects=0}
  def good_case_9
    # ok: ruby-model-attr-accessible
    # Safe method for permitted parameters
    @profile = Profile.find(params[:id])
    @profile.update(safe_profile_params)
    
    # Handle sensitive attributes separately with authorization
    if current_user.admin? && params[:profile][:banned].present?
      @profile.banned = params[:profile][:banned]
      @profile.save
    end
    
    redirect_to @profile
  end
  # {/fact}
  
  private
  
  def safe_profile_params
    params.require(:profile).permit(:name, :bio, :avatar)
  end
end

class SafeRolesController < ApplicationController
  # {fact rule=mass-assignment@v1.0 defects=0}
  def good_case_10
    # ok: ruby-model-attr-accessible
    # Safe nested attributes without sensitive fields
    role_params = params.require(:role).permit(
      :name, 
      :description,
      permissions: [:read, :write, :delete]
    )
    
    @role = Role.create(role_params)
    
    # Handle admin flag separately with authorization
    if current_user.super_admin? && params[:role][:admin] == '1'
      @role.admin = true
      @role.save
    end
    
    redirect_to @role
  end
  # {/fact}
end

class SafeApiKeysController < ApplicationController
  # {fact rule=mass-assignment@v1.0 defects=0}
  def good_case_11
    # ok: ruby-model-attr-accessible
    # Safe nested arrays without sensitive attributes
    key_params = params.require(:api_key).permit(
      :name,
      :expires_at,
      scopes: []
    )
    
    @api_key = ApiKey.new(key_params)
    
    # Generate token securely instead of accepting it from params
    @api_key.token = SecureRandom.hex(32)
    @api_key.save
  end
  # {/fact}
end

class SafeSessionsController < ApplicationController
  # {fact rule=mass-assignment@v1.0 defects=0}
  def good_case_12
    # ok: ruby-model-attr-accessible
    # Safe conditional parameters without sensitive attributes
    if current_user.present?
      session_params = params.require(:session).permit(:remember_me, :expires_at)
    else
      session_params = params.require(:session).permit(:remember_me)
    end
    
    @session = Session.create(session_params)
    # Generate token securely
    @session.token = SecureRandom.urlsafe_base64
  end
  # {/fact}
end

class SafeCommentsController < ApplicationController
  # {fact rule=mass-assignment@v1.0 defects=0}
  def good_case_13
    # ok: ruby-model-attr-accessible
    # Using strong parameters without any sensitive attributes
    comment_params = params.require(:comment).permit(:body, :author_name)
    
    @comment = Comment.new(comment_params)
    @comment.user_id = current_user.id
    @comment.save
  end
  # {/fact}
end

class SafeTagsController < ApplicationController
  # {fact rule=mass-assignment@v1.0 defects=0}
  def good_case_14
    # ok: ruby-model-attr-accessible
    # Using attribute accessors instead of mass assignment for sensitive attributes
    tag_params = params.require(:tag).permit(:name, :description)
    
    @tag = Tag.new(tag_params)
    
    # Handle admin-only flag with proper authorization
    if current_user.admin?
      @tag.admin_only = params[:tag][:admin_only] == '1'
    end
    
    @tag.save
  end
  # {/fact}
end

class SafeNotificationsController < ApplicationController
  # {fact rule=mass-assignment@v1.0 defects=0}
  def good_case_15
    # ok: ruby-model-attr-accessible
    # Using form objects to handle parameter validation before assignment
    form = NotificationForm.new(params.require(:notification).permit(:title, :message, :priority))
    
    if form.valid?
      @notification = Notification.new(
        title: form.title,
        message: form.message,
        priority: form.priority
      )
      
      # Set sensitive attributes with proper authorization
      if current_user.admin? && params[:notification][:all_users].present?
        @notification.all_users = true
      end
      
      @notification.save
    else
      render :new
    end
  end
  # {/fact}
end