# frozen_string_literal: true

class ApplicationController < ActionController::Base
  # True Positive Examples (Vulnerable Code)

  # bad_case_1: Only checks for GET without handling HEAD
  # {fact rule=trusting-http-permission-methods@v1.0 defects=1}
  def bad_case_1
    if request.get?
      # ruleid: ruby-sensitive-http-action
      render json: { data: "This is sensitive data" }
    else
      render json: { error: "Method not allowed" }, status: :method_not_allowed
    end
  end
  # {/fact}

  # bad_case_2: Using GET check for authentication bypass
  # {fact rule=trusting-http-permission-methods@v1.0 defects=1}
  def bad_case_2
    if request.get?
      # ruleid: ruby-sensitive-http-action
      skip_authentication
      render json: User.all
    else
      authenticate_user!
      render json: { message: "Authenticated" }
    end
  end
  # {/fact}

  # bad_case_3: Different behavior for GET vs other methods
  # {fact rule=trusting-http-permission-methods@v1.0 defects=1}
  def bad_case_3
    if request.get?
      # ruleid: ruby-sensitive-http-action
      @user = User.find(params[:id])
      render json: @user.public_attributes
    else
      authenticate_user!
      @user = User.find(params[:id])
      render json: @user.all_attributes
    end
  end
  # {/fact}

  # bad_case_4: Using GET check for CSRF protection
  # {fact rule=trusting-http-permission-methods@v1.0 defects=1}
  def bad_case_4
    if request.get?
      # ruleid: ruby-sensitive-http-action
      skip_before_action :verify_authenticity_token
      render json: { data: "This bypasses CSRF protection" }
    else
      render json: { message: "Protected" }
    end
  end
  # {/fact}

  # bad_case_5: Conditional logging based on request method
  # {fact rule=trusting-http-permission-methods@v1.0 defects=1}
  def bad_case_5
    if request.get?
      # ruleid: ruby-sensitive-http-action
      logger.info "Skipping detailed logging for GET request"
    else
      logger.info "Detailed logging for non-GET request: #{request.body.read}"
    end
    render json: { status: "ok" }
  end
  # {/fact}

  # bad_case_6: Rate limiting bypass for GET requests
  # {fact rule=trusting-http-permission-methods@v1.0 defects=1}
  def bad_case_6
    if request.get?
      # ruleid: ruby-sensitive-http-action
      skip_before_action :rate_limit
      render json: { data: "Rate limiting bypassed" }
    else
      render json: { message: "Rate limited" }
    end
  end
  # {/fact}

  # bad_case_7: Different authorization for GET requests
  # {fact rule=trusting-http-permission-methods@v1.0 defects=1}
  def bad_case_7
    if request.get?
      # ruleid: ruby-sensitive-http-action
      @resource = Resource.find(params[:id])
      render json: @resource
    else
      authorize! :manage, Resource
      @resource = Resource.find(params[:id])
      render json: @resource
    end
  end
  # {/fact}

  # bad_case_8: Caching only for GET requests
  # {fact rule=trusting-http-permission-methods@v1.0 defects=1}
  def bad_case_8
    if request.get?
      # ruleid: ruby-sensitive-http-action
      expires_in 1.hour, public: true
      render json: expensive_operation
    else
      render json: expensive_operation
    end
  end
  # {/fact}

  # bad_case_9: Different error handling for GET
  # {fact rule=trusting-http-permission-methods@v1.0 defects=1}
  def bad_case_9
    begin
      result = process_data(params[:data])
      render json: result
    rescue => e
      if request.get?
        # ruleid: ruby-sensitive-http-action
        render json: { error: "An error occurred" }, status: :ok
      else
        render json: { error: e.message }, status: :internal_server_error
      end
    end
  end
  # {/fact}

  # bad_case_10: Conditional database operations
  # {fact rule=trusting-http-permission-methods@v1.0 defects=1}
  def bad_case_10
    if request.get?
      # ruleid: ruby-sensitive-http-action
      @records = Record.where(public: true)
    else
      authenticate_user!
      @records = current_user.records
    end
    render json: @records
  end
  # {/fact}

  # bad_case_11: Different validation for GET requests
  # {fact rule=trusting-http-permission-methods@v1.0 defects=1}
  def bad_case_11
    @user = User.new(user_params)
    
    if request.get?
      # ruleid: ruby-sensitive-http-action
      @user.save(validate: false)
      render json: @user
    else
      if @user.save
        render json: @user
      else
        render json: @user.errors, status: :unprocessable_entity
      end
    end
  end
  # {/fact}

  # bad_case_12: Conditional access control
  # {fact rule=trusting-http-permission-methods@v1.0 defects=1}
  def bad_case_12
    @document = Document.find(params[:id])
    
    if request.get?
      # ruleid: ruby-sensitive-http-action
      render json: @document
    else
      if @document.user_id == current_user.id
        render json: @document
      else
        render json: { error: "Unauthorized" }, status: :unauthorized
      end
    end
  end
  # {/fact}

  # bad_case_13: Bypassing IP restrictions
  # {fact rule=trusting-http-permission-methods@v1.0 defects=1}
  def bad_case_13
    if request.get?
      # ruleid: ruby-sensitive-http-action
      render json: { data: "Access granted regardless of IP" }
    else
      allowed_ips = ['192.168.1.1', '10.0.0.1']
      if allowed_ips.include?(request.remote_ip)
        render json: { data: "Access granted" }
      else
        render json: { error: "IP not allowed" }, status: :forbidden
      end
    end
  end
  # {/fact}

  # bad_case_14: Different content based on request method
  # {fact rule=trusting-http-permission-methods@v1.0 defects=1}
  def bad_case_14
    @article = Article.find(params[:id])
    
    if request.get?
      # ruleid: ruby-sensitive-http-action
      render json: @article.attributes.merge(secret_key: ENV['API_KEY'])
    else
      render json: @article.public_attributes
    end
  end
  # {/fact}

  # bad_case_15: Conditional audit logging
  # {fact rule=trusting-http-permission-methods@v1.0 defects=1}
  def bad_case_15
    if request.get?
      # ruleid: ruby-sensitive-http-action
      # No audit logging for GET requests
      render json: perform_sensitive_operation
    else
      AuditLog.create(
        user_id: current_user.id,
        action: "sensitive_operation",
        details: request.parameters
      )
      render json: perform_sensitive_operation
    end
  end
  # {/fact}

  # True Negative Examples (Secure Code)

  # good_case_1: Properly handling both GET and HEAD requests
  # {fact rule=trusting-http-permission-methods@v1.0 defects=0}
  def good_case_1
    if request.get? || request.head?
      # ok: ruby-sensitive-http-action
      render json: { data: "This handles both GET and HEAD" }
    else
      render json: { error: "Method not allowed" }, status: :method_not_allowed
    end
  end
  # {/fact}

  # good_case_2: Using request.method for more precise control
  # {fact rule=trusting-http-permission-methods@v1.0 defects=0}
  def good_case_2
    case request.method
    when 'GET', 'HEAD'
      # ok: ruby-sensitive-http-action
      render json: { data: "Handling GET and HEAD explicitly" }
    when 'POST'
      render json: { data: "Handling POST" }
    else
      render json: { error: "Method not supported" }, status: :method_not_allowed
    end
  end
  # {/fact}

  # good_case_3: Same behavior regardless of HTTP method
  # {fact rule=trusting-http-permission-methods@v1.0 defects=0}
  def good_case_3
    authenticate_user!
    # ok: ruby-sensitive-http-action
    @user = User.find(params[:id])
    render json: @user
  end
  # {/fact}

  # good_case_4: Using Rails' HTTP verb helpers
  # {fact rule=trusting-http-permission-methods@v1.0 defects=0}
  def good_case_4
    respond_to do |format|
      format.html do
        # ok: ruby-sensitive-http-action
        render html: "<h1>Hello</h1>".html_safe
      end
  # {/fact}
      format.json do
        render json: { message: "Hello" }
      end
    end
  end

  # good_case_5: Using HTTP method constraints in routes
  # {fact rule=trusting-http-permission-methods@v1.0 defects=0}
  def good_case_5
    # This would be defined in routes.rb with proper constraints
    # get 'resource', to: 'controller#action'
    # head 'resource', to: 'controller#action'
    
    # ok: ruby-sensitive-http-action
    render json: { data: "This action is properly constrained in routes" }
  end
  # {/fact}

  # good_case_6: Same authorization regardless of method
  # {fact rule=trusting-http-permission-methods@v1.0 defects=0}
  def good_case_6
    authorize! :read, Resource
    # ok: ruby-sensitive-http-action
    @resource = Resource.find(params[:id])
    render json: @resource
  end
  # {/fact}

  # good_case_7: Consistent error handling
  # {fact rule=trusting-http-permission-methods@v1.0 defects=0}
  def good_case_7
    begin
      result = process_data(params[:data])
      # ok: ruby-sensitive-http-action
      render json: result
    rescue => e
      render json: { error: e.message }, status: :internal_server_error
    end
  end
  # {/fact}

  # good_case_8: Using before_action for consistent authentication
  # {fact rule=trusting-http-permission-methods@v1.0 defects=0}
  def good_case_8
    # Would be defined at class level: before_action :authenticate_user!
    
    # ok: ruby-sensitive-http-action
    @records = current_user.records
    render json: @records
  end
  # {/fact}

  # good_case_9: Consistent validation
  # {fact rule=trusting-http-permission-methods@v1.0 defects=0}
  def good_case_9
    @user = User.new(user_params)
    
    # ok: ruby-sensitive-http-action
    if @user.save
      render json: @user
    else
      render json: @user.errors, status: :unprocessable_entity
    end
  end
  # {/fact}

  # good_case_10: Proper method-specific actions with consistent security
  # {fact rule=trusting-http-permission-methods@v1.0 defects=0}
  def good_case_10
    authenticate_user!
    
    case request.method
    when 'GET', 'HEAD'
      # ok: ruby-sensitive-http-action
      @data = current_user.read_data
    when 'POST'
      @data = current_user.create_data(params[:data])
    when 'PUT'
      @data = current_user.update_data(params[:id], params[:data])
    when 'DELETE'
      @data = current_user.delete_data(params[:id])
    end
    
    render json: @data
  end
  # {/fact}

  # good_case_11: Using Rails' built-in CSRF protection
  # {fact rule=trusting-http-permission-methods@v1.0 defects=0}
  def good_case_11
    # Would be defined at class level: protect_from_forgery with: :exception
    
    # ok: ruby-sensitive-http-action
    render json: { data: "This action is protected by CSRF token verification" }
  end
  # {/fact}

  # good_case_12: Consistent IP restrictions
  # {fact rule=trusting-http-permission-methods@v1.0 defects=0}
  def good_case_12
    allowed_ips = ['192.168.1.1', '10.0.0.1']
    
    # ok: ruby-sensitive-http-action
    if allowed_ips.include?(request.remote_ip)
      render json: { data: "Access granted" }
    else
      render json: { error: "IP not allowed" }, status: :forbidden
    end
  end
  # {/fact}

  # good_case_13: Using request.request_method for accurate method detection
  # {fact rule=trusting-http-permission-methods@v1.0 defects=0}
  def good_case_13
    # ok: ruby-sensitive-http-action
    if ['GET', 'HEAD'].include?(request.request_method)
      render json: { data: "This handles both GET and HEAD accurately" }
    else
      render json: { error: "Method not allowed" }, status: :method_not_allowed
    end
  end
  # {/fact}

  # good_case_14: Consistent audit logging
  # {fact rule=trusting-http-permission-methods@v1.0 defects=0}
  def good_case_14
    # ok: ruby-sensitive-http-action
    AuditLog.create(
      user_id: current_user.id,
      action: "sensitive_operation",
      method: request.method,
      details: request.parameters
    )
    
    render json: perform_sensitive_operation
  end
  # {/fact}

  # good_case_15: Using Rails' HTTP verb detection with proper HEAD handling
  # {fact rule=trusting-http-permission-methods@v1.0 defects=0}
  def good_case_15
    # ok: ruby-sensitive-http-action
    if request.get?
      render json: { data: "GET request" }
    elsif request.head?
      head :ok
    elsif request.post?
      render json: { data: "POST request" }
    else
      render json: { error: "Unsupported method" }, status: :method_not_allowed
    end
  end
  # {/fact}

  private

  def user_params
    params.require(:user).permit(:name, :email)
  end

  def perform_sensitive_operation
    # Simulating a sensitive operation
    { result: "Operation completed" }
  end

  def expensive_operation
    # Simulating an expensive operation
    { result: "Expensive operation completed" }
  end

  def process_data(data)
    # Simulating data processing
    { processed: data }
  end

  def skip_authentication
    # Simulating authentication bypass
  end
end