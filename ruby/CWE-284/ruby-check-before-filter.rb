# This file contains examples of secure and insecure usage of before_filter/before_action in Rails controllers
# The rule detects when 'except' is used instead of the more secure 'only' approach

# True Positives (Vulnerable Code)

class BadCase1Controller < ApplicationController
  # ruleid: ruby-check-before-filter
  before_filter :authenticate_user, except: [:index, :show]
  
  def index
    @posts = Post.all
  end
  
  def show
    @post = Post.find(params[:id])
  end
  
  def edit
    @post = Post.find(params[:id])
  end
  
  private
  
  def authenticate_user
    redirect_to login_path unless current_user
  end
end

class BadCase2Controller < ApplicationController
  # ruleid: ruby-check-before-filter
  before_action :require_login, except: [:public_page]
  
  def public_page
    @content = Content.public_content
  end
  
  def admin_dashboard
    @stats = AdminStats.summary
  end
  
  private
  
  def require_login
    unless logged_in?
      flash[:error] = "You must be logged in to access this section"
      redirect_to login_url
    end
  end
end

class BadCase3Controller < ApplicationController
  # ruleid: ruby-check-before-filter
  before_filter :check_permissions, except: [:index]
  
  def index
    @items = Item.all
  end
  
  def edit
    @item = Item.find(params[:id])
  end
  
  def update
    @item = Item.find(params[:id])
    if @item.update(item_params)
      redirect_to @item
    else
      render 'edit'
    end
  end
  
  private
  
  def check_permissions
    redirect_to root_path unless current_user.admin?
  end
end

class BadCase4Controller < ApplicationController
  # ruleid: ruby-check-before-filter
  before_action :verify_admin, except: [:login, :logout, :home]
  
  def login
    # Authentication logic
  end
  
  def logout
    # Logout logic
  end
  
  def home
    @welcome_message = "Welcome to our site"
  end
  
  def user_management
    @users = User.all
  end
  
  private
  
  def verify_admin
    unless current_user && current_user.admin?
      flash[:error] = "Admin access required"
      redirect_to root_path
    end
  end
end

class BadCase5Controller < ApplicationController
  # ruleid: ruby-check-before-filter
  before_filter :authenticate, except: :public_api
  
  def public_api
    data = { status: "success", message: "Public API endpoint" }
    render json: data
  end
  
  def private_api
    data = { user: current_user, data: current_user.data }
    render json: data
  end
  
  private
  
  def authenticate
    authenticate_or_request_with_http_token do |token, options|
      ApiKey.exists?(access_token: token)
    end
  end
end

class BadCase6Controller < ApplicationController
  # ruleid: ruby-check-before-filter
  skip_before_action :verify_authenticity_token, except: [:update_password, :update_email]
  
  def update_password
    # Secure password update logic
  end
  
  def update_email
    # Secure email update logic
  end
  
  def update_profile
    current_user.update(profile_params)
    render json: { success: true }
  end
end

class BadCase7Controller < ApplicationController
  # ruleid: ruby-check-before-filter
  before_action :authorize_user, except: [:new, :create]
  
  def new
    @user = User.new
  end
  
  def create
    @user = User.new(user_params)
    if @user.save
      redirect_to @user
    else
      render 'new'
    end
  end
  
  def edit
    @user = User.find(params[:id])
  end
  
  private
  
  def authorize_user
    @user = User.find(params[:id])
    redirect_to root_path unless current_user == @user
  end
end

class BadCase8Controller < ApplicationController
  # ruleid: ruby-check-before-filter
  before_filter :check_api_key, except: [:status, :version]
  
  def status
    render json: { status: "operational" }
  end
  
  def version
    render json: { version: "1.0.0" }
  end
  
  def user_data
    render json: current_user.data
  end
  
  private
  
  def check_api_key
    api_key = request.headers["X-API-Key"]
    head :unauthorized unless ApiKey.valid?(api_key)
  end
end

class BadCase9Controller < ApplicationController
  # ruleid: ruby-check-before-filter
  before_action :require_subscription, except: [:pricing, :features]
  
  def pricing
    @plans = SubscriptionPlan.all
  end
  
  def features
    @features = Feature.all
  end
  
  def dashboard
    @subscription = current_user.subscription
    @usage = @subscription.usage_stats
  end
  
  private
  
  def require_subscription
    redirect_to pricing_path unless current_user&.subscription&.active?
  end
end

class BadCase10Controller < ApplicationController
  # ruleid: ruby-check-before-filter
  prepend_before_action :verify_user, except: [:index, :about, :contact]
  
  def index
    @featured_items = Item.featured
  end
  
  def about
    @company_info = CompanyInfo.first
  end
  
  def contact
    @contact_info = ContactInfo.first
  end
  
  def account
    @user = current_user
  end
  
  private
  
  def verify_user
    redirect_to login_path unless user_signed_in?
  end
end

class BadCase11Controller < ApplicationController
  # ruleid: ruby-check-before-filter
  append_before_filter :log_activity, except: [:health_check]
  
  def health_check
    render plain: "OK"
  end
  
  def show_product
    @product = Product.find(params[:id])
  end
  
  private
  
  def log_activity
    ActivityLog.create(
      user_id: current_user&.id,
      action: action_name,
      controller: controller_name,
      ip_address: request.remote_ip
    )
  end
end

class BadCase12Controller < ApplicationController
  # ruleid: ruby-check-before-filter
  before_action :set_locale, :track_request
  before_action :authenticate_user!, except: [:welcome, :language]
  
  def welcome
    @greeting = I18n.t('welcome')
  end
  
  def language
    I18n.locale = params[:locale] || I18n.default_locale
    redirect_to root_path
  end
  
  def dashboard
    @stats = current_user.dashboard_stats
  end
  
  private
  
  def set_locale
    I18n.locale = params[:locale] || I18n.default_locale
  end
  
  def track_request
    RequestTracker.track(request)
  end
end

class BadCase13Controller < ApplicationController
  # ruleid: ruby-check-before-filter
  before_action :set_paper_trail_whodunnit
  before_filter :authorize_admin, except: [:public_stats]
  
  def public_stats
    @stats = PublicStats.summary
  end
  
  def admin_panel
    @users = User.all
    @activities = Activity.recent
  end
  
  private
  
  def authorize_admin
    redirect_to root_path unless current_user&.admin?
  end
end

class BadCase14Controller < ApplicationController
  # ruleid: ruby-check-before-filter
  before_action :load_resource
  before_filter :check_ownership, except: [:index, :new, :create]
  
  def index
    @resources = Resource.all
  end
  
  def new
    @resource = Resource.new
  end
  
  def create
    @resource = Resource.new(resource_params)
    @resource.user = current_user
    
    if @resource.save
      redirect_to @resource
    else
      render 'new'
    end
  end
  
  def edit
    # @resource already loaded by before_action
  end
  
  private
  
  def load_resource
    @resource = Resource.find(params[:id]) if params[:id]
  end
  
  def check_ownership
    redirect_to resources_path unless @resource.user == current_user
  end
end

class BadCase15Controller < ApplicationController
  # ruleid: ruby-check-before-filter
  before_filter :require_login
  skip_before_filter :require_login, except: [:account, :billing, :settings]
  
  def home
    @featured = Product.featured
  end
  
  def account
    @user = current_user
  end
  
  def billing
    @subscription = current_user.subscription
  end
  
  def settings
    @preferences = current_user.preferences
  end
  
  private
  
  def require_login
    redirect_to login_path unless current_user
  end
end

# True Negatives (Secure Code)

class GoodCase1Controller < ApplicationController
  # ok: ruby-check-before-filter
  before_filter :authenticate_user, only: [:edit, :update, :destroy]
  
  def index
    @posts = Post.all
  end
  
  def show
    @post = Post.find(params[:id])
  end
  
  def edit
    @post = Post.find(params[:id])
  end
  
  private
  
  def authenticate_user
    redirect_to login_path unless current_user
  end
end

class GoodCase2Controller < ApplicationController
  # ok: ruby-check-before-filter
  before_action :require_login, only: [:admin_dashboard, :user_management]
  
  def public_page
    @content = Content.public_content
  end
  
  def admin_dashboard
    @stats = AdminStats.summary
  end
  
  private
  
  def require_login
    unless logged_in?
      flash[:error] = "You must be logged in to access this section"
      redirect_to login_url
    end
  end
end

class GoodCase3Controller < ApplicationController
  # ok: ruby-check-before-filter
  before_filter :check_permissions, only: [:edit, :update, :destroy]
  
  def index
    @items = Item.all
  end
  
  def edit
    @item = Item.find(params[:id])
  end
  
  def update
    @item = Item.find(params[:id])
    if @item.update(item_params)
      redirect_to @item
    else
      render 'edit'
    end
  end
  
  private
  
  def check_permissions
    redirect_to root_path unless current_user.admin?
  end
end

class GoodCase4Controller < ApplicationController
  # ok: ruby-check-before-filter
  before_action :verify_admin, only: [:user_management, :system_settings, :reports]
  
  def login
    # Authentication logic
  end
  
  def logout
    # Logout logic
  end
  
  def home
    @welcome_message = "Welcome to our site"
  end
  
  def user_management
    @users = User.all
  end
  
  private
  
  def verify_admin
    unless current_user && current_user.admin?
      flash[:error] = "Admin access required"
      redirect_to root_path
    end
  end
end

class GoodCase5Controller < ApplicationController
  # ok: ruby-check-before-filter
  before_filter :authenticate, only: [:private_api, :admin_api]
  
  def public_api
    data = { status: "success", message: "Public API endpoint" }
    render json: data
  end
  
  def private_api
    data = { user: current_user, data: current_user.data }
    render json: data
  end
  
  private
  
  def authenticate
    authenticate_or_request_with_http_token do |token, options|
      ApiKey.exists?(access_token: token)
    end
  end
end

class GoodCase6Controller < ApplicationController
  # ok: ruby-check-before-filter
  skip_before_action :verify_authenticity_token, only: [:api_webhook, :external_callback]
  
  def update_password
    # Secure password update logic
  end
  
  def update_email
    # Secure email update logic
  end
  
  def api_webhook
    # Handle webhook from external service
    head :ok
  end
  
  def external_callback
    # Handle callback from external service
    redirect_to dashboard_path
  end
end

class GoodCase7Controller < ApplicationController
  # ok: ruby-check-before-filter
  before_action :authorize_user, only: [:edit, :update, :destroy]
  
  def new
    @user = User.new
  end
  
  def create
    @user = User.new(user_params)
    if @user.save
      redirect_to @user
    else
      render 'new'
    end
  end
  
  def edit
    @user = User.find(params[:id])
  end
  
  private
  
  def authorize_user
    @user = User.find(params[:id])
    redirect_to root_path unless current_user == @user
  end
end

class GoodCase8Controller < ApplicationController
  # ok: ruby-check-before-filter
  before_filter :check_api_key, only: [:user_data, :transactions, :settings]
  
  def status
    render json: { status: "operational" }
  end
  
  def version
    render json: { version: "1.0.0" }
  end
  
  def user_data
    render json: current_user.data
  end
  
  private
  
  def check_api_key
    api_key = request.headers["X-API-Key"]
    head :unauthorized unless ApiKey.valid?(api_key)
  end
end

class GoodCase9Controller < ApplicationController
  # ok: ruby-check-before-filter
  before_action :require_subscription, only: [:dashboard, :reports, :downloads]
  
  def pricing
    @plans = SubscriptionPlan.all
  end
  
  def features
    @features = Feature.all
  end
  
  def dashboard
    @subscription = current_user.subscription
    @usage = @subscription.usage_stats
  end
  
  private
  
  def require_subscription
    redirect_to pricing_path unless current_user&.subscription&.active?
  end
end

class GoodCase10Controller < ApplicationController
  # ok: ruby-check-before-filter
  prepend_before_action :verify_user, only: [:account, :profile, :settings]
  
  def index
    @featured_items = Item.featured
  end
  
  def about
    @company_info = CompanyInfo.first
  end
  
  def contact
    @contact_info = ContactInfo.first
  end
  
  def account
    @user = current_user
  end
  
  private
  
  def verify_user
    redirect_to login_path unless user_signed_in?
  end
end

class GoodCase11Controller < ApplicationController
  # ok: ruby-check-before-filter
  append_before_filter :log_activity, only: [:show_product, :add_to_cart, :checkout]
  
  def health_check
    render plain: "OK"
  end
  
  def show_product
    @product = Product.find(params[:id])
  end
  
  private
  
  def log_activity
    ActivityLog.create(
      user_id: current_user&.id,
      action: action_name,
      controller: controller_name,
      ip_address: request.remote_ip
    )
  end
end

class GoodCase12Controller < ApplicationController
  # ok: ruby-check-before-filter
  before_action :set_locale, :track_request
  before_action :authenticate_user!, only: [:dashboard, :profile, :settings]
  
  def welcome
    @greeting = I18n.t('welcome')
  end
  
  def language
    I18n.locale = params[:locale] || I18n.default_locale
    redirect_to root_path
  end
  
  def dashboard
    @stats = current_user.dashboard_stats
  end
  
  private
  
  def set_locale
    I18n.locale = params[:locale] || I18n.default_locale
  end
  
  def track_request
    RequestTracker.track(request)
  end
end

class GoodCase13Controller < ApplicationController
  # ok: ruby-check-before-filter
  before_action :set_paper_trail_whodunnit
  before_filter :authorize_admin, only: [:admin_panel, :user_management, :system_settings]
  
  def public_stats
    @stats = PublicStats.summary
  end
  
  def admin_panel
    @users = User.all
    @activities = Activity.recent
  end
  
  private
  
  def authorize_admin
    redirect_to root_path unless current_user&.admin?
  end
end

class GoodCase14Controller < ApplicationController
  # ok: ruby-check-before-filter
  before_action :load_resource
  before_filter :check_ownership, only: [:edit, :update, :destroy]
  
  def index
    @resources = Resource.all
  end
  
  def new
    @resource = Resource.new
  end
  
  def create
    @resource = Resource.new(resource_params)
    @resource.user = current_user
    
    if @resource.save
      redirect_to @resource
    else
      render 'new'
    end
  end
  
  def edit
    # @resource already loaded by before_action
  end
  
  private
  
  def load_resource
    @resource = Resource.find(params[:id]) if params[:id]
  end
  
  def check_ownership
    redirect_to resources_path unless @resource.user == current_user
  end
end

class GoodCase15Controller < ApplicationController
  # ok: ruby-check-before-filter
  before_filter :require_login, only: [:account, :billing, :settings]
  
  def home
    @featured = Product.featured
  end
  
  def account
    @user = current_user
  end
  
  def billing
    @subscription = current_user.subscription
  end
  
  def settings
    @preferences = current_user.preferences
  end
  
  private
  
  def require_login
    redirect_to login_path unless current_user
  end
end