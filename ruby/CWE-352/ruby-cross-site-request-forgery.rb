# Ruby CSRF Protection Examples

# True Positives (Vulnerable Code)

# Example 1: Disabling CSRF protection in a controller
class BadCase1Controller < ApplicationController
  # ruleid: ruby-cross-site-request-forgery
  skip_before_action :verify_authenticity_token
  
  def create
    @user = User.new(user_params)
    if @user.save
      redirect_to @user
    else
      render 'new'
    end
  end
  
  private
  
  def user_params
    params.require(:user).permit(:name, :email)
  end
end

# Example 2: Disabling CSRF for specific actions
class BadCase2Controller < ApplicationController
  # ruleid: ruby-cross-site-request-forgery
  skip_before_action :verify_authenticity_token, only: [:update, :delete]
  
  def update
    @post = Post.find(params[:id])
    if @post.update(post_params)
      redirect_to @post
    else
      render 'edit'
    end
  end
  
  def delete
    @post = Post.find(params[:id])
    @post.destroy
    redirect_to posts_path
  end
  
  private
  
  def post_params
    params.require(:post).permit(:title, :content)
  end
end

# Example 3: Setting protect_from_forgery to false
class BadCase3Controller < ApplicationController
  # ruleid: ruby-cross-site-request-forgery
  protect_from_forgery with: :null_session
  
  def create
    @comment = Comment.new(comment_params)
    if @comment.save
      redirect_to @comment.post
    else
      redirect_to root_path
    end
  end
  
  private
  
  def comment_params
    params.require(:comment).permit(:body, :post_id)
  end
end

# Example 4: Disabling CSRF in API controller
class BadCase4Controller < ApplicationController
  # ruleid: ruby-cross-site-request-forgery
  skip_before_action :verify_authenticity_token, if: :json_request?
  
  def create
    @product = Product.new(product_params)
    if @product.save
      render json: @product
    else
      render json: @product.errors, status: :unprocessable_entity
    end
  end
  
  private
  
  def product_params
    params.require(:product).permit(:name, :price)
  end
  
  def json_request?
    request.format.json?
  end
end

# Example 5: Disabling CSRF in application controller
class BadCase5Controller < ActionController::Base
  # ruleid: ruby-cross-site-request-forgery
  skip_forgery_protection
  
  def index
    @users = User.all
  end
  
  def show
    @user = User.find(params[:id])
  end
end

# Example 6: Setting null_session but with if condition
class BadCase6Controller < ApplicationController
  # ruleid: ruby-cross-site-request-forgery
  protect_from_forgery with: :null_session, if: Proc.new { |c| c.request.format == 'application/json' }
  
  def update
    @user = User.find(params[:id])
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

# Example 7: Disabling CSRF in a Sinatra application
require 'sinatra'

class BadCase7 < Sinatra::Base
  # ruleid: ruby-cross-site-request-forgery
  disable :protection
  
  post '/users' do
    user = User.create(
      name: params[:name],
      email: params[:email]
    )
    redirect "/users/#{user.id}"
  end
end

# Example 8: Disabling specific protections in Sinatra including CSRF
require 'sinatra'

class BadCase8 < Sinatra::Base
  # ruleid: ruby-cross-site-request-forgery
  set :protection, except: [:csrf]
  
  post '/comments' do
    comment = Comment.create(
      body: params[:body],
      post_id: params[:post_id]
    )
    redirect "/posts/#{comment.post_id}"
  end
end

# Example 9: Disabling CSRF for multiple actions
class BadCase9Controller < ApplicationController
  # ruleid: ruby-cross-site-request-forgery
  skip_before_action :verify_authenticity_token, only: [:create, :update, :destroy]
  
  def create
    @article = Article.new(article_params)
    if @article.save
      redirect_to @article
    else
      render 'new'
    end
  end
  
  def update
    @article = Article.find(params[:id])
    if @article.update(article_params)
      redirect_to @article
    else
      render 'edit'
    end
  end
  
  def destroy
    @article = Article.find(params[:id])
    @article.destroy
    redirect_to articles_path
  end
  
  private
  
  def article_params
    params.require(:article).permit(:title, :text)
  end
end

# Example 10: Disabling CSRF with except option
class BadCase10Controller < ApplicationController
  # ruleid: ruby-cross-site-request-forgery
  skip_before_action :verify_authenticity_token, except: [:index, :show]
  
  def index
    @products = Product.all
  end
  
  def show
    @product = Product.find(params[:id])
  end
  
  def create
    @product = Product.new(product_params)
    if @product.save
      redirect_to @product
    else
      render 'new'
    end
  end
  
  private
  
  def product_params
    params.require(:product).permit(:name, :price)
  end
end

# Example 11: Using reset_session to bypass CSRF protection
class BadCase11Controller < ApplicationController
  def update
    # ruleid: ruby-cross-site-request-forgery
    reset_session
    
    @user = User.find(params[:id])
    if @user.update(user_params)
      redirect_to @user
    else
      render 'edit'
    end
  end
  
  private
  
  def user_params
    params.require(:user).permit(:name, :email)
  end
end

# Example 12: Disabling CSRF in a Rails API application
class BadCase12Controller < ActionController::API
  # ruleid: ruby-cross-site-request-forgery
  # ActionController::API doesn't include CSRF protection by default
  
  def create
    @order = Order.new(order_params)
    if @order.save
      render json: @order, status: :created
    else
      render json: @order.errors, status: :unprocessable_entity
    end
  end
  
  private
  
  def order_params
    params.require(:order).permit(:product_id, :quantity)
  end
end

# Example 13: Setting null_session for all actions
class BadCase13Controller < ApplicationController
  # ruleid: ruby-cross-site-request-forgery
  protect_from_forgery with: :null_session
  
  def index
    @posts = Post.all
  end
  
  def create
    @post = Post.new(post_params)
    if @post.save
      redirect_to @post
    else
      render 'new'
    end
  end
  
  private
  
  def post_params
    params.require(:post).permit(:title, :content)
  end
end

# Example 14: Disabling CSRF in a Rails engine
module MyEngine
  class BadCase14Controller < ApplicationController
    # ruleid: ruby-cross-site-request-forgery
    skip_before_action :verify_authenticity_token
    
    def create
      @item = Item.new(item_params)
      if @item.save
        redirect_to @item
      else
        render 'new'
      end
    end
    
    private
    
    def item_params
      params.require(:item).permit(:name, :description)
    end
  end
end

# Example 15: Disabling CSRF in a Grape API
require 'grape'

module API
  class BadCase15 < Grape::API
    format :json
    
    # ruleid: ruby-cross-site-request-forgery
    # Grape doesn't include CSRF protection by default
    
    post '/users' do
      user = User.create!(
        name: params[:name],
        email: params[:email]
      )
      { id: user.id }
    end
  end
end

# True Negatives (Secure Code)

# Example 1: Properly enabling CSRF protection
class GoodCase1Controller < ApplicationController
  # ok: ruby-cross-site-request-forgery
  protect_from_forgery with: :exception
  
  def create
    @user = User.new(user_params)
    if @user.save
      redirect_to @user
    else
      render 'new'
    end
  end
  
  private
  
  def user_params
    params.require(:user).permit(:name, :email)
  end
end

# Example 2: Using default Rails CSRF protection
class GoodCase2Controller < ApplicationController
  # Rails includes CSRF protection by default
  # ok: ruby-cross-site-request-forgery
  
  def update
    @post = Post.find(params[:id])
    if @post.update(post_params)
      redirect_to @post
    else
      render 'edit'
    end
  end
  
  private
  
  def post_params
    params.require(:post).permit(:title, :content)
  end
end

# Example 3: Using exception for CSRF failures
class GoodCase3Controller < ApplicationController
  # ok: ruby-cross-site-request-forgery
  protect_from_forgery with: :exception
  
  def create
    @comment = Comment.new(comment_params)
    if @comment.save
      redirect_to @comment.post
    else
      redirect_to root_path
    end
  end
  
  private
  
  def comment_params
    params.require(:comment).permit(:body, :post_id)
  end
end

# Example 4: Using CSRF protection with API and session authentication
class GoodCase4Controller < ApplicationController
  # ok: ruby-cross-site-request-forgery
  protect_from_forgery with: :exception
  
  def create
    @product = Product.new(product_params)
    if @product.save
      render json: @product
    else
      render json: @product.errors, status: :unprocessable_entity
    end
  end
  
  private
  
  def product_params
    params.require(:product).permit(:name, :price)
  end
end

# Example 5: Using token-based authentication for APIs
class GoodCase5Controller < ApplicationController
  # ok: ruby-cross-site-request-forgery
  protect_from_forgery with: :exception
  before_action :authenticate_token
  
  def update
    @user = User.find(params[:id])
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
  
  def authenticate_token
    authenticate_or_request_with_http_token do |token, options|
      ActiveSupport::SecurityUtils.secure_compare(token, ENV['API_TOKEN'])
    end
  end
end

# Example 6: Using Sinatra with CSRF protection enabled
require 'sinatra'

class GoodCase6 < Sinatra::Base
  # ok: ruby-cross-site-request-forgery
  use Rack::Protection
  
  post '/users' do
    user = User.create(
      name: params[:name],
      email: params[:email]
    )
    redirect "/users/#{user.id}"
  end
end

# Example 7: Using Sinatra with specific protections enabled
require 'sinatra'

class GoodCase7 < Sinatra::Base
  # ok: ruby-cross-site-request-forgery
  set :protection, :csrf => true
  
  post '/comments' do
    comment = Comment.create(
      body: params[:body],
      post_id: params[:post_id]
    )
    redirect "/posts/#{comment.post_id}"
  end
end

# Example 8: Using Rails API with JWT authentication
class GoodCase8Controller < ActionController::API
  # ok: ruby-cross-site-request-forgery
  before_action :authenticate_jwt_token
  
  def create
    @order = Order.new(order_params)
    if @order.save
      render json: @order, status: :created
    else
      render json: @order.errors, status: :unprocessable_entity
    end
  end
  
  private
  
  def order_params
    params.require(:order).permit(:product_id, :quantity)
  end
  
  def authenticate_jwt_token
    token = request.headers['Authorization']&.split(' ')&.last
    begin
      @decoded = JWT.decode(token, ENV['JWT_SECRET'], true, algorithm: 'HS256')
      @current_user = User.find(@decoded[0]['user_id'])
    rescue JWT::DecodeError
      render json: { errors: ['Invalid token'] }, status: :unauthorized
    end
  end
end

# Example 9: Using Rails with proper CSRF protection and handling AJAX requests
class GoodCase9Controller < ApplicationController
  # ok: ruby-cross-site-request-forgery
  protect_from_forgery with: :exception
  
  def create
    @article = Article.new(article_params)
    
    respond_to do |format|
      if @article.save
        format.html { redirect_to @article }
        format.json { render json: @article, status: :created }
      else
        format.html { render 'new' }
        format.json { render json: @article.errors, status: :unprocessable_entity }
      end
    end
  end
  
  private
  
  def article_params
    params.require(:article).permit(:title, :text)
  end
end

# Example 10: Using Rails with proper CSRF protection and custom error handling
class GoodCase10Controller < ApplicationController
  # ok: ruby-cross-site-request-forgery
  protect_from_forgery with: :exception
  rescue_from ActionController::InvalidAuthenticityToken, with: :handle_csrf_error
  
  def update
    @product = Product.find(params[:id])
    if @product.update(product_params)
      redirect_to @product
    else
      render 'edit'
    end
  end
  
  private
  
  def product_params
    params.require(:product).permit(:name, :price)
  end
  
  def handle_csrf_error
    redirect_to root_path, alert: "Invalid request. Please try again."
  end
end

# Example 11: Using Rails with proper session management and CSRF protection
class GoodCase11Controller < ApplicationController
  # ok: ruby-cross-site-request-forgery
  protect_from_forgery with: :exception
  
  def update
    @user = User.find(params[:id])
    if @user.update(user_params)
      # Proper session handling without disabling CSRF
      session[:user_id] = @user.id
      redirect_to @user
    else
      render 'edit'
    end
  end
  
  private
  
  def user_params
    params.require(:user).permit(:name, :email)
  end
end

# Example 12: Using Rails API with proper authentication
class GoodCase12Controller < ActionController::API
  # ok: ruby-cross-site-request-forgery
  include ActionController::HttpAuthentication::Basic::ControllerMethods
  before_action :authenticate
  
  def create
    @order = Order.new(order_params)
    if @order.save
      render json: @order, status: :created
    else
      render json: @order.errors, status: :unprocessable_entity
    end
  end
  
  private
  
  def order_params
    params.require(:order).permit(:product_id, :quantity)
  end
  
  def authenticate
    authenticate_or_request_with_http_basic do |username, password|
      ActiveSupport::SecurityUtils.secure_compare(username, ENV['API_USERNAME']) &
      ActiveSupport::SecurityUtils.secure_compare(password, ENV['API_PASSWORD'])
    end
  end
end

# Example 13: Using Rails with proper CSRF protection in a form
class GoodCase13Controller < ApplicationController
  # ok: ruby-cross-site-request-forgery
  protect_from_forgery with: :exception
  
  def new
    @post = Post.new
  end
  
  def create
    @post = Post.new(post_params)
    if @post.save
      redirect_to @post
    else
      render 'new'
    end
  end
  
  private
  
  def post_params
    params.require(:post).permit(:title, :content)
  end
end

# Example 14: Using Rails engine with proper CSRF protection
module MyEngine
  class GoodCase14Controller < ApplicationController
    # ok: ruby-cross-site-request-forgery
    protect_from_forgery with: :exception
    
    def create
      @item = Item.new(item_params)
      if @item.save
        redirect_to @item
      else
        render 'new'
      end
    end
    
    private
    
    def item_params
      params.require(:item).permit(:name, :description)
    end
  end
end

# Example 15: Using Grape API with token authentication
require 'grape'

module API
  class GoodCase15 < Grape::API
    format :json
    
    # ok: ruby-cross-site-request-forgery
    before do
      error!('Unauthorized', 401) unless valid_token?
    end
    
    post '/users' do
      user = User.create!(
        name: params[:name],
        email: params[:email]
      )
      { id: user.id }
    end
    
    private
    
    def valid_token?
      token = headers['Authorization']&.split(' ')&.last
      token && ActiveSupport::SecurityUtils.secure_compare(token, ENV['API_TOKEN'])
    end
  end
end