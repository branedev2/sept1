# This file contains test cases for the ruby-untrusted-find rule
# which detects potential IDOR vulnerabilities in Ruby on Rails applications
# where unscoped find() methods are used with user-controlled input

require 'rails'
require 'active_record'

# Models for our examples
class User < ActiveRecord::Base
  has_many :documents
  has_many :posts
end

class Document < ActiveRecord::Base
  belongs_to :user
end

class Post < ActiveRecord::Base
  belongs_to :user
  scope :published, -> { where(published: true) }
end

class Order < ActiveRecord::Base
  belongs_to :user
end

class AdminController < ActionController::Base
  # Admin controllers might be allowed to access any record
end

class ApplicationController < ActionController::Base
  # Base controller with helper methods
  def current_user
    @current_user ||= User.find(session[:user_id]) if session[:user_id]
  end
end

# TRUE POSITIVES - Vulnerable code examples

# Case 1: Basic unscoped find with params
class DocumentsController < ApplicationController
  # {fact rule=insecure-direct-object-ref@v1.0 defects=1}
  def bad_case_1
    # Direct use of user input in find without scoping
    document_id = params[:id]
    # ruleid: ruby-untrusted-find
    document = Document.find(document_id)
    render json: document
  end
  # {/fact}
end

# Case 2: Using request parameters directly
class PostsController < ApplicationController
  # {fact rule=insecure-direct-object-ref@v1.0 defects=1}
  def bad_case_2
    # Using request.params directly
    # ruleid: ruby-untrusted-find
    post = Post.find(request.params[:post_id])
    render json: post
  end
  # {/fact}
end

# Case 3: Using params with string interpolation
class OrdersController < ApplicationController
  # {fact rule=insecure-direct-object-ref@v1.0 defects=1}
  def bad_case_3
    order_id = params[:order_id]
    # ruleid: ruby-untrusted-find
    order = Order.find("#{order_id}")
    render json: order
  end
  # {/fact}
end

# Case 4: Using params with to_i but still unscoped
class UsersController < ApplicationController
  # {fact rule=insecure-direct-object-ref@v1.0 defects=1}
  def bad_case_4
    # Even with to_i, this is still unscoped and vulnerable
    # ruleid: ruby-untrusted-find
    user = User.find(params[:id].to_i)
    render json: user
  end
  # {/fact}
end

# Case 5: Using find_by with user input
class ProductsController < ApplicationController
  # {fact rule=insecure-direct-object-ref@v1.0 defects=1}
  def bad_case_5
    # find_by with user input is also vulnerable
    # ruleid: ruby-untrusted-find
    product = Product.find_by(id: params[:id])
    render json: product
  end
  # {/fact}
end

# Case 6: Using find with JSON input
class ApiController < ApplicationController
  # {fact rule=insecure-direct-object-ref@v1.0 defects=1}
  def bad_case_6
    data = JSON.parse(request.body.read)
    # ruleid: ruby-untrusted-find
    user = User.find(data["user_id"])
    render json: user
  end
  # {/fact}
end

# Case 7: Using find with form data
class FormController < ApplicationController
  # {fact rule=insecure-direct-object-ref@v1.0 defects=1}
  def bad_case_7
    # ruleid: ruby-untrusted-find
    document = Document.find(params[:document][:id])
    render json: document
  end
  # {/fact}
end

# Case 8: Using find with query parameters
class SearchController < ApplicationController
  # {fact rule=insecure-direct-object-ref@v1.0 defects=1}
  def bad_case_8
    # ruleid: ruby-untrusted-find
    result = Document.find(request.query_parameters[:doc_id])
    render json: result
  end
  # {/fact}
end

# Case 9: Using find with path parameters
class ApiV2Controller < ApplicationController
  # {fact rule=insecure-direct-object-ref@v1.0 defects=1}
  def bad_case_9
    # ruleid: ruby-untrusted-find
    post = Post.find(request.path_parameters[:id])
    render json: post
  end
  # {/fact}
end

# Case 10: Using find with header value
class HeaderBasedController < ApplicationController
  # {fact rule=insecure-direct-object-ref@v1.0 defects=1}
  def bad_case_10
    doc_id = request.headers["X-Document-Id"]
    # ruleid: ruby-untrusted-find
    doc = Document.find(doc_id)
    render json: doc
  end
  # {/fact}
end

# Case 11: Using find with cookie value
class CookieBasedController < ApplicationController
  # {fact rule=insecure-direct-object-ref@v1.0 defects=1}
  def bad_case_11
    user_id = cookies[:user_id]
    # ruleid: ruby-untrusted-find
    user = User.find(user_id)
    render json: user
  end
  # {/fact}
end

# Case 12: Using find with multiple IDs from params
class BatchController < ApplicationController
  # {fact rule=insecure-direct-object-ref@v1.0 defects=1}
  def bad_case_12
    ids = params[:ids].split(',')
    # ruleid: ruby-untrusted-find
    documents = Document.find(ids)
    render json: documents
  end
  # {/fact}
end

# Case 13: Using find with session data that could be manipulated
class SessionController < ApplicationController
  # {fact rule=insecure-direct-object-ref@v1.0 defects=1}
  def bad_case_13
    # ruleid: ruby-untrusted-find
    document = Document.find(session[:last_viewed_document_id])
    render json: document
  end
  # {/fact}
end

# Case 14: Using find with a complex expression but still user input
class ComplexController < ApplicationController
  # {fact rule=insecure-direct-object-ref@v1.0 defects=1}
  def bad_case_14
    id = params[:prefix] + params[:id] + params[:suffix]
    # ruleid: ruby-untrusted-find
    document = Document.find(id)
    render json: document
  end
  # {/fact}
end

# Case 15: Using find with input from URL fragment
class FragmentController < ApplicationController
  # {fact rule=insecure-direct-object-ref@v1.0 defects=1}
  def bad_case_15
    fragment = request.url.split('#').last
    id = fragment.split('=').last
    # ruleid: ruby-untrusted-find
    document = Document.find(id)
    render json: document
  end
  # {/fact}
end

# TRUE NEGATIVES - Secure code examples

# Case 1: Properly scoped find with current_user
class DocumentsController < ApplicationController
  # {fact rule=insecure-direct-object-ref@v1.0 defects=0}
  def good_case_1
    document_id = params[:id]
    # ok: ruby-untrusted-find
    document = current_user.documents.find(document_id)
    render json: document
  end
  # {/fact}
end

# Case 2: Using find with hardcoded ID (not user input)
class StaticController < ApplicationController
  # {fact rule=insecure-direct-object-ref@v1.0 defects=0}
  def good_case_2
    # ok: ruby-untrusted-find
    welcome_post = Post.find(1) # Hardcoded ID is safe
    render json: welcome_post
  end
  # {/fact}
end

# Case 3: Using find with proper authorization check
class PostsController < ApplicationController
  # {fact rule=insecure-direct-object-ref@v1.0 defects=0}
  def good_case_3
    post = Post.find(params[:id])
    # ok: ruby-untrusted-find
    if post.user_id == current_user.id || current_user.admin?
      render json: post
    else
      render json: { error: "Unauthorized" }, status: :forbidden
    end
  end
  # {/fact}
end

# Case 4: Using find with scope
class OrdersController < ApplicationController
  # {fact rule=insecure-direct-object-ref@v1.0 defects=0}
  def good_case_4
    # ok: ruby-untrusted-find
    order = current_user.orders.find(params[:id])
    render json: order
  end
  # {/fact}
end

# Case 5: Using find_by with proper scope
class ProductsController < ApplicationController
  # {fact rule=insecure-direct-object-ref@v1.0 defects=0}
  def good_case_5
    # ok: ruby-untrusted-find
    product = current_user.products.find_by(id: params[:id])
    render json: product
  end
  # {/fact}
end

# Case 6: Using where clause before find
class DocumentsController < ApplicationController
  # {fact rule=insecure-direct-object-ref@v1.0 defects=0}
  def good_case_6
    # ok: ruby-untrusted-find
    document = Document.where(user_id: current_user.id).find(params[:id])
    render json: document
  end
  # {/fact}
end

# Case 7: Using find with proper policy check
class PostsController < ApplicationController
  # {fact rule=insecure-direct-object-ref@v1.0 defects=0}
  def good_case_7
    post = Post.find(params[:id])
    # ok: ruby-untrusted-find
    authorize post # Using Pundit or similar authorization gem
    render json: post
  end
  # {/fact}
end

# Case 8: Using find with published scope
class PublicPostsController < ApplicationController
  # {fact rule=insecure-direct-object-ref@v1.0 defects=0}
  def good_case_8
    # ok: ruby-untrusted-find
    post = Post.published.find(params[:id])
    render json: post
  end
  # {/fact}
end

# Case 9: Admin controller with proper role check
class AdminDocumentsController < ApplicationController
  before_action :ensure_admin
  
  # {fact rule=insecure-direct-object-ref@v1.0 defects=0}
  def good_case_9
    # ok: ruby-untrusted-find
    document = Document.find(params[:id]) # Safe because we checked admin status
    render json: document
  end
  # {/fact}
  
  private
  
  def ensure_admin
    redirect_to root_path unless current_user&.admin?
  end
end

# Case 10: Using find with proper joins and conditions
class TeamDocumentsController < ApplicationController
  # {fact rule=insecure-direct-object-ref@v1.0 defects=0}
  def good_case_10
    # ok: ruby-untrusted-find
    document = Document.joins(:team_memberships)
                      .where(team_memberships: { user_id: current_user.id })
                      .find(params[:id])
    render json: document
  end
  # {/fact}
end

# Case 11: Using find with a whitelist approach
class WhitelistController < ApplicationController
  # {fact rule=insecure-direct-object-ref@v1.0 defects=0}
  def good_case_11
    allowed_ids = current_user.accessible_document_ids
    document_id = params[:id]
    
    if allowed_ids.include?(document_id.to_i)
      # ok: ruby-untrusted-find
      document = Document.find(document_id)
      render json: document
    else
      render json: { error: "Not found" }, status: :not_found
    end
  end
  # {/fact}
end

# Case 12: Using find after proper validation
class ValidatedController < ApplicationController
  # {fact rule=insecure-direct-object-ref@v1.0 defects=0}
  def good_case_12
    document_id = params[:id]
    
    # Validate ownership first
    ownership = DocumentOwnership.find_by(
      user_id: current_user.id,
      document_id: document_id
    )
    
    if ownership
      # ok: ruby-untrusted-find
      document = Document.find(document_id)
      render json: document
    else
      render json: { error: "Not found" }, status: :not_found
    end
  end
  # {/fact}
end

# Case 13: Using find with proper access control list check
class AclController < ApplicationController
  # {fact rule=insecure-direct-object-ref@v1.0 defects=0}
  def good_case_13
    document_id = params[:id]
    
    if AccessControl.can_access?(current_user, 'Document', document_id)
      # ok: ruby-untrusted-find
      document = Document.find(document_id)
      render json: document
    else
      render json: { error: "Access denied" }, status: :forbidden
    end
  end
  # {/fact}
end

# Case 14: Using find with proper scope through association
class ProjectDocumentsController < ApplicationController
  # {fact rule=insecure-direct-object-ref@v1.0 defects=0}
  def good_case_14
    project = current_user.projects.find(params[:project_id])
    # ok: ruby-untrusted-find
    document = project.documents.find(params[:id])
    render json: document
  end
  # {/fact}
end

# Case 15: Using find with proper role-based access control
class RbacController < ApplicationController
  # {fact rule=insecure-direct-object-ref@v1.0 defects=0}
  def good_case_15
    document_id = params[:id]
    
    # Check permissions through a proper RBAC system
    if Permission.check(current_user, 'read', 'Document', document_id)
      # ok: ruby-untrusted-find
      document = Document.find(document_id)
      render json: document
    else
      render json: { error: "Permission denied" }, status: :forbidden
    end
  end
  # {/fact}
end