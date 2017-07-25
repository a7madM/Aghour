module AuthHelper
  attr_reader :current_user

  def authenticate_request
    load_current_user! unless !payload || !JsonWebToken.valid_payload(payload.first)
  end

  # Returns 401 response. To handle malformed / invalid requests.
  def unauthorized
    respond_to do |format|
      format.html { redirect_back fallback_location: users_login_path }
      format.json { render json: { error: 'Unauthorized' }, status: :unauthorized }
    end
  end

  def bad_request
    respond_to do |format|
      format.html { redirect_back fallback_location: questions_path }
      format.json { render json: { error: 'Bad Request' }, status: :bad_request }
    end
  end

  private

  # Deconstructs the Authorization header and decodes the JWT token.
  def payload
    auth_header = request.headers['Authorization']
    auth_header ||= session[:token]
    token = auth_header.split(' ').last
    JsonWebToken.decode(token)
  rescue
    nil
  end

  # Sets the @current_user with the user_id from payload
  def load_current_user!
    @current_user = User.find_by(id: payload[0]['user_id'])
  end
end
