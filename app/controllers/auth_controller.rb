class AuthController < ApplicationController
  def index
    @user = User.find_by(email: params[:email].to_s.downcase) # pulk(User.attribute_names - ['enormous_field'])
    if @user && @user.authenticate(params[:password])
      auth_token = JsonWebToken.encode(user_id: @user.id)
      session[:token] = auth_token
      respond_to do |format|
        format.json { render json: { user: @user.as_json, token: auth_token }, status: :ok }
        format.html {}
      end # end of format respond
    else
      respond_to do |format|
        format.json { render json: { error: 'Invalid Email/Password' }, status: :unauthorized }
        format.html {}
      end # end of format respond
    end # end of if/else statment
  end # end of method

  private

  def payload(user)
    return nil unless user && user.id
    {
      auth_token: JsonWebToken.encode(user_id: user.id),
      user: { id: user.id, email: user.email }
    }
  end
end
