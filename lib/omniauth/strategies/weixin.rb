require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class Weixin < OmniAuth::Strategies::OAuth2
      option :client_options, {
        :site => 'https://api.weixin.qq.com',
        :authorize_url => 'https://open.weixin.qq.com/connect/oauth2/authorize',
        :token_url => "https://api.weixin.qq.com/sns/oauth2/access_token"
      }

      option :provider_ignores_state, true

      def request_phase
        redirect client.authorize_url(authorize_params) + "#wechat_redirect"
      end

      def authorize_params
        options[:scope] = "snsapi_userinfo" if options[:scope].nil?

        hash = {
          :appid => options.client_id, 
          :redirect_uri => callback_url, 
          :response_type => 'code', 
          :scope => options[:scope]
        }

        # additional params
        %w{scope state before_url}.each do |v|
          if request.params[v]
            session["omniauth.weixin.#{v.to_s}"] = hash[v.to_sym] = request.params[v]
          end
        end

        hash
      end

      def token_params
        params = super
        params.merge({:appid => options.client_id, :secret => options.client_secret})
      end

      def build_access_token

        code = request.params['code']

        # save code and state
        session["omniauth.weixin.code"] = code
        session["omniauth.weixin.state"] = request.params['state']

        client.auth_code.get_token(
          code,
          {:redirect_uri => callback_url, :parse => :json}.merge(token_params.to_hash(:symbolize_keys => true)),
          {:mode => :query, :param_name => 'access_token'}
        )
      end
      
      uid do
        @uid ||= begin
          access_token["openid"]
        end
      end

      info do 
        { 
          :nickname => raw_info['nickname'],
          :name => raw_info['nickname'],
          :image => raw_info['headimgurl'],
        }
      end
      
      extra do
        {
          :raw_info => raw_info
        }
      end

      def raw_info
        @raw_info ||= begin
          response =  access_token.get(
            '/sns/userinfo',
             {:params => {:openid => uid}, :parse => :json}
          ).parsed
        end
      end
    end
  end
end

OmniAuth.config.add_camelization('weixin', 'Weixin')