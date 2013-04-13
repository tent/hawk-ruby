require 'securerandom'

module Hawk
  module Client
    extend self

    def authenticate(authorization_header, options)
      Hawk::AuthorizationHeader.authenticate(authorization_header, {
        :credentials_lookup => lambda { |id| options[:credentials][:id] == id ? options[:credentials] : nil }
      }.merge(options))
    end

    def build_authorization_header(options)
      Hawk::AuthorizationHeader.build(options)
    end
  end
end
