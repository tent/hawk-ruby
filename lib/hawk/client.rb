require 'securerandom'

module Hawk
  module Client
    extend self

    def authenticate(authorization_header, options)
      Hawk::AuthorizationHeader.authenticate(authorization_header, { :server_response => true, :type => 'response' }.merge(options))
    end

    def build_authorization_header(options)
      Hawk::AuthorizationHeader.build(options)
    end

    def calculate_time_offset(authorization_header, options)
      parts = AuthorizationHeader.parse(authorization_header)
      expected_mac = Crypto.ts_mac(:ts => parts[:ts], :credentials => options[:credentials]).to_s
      return unless expected_mac == parts[:tsm]
      parts[:ts].to_i - Time.now.to_i
    end
  end
end
