require 'securerandom'

module Hawk
  class Client
    def self.build_authorization_header(options)
      Hawk::AuthorizationHeader.build(options)
    end
  end
end
