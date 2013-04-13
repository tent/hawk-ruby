module Hawk
  module Server
    extend self

    def authenticate(authorization_header, options)
      Hawk::AuthorizationHeader.authenticate(authorization_header, options)
    end

    def build_authorization_header(options)
      Hawk::AuthorizationHeader.build(options, [:hash, :ext, :mac])
    end
  end
end
