module Hawk
  module Server
    extend self

    AuthenticationFailure = Struct.new(:key)

    def authenticate(authorization_header, options)
      parts = parse_authorization_header(authorization_header)

      now = Time.now.to_i

      if (now - parts[:ts].to_i > 1000) || (parts[:ts].to_i - now > 1000)
        # Stale timestamp
        return AuthenticationFailure.new(:ts)
      end

      unless parts[:nonce]
        return AuthenticationFailure.new(:nonce)
      end

      if options[:nonce_lookup].respond_to?(:call) && options[:nonce_lookup].call(parts[:nonce])
        # Replay
        return AuthenticationFailure.new(:nonce)
      end

      unless options[:credentials_lookup] && (credentials = options[:credentials_lookup].call(parts[:id]))
        return AuthenticationFailure.new(:id)
      end

      expected_mac = Crypto.mac(options.merge(
        :credentials => credentials,
        :ts => parts[:ts],
        :nonce => parts[:nonce],
        :ext => parts[:ext]
      ))
      unless expected_mac == parts[:mac]
        return AuthenticationFailure.new(:mac)
      end

      expected_hash = parts[:hash] ? Crypto.hash(options.merge(:credentials => credentials)) : nil
      if expected_hash && expected_hash != parts[:hash]
        return AuthenticationFailure.new(:hash)
      end

      credentials
    end

    def parse_authorization_header(header)
      parts = header.sub(/\AHawk\s+/, '').split(/,\s*/)
      parts.inject(Hash.new) do |memo, part|
        next memo unless part =~ %r{([a-z]+)=(['"])([^\2]+)\2}
        key, val = $1, $3
        memo[key.to_sym] = val
        memo
      end
    end
  end
end
