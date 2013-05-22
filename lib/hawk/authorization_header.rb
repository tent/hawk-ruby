module Hawk
  module AuthorizationHeader
    extend self

    REQUIRED_OPTIONS = [:method, :path, :host, :port].freeze
    REQUIRED_CREDENTIAL_MEMBERS = [:id, :key, :algorithm].freeze
    SUPPORTED_ALGORITHMS = ['sha256', 'sha1'].freeze
    HEADER_PARTS = [:id, :ts, :nonce, :hash, :ext, :mac].freeze

    DEFAULT_TIMESTAMP_SKEW = 60.freeze # ±60 seconds

    MissingOptionError = Class.new(StandardError)
    InvalidCredentialsError = Class.new(StandardError)
    InvalidAlgorithmError = Class.new(StandardError)

    def build(options, only=nil)
      options[:ts] ||= Time.now.to_i
      options[:nonce] ||= SecureRandom.hex(4)

      REQUIRED_OPTIONS.each do |key|
        unless options.has_key?(key)
          raise MissingOptionError.new("#{key.inspect} is missing!")
        end
      end

      credentials = options[:credentials]
      REQUIRED_CREDENTIAL_MEMBERS.each do |key|
        unless credentials.has_key?(key)
          raise InvalidCredentialsError.new("#{key.inspect} is missing!")
        end
      end

      unless SUPPORTED_ALGORITHMS.include?(credentials[:algorithm])
        raise InvalidAlgorithmError.new("#{credentials[:algorithm].inspect} is not a supported algorithm! Use one of the following: #{SUPPORTED_ALGORITHMS.join(', ')}")
      end

      hash = Crypto.hash(options)
      mac = Crypto.mac(options)

      parts = {
        :id => credentials[:id],
        :ts => options[:ts],
        :nonce => options[:nonce],
        :mac => mac
      }
      parts[:hash] = hash if options.has_key?(:payload)
      parts[:ext] = options[:ext] if options.has_key?(:ext)

      "Hawk " << (only || HEADER_PARTS).inject([]) { |memo, key|
        next memo unless parts.has_key?(key)
        memo << %(#{key}="#{parts[key]}")
        memo
      }.join(', ')
    end

    def authenticate(header, options)
      parts = parse(header)

      now = Time.now.to_i

      options[:timestamp_skew] ||= DEFAULT_TIMESTAMP_SKEW

      if options[:server_response]
        credentials = options[:credentials]
        parts.merge!(
          :ts => options[:ts],
          :nonce => options[:nonce]
        )
      else
        unless options[:credentials_lookup].respond_to?(:call) && (credentials = options[:credentials_lookup].call(parts[:id]))
          return AuthenticationFailure.new(:id, "Unidentified id")
        end

        if (now - parts[:ts].to_i > options[:timestamp_skew]) || (parts[:ts].to_i - now > options[:timestamp_skew])
          # Stale timestamp
          return AuthenticationFailure.new(:ts, "Stale ts", :credentials => credentials)
        end

        unless parts[:nonce]
          return AuthenticationFailure.new(:nonce, "Missing nonce")
        end

        if options[:nonce_lookup].respond_to?(:call) && options[:nonce_lookup].call(parts[:nonce])
          # Replay
          return AuthenticationFailure.new(:nonce, "Invalid nonce")
        end
      end

      expected_mac = Crypto.mac(options.merge(
        :credentials => credentials,
        :ts => parts[:ts],
        :nonce => parts[:nonce],
        :ext => parts[:ext]
      ))
      unless expected_mac == parts[:mac]
        return AuthenticationFailure.new(:mac, "Invalid mac")
      end

      expected_hash = parts[:hash] ? Crypto.hash(options.merge(:credentials => credentials)) : nil
      if expected_hash && expected_hash != parts[:hash]
        return AuthenticationFailure.new(:hash, "Invalid hash")
      end

      credentials
    end

    def parse(header)
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
