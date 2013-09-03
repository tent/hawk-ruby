module Hawk
  module TimestampMacHeader
    extend self

    REQUIRED_CREDENTIAL_MEMBERS = AuthorizationHeader::REQUIRED_CREDENTIAL_MEMBERS
    SUPPORTED_ALGORITHMS = AuthorizationHeader::SUPPORTED_ALGORITHMS

    InvalidCredentialsError = Class.new(StandardError)
    InvalidAlgorithmError = Class.new(StandardError)

    def build(options)
      options[:ts] ||= Time.now.to_i

      credentials = options[:credentials]
      REQUIRED_CREDENTIAL_MEMBERS.each do |key|
        unless credentials.has_key?(key)
          raise InvalidCredentialsError.new("#{key.inspect} is missing!")
        end
      end

      unless SUPPORTED_ALGORITHMS.include?(credentials[:algorithm])
        raise InvalidAlgorithmError.new("#{credentials[:algorithm].inspect} is not a supported algorithm! Use one of the following: #{SUPPORTED_ALGORITHMS.join(', ')}")
      end

      tsm = Crypto.ts_mac(options)

      %(Hawk ts="#{options[:ts]}", tsm="#{tsm}")
    end
  end
end
