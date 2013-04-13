require 'securerandom'

module Hawk
  class Client
    REQUIRED_OPTIONS = [:method, :path, :host, :port].freeze
    REQUIRED_CREDENTIAL_MEMBERS = [:id, :key, :algorithm].freeze
    SUPPORTED_ALGORITHMS = ['sha256', 'sha1'].freeze

    MissingOptionError = Class.new(StandardError)
    InvalidCredentialsError = Class.new(StandardError)
    InvalidAlgorithmError = Class.new(StandardError)

    def self.build_authorization_header(options)
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

      parts = []
      parts << %(id="#{credentials[:id]}")
      parts << %(ts="#{options[:ts]}")
      parts << %(nonce="#{options[:nonce]}")
      parts << %(hash="#{hash}") if options.has_key?(:payload)
      parts << %(ext="#{options[:ext]}") if options.has_key?(:ext)
      parts << %(mac="#{mac}")
      "Hawk #{parts.join(', ')}"
    end
  end
end
