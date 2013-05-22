require 'base64'
require 'openssl'

##
# Ruby 1.8.7 compatibility
unless Base64.respond_to?(:strict_encode64)
  Base64.class_eval do
    def strict_encode64(bin)
      [bin].pack("m0")
    end
  end
end
unless Base64.respond_to?(:urlsafe_encode64)
  Base64.class_eval do
    def urlsafe_encode64(bin)
      strict_encode64(bin).tr("+/", "-_").gsub("\n", '')
    end
  end
end

module Hawk
  module Crypto
    extend self

    def hash(options)
      parts = []

      parts << "hawk.1.payload"
      parts << options[:content_type]
      parts << options[:payload].to_s
      parts << nil # trailing newline

      Base64.encode64(OpenSSL::Digest.const_get(options[:credentials][:algorithm].upcase).digest(parts.join("\n"))).chomp
    end

    def normalized_string(options)
      parts = []

      parts << "hawk.1.#{options[:type] || 'header'}"
      parts << options[:ts]
      parts << options[:nonce]
      parts << options[:method].to_s.upcase
      parts << options[:path]
      parts << options[:host]
      parts << options[:port]
      parts << options[:hash]
      parts << options[:ext]

      if options[:app]
        parts << options[:app]
        parts << options[:dig]
      end

      parts << nil # trailing newline

      parts.join("\n")
    end

    def mac(options)
      if !options[:hash] && options.has_key?(:payload)
        options[:hash] = hash(options)
      end

      Base64.encode64(
        OpenSSL::HMAC.digest(
          openssl_digest(options[:credentials][:algorithm]).new,
          options[:credentials][:key],
          normalized_string(options)
        )
      ).chomp
    end

    def ts_mac(options)
      Base64.encode64(
        OpenSSL::HMAC.digest(
          openssl_digest(options[:credentials][:algorithm]).new,
          options[:credentials][:key],
          "hawk.1.ts\n#{options[:ts]}\n"
        )
      ).chomp
    end

    def bewit(options)
      options[:ts] ||= Time.now.to_i + options[:ttl].to_i

      _mac = mac(options.merge(:type => 'bewit'))

      parts = []

      parts << options[:credentials][:id]
      parts << options[:ts]
      parts << _mac
      parts << options[:ext]

      Base64.urlsafe_encode64(parts.join("\\")).chomp.sub(/=+\Z/, '')
    end

    def openssl_digest(algorithm)
      OpenSSL::Digest.const_get(algorithm.upcase)
    end
  end
end
