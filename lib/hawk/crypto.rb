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

    class Mac
      attr_reader :normalized_string, :algorithm
      def initialize(normalized_string, key, algorithm = 'sha256')
        @normalized_string, @key, @algorithm = normalized_string, key, algorithm
      end

      def digest
        @digest ||= OpenSSL::HMAC.digest(openssl_digest(@algorithm).new, @key, @normalized_string)
      end

      def to_s(options = {})
        if options[:raw]
          digest
        else
          encode64
        end
      end

      def encode64
        Base64.encode64(digest).chomp
      end

      def ==(other)
        if self.class === other
          Crypto.secure_compare(to_s(:raw => true), other.to_s(:raw => true))
        else
          # assume base64 encoded mac
          Crypto.secure_compare(to_s(:raw => true), Base64.decode64(other))
        end
      end

      def eql?(other)
        self == other
      end

      private

      def openssl_digest(algorithm)
        Crypto.openssl_digest(algorithm)
      end
    end

    def hash(options)
      parts = []

      parts << "hawk.1.payload"
      parts << options[:content_type]
      parts << options[:payload].to_s
      parts << nil # trailing newline

      Base64.encode64(OpenSSL::Digest.const_get(options[:credentials][:algorithm].upcase).digest(parts.join("\n"))).chomp
    end

    def normalized_string(options)
      options = options.dup
      if !options[:hash] && options.has_key?(:payload) && !options[:payload].nil?
        options[:hash] = hash(options)
      end

      parts = []

      parts << "hawk.1.#{options[:type] || 'header'}"
      parts << options[:ts]
      parts << options[:nonce]
      parts << options[:method].to_s.upcase
      parts << options[:request_uri]
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
      Mac.new(normalized_string(options), options[:credentials][:key], options[:credentials][:algorithm])
    end

    def encode64(m)
      Base64.encode64(m).chomp
    end

    def decode64(string)
      Base64.decode64(string)
    end

    def secure_compare(a, b)
      return false if a.empty? || b.empty? || a.bytesize != b.bytesize
      b_bytes = b.unpack "C#{b.bytesize}"

      res = 0
      a.each_byte { |byte| res |= byte ^ b_bytes.shift }
      res == 0
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
