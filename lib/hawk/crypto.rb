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

    class Base
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
          secure_compare(to_s(:raw => true), other.to_s(:raw => true))
        else
          # assume base64 encoded mac
          secure_compare(to_s(:raw => true), Base64.decode64(other.to_s))
        end
      end

      def eql?(other)
        self == other
      end

      private

      def secure_compare(a, b)
        return false if a.empty? || b.empty? || a.bytesize != b.bytesize
        b_bytes = b.unpack "C#{b.bytesize}"

        res = 0
        a.each_byte { |byte| res |= byte ^ b_bytes.shift }
        res == 0
      end

      def openssl_digest(algorithm)
        OpenSSL::Digest.const_get(algorithm.upcase)
      end
    end

    class Mac < Base
      def initialize(key, options, algorithm = 'sha256')
        @key, @options, @algorithm = key, options, algorithm
      end

      def normalized_string
        options = @options.dup
        if !options[:hash] && options.has_key?(:payload) && !options[:payload].nil?
          options[:hash] = Crypto.hash(options)
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
          parts << options[:dlg]
        end

        parts << nil # trailing newline

        parts.join("\n")
      end

      def digest
        @digest ||= OpenSSL::HMAC.digest(openssl_digest(@algorithm).new, @key, normalized_string)
      end
    end

    class Hash < Base
      def initialize(content_type, payload, algorithm)
        @content_type, @payload, @algorithm = content_type, payload, algorithm

        @content_type = @content_type.to_s.split(';').first.to_s.sub(/\A\s*/, '').sub(/\s*\Z/, '')
      end

      def normalized_string
        @normalized_string ||= begin
          parts = []

          parts << "hawk.1.payload"
          parts << @content_type
          parts << @payload.to_s
          parts << nil # trailing newline

          parts.join("\n")
        end
      end

      def digest
        @digest ||= openssl_digest(@algorithm).digest(normalized_string)
      end
    end

    class TSMac < Base
      def initialize(key, ts, algorithm = 'sha256')
        @key, @ts, @algorithm = key, ts, algorithm
      end

      def normalized_string
        @normalized_string ||= "hawk.1.ts\n#{@ts}\n"
      end

      def digest
        @digest ||= OpenSSL::HMAC.digest(openssl_digest(@algorithm).new, @key, normalized_string)
      end
    end

    class Bewit < Base
      def self.decode(bewit)
        padding = '=' * ((4 - bewit.size) % 4)
        id, timestamp, mac, ext = Base64.decode64(bewit + padding).split('\\')

        new(id, nil, { :mac => mac, :ext => ext, :ts => timestamp }, nil)
      end

      attr_reader :id, :ts, :ext
      def initialize(id, key, options, algorithm = 'sha256')
        @ts = options[:ts] ||= Time.now.to_i + options[:ttl].to_i
        @ext = options[:ext]
        @id, @key, @options, @algorithm = id, key, options.dup, algorithm
        @mac = options.delete(:mac) if options[:mac]
      end

      def mac
        @mac ||= Crypto::Mac.new(@key, @options.merge(:type => 'bewit'), @algorithm)
      end

      def normalized_string
        @normalized_string ||= begin
          parts = []

          parts << @id
          parts << @ts
          parts << mac.to_s
          parts << @ext

          parts.join("\\")
        end
      end

      def encode64
        @encoded ||= Base64.urlsafe_encode64(normalized_string).chomp.sub(/=+\Z/, '')
      end

      def to_s(options = {})
        encode64
      end

      def ==(other)
        if self.class === other
          mac == other.mac
        else
          # assume base64 encoded bewit
          self == self.class.decode(other)
        end
      end
    end

    def hash(options)
      Hash.new(options[:content_type], options[:payload], options[:credentials][:algorithm])
    end

    def mac(options)
      Mac.new(options[:credentials][:key], options, options[:credentials][:algorithm])
    end

    def ts_mac(options)
      TSMac.new(options[:credentials][:key], options[:ts], options[:credentials][:algorithm])
    end

    def bewit(options)
      Bewit.new(
        options[:credentials][:id],
        options[:credentials][:key],
        options,
        options[:credentials][:algorithm]
      )
    end
  end
end
