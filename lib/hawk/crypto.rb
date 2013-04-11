module Hawk
  module Crypto
    extend self

    def normalized_string(options)
      parts = []

      parts << "hawk.1.header"
      parts << options[:ts]
      parts << options[:nonce]
      parts << options[:method].to_s.upcase
      parts << options[:path]
      parts << options[:host]
      parts << options[:port]
      parts << options[:hash]
      parts << options[:ext]
      parts << nil # trailing newline

      parts.join("\n")
    end
  end
end
