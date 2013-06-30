module Hawk
  class AuthenticationFailure
    attr_reader :key, :message
    def initialize(key, message, options = {})
      @key, @message, @options = key, message, options
    end

    def header
      timestamp = Time.now.to_i
      if @options[:credentials]
        timestamp_mac = Crypto.ts_mac(:ts => timestamp, :credentials => @options[:credentials]).to_s
        %(Hawk ts="#{timestamp}", tsm="#{timestamp_mac}", error="#{message}")
      else
        %(Hawk error="#{message}")
      end
    end
  end
end
