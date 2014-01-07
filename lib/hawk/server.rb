module Hawk
  module Server
    extend self

    def authenticate(authorization_header, options)
      Hawk::AuthorizationHeader.authenticate(authorization_header, options)
    end

    def authenticate_bewit(encoded_bewit, options)
      bewit = Crypto::Bewit.decode(encoded_bewit)

      unless options[:credentials_lookup].respond_to?(:call) && (credentials = options[:credentials_lookup].call(bewit.id))
        return AuthenticationFailure.new(:id, "Unidentified id")
      end

      if Time.at(bewit.ts.to_i) < Time.now
        return AuthenticationFailure.new(:ts, "Stale timestamp")
      end

      expected_bewit = Crypto.bewit(
        :credentials => credentials,
        :host => options[:host],
        :request_uri => remove_bewit_param_from_path(options[:request_uri]),
        :port => options[:port],
        :method => options[:method],
        :ts => bewit.ts,
        :ext => bewit.ext
      )

      unless expected_bewit.eql?(bewit)
        if options[:request_uri].to_s =~ /\Ahttp/
          return authenticate_bewit(encoded_bewit, options.merge(
            :request_uri => options[:request_uri].sub(%r{\Ahttps?://[^/]+}, '')
          ))
        else
          return AuthenticationFailure.new(:bewit, "Invalid signature #{expected_bewit.mac.normalized_string}")
        end
      end

      credentials
    end

    def build_authorization_header(options)
      options[:type] = 'response'
      Hawk::AuthorizationHeader.build(options, [:hash, :ext, :mac])
    end

    def build_tsm_header(options)
      Hawk::TimestampMacHeader.build(options)
    end

    private

    def remove_bewit_param_from_path(path)
      path, query = path.split('?')
      return path unless query
      query, fragment = query.split('#')
      query = query.split('&').reject { |i| i =~ /\Abewit=/ }.join('&')
      path << "?#{query}" if query != ''
      path << "#{fragment}" if fragment
      path
    end
  end
end
