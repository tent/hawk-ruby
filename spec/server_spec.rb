require 'spec_helper'
require 'support/shared_examples/authorization_header'

describe Hawk::Server do
  let(:credentials) do
    {
      :id => '123456',
      :key => '2983d45yun89q',
      :algorithm => algorithm
    }
  end

  describe ".authenticate" do
    let(:credentials_lookup) do
      lambda { |id|
        if id == credentials[:id]
          credentials
        end
      }
    end

    let(:nonce_lookup) do
      lambda { |nonce| nil }
    end

    let(:payload) {}
    let(:ext) {}
    let(:timestamp) { Time.now.to_i }
    let(:nonce) { 'Ygvqdz' }

    let(:timestamp_skew) { Hawk::AuthorizationHeader::DEFAULT_TIMESTAMP_SKEW }

    let(:input) do
      _input = {
        :method => 'POST',
        :request_uri => '/somewhere/over/the/rainbow',
        :host => 'example.net',
        :port => 80,
        :content_type => 'text/plain',
        :credentials_lookup => credentials_lookup,
        :nonce_lookup => nonce_lookup
      }
      _input[:payload] = payload if payload
      _input
    end

    let(:client_input) do
      _input = input.merge(
        :credentials => credentials,
        :ts => timestamp,
        :nonce => nonce
      )
      _input[:ext] = ext if ext
      _input
    end

    let(:expected_mac) { Hawk::Crypto.mac(client_input).to_s }
    let(:expected_hash) { client_input[:payload] ? Hawk::Crypto.hash(client_input).to_s : nil }

    let(:authorization_header) do
      parts = []
      parts << %(id="#{credentials[:id]}")
      parts << %(ts="#{timestamp}")
      parts << %(nonce="#{nonce}") if nonce
      parts << %(hash="#{expected_hash}") if expected_hash
      parts << %(mac="#{expected_mac}")
      parts << %(ext="#{ext}") if ext
      "Hawk #{parts.join(', ')}"
    end

    shared_examples "an authorization request header authenticator" do
      it_behaves_like "an authorization header authenticator"

      context "when unidentified id" do
        let(:credentials_lookup) do
          lambda { |id| }
        end

        it "returns error object" do
          actual = described_class.authenticate(authorization_header, input)
          expect(actual).to be_a(Hawk::AuthenticationFailure)
          expect(actual.key).to eql(:id)
          expect(actual.message).to_not eql(nil)
        end
      end

      context "when stale timestamp" do
        context "when too old" do
          let(:timestamp) { Time.now.to_i - timestamp_skew - 1 }

          it "returns error object" do
            actual = described_class.authenticate(authorization_header, input)
            expect(actual).to be_a(Hawk::AuthenticationFailure)
            expect(actual.key).to eql(:ts)
            expect(actual.message).to_not eql(nil)
          end
        end

        context "when too far in the future" do
          let(:timestamp) { Time.now.to_i + timestamp_skew + 1 }

          it "returns error object" do
            actual = described_class.authenticate(authorization_header, input)
            expect(actual).to be_a(Hawk::AuthenticationFailure)
            expect(actual.key).to eql(:ts)
            expect(actual.message).to_not eql(nil)
          end
        end

        context "when invalid content type" do
          let(:payload) { 'baz' }
          before do
            client_input[:content_type] = 'application/foo'
          end

          it "returns error object" do
            actual = described_class.authenticate(authorization_header, input)
            expect(actual).to be_a(Hawk::AuthenticationFailure)
            expect(actual.key).to eql(:hash)
            expect(actual.message).to_not eql(nil)
          end
        end

        context "when nonce missing" do
          let(:nonce) { nil }

          it "returns error object" do
            actual = described_class.authenticate(authorization_header, input)
            expect(actual).to be_a(Hawk::AuthenticationFailure)
            expect(actual.key).to eql(:nonce)
            expect(actual.message).to_not eql(nil)
          end
        end
      end

      context "when replay" do
        let(:nonce_lookup) do
          lambda do |nonce|
            true
          end
        end

        it "returns error object" do
          actual = described_class.authenticate(authorization_header, input)
          expect(actual).to be_a(Hawk::AuthenticationFailure)
          expect(actual.key).to eql(:nonce)
          expect(actual.message).to_not eql(nil)
        end
      end

      context "when no credentials_lookup given" do
        before do
          input.delete(:credentials_lookup)
        end

        it "returns error object" do
          actual = described_class.authenticate(authorization_header, input)
          expect(actual).to be_a(Hawk::AuthenticationFailure)
          expect(actual.key).to eql(:id)
          expect(actual.message).to_not eql(nil)
        end
      end
    end

    context "when using sha256" do
      let(:algorithm) { "sha256" }

      it_behaves_like "an authorization request header authenticator"
    end

    context "when using sha1" do
      let(:algorithm) { "sha1" }

      it_behaves_like "an authorization request header authenticator"
    end
  end

  describe ".build_authorization_header" do
    let(:expected_mac) { Hawk::Crypto.mac(input).to_s }
    let(:expected_hash) { input[:payload] ? Hawk::Crypto.hash(input).to_s : nil }
    let(:timestamp) { Time.now.to_i }
    let(:nonce) { 'Ygvqdz' }

    let(:input) do
      _input = {
        :credentials => credentials,
        :ts => timestamp,
        :method => 'POST',
        :request_uri => '/somewhere/over/the/rainbow',
        :host => 'example.net',
        :port => 80,
        :payload => 'something to write about',
        :ext => 'Bazinga!'
      }
      _input[:nonce] = nonce if nonce
      _input
    end

    let(:expected_output_parts) do
      parts = []
      parts << %(hash="#{expected_hash}") if input[:payload]
      parts << %(ext="#{input[:ext]}") if input[:ext]
      parts << %(mac="#{expected_mac}")
      parts
    end

    let(:expected_output) do
      "Hawk #{expected_output_parts.join(', ')}"
    end

    context "when using sha256" do
      let(:algorithm) { "sha256" }

      it_behaves_like "an authorization header builder"
    end

    context "when using sha1" do
      let(:algorithm) { "sha1" }

      it_behaves_like "an authorization header builder"
    end
  end

  describe ".build_tsm_header" do
    let(:expected_tsm) { Hawk::Crypto.ts_mac(input).to_s }
    let(:timestamp) { Time.now.to_i }

    let(:input) do
      {
        :credentials => credentials,
        :ts => timestamp
      }
    end

    let(:expected_output_parts) do
      [
        %(ts="#{timestamp}"),
        %(tsm="#{expected_tsm}")
      ]
    end

    let(:expected_output) do
      "Hawk #{expected_output_parts.join(', ')}"
    end

    context "when using sha256" do
      let(:algorithm) { "sha256" }

      it "builds tsm header" do
        actual = described_class.build_tsm_header(input)

        expected_output_parts.each do |expected_part|
          matcher = Regexp === expected_part ? expected_part : Regexp.new(Regexp.escape(expected_part))
          expect(actual).to match(matcher)
        end

        expect(actual).to eql(expected_output)
      end
    end
  end

  describe ".authenticate_bewit" do
    shared_examples "authenticate_bewit" do
      context "when valid" do
        it "returns credentials" do
          expect(described_class.authenticate_bewit(bewit, input)).to eql(credentials)
        end
      end

      context "when invalid format" do
        let(:bewit) { "invalid-bewit" }

        it "returns error object" do
          actual = described_class.authenticate_bewit(bewit, input)
          expect(actual).to be_a(Hawk::AuthenticationFailure)
          expect(actual.key).to eql(:id)
          expect(actual.message).to_not eql(nil)
        end
      end

      context "when invalid ext" do
        let(:bewit) { "MTIzNDU2XDQ1MTkzMTE0NThcVTN4dVF5TEVXUGNOa3Q4Vm5oRy9BSDg4VERQZXlKT2JKeGVNb0tkZWZUQT1caW52YWxpZCBleHQ" }

        it "returns error object" do
          actual = described_class.authenticate_bewit(bewit, input)
          expect(actual).to be_a(Hawk::AuthenticationFailure)
          expect(actual.key).to eql(:bewit)
          expect(actual.message).to_not eql(nil)
        end
      end

      context "when stale timestamp" do
        let(:now) { 4519311459 }

        it "returns error object" do
          actual = described_class.authenticate_bewit(bewit, input)
          expect(actual).to be_a(Hawk::AuthenticationFailure)
          expect(actual.key).to eql(:ts)
          expect(actual.message).to_not eql(nil)
        end
      end
    end

    let(:credentials_lookup) do
      lambda { |id|
        if id == credentials[:id]
          credentials
        end
      }
    end

    let(:algorithm) { "sha256" }

    let(:input) do
      {
        :credentials_lookup => credentials_lookup,
        :method => 'GET',
        :request_uri => "/resource/4?a=1&bewit=#{bewit}&b=2",
        :host => 'example.com',
        :port => 80,
      }
    end

    let(:bewit) { "MTIzNDU2XDQ1MTkzMTE0NThcYkkwanFlS1prUHE0V1hRMmkxK0NrQ2lOanZEc3BSVkNGajlmbElqMXphWT1cc29tZS1hcHAtZGF0YQ" }

    let(:now) { 1365711458 }
    before do
      Time.stubs(:now).returns(Time.at(now))
    end

    context "when request_uri is path" do
      it_behaves_like "authenticate_bewit"
    end

    context "when request_uri is full url" do
      before do
        input[:request_uri] = "http://example.com/resource/4?a=1&bewit=#{bewit}&b=2"
      end

      it_behaves_like "authenticate_bewit"
    end
  end

end
