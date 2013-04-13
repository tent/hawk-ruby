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

    let(:input) do
      _input = {
        :method => 'POST',
        :path => '/somewhere/over/the/rainbow',
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
        :nonce => nonce,
      )
      _input[:ext] = ext if ext
      _input
    end

    let(:expected_mac) { Hawk::Crypto.mac(client_input) }
    let(:expected_hash) { client_input[:payload] ? Hawk::Crypto.hash(client_input) : nil }

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
          expect(actual).to be_a(Hawk::AuthorizationHeader::AuthenticationFailure)
          expect(actual.key).to eql(:id)
          expect(actual.message).to_not eql(nil)
        end
      end

      context "when stale timestamp" do
        context "when too old" do
          let(:timestamp) { Time.now.to_i - 1001 }

          it "returns error object" do
            actual = described_class.authenticate(authorization_header, input)
            expect(actual).to be_a(Hawk::AuthorizationHeader::AuthenticationFailure)
            expect(actual.key).to eql(:ts)
            expect(actual.message).to_not eql(nil)
          end
        end

        context "when too far in the future" do
          let(:timestamp) { Time.now.to_i + 1001 }

          it "returns error object" do
            actual = described_class.authenticate(authorization_header, input)
            expect(actual).to be_a(Hawk::AuthorizationHeader::AuthenticationFailure)
            expect(actual.key).to eql(:ts)
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
          expect(actual).to be_a(Hawk::AuthorizationHeader::AuthenticationFailure)
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
          expect(actual).to be_a(Hawk::AuthorizationHeader::AuthenticationFailure)
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
    let(:expected_mac) { Hawk::Crypto.mac(input) }
    let(:expected_hash) { input[:payload] ? Hawk::Crypto.hash(input) : nil }
    let(:timestamp) { Time.now.to_i }
    let(:nonce) { 'Ygvqdz' }

    let(:input) do
      _input = {
        :credentials => credentials,
        :ts => timestamp,
        :method => 'POST',
        :path => '/somewhere/over/the/rainbow',
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

end
