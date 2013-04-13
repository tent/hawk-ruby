require 'spec_helper'

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

    shared_examples "an authorization header authenticator" do
      context "with valid authorization header" do
        it "returns credentials object" do
          expect(described_class.authenticate(authorization_header, input)).to eql(credentials)
        end

        context "when hash present" do
          let(:payload) { 'something to write about' }

          it "returns credentials object" do
            expect(described_class.authenticate(authorization_header, input)).to eql(credentials)
          end
        end

        context "when ext present" do
          let(:ext) { 'some random ext' }

          it "returns credentials object" do
            expect(described_class.authenticate(authorization_header, input)).to eql(credentials)
          end
        end
      end

      context "with invalid authorization header" do
        context "when unidentified id" do
          let(:credentials_lookup) do
            lambda { |id| }
          end

          it "returns error object" do
            actual = described_class.authenticate(authorization_header, input)
            expect(actual).to be_a(Hawk::Server::AuthenticationFailure)
            expect(actual.key).to eql(:id)
            expect(actual.message).to_not eql(nil)
          end
        end

        context "when invalid mac" do
          let(:expected_mac) { 'foobar' }

          it "returns error object" do
            actual = described_class.authenticate(authorization_header, input)
            expect(actual).to be_a(Hawk::Server::AuthenticationFailure)
            expect(actual.key).to eql(:mac)
            expect(actual.message).to_not eql(nil)
          end
        end

        context "when invalid hash" do
          let(:expected_hash) { 'foobar' }
          let(:payload) { 'baz' }

          it "returns error object" do
            actual = described_class.authenticate(authorization_header, input)
            expect(actual).to be_a(Hawk::Server::AuthenticationFailure)
            expect(actual.key).to eql(:hash)
            expect(actual.message).to_not eql(nil)
          end
        end

        context "when invalid ext" do
          before do
            client_input[:ext] = 'something else'
          end

          it "returns error object" do
            actual = described_class.authenticate(authorization_header, input)
            expect(actual).to be_a(Hawk::Server::AuthenticationFailure)
            expect(actual.key).to eql(:mac)
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
            expect(actual).to be_a(Hawk::Server::AuthenticationFailure)
            expect(actual.key).to eql(:mac)
            expect(actual.message).to_not eql(nil)
          end
        end

        context "when stale timestamp" do
          context "when too old" do
            let(:timestamp) { Time.now.to_i - 1001 }

            it "returns error object" do
              actual = described_class.authenticate(authorization_header, input)
              expect(actual).to be_a(Hawk::Server::AuthenticationFailure)
              expect(actual.key).to eql(:ts)
              expect(actual.message).to_not eql(nil)
            end
          end

          context "when too far in the future" do
            let(:timestamp) { Time.now.to_i + 1001 }

            it "returns error object" do
              actual = described_class.authenticate(authorization_header, input)
              expect(actual).to be_a(Hawk::Server::AuthenticationFailure)
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
            expect(actual).to be_a(Hawk::Server::AuthenticationFailure)
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
            expect(actual).to be_a(Hawk::Server::AuthenticationFailure)
            expect(actual.key).to eql(:id)
            expect(actual.message).to_not eql(nil)
          end
        end

        context "when nonce missing" do
          let(:nonce) { nil }

          it "returns error object" do
            actual = described_class.authenticate(authorization_header, input)
            expect(actual).to be_a(Hawk::Server::AuthenticationFailure)
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
            expect(actual).to be_a(Hawk::Server::AuthenticationFailure)
            expect(actual.key).to eql(:id)
          end
        end
      end
    end

    context "when using sha256" do
      let(:algorithm) { "sha256" }

      it_behaves_like "an authorization header authenticator"
    end

    context "when using sha1" do
      let(:algorithm) { "sha1" }

      it_behaves_like "an authorization header authenticator"
    end
  end

end
