require 'spec_helper'
require 'support/shared_examples/authorization_header'

describe Hawk::Client do

  let(:credentials) do
    {
      :id => '123456',
      :key => '2983d45yun89q',
      :algorithm => algorithm
    }
  end

  let(:timestamp) { Time.now.to_i }
  let(:nonce) { 'Ygvqdz' }

  describe ".authenticate" do
    let(:payload) {}
    let(:ext) {}

    let(:input) do
      _input = {
        :method => 'POST',
        :request_uri => '/somewhere/over/the/rainbow',
        :host => 'example.net',
        :port => 80,
        :content_type => 'text/plain',
        :credentials => credentials,
        :ts => timestamp,
        :nonce => nonce
      }
      _input[:payload] = payload if payload
      _input
    end

    let(:client_input) do
      _input = input
      _input[:type] = 'response'
      _input[:ext] = ext if ext
      _input
    end

    let(:expected_mac) { Hawk::Crypto.mac(client_input).to_s }
    let(:expected_hash) { client_input[:payload] ? Hawk::Crypto.hash(client_input).to_s : nil }

    let(:authorization_header) do
      parts = []
      parts << %(hash="#{expected_hash}") if expected_hash
      parts << %(mac="#{expected_mac}")
      parts << %(ext="#{ext}") if ext
      "Hawk #{parts.join(', ')}"
    end

    shared_examples "an authorization response header authenticator" do
      it_behaves_like "an authorization header authenticator"
    end

    context "when using sha256" do
      let(:algorithm) { "sha256" }

      it_behaves_like "an authorization response header authenticator"
    end

    context "when using sha1" do
      let(:algorithm) { "sha1" }

      it_behaves_like "an authorization response header authenticator"
    end
  end

  describe ".build_authorization_header" do
    before do
      now = Time.now
      Time.stubs(:now).returns(now)
    end

    let(:expected_mac) { Hawk::Crypto.mac(input).to_s }
    let(:expected_hash) { input[:payload] ? Hawk::Crypto.hash(input).to_s : nil }

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
      parts << %(id="#{credentials[:id]}")
      parts << %(ts="#{timestamp}")
      parts << %(nonce="#{input[:nonce]}")
      parts << %(hash="#{expected_hash}") if input[:payload]
      parts << %(ext="#{input[:ext]}") if input[:ext]
      parts << %(mac="#{expected_mac}")
      parts
    end

    let(:expected_output) do
      "Hawk #{expected_output_parts.join(', ')}"
    end

    shared_examples "an authorization request header builder" do
      it_behaves_like "an authorization header builder"

      context "without nonce" do
        let(:nonce) { nil }

        it "generates a nonce" do
          actual = described_class.build_authorization_header(input)
          expect(actual).to match(%r{\bnonce="[^"]+"})
        end
      end
    end

    context "when using sha256" do
      let(:algorithm) { "sha256" }

      it_behaves_like "an authorization request header builder"
    end

    context "when using sha1" do
      let(:algorithm) { "sha1" }

      it_behaves_like "an authorization request header builder"
    end
  end

  describe ".calculate_time_offset" do
    let(:algorithm) { 'sha256' }
    let(:timestamp) { 1365741469 }
    let(:header) do
      %(Hawk ts="#{timestamp}", tsm="#{timestamp_mac}", error="Some Error Message")
    end

    before do
      Time.stubs(:now).returns(Time.at(timestamp + offset))
    end

    context "with valid timestamp mac" do
      let(:timestamp_mac) { Hawk::Crypto.ts_mac(:ts => timestamp, :credentials => credentials) }

      context "with positive offset" do
        let(:offset) { -2030 }
        it "returns time offset in seconds" do
          expect(described_class.calculate_time_offset(header, :credentials => credentials)).to eql(offset * -1)
        end
      end

      context "with negative offset" do
        let(:offset) { 12345 }
        it "returns time offset in seconds" do
          expect(described_class.calculate_time_offset(header, :credentials => credentials)).to eql(offset * -1)
        end
      end
    end

    context "with invalid timestamp mac" do
      let(:timestamp_mac) { "fooabr" }
      let(:offset) { 1432 }

      it "returns nil" do
        expect(described_class.calculate_time_offset(header, :credentials => credentials)).to be_nil
      end
    end
  end

end
