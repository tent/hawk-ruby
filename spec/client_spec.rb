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

  before do
    now = Time.now
    Time.stubs(:now).returns(now)
  end
  let(:timestamp) { Time.now.to_i }

  let(:expected_mac) { Hawk::Crypto.mac(input) }
  let(:expected_hash) { input[:payload] ? Hawk::Crypto.hash(input) : nil }

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

  describe ".build_authorization_header" do
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

end
