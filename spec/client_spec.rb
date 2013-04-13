require 'spec_helper'

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
    shared_examples "an authorization header builder" do
      returns_valid_authorization_header = proc do
        it "returns valid authorization header" do
          actual = described_class.build_authorization_header(input)

          expected_output_parts.each do |expected_part|
            matcher = Regexp === expected_part ? expected_part : Regexp.new(Regexp.escape(expected_part))
            expect(actual).to match(matcher)
          end

          expect(actual).to eql(expected_output)
        end
      end

      context "with full options", &returns_valid_authorization_header

      context "without ext" do
        before do
          input.delete(:ext)
        end
        context '', &returns_valid_authorization_header
      end

      context "without payload" do
        before do
          input.delete(:payload)
        end
        context '', &returns_valid_authorization_header
      end

      context "without ts" do
        before do
          input.delete(:ts)
        end
        context '', &returns_valid_authorization_header
      end

      context "without nonce" do
        let(:nonce) { nil }

        it "generates a nonce" do
          actual = described_class.build_authorization_header(input)
          expect(actual).to match(%r{\bnonce="[^"]+"})
        end
      end

      %w( method path host port ).each do |missing_option|
        context "when missing #{missing_option} option" do
          before do
            input.delete(missing_option.to_sym)
          end

          it "raises MissingOptionError" do
            expect { described_class.build_authorization_header(input) }.to raise_error(Hawk::Client::MissingOptionError)
          end
        end
      end

      context "with invalid credentials" do
        context "when missing id" do
          before do
            credentials.delete(:id)
          end

          it "raises InvalidCredentialsError" do
            expect { described_class.build_authorization_header(input) }.to raise_error(Hawk::Client::InvalidCredentialsError)
          end
        end

        context "when missing key" do
          before do
            credentials.delete(:key)
          end

          it "raises InvalidCredentialsError" do
            expect { described_class.build_authorization_header(input) }.to raise_error(Hawk::Client::InvalidCredentialsError)
          end
        end

        context "when missing algorithm" do
          before do
            credentials.delete(:algorithm)
          end

          it "raises InvalidCredentialsError" do
            expect { described_class.build_authorization_header(input) }.to raise_error(Hawk::Client::InvalidCredentialsError)
          end
        end

        context "when invalid algorithm" do
          before do
            credentials[:algorithm] = 'foobar'
          end

          it "raises InvalidAlgorithmError" do
            expect { described_class.build_authorization_header(input) }.to raise_error(Hawk::Client::InvalidAlgorithmError)
          end
        end
      end
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
