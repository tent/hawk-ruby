require 'spec_helper'

describe Hawk::Crypto do

  describe "#normalized_string" do
    let(:normalization_method) { "normalized_string" }

    shared_examples "an input normalization method" do
      it "returns a valid normalized string" do
        expect(described_class.send(normalization_method, input)).to eql(expected_output)
      end
    end

    let(:input) do
      {
        :ts => 1365701514,
        :nonce => '5b4e',
        :method => 'GET',
        :path => "/path/to/foo?bar=baz",
        :host => 'example.com',
        :port => 8080
      }
    end

    let(:expected_output) do
      %(hawk.1.header\n#{input[:ts]}\n#{input[:nonce]}\n#{input[:method]}\n#{input[:path]}\n#{input[:host]}\n#{input[:port]}\n\n\n)
    end

    it_behaves_like "an input normalization method"

    context "with ext" do
      let(:input) do
        {
          :ts => 1365701514,
          :nonce => '5b4e',
          :method => 'GET',
          :path => '/path/to/foo?bar=baz',
          :host => 'example.com',
          :port => 8080,
          :ext => 'this is some app data'
        }
      end

      let(:expected_output) do
        %(hawk.1.header\n#{input[:ts]}\n#{input[:nonce]}\n#{input[:method]}\n#{input[:path]}\n#{input[:host]}\n#{input[:port]}\n\n#{input[:ext]}\n)
      end

      it_behaves_like "an input normalization method"
    end

    context "with payload and ext" do
      let(:input) do
        {
          :ts => 1365701514,
          :nonce => '5b4e',
          :method => 'GET',
          :path => '/path/to/foo?bar=baz',
          :host => 'example.com',
          :port => 8080,
          :hash => 'U4MKKSmiVxk37JCCrAVIjV/OhB3y+NdwoCr6RShbVkE=',
          :ext => 'this is some app data'
        }
      end

      let(:expected_output) do
        %(hawk.1.header\n#{input[:ts]}\n#{input[:nonce]}\n#{input[:method]}\n#{input[:path]}\n#{input[:host]}\n#{input[:port]}\n#{input[:hash]}\n#{input[:ext]}\n)
      end

      it_behaves_like "an input normalization method"
    end
  end

end
