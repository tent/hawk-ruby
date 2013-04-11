require 'spec_helper'

describe Hawk::Crypto do

  let(:algorithm) { "sha256" }
  let(:credentials) do
    {
      :id => '123456',
      :key => '2983d45yun89q',
      :algorithm => algorithm
    }
  end

  describe "#hash" do
    let(:hashing_method) { "hash" }

    shared_examples "a payload hashing method" do
      it "returns valid base64 encoded hash of payload" do
        expect(described_class.send(hashing_method, input)).to eql(expected_output)
      end
    end

    let(:input) do
      {
        :credentials => credentials,
        :ts => 1353809207,
        :nonce => 'Ygvqdz',
        :method => 'POST',
        :path => '/somewhere/over/the/rainbow',
        :host => 'example.net',
        :port => 80,
        :payload => 'something to write about',
        :ext => 'Bazinga!'
      }
    end

    context "when using sha1 algorithm" do
      let(:expected_output) { "bsvY3IfUllw6V5rvk4tStEvpBhE=" }
      let(:algorithm) { "sha1" }

      it_behaves_like "a payload hashing method"
    end

    context "when using sha256 algorithm" do
      let(:expected_output) { "LjRmtkSKTW0ObTUyZ7N+vjClKd//KTTdfhF1M4XCuEM=" }

      it_behaves_like "a payload hashing method"
    end
  end

  describe "#mac" do
    let(:mac_digest_method) { "mac" }

    shared_examples "a mac digest method" do
      it "returns valid base64 encoded hmac" do
        expect(described_class.send(mac_digest_method, input)).to eql(expected_output)
      end
    end

    let(:input) do
      {
        :credentials => credentials,
        :ts => 1353809207,
        :nonce => 'Ygvqdz',
        :method => 'POST',
        :path => '/somewhere/over/the/rainbow',
        :host => 'example.net',
        :port => 80,
        :payload => 'something to write about',
        :ext => 'Bazinga!'
      }
    end

    context "when using sha1 algorithm" do
      let(:expected_output) { "qbf1ZPG/r/e06F4ht+T77LXi5vw=" }
      let(:algorithm) { "sha1" }

      it_behaves_like "a mac digest method"
    end

    context "when using sha256 algorithm" do
      let(:expected_output) { "dh5kEkotNusOuHPolRYUhvy2vlhJybTC2pqBdUQk5z0=" }

      it_behaves_like "a mac digest method"
    end
  end

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
