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
        expect(described_class.send(hashing_method, input).to_s).to eql(expected_output)
      end
    end

    let(:input) do
      {
        :credentials => credentials,
        :ts => 1353809207,
        :nonce => 'Ygvqdz',
        :method => 'POST',
        :request_uri => '/somewhere/over/the/rainbow',
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

      context "when Content-Type has parameters" do
        let(:input) do
          {
            :credentials => credentials,
            :content_type => ' text/plain ; type="something"',
            :payload => 'Something to write about',
          }
        end

        let(:expected_output) { "RBzsyF5kNxkvMWvOKj90ULW1LHqOwqRo1sAEjjUkPuo=" }

        it_behaves_like "a payload hashing method"
      end
    end
  end

  shared_examples "a mac digest method" do
    it "returns valid base64 encoded hmac" do
      expect(described_class.send(mac_digest_method, input)).to eql(expected_output)
    end
  end

  describe ".bewit" do
    let(:mac_digest_method) { "bewit" }

    context "when using sha256 algorithm" do
      let(:input) do
        {
          :credentials => credentials,
          :method => 'GET',
          :request_uri => '/resource/4?a=1&b=2',
          :host => 'example.com',
          :port => 80,
          :ext => 'some-app-data',
          :ttl => 60 * 60 * 24 * 365 * 100
        }
      end

      let(:expected_output) {
        "MTIzNDU2XDQ1MTkzMTE0NThcYkkwanFlS1prUHE0V1hRMmkxK0NrQ2lOanZEc3BSVkNGajlmbElqMXphWT1cc29tZS1hcHAtZGF0YQ"
      }

      before do
        Time.stubs(:now).returns(Time.at(1365711458))
      end

      it_behaves_like "a mac digest method"
    end
  end

  describe ".mac" do
    let(:mac_digest_method) { "mac" }

    let(:input) do
      {
        :credentials => credentials,
        :ts => 1353809207,
        :nonce => 'Ygvqdz',
        :method => 'POST',
        :request_uri => '/somewhere/over/the/rainbow',
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

  describe ".ts_mac" do
    let(:input) do
      {
        :credentials => credentials,
        :ts => 1365741469
      }
    end

    it "returns valid timestamp mac" do
      expect(described_class.ts_mac(input)).to eql("h/Ff6XI1euObD78ZNflapvLKXGuaw1RiLI4Q6Q5sAbM=")
    end
  end
end

describe Hawk::Crypto::Mac do
  describe ".normalized_string" do
    let(:normalization_method) { "normalized_string" }

    shared_examples "an input normalization method" do
      it "returns a valid normalized string" do
        expect(described_class.new(nil, input, nil).send(normalization_method)).to eql(expected_output)
      end
    end

    let(:input) do
      {
        :ts => 1365701514,
        :nonce => '5b4e',
        :method => 'GET',
        :request_uri => "/path/to/foo?bar=baz",
        :host => 'example.com',
        :port => 8080
      }
    end

    let(:expected_output) do
      %(hawk.1.header\n#{input[:ts]}\n#{input[:nonce]}\n#{input[:method]}\n#{input[:request_uri]}\n#{input[:host]}\n#{input[:port]}\n\n\n)
    end

    it_behaves_like "an input normalization method"

    context "with app" do
      let(:input) do
        {
          :ts => 1365701514,
          :nonce => '5b4e',
          :method => 'GET',
          :request_uri => '/path/to/foo?bar=baz',
          :host => 'example.com',
          :port => 8080,
          :app => 'some app id'
        }
      end

      let(:expected_output) do
        %(hawk.1.header\n#{input[:ts]}\n#{input[:nonce]}\n#{input[:method]}\n#{input[:request_uri]}\n#{input[:host]}\n#{input[:port]}\n\n\n#{input[:app]}\n\n)
      end

      it_behaves_like "an input normalization method"
    end

    context "with app and dlg" do
      let(:input) do
        {
          :ts => 1365701514,
          :nonce => '5b4e',
          :method => 'GET',
          :request_uri => '/path/to/foo?bar=baz',
          :host => 'example.com',
          :port => 8080,
          :app => 'some app id',
          :dlg => 'some dlg'
        }
      end

      let(:expected_output) do
        %(hawk.1.header\n#{input[:ts]}\n#{input[:nonce]}\n#{input[:method]}\n#{input[:request_uri]}\n#{input[:host]}\n#{input[:port]}\n\n\n#{input[:app]}\n#{input[:dlg]}\n)
      end

      it_behaves_like "an input normalization method"
    end

    context "with ext" do
      let(:input) do
        {
          :ts => 1365701514,
          :nonce => '5b4e',
          :method => 'GET',
          :request_uri => '/path/to/foo?bar=baz',
          :host => 'example.com',
          :port => 8080,
          :ext => 'this is some app data'
        }
      end

      let(:expected_output) do
        %(hawk.1.header\n#{input[:ts]}\n#{input[:nonce]}\n#{input[:method]}\n#{input[:request_uri]}\n#{input[:host]}\n#{input[:port]}\n\n#{input[:ext]}\n)
      end

      it_behaves_like "an input normalization method"
    end

    context "with payload and ext" do
      let(:input) do
        {
          :ts => 1365701514,
          :nonce => '5b4e',
          :method => 'GET',
          :request_uri => '/path/to/foo?bar=baz',
          :host => 'example.com',
          :port => 8080,
          :hash => 'U4MKKSmiVxk37JCCrAVIjV/OhB3y+NdwoCr6RShbVkE=',
          :ext => 'this is some app data'
        }
      end

      let(:expected_output) do
        %(hawk.1.header\n#{input[:ts]}\n#{input[:nonce]}\n#{input[:method]}\n#{input[:request_uri]}\n#{input[:host]}\n#{input[:port]}\n#{input[:hash]}\n#{input[:ext]}\n)
      end

      it_behaves_like "an input normalization method"
    end
  end

end
