require 'spec_helper'

describe Hawk::AuthenticationFailure do
  let(:algorithm) { "sha256" }
  let(:credentials) do
    {
      :id => '123456',
      :key => '2983d45yun89q',
      :algorithm => algorithm
    }
  end

  describe "#header" do
    let(:instance) {
      described_class.new(:mac, "Invalid mac", :credentials => credentials)
    }

    let(:timestamp) { Time.now.to_i }

    let(:timestamp_mac) {
      Hawk::Crypto.ts_mac({ :ts => timestamp, :credentials => credentials })
    }

    before do
      now = Time.now
      Time.stubs(:now).returns(now)
    end

    it "returns valid hawk authentication failure header" do
      expect(instance.header).to eql(%(Hawk ts="#{timestamp}", tsm="#{timestamp_mac}", error="#{instance.message}"))
    end
  end
end
