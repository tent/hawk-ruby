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

  %w( method request_uri host port ).each do |missing_option|
    context "when missing #{missing_option} option" do
      before do
        input.delete(missing_option.to_sym)
      end

      it "raises MissingOptionError" do
        expect { described_class.build_authorization_header(input) }.to raise_error(Hawk::AuthorizationHeader::MissingOptionError)
      end
    end
  end

  context "with invalid credentials" do
    context "when missing id" do
      before do
        credentials.delete(:id)
      end

      it "raises InvalidCredentialsError" do
        expect { described_class.build_authorization_header(input) }.to raise_error(Hawk::AuthorizationHeader::InvalidCredentialsError)
      end
    end

    context "when missing key" do
      before do
        credentials.delete(:key)
      end

      it "raises InvalidCredentialsError" do
        expect { described_class.build_authorization_header(input) }.to raise_error(Hawk::AuthorizationHeader::InvalidCredentialsError)
      end
    end

    context "when missing algorithm" do
      before do
        credentials.delete(:algorithm)
      end

      it "raises InvalidCredentialsError" do
        expect { described_class.build_authorization_header(input) }.to raise_error(Hawk::AuthorizationHeader::InvalidCredentialsError)
      end
    end

    context "when invalid algorithm" do
      before do
        credentials[:algorithm] = 'foobar'
      end

      it "raises InvalidAlgorithmError" do
        expect { described_class.build_authorization_header(input) }.to raise_error(Hawk::AuthorizationHeader::InvalidAlgorithmError)
      end
    end
  end
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
    context "when invalid mac" do
      let(:expected_mac) { 'foobar' }

      it "returns error object" do
        actual = described_class.authenticate(authorization_header, input)
        expect(actual).to be_a(Hawk::AuthenticationFailure)
        expect(actual.key).to eql(:mac)
        expect(actual.message).to_not eql(nil)
      end
    end

    context "when invalid hash" do
      let(:expected_hash) { 'foobar' }
      let(:payload) { 'baz' }

      it "returns error object" do
        actual = described_class.authenticate(authorization_header, input)
        expect(actual).to be_a(Hawk::AuthenticationFailure)
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
        expect(actual).to be_a(Hawk::AuthenticationFailure)
        expect(actual.key).to eql(:mac)
        expect(actual.message).to_not eql(nil)
      end
    end

    context "when empty header" do
      let(:authorization_header) { "" }

      it "returns an error object" do
        actual = described_class.authenticate(authorization_header, input)
        expect(actual).to be_a(Hawk::AuthenticationFailure)
        expect(actual.message).to_not eql(nil)
      end
    end
  end
end

