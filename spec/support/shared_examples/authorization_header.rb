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

  %w( method path host port ).each do |missing_option|
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

