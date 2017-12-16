require "openssl_pkcs8_pure"

module Onionurigen

  class << self
    attr_accessor :result

    def find(pattern)
      self.result = Onionurigen::UriFinder.new(pattern)
    end
  end

  class UriFinder
    attr_reader :match, :private_key, :onion_uri, :rsa

    def initialize(match)
      @match = /\A#{Regexp.quote(match.upcase)}/
      compute
    end

    def compute
      loop do
        @rsa = Onionurigen::RSAGen.new
        @spki = Onionurigen::SPKI.new(@rsa)
        break if @spki.encoded =~ @match
      end
      @private_key = @rsa.private_key.to_pem_pkcs8
      @onion_uri = "http://#{@spki.encoded.downcase}.onion"
    end
  end
end