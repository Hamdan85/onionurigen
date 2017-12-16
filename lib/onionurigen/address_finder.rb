require "openssl_pkcs8_pure"

module Onionurigen

  class << self
    attr_accessor :result

    def find(pattern)
      Onionurigen::AddressFinder.new(pattern)
    end
  end

  class AddressFinder
    attr_reader :match, :private_key, :onion_url, :rsa, :found

    def initialize(match, multi_threading = false)
      raise 'Invalid Pattern' unless [String, Regexp].include?(match.class)
      @found = false
      @match = match.class.eql?(String) ? /\A#{Regexp.quote(match.upcase)}/ : match
      multi_threading ? multi_thread_process : single_thread_process
    end

    def single_thread_process
      loop do
        @rsa = Onionurigen::RSAGen.new
        @spki = Onionurigen::SPKI.new(@rsa)
        break if @spki.encoded =~ @match
      end
      @private_key = @rsa.private_key.to_pem_pkcs8
      @onion_url = "http://#{@spki.encoded.downcase}.onion"
    end

    def multi_thread_process
      @rsa = Onionurigen::RSAGen.new
      @spki = Onionurigen::SPKI.new(@rsa)
      if @spki.encoded =~ @match
        @found = true
        @private_key = @rsa.private_key.to_pem_pkcs8
        @onion_url = "http://#{@spki.encoded.downcase}.onion"
      end
    end

    def found?
      @found
    end
  end
end