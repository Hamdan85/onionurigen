require 'openssl'
require 'securerandom'
module Onionurigen
  class RSAGen
    attr_accessor :public_key, :private_key

    def initialize
      @private_key = OpenSSL::PKey::RSA.new 1024
      @public_key = @private_key.public_key
    end
  end
end