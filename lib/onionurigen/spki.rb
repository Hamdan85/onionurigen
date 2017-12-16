require 'openssl'
require 'securerandom'

module Onionurigen
  class SPKI
    attr_accessor :rsa, :der, :digest, :encoded

    def initialize(rsa)
      raise 'Object must be of RSAGen Type' unless rsa.class.eql?(Onionurigen::RSAGen)
      @rsa = rsa
      # Export the DER encoding of the SubjectPublicKeyInfo structure.
      @der = @rsa.public_key.to_der
      # Compute the SHA-1 digest of the SPKI.
      # Skip 22 bytes (the SPKI header) that are ignored by Tor.
      @digest = OpenSSL::Digest::SHA1.digest @der[22..-1]
      # Base32-encode the first half of the digest.
      @encoded = Base32.encode(@digest[0..9])
    end
  end
end