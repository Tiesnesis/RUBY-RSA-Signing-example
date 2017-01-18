require 'digest/md5'
class Integer
  # This method to check for primes is not 100% reliable, but almost.
  # Advantage: speed
   def prime?
     n = self.abs
     return true if n == 2
     return false if n == 1 || n & 1 == 0
     return false if n > 3 && n % 6 != 1 && n % 6 != 5

     d = n-1
     d >>= 1 while d & 1 == 0
     20.times do
       a = rand(n-2) + 1
       t = d
       y = Integer.mod_pow( a, t, n )
       while t != n-1 && y != 1 && y != n-1
         y = (y * y) % n
         t <<= 1
       end
       return false if y != n-1 && t & 1 == 0
     end
     return true
   end

   # a^b mod c , using much quicker squaring-method
   def self.mod_pow( base, power, mod )
     res = 1
     while power > 0
       res = (res * base) % mod if power & 1 == 1
       base = base ** 2 % mod
       power >>= 1
     end
     res
   end
end

class RSA
  E = 65537

  class << self

    # Returns the public modulus, the public exponent and the private key.
    def generate_keys( bits )
      n, d = 0
      p = random_prime( bits )
      q = random_prime( bits )
      n = p * q
      d = get_d( p, q, E )
      [{pub_1: n, pub_2: E}, {priv_1: n, priv_2: d}]
    end

    # Encrypts a message with the public modulus (of the receiver).
    # First encode string as a (large) number.
    def encrypt( m, n )
      m = s_to_n( m )
      Integer.mod_pow( m, E, n )
    end

    # Decrypts using the private exponent
    def decrypt( c, n, d )
      m = Integer.mod_pow( c, d, n )
      n_to_s( m )
    end

    private

    # Convert number to string
    def n_to_s( n )
      s = ""
      while( n > 0 )
        s = ( n & 0xFF ).chr + s
        n >>= 8
      end
      s
    end

    # Convert string to number
    def s_to_n( s )
      n = 0
      s.each_byte do |b|
        n = n * 256 + b
      end
      n
    end

    # Generate a random number and check if
    # it's prime until a prime is found.
    def random_prime( bits )
      begin
        n = random_number( bits )
        return n if n.prime?
      end while true
    end

    # Concatenate string (begins and ends with 1)
    # to get desired length and an uneven value.
    def random_number( bits )
      m = (1..bits-2).map{ rand() > 0.5 ? '1' : '0' }.join
      s = "1" + m + "1"
      s.to_i( 2 )
    end

    # Euler's totient function, φ(p,q)
    # needed so a multiplicative inverse (private key)
    # can be calculated.
    def phi( a, b )
      (a - 1) * (b - 1)
    end

    def extended_gcd( a, b )
      return [0,1] if a % b == 0
      x, y = extended_gcd( b, a % b )
      [y, x - y * (a / b)]
    end

    # Calculate the multiplicative inverse d with d * e = 1 (mod φ(p,q)),
    # using the extended euclidian algorithm.
    def get_d(p, q, e)
      t = phi( p, q )
      x, y = extended_gcd( e, t )
      x += t if x < 0
      x
    end
  end
end

class Sender
  @message = ''
  @signature = ''
  @public_key = {}
  def initialize
    @message = 'KINO'
    @signature = Digest::MD5.new.hexdigest(@message)[0]
  end

  def receive_key(public_key)
    @public_key = public_key
  end

  def send
    {message: @message, signature: RSA.encrypt( @signature, @public_key[:pub_1] )}
  end
end

class Receiver
  @message = ''
  @private_key = {}
  @public_key = {}
  @signature = ''

  def initialize
    generate_keys
  end

  def generate_keys
    @public_key, @private_key = RSA.generate_keys( 256 )
  end

  def send_public_key
    @public_key
  end

  def receive(hash)
    @signature = hash[:signature]
    @message = hash[:message]
  end

  def validate_signature
    decrypted_signature = RSA.decrypt(
      @signature, @private_key[:priv_1], @private_key[:priv_2]
    )
    message_hash = Digest::MD5.new.hexdigest(@message)[0]
    print 'Decripted received MD5: ' + decrypted_signature.to_s + "\n"
    print 'Generated MD5 from message: ' + message_hash.to_s + "\n"
    print 'Message: ' + @message + "\n"
  end
end
# Create sender
sender = Sender.new
# Create receiver
receiver = Receiver.new

# Send public key to sender for signing
sender.receive_key receiver.send_public_key
# Sender send signed message to receiver
receiver.receive sender.send
#Receiver validate signature
receiver.validate_signature
