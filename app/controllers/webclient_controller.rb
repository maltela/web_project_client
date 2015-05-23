

require 'rest-client'
require 'pbkdf2'
require 'openssl'
require 'base64'
require 'rubygems'
require 'rest_client'

class WebclientController < ActionController::Base
  # Prevent CSRF attacks by raising an exception.
  # For APIs, you may want to use :null_session instead.
  protect_from_forgery with: :exception



  # Client Variablen
  @Identity
  @salt_masterkey
  @pubkey_user
  @privkey_user_enc
  @privkey_user
  @timestamp
  @Recipient
  @sig_service
  @cipher
  @iv
  @key_recipient_enc
  @sig_recipient
  @Signature
  @password



  def register

    # Erhalte PubKey vom Server

    response =RestClient.create 'http://fh.thomassennekamp.de/server/user' , {:params => {:identity => 'TestWEB',:salt_masterkey => 12345679876543,:pubkey_user => 123456765432,:privkey_user_enc => 123456765432 }}



  end



  def login

    # Erhalte PubKey vom Server
    response = RestClient.get 'http://fh.thomassennekamp.de/server/User', {:params => {:identity => 'thomas06'}}
   # RestClient::NotImplemented: 501 Not Implemen
    # Pubkey User auslesen
    @pubkey_user = response['pubkey_user'].decode64
    @salt_masterkey = response['salt_masterkey'].decode64
    @privkey_user_enc = response['privkey_user_enc'].decode64
    # Masterkey genieren mit PDKDF default: sha 256

    @masterkey = PBKDF2.new do |p|
                    p.password = @password
                    p.salt = @salt_masterkey
                    p.iterations = 10000
                  end


    #   Entschlüsslung privkey_user_enc


      @KEY = @masterkey
      @ALGORITHM = 'AES-128-ECB'

      def self.encryption(msg)
        begin
          cipher = OpenSSL::Cipher.new(@ALGORITHM)
          cipher.encrypt()
          cipher.key = KEY
          crypt = cipher.update(msg) + cipher.final()
          crypt_string = (Base64.encode64(crypt))
          return crypt_string
        rescue Exception => exc
          puts ('Message for the encryption log file for message #{msg} = #{exc.message}')
        end
      end
      def self.decryption(msg)
        begin
          cipher = OpenSSL::Cipher.new(ALGORITHM)
          cipher.decrypt()
          cipher.key = KEY
          tempkey = Base64.decode64(msg)
          crypt = cipher.update(tempkey)
          crypt << cipher.final()
          return crypt
          rescue Exception => exc
          puts ('Message for the decryption log file : message#{msg} = #{exc.message}')
        end
      end

    # Aufruf zur Entschlüssung
    @privkey_user = AesEncryptDecrypt.encryption(@privkey_user_enc)

    end
  end


  def sendMessage
    RestClient.Post 'http://fh.thomassennekamp.de/server/Message'

  end

  def getMessage

    RestClient.get 'http://fh.thomassennekamp.de/server/Message',{:params => {:identity => 'thomas06',:timestamp => 54322222,Signature => 'hbtsthbtbsthbs3'}}


  end

  def getUserKey
    RestClient.get 'http://fh.thomassennekamp.de/server/PubKey', {:params => {:identity => 'thomas06'}}
    #RestClient::NotImplemented: 501 Not Implemented


  end


  def getUsers
    RestClient.get 'http://fh.thomassennekamp.de/server/AllUsers'
    #    => "{\"users\":[\"thomas04\",\"thomas05\",\"thomas06\",\"thomas07\",\"thomas08\",\"thomas09\",\"thomas10\",\"thomas11\"]}"

  end

  def getTime
    RestClient.get 'http://fh.thomassennekamp.de/server/Time'
    # => "1432395712"

  end




end
