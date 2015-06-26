

require 'rest-client'
require 'pbkdf2'
require 'openssl'
require 'base64'
require 'rubygems'
require 'rest_client'
require 'digest'

class WebclientController < ActionController::Base
  # Prevent CSRF attacks by raising an exception.
  # For APIs, you may want to use :null_session instead.
  protect_from_forgery with: :exception



  # Client Variablen
  @identity
  #@salt_masterkey
  #@pubkey_user
  #@privkey_user_enc
  #@privkey_user
  #@timestamp
  #@Recipient
  #@sig_service
  #@cipher
  #@iv
  #@key_recipient_enc
  #@key_recipient
  #@sig_recipient
  #@Signature
  @password



  def index

  end

  def new
    @webclient = Webclient.new
  end

  def registration
   @webclient = Webclient.new(user_params)

  end
  def register

    # View auslesen identity + passwort



    # Salt-Masterkey erzeugen

    salt_masterkey= OpenSSL::Random.random_bytes 64

    # Masterkey erzeugen

    masterkey = PBKDF2.new do |p|
      p.password = @password
      p.salt = salt_masterkey
      p.iterations = 10000
    end


    # RSA Keys erzeugen

    rsakeys = OpenSSL::PKey::RSA.new(2048)
    privkey_user = rsakeys.to_pem
    pubkey_user  = rsakeys.public_key

    # privkey verschlüsseln
    aes = OpenSSL::Cipher::AES.new(128, :ECB)
    aes.encrypt
    aes.key = masterkey

    crypt = aes.update(privkey_user) + aes.final

    privkey_user_enc =  (Base64.encode64(crypt))

    # Daten an Server übertragen
    response = RestClient.post('http://fh.thomassennekamp.de/server/user' ,
                                      {
                                      :identity          => identity,
                                      :salt_masterkey    => salt_masterkey,
                                      :privkey_user_enc  => privkey_user_enc,
                                      :pubkey_user       => pubkey_user
                                      }
                                 )

    response.code

  end



  def login

    # Erhalte PubKey vom Server
    response = RestClient.get 'http://fh.thomassennekamp.de/server/User', {:params => {:identity => 'thomas06'}}
    response.code

   # RestClient::NotImplemented: 501 Not Implemen
    # Pubkey User auslesen

    pubkey_user = response['pubkey_user'].decode64
    salt_masterkey = response['salt_masterkey'].decode64
    privkey_user_enc = response['privkey_user_enc'].decode64
    # Masterkey genieren mit PDKDF default: sha 256

    masterkey = PBKDF2.new do |p|
                    p.password = password
                    p.salt = salt_masterkey
                    p.iterations = 10000
                  end

    #Entschlüsslung privkey_user_enc

          cipher = OpenSSL::Cipher.new('AES-128-ECB')
          cipher.decrypt()
          cipher.key = masterkey
          tempkey = Base64.decode64(privkey_user_enc)
          crypt = cipher.update(tempkey)
          crypt << cipher.final()


  end


  def sendMessage

    # pubkey_recipient
    # Erhalte PubKey vom Server
    response = RestClient.get 'http://fh.thomassennekamp.de/server/User', {:params => {:identity => 'thomas07'}}
    response.code

    pubkey_recipient = response[pubkey_user]

    # Nachricht erzeugen

    msg='Geheimnachricht'
    # Key-Recipient erzeugen
    key_recipient = OpenSSL::Random.random_bit 128

    # IV erzeugen
    iv = OpenSSL::Random.random_bit 128

    # Verschlüsslung Nachricht mit IV und KEY_RECIPIENT


        cipher = OpenSSL::Cipher.new('AES-128-ECB')
        cipher.encrypt()
        cipher.key = key_recipient+iv
        crypt = cipher.update(msg) + cipher.final()
        secureMsg = (Base64.encode64(crypt))

    # RSA key_recipient_key_enc

    rsakeys = OpenSSL::PKey::RSA.new pubkey_recipient
    if (rsakeys.public?)
      key_recipient_enc = rsakeys.public_encrypt key_recipient
    end

      # SHA 256 digitale Signature bilden

      data = identity+cipher+iv+key_recipient_enc
      sig_recipient = OpenSSL::HMAC.hexdigest('sha256', privkey_user,data)

      # Zeit ermitteln
      time = RestClient.get 'http://fh.thomassennekamp.de/server/Time'

      # Nachricht verschicken




    response=RestClient.post('http://fh.thomassennekamp.de/server/Message',
                             {:inner_umschlag  => {:identity              => identity,
                                                   :cipher                => cipher,
                                                   :iv                    => iv,
                                                   :key_recipient_enc     => key_recipient_enc,
                                                   :sig_recipient         => sig_recipient},
                              :timestamp    => time,
                              :recipient    => recipient,
                              :sig_service  => sig_service
                             })

    response.code
  end

  def getMessage

    RestClient.get 'http://fh.thomassennekamp.de/server/Message',
                   {:params => {
                                  :identity  => 'thomas06',
                                  :timestamp => 54322222,
                                  :signature => 'hbtsthbtbsthbs3'
                               }
                   }


  end



  def getUsers
    RestClient.get 'http://fh.thomassennekamp.de/server/AllUsers'
  end


  def user_params
    params.permit(:identity,:password,:username,:salt_masterkey, :pubkey_user, :privkey_user_enc)
  end



end
