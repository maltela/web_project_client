
require 'rest-client'
require 'pbkdf2'
require 'openssl'
require 'base64'
require 'rubygems'
require 'rest_client'
require 'digest'

class RestWebClientsController < ApplicationController
  before_action :set_rest_web_client, only: [:show, :edit, :update, :destroy]

  # GET /rest_web_clients
  # GET /rest_web_clients.json
  def index
    @rest_web_clients = RestWebClient.all
  end

  # GET /rest_web_clients/1
  # GET /rest_web_clients/1.json
  def show
  end


  # GET /rest_web_clients/new
  def new
    @rest_web_client = RestWebClient.new
  end

  # GET /rest_web_clients/1/edit
  def edit
  end

  # POST /rest_web_clients
  # POST /rest_web_clients.json
  def create
    @rest_web_client = RestWebClient.new(rest_web_client_params)

    # View auslesen identity + passwort

    # Salt-Masterkey erzeugen
    # Implementierung Unklar !!
    salt_masterkey= SecureRandom.random_number (100000000000000000000)

    salt_masterkey=salt_masterkey.to_s
    logger.debug("Salt_Masterkey: "+salt_masterkey.to_s)

    # Masterkey erzeugen

    masterkey = PBKDF2.new(:password=>@rest_web_client.password, :salt=>salt_masterkey, :iterations=>10000)

    #logger.debug(masterkey.bin_string)


    # RSA Keys erzeugen

    rsakeys = OpenSSL::PKey::RSA.new(2048)
    privkey_user = rsakeys.to_pem
    pubkey_user  = rsakeys.public_key.to_pem

    logger.debug("After RSA Privatkey :"+privkey_user.size.to_s)
    logger.debug("After RSA Pubkey :"+pubkey_user.size.to_s)
    # privkey verschlüsseln
    aes = OpenSSL::Cipher::AES.new(128, :ECB)
    aes.encrypt
    aes.key = masterkey.to_s
    crypt = aes.update(privkey_user) + aes.final
    logger.debug("After AES :"+crypt.size.to_s)
    #Base64
    privkey_user_enc =  (Base64.encode64(crypt))
    logger.debug("After Base64 :"+privkey_user_enc.size.to_s)
    # Daten an Server übertragen
   # response = RestClient.post('http://fh.thomassennekamp.de/server/user' ,
    #                           {
     #                              :identity          => @rest_web_client.username,
      #                             :salt_masterkey    => salt_masterkey,
       #                            :privkey_user_enc  => privkey_user_enc,
        #                           :pubkey_user       => pubkey_user
       #                        }
    #)


    response = RestClient.post('http://webengproject.herokuapp.com' ,
                               {
                                   :identity          => @rest_web_client.username,
                                   :privkey_user_enc  => privkey_user_enc,
                                   :pubkey_user       => pubkey_user,
                                   :salt_masterkey    => salt_masterkey
                               }
                             # Reihenfolge nicht relevant
                              )



    logger.debug(response.to_s + " CODE : " + response['status_code'].to_s)
    respond_to do |format|
      if @rest_web_client.save
        format.html { redirect_to @rest_web_client, notice: 'Rest web client was successfully created.' }
        format.json { render :show, status: :created, location: @rest_web_client }
      else
        format.html { render :new }
        format.json { render json: @rest_web_client.errors, status: :unprocessable_entity }
      end
    end
  end


  def login
    @rest_web_client = RestWebClient.new

  end
  def loginAction

    @rest_web_client = RestWebClient.new(rest_web_client_params)

    identity = @rest_web_client.username
    password = @rest_web_client.password

    logger.debug("Parameter: "+identity)
    # Erhalte PubKey vom Server
    response = JSON.parse(RestClient.get 'http://webengproject.herokuapp.com/'+identity)
    #response = RestClient.get 'http://fh.thomassennekamp.de/server/User', {:params => {:identity => 'thomas06'}}


    logger.debug("Code : "+response['status_code'].to_s)
    # RestClient::NotImplemented: 501 Not Implemen
    # Pubkey User auslesen

    pubkey_user       = response['pubkey_user'].to_s
    salt_masterkey    = response['salt_masterkey'].to_s
    privkey_user_enc  = response['privkey_user_enc'].to_s
    # Masterkey genieren mit PDKDF default: sha 256

    logger.debug("Pubkey:"+pubkey_user+" Salt_Masterkey:"+salt_masterkey+" Privkey"+privkey_user_enc)
    masterkey = PBKDF2.new do |p|
      p.password    = password
      p.salt        = salt_masterkey
      p.iterations  = 10000
    end


    #Entschlüsslung privkey_user_enc

    cipher = OpenSSL::Cipher.new('AES-128-ECB')
    cipher.decrypt()
    cipher.key = masterkey.bin_string
    privkey_user = Base64.decode64(privkey_user_enc)

    redirect_to receive_url :controller => 'rest_web_clients', :action => 'sendMessage', :parmUser => identity ,:parmKey => privkey_user


  end


  def receive

    identity = params[:parmUser]
    privkey_user = params[:privkey_user]

    response =      RestClient.post 'http://webengproject.herokuapp.com/'+identity.to_s+'/message',
                     {
                         :message_id  => 2,
                         :timestamp   => 54322222,
                         :sig_message => 'hbtsthbtbsthbs3'
                     }
    logger.debug(response.to_s)
      #RestClient.get 'http://fh.thomassennekamp.de/server/Message',
       #              {:params => {
        #                 :identity  => 'thomas06',
          #               :timestamp => 54322222,
         #                :signature => 'hbtsthbtbsthbs3'
          #           }
           #          }


    recipient         =response['recipient']
    @cipher            =response['cipher']
    @iv                =response['iv']
    @key_recipient_enc =response['key_recipient_enc']



  end


  def sendMessage


    @rest_web_client = RestWebClient.new(rest_web_client_params)

    identity = @rest_web_client.username
    password = @rest_web_client.password

    logger.debug("Parameter: "+identity)
    # Erhalte PubKey vom Server
    response = JSON.parse(RestClient.get 'http://webengproject.herokuapp.com/'+identity)
    #response = RestClient.get 'http://fh.thomassennekamp.de/server/User', {:params => {:identity => 'thomas06'}}


    logger.debug("Code : "+response['status_code'].to_s)
    # RestClient::NotImplemented: 501 Not Implemen
    # Pubkey User auslesen

    pubkey_user       = response['pubkey_user'].to_s
    salt_masterkey    = response['salt_masterkey'].to_s
    privkey_user_enc  = response['privkey_user_enc'].to_s
    # Masterkey genieren mit PDKDF default: sha 256

    logger.debug("Pubkey:"+pubkey_user+" Salt_Masterkey:"+salt_masterkey+" Privkey"+privkey_user_enc)
    masterkey = PBKDF2.new do |p|
      p.password    = password
      p.salt        = salt_masterkey
      p.iterations  = 10000
    end


    #Entschlüsslung privkey_user_enc

    cipher = OpenSSL::Cipher.new('AES-128-ECB')
    cipher.decrypt()
    cipher.key = masterkey.bin_string
    privkey_user = Base64.decode64(privkey_user_enc)



    # Pubkey abrufen
    #response = RestClient.get 'http://fh.thomassennekamp.de/server/User', {:params => {:identity => 'thomas07'}}
    response = JSON.parse(RestClient.get 'http://webengproject.herokuapp.com/'+identity+'/pubkey')
    pubkey_recipient = response["pubkey_user"].to_s
    statuscode        = response["status_code"].to_s
    logger.debug("Ausgabe : "+statuscode+" Pubkey: "+pubkey_recipient)


    # Nachricht erzeugen
    msg='Geheimnachricht'
    # Key-Recipient erzeugen
    key_recipient = OpenSSL::Random.random_bytes 128
    key_recipient = key_recipient.to_s
    # IV erzeugen
    iv = OpenSSL::Random.random_bytes 128

    # Verschlüsslung Nachricht mit IV und KEY_RECIPIENT
    cipher = OpenSSL::Cipher.new('AES-128-ECB')
    cipher.encrypt()
    cipher.key = key_recipient+iv
    crypt = cipher.update(msg) + cipher.final()
    secureMsg = (Base64.encode64(crypt))

    # RSA key_recipient_key_enc

    rsakeys = OpenSSL::PKey::RSA.new pubkey_recipient
    if (rsakeys.public?)
      logger.debug("string test"+key_recipient)
      key_recipient_enc = rsakeys.public_encrypt(key_recipient)
    end


    # SHA 256 digitale Signature bilden

    data = identity+cipher.to_s+iv+key_recipient_enc
    sig_recipient = OpenSSL::HMAC.hexdigest('sha256', privkey_user,data)

    timestamp  = Time.now.to_i
    # Empfänger auswählen

    # Auruf verfübarer User -> restclient /all

    recipient='MylesTest'

    data = identity+cipher.to_s+iv+key_recipient_enc+sig_recipient.to_s+timestamp.to_s+recipient
    sig_service = OpenSSL::HMAC.hexdigest('sha256', privkey_user,data)

    # Nachricht verschicken

    response=RestClient.post('http://webengproject.herokuapp.com/message',
                             {:inner_umschlag  => {:identity              => identity,
                                                   :cipher                => Base64.encode64(cipher.to_s),
                                                   :iv                    => Base64.encode64(iv),
                                                   :key_recipient_enc     => Base64.encode64(key_recipient_enc),
                                                   :sig_recipient         => sig_recipient},
                              :timestamp    => timestamp,
                              :recipient    => recipient,
                              :sig_service  => sig_service
                             })

    logger.debug(response.code.to_s)
    logger.debug(response['status_code'].to_s)

  end
  # PATCH/PUT /rest_web_clients/1
  # PATCH/PUT /rest_web_clients/1.json
  def update
    respond_to do |format|
      if @rest_web_client.update(rest_web_client_params)
        format.html { redirect_to @rest_web_client, notice: 'Rest web client was successfully updated.' }
        format.json { render :show, status: :ok, location: @rest_web_client }
      else
        format.html { render :edit }
        format.json { render json: @rest_web_client.errors, status: :unprocessable_entity }
      end
    end
  end


  def showUser

    response = RestClient.get 'http://fh.thomassennekamp.de/server/AllUsers'
    @output=JSON.parse(response)
    logger.debug(response.to_str)



  end

  # DELETE /rest_web_clients/1
  # DELETE /rest_web_clients/1.json
  def destroy
    @rest_web_client.destroy
    respond_to do |format|
      format.html { redirect_to rest_web_clients_url, notice: 'Rest web client was successfully destroyed.' }
      format.json { head :no_content }
    end
  end

  private
    # Use callbacks to share common setup or constraints between actions.
    def set_rest_web_client
      @rest_web_client = RestWebClient.find(params[:id])
    end

    # Never trust parameters from the scary internet, only allow the white list through.
    def rest_web_client_params
      params.require(:rest_web_client).permit(:username, :password)
    end
end
