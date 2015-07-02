
require 'rest-client'
require 'pbkdf2'
require 'openssl'
require 'base64'
require 'rubygems'
require 'rest_client'
require 'digest'
require 'httparty'

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

  def afterlogin
    username = params[:parm_username]
    password = params[:parm_password]

    @rest_web_client = RestWebClient.new()



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


    # Salt-Masterkey erzeugen
    salt_masterkey= SecureRandom.hex(64)
    salt_masterkey=salt_masterkey.to_i(16)
    salt_masterkey=salt_masterkey.to_s
    logger.debug("Salt_Masterkey: "+salt_masterkey.to_s)

    # Masterkey erzeugen

    masterkey = PBKDF2.new(:password=>@rest_web_client.password, :salt=>salt_masterkey, :iterations=>10000)

    # RSA Keys erzeugen

    rsakeys = OpenSSL::PKey::RSA.new(2048)
    privkey_user = rsakeys.to_pem
    pubkey_user  = rsakeys.public_key.to_pem
    # privkey verschlüsseln
    aes = OpenSSL::Cipher::AES.new(128, :ECB)
    aes.encrypt
    aes.key = masterkey.to_s
    crypt = aes.update(privkey_user) + aes.final
    #Base64
    privkey_user_enc =  (Base64.encode64(crypt))

    #Daten an Server übertragen
    response = RestClient.post('http://fh.thomassennekamp.de/server/user',
                            {
                                :identity          => @rest_web_client.username,
                                :privkey_user_enc  => privkey_user_enc,
                                :pubkey_user       => pubkey_user,
                                :salt_masterkey    => salt_masterkey
                             }.to_json, :content_type => :json, :accept => :json
                             ){|response, request, result| response }

    if(response.to_s == '"User exists!"')
      then
        redirect_to action: "index",  alert: "User bereits registriert !"
      else
        logger.debug("Request_Create:"+response.to_s)
        result = JSON.parse response
        username = result['identity']

        if(username!=nil)
        then
          redirect_to action: "index",  alert: "ok "
        else
          redirect_to action: "index",  alert: "User nicht registriert !"
        end
    end
  end


  def login
    @rest_web_client = RestWebClient.new
  end


  def loginAction
    @rest_web_client = RestWebClient.new(rest_web_client_params)
    username=@rest_web_client.username
    password=@rest_web_client.password


    # Zugangsdaten vom Dienstleister abfragen

    url='http://fh.thomassennekamp.de/server/User'
    request = RestClient.put(url, {:identity => @rest_web_client.username }.to_json, :content_type => :json, :accept => :json )
    response = JSON.parse request
    logger.debug("Request_Login:"+response.to_s)

    #Daten-Bereitstellung
    salt_masterkey    =response['salt_masterkey']
    privkey_user_enc  =response['privkey_user_enc']
    pubkey_user       =response['pubkey_user']
    identity          =response['identity']

    # Entschlüssung Privkey_enc
    masterkeyLogin = PBKDF2.new(:password=>password, :salt=>salt_masterkey, :iterations=>10000)
    cipher = OpenSSL::Cipher.new('AES-128-ECB')
    cipher.decrypt()
    cipher.key = masterkeyLogin.bin_string
    $privkey_user = Base64.decode64(privkey_user_enc)


    if(identity!=nil)
     then
      redirect_to action: "afterlogin",  alert: "ok - UserDaten anzeigen ", :parm_username => username, :parm_password => password
    else
      redirect_to action: "login",  alert: "Error User fehler "
    end
  end


  def sendMessage

    @rest_web_client = RestWebClient.new(rest_web_client_params)

    logger.debug("SendMessage:"+session[:privkey_user].to_s)

    ## Empfänger auswählen

   # url = 'http://fh.thomassennekamp.de/server/Message'

    #response = JSON.parse(RestClient.get(url))


    #response.each do |user|
    #  logger.debug(user['identity'])
    #end

  end



  def receiveAction


    @rest_web_client = RestWebClient.new(rest_web_client_params)
    url = 'http://fh.thomassennekamp.de/server/Message'
    signature = 'MmOZ2q9p78USUad70\/ToamC4JBbe+uHnlHg1TCpMRQKhGwkLICgOwCTQWMQswC8K6s\/TzBpfrC6JAq9kLtGh5iTYB62zyGIDSPkadCuV7hqAUR05GF6AXnDKAer5Ex+OShKhqye+qpRUq4rxDEMCnnHpulCorEru6+NsKYts+tIMTXoQDRtyICf4uX5+V\/qkJ1kazRwJzHSUucCkWLzbIzyXxmwNA1kqiwDv\/\/dPZ+fkHYY95ts0vIlWYnvFkM5A3io5m9U5fThD+RuwoRagQu9q6XdchPsu8E3sCYl33foriKyuhH3wA+5GVaY6u5Y5JXGO6gRHAIPDL13KcAJjhZj3PujT2gdqojIzfUMgcsEwnGhV0xcT\/j95V23deSST2wBK5SazdZBtO9TxGRHBHMyhXpmlYUjBEMfxvWpIU9si865msYPmrKsjr+6Kzr9IihnW7hxPt6LkCOvHkmLmJZTWKpWvVVU383t8CA+j7gcE6jYAOYnEarZm3q95Bi3s51TGoNzJhgdvYcBdMLFVUdcbPqdxsB1ZcElwitCxqdZtlxisMv7OW+Yw58QRBa1sMU7WVD0u59RUIshr5Zm\/Zt1srjePyYk\/JhHeg3C3CHUzFVScAXAnq97RLGSYKnYNH\/X4rihQy4jEIHmcijlSf31xzMg43nM3PMyC1FiRaIg='
    logger.debug('User: '+@rest_web_client.username.to_s())
    response = JSON.parse(RestClient.get url, {:params => {:identity => @rest_web_client.username,
                                                 :timestamp => Time.now.to_i,
                                                 :signature => signature}.to_json} #, :content_type => :json, :accept => :json
    )
    logger.debug(response.to_s + response.code)

   #response = RestClient.get 'http://fh.thomassennekamp.de/server/Message',
     #               {:params => {
    #                     :identity  => @rest_web_client.username,
      #                   :timestamp => Time.now.to_i,
       #                  :signature => 'hbtsthbtbsthbs3'
        #              }
         #       }


    @recipient         =response['recipient']
    @cipher            =response['cipher']
    @iv                =response['iv']
    @key_recipient_enc =response['key_recipient_enc']
    logger.debug('')


  end


  def sendMessageAction

    @rest_web_client = RestWebClient.new(rest_web_client_params)
    logger.debug("SendMessage_Action:"+@rest_web_clients.to_s)
    identity = @rest_web_client.username
    password = @rest_web_client.password
    message  = @rest_web_client.msg
    receiver  = @rest_web_client.receiver


    logger.debug("User: "+identity+",Password: "+password+",Message: "+message+",Empfänger: "+receiver)


    # Überflüssig bereits bei Login erfolgt
    # Erhalte den Sender PubKey vom Server

    #url = 'http://fh.thomassennekamp.de/server/PubKey'
    #response = JSON.parse(RestClient.get url, {:params => {:identity => identity}.to_json, :content_type => :json, :accept => :json})

    #request = RestClient.put(url, {:identity => @rest_web_client.username }.to_json, :content_type => :json, :accept => :json )
    #statuscode = response["pubkey"].to_s

    #if statuscode>399

     # redirect_to action: "sendMessage",  alert: "Error User fehler "
    #end


    # Pubkey User auslesen
    #pubkey_user       = response['pubkey_user'].to_s
    #salt_masterkey    = response['salt_masterkey'].to_s
    #privkey_user_enc  = response['privkey_user_enc'].to_s


    #logger.debug("Pubkey:"+pubkey_user+" Salt_Masterkey:"+salt_masterkey+" Privkey"+privkey_user_enc)


    #masterkey = PBKDF2.new do |p|
     # p.password    = password
      #p.salt        = salt_masterkey
      #p.iterations  = 10000
    #end


    #Entschlüsslung privkey_user_enc

    #cipher = OpenSSL::Cipher.new('AES-128-ECB')
    #cipher.decrypt()
    #cipher.key = masterkey.bin_string
    #privkey_user = Base64.decode64(privkey_user_enc)
    ###########################################

    # Alternativ $privkey_user nutzen


    # Pubkey des Empfängers abrufen
    #response = RestClient.get 'http://fh.thomassennekamp.de/server/User', {:params => {:identity => 'thomas07'}}
    #url = 'http://fh.thomassennekamp.de/server/PubKey'
    url = 'http://fh.thomassennekamp.de/server/User'

    request = RestClient.put(url, {:identity => @rest_web_client.username }.to_json, :content_type => :json, :accept => :json )
    response = JSON.parse request


    pubkey_recipient = response["pubkey_user"].to_s

    if pubkey_recipient==nil

      redirect_to action: "afterlogin",  alert: "Error User fehler "
    end

    # Nachricht erzeugen

    # Key-Recipient erzeugen
    key_recipient = OpenSSL::Random.random_bytes 128
    key_recipient = key_recipient.to_s
    # IV erzeugen
    iv = OpenSSL::Random.random_bytes 128

    # Verschlüsslung Nachricht mit IV und KEY_RECIPIENT


    cipher = OpenSSL::Cipher.new('AES-128-ECB')
    cipher.encrypt()
    cipher.key = key_recipient+iv
    crypt = cipher.update(message) + cipher.final()
    secureMsg = (Base64.encode64(crypt))

    # RSA key_recipient_key_enc

    rsakeys = OpenSSL::PKey::RSA.new pubkey_recipient
    if (rsakeys.public?)
      logger.debug("string test"+key_recipient)
      key_recipient_enc = rsakeys.public_encrypt(key_recipient)
    end

    # Variable Wert aus Login Methode
    privkey_user = $privkey_user
    # SHA 256 digitale Signature bilden

    data = identity+cipher.to_s+iv+key_recipient_enc
    sig_recipient = OpenSSL::HMAC.hexdigest('sha256', privkey_user,data)

    timestamp  = Time.now.to_i
    # Empfänger auswählen

    # Auruf verfübarer User -> restclient /all

    recipient=receiver

    data = identity+cipher.to_s+iv+key_recipient_enc+sig_recipient.to_s+timestamp.to_s+recipient
    sig_service = OpenSSL::HMAC.hexdigest('sha256', privkey_user,data)

    # Nachricht verschicken

    response=RestClient.post('http://fh.thomassennekamp.de/server/Message',
                             {:inner_envelope  => {:sender              => identity,
                                                   :cipher                => Base64.encode64(cipher.to_s),
                                                   :iv                    => Base64.encode64(iv),
                                                   :key_recipient_enc     => Base64.encode64(key_recipient_enc),
                                                   :sig_recipient         => sig_recipient},
                              :recipient    => recipient,
                              :timestamp    => timestamp,
                              :pubkey_user  => pubkey_recipient,
                              :sig_service  => sig_service
                             }.to_json, :content_type => :json, :accept => :json){|response, request, result| response }

    logger.debug("Request_Message:"+response.to_s)

    redirect_to action: "afterlogin",  alert: response
  end
  # PATCH/PUT /rest_web_clients/1
  # PATCH/PUT /rest_web_clients/1.json



  def showUser

    url = 'http://fh.thomassennekamp.de/server/AllUsers'
    response = JSON.parse(RestClient.get url)
    @output=(response['users'])

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
      params.require(:rest_web_client).permit(:username, :password, :msg, :receiver)
    end
end
