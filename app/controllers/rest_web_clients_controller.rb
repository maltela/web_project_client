
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

    # View auslesen identity + passwort

    # Salt-Masterkey erzeugen
    # Implementierung Unklar !!
    salt_masterkey= SecureRandom.hex(64)
    salt_masterkey=salt_masterkey.to_i(16)
    #logger.debug(salt_masterkey.size)
    salt_masterkey=salt_masterkey.to_s
    logger.debug("Salt_Masterkey: "+salt_masterkey.to_s)

    # Masterkey erzeugen

    masterkey = PBKDF2.new(:password=>@rest_web_client.password, :salt=>salt_masterkey, :iterations=>10000)

    #logger.debug(masterkey.bin_string)


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
    response1 = RestClient.post('http://fh.thomassennekamp.de/server/user',
                            {
                                :identity          => @rest_web_client.username,
                                :privkey_user_enc  => privkey_user_enc,
                                :pubkey_user       => pubkey_user,
                                :salt_masterkey    => salt_masterkey
                             }.to_json, :content_type => :json, :accept => :json
                             )

    #response1 = HTTParty.post("http://fh.thomassennekamp.de/server/user", :query => { :identity => "alan+thinkvitamin@ee.com",:salt_masterkey => 'test',:privkey_user_enc => 'test',:pubkey_user =>'2345' })

    logger.debug("JSON:"+response1.to_s)
    result1 = JSON.parse response1

    logger.debug("Gruppe2: " + result1.to_s)



    response2 = RestClient.post('http://webengproject.herokuapp.com' ,
                               {
                                   :identity          => @rest_web_client.username,
                                   :privkey_user_enc  => privkey_user_enc,
                                   :pubkey_user       => pubkey_user,
                                   :salt_masterkey    => salt_masterkey
                               }.to_json, :content_type => :json, :accept => :json
                              )

    result2 = JSON.parse response2

    logger.debug("MAJOM"+result2.to_s + " CODE : " + result2["status_code"].to_s)

    status=result2['status_code']
    if(status==110)
    then



      #redirect_to action: "sendMessage",  alert: "ok "
      redirect_to action: "index",  alert: "ok "
    else

      redirect_to action: "index",  alert: "User nicht registriert !"
    end

  end


  def login
    @rest_web_client = RestWebClient.new



  end


  def loginAction
    @rest_web_client = RestWebClient.new(rest_web_client_params)
    username=@rest_web_client.username
    password=@rest_web_client.password
    logger.debug("log:"+rest_web_client_params.to_s)
    url ='http://webengproject.herokuapp.com/'+username
    url2='http://fh.thomassennekamp.de/server/User'

    # Zugangsdaten vom Dienstleister abfragen
    request = RestClient.put('http://fh.thomassennekamp.de/server/User' , {
                        :identity          => @rest_web_client.username,
                    }.to_json, :content_type => :json, :accept => :json
    )
    response = JSON.parse request
    logger.debug("Login:"+response.to_s)
    salt_masterkey=response['salt_masterkey']
    privkey_user_enc=response['privkey_user_enc']
    pubkey_user=response['pubkey_user']
    identity=response['identity']

    #Authorizierung prüfen

    String password = @rest_web_client.password

    masterkeyLogin = PBKDF2.new(:password=>password, :salt=>salt_masterkey, :iterations=>10000)

    cipher = OpenSSL::Cipher.new('AES-128-ECB')
    cipher.decrypt()
    cipher.key = masterkeyLogin.bin_string
    privkey_user = Base64.decode64(privkey_user_enc)



    if(identity!=nil)
     then
      redirect_to action: "afterlogin",  alert: "ok - UserDaten anzeigen ", :parm_username => username, :parm_password => password
    else

    redirect_to action: "login",  alert: "Error User fehler "
    end
  end


  def sendMessage

    @rest_web_client = RestWebClient.new(rest_web_client_params)

    #logger.debug("SendMessage:"+@rest_web_clients.to_s)

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
    username = @rest_web_client.username
    timestamp = Time.now.to_s
    signature = (username+timestamp)
    logger.debug('User: '+username+', Signature: '+signature)
    response = JSON.parse(RestClient.put url, {:identity => username,
                                                 :timestamp => timestamp,
                                                 :signature => signature}.to_json , :content_type => :json, :accept => :json
    )
    logger.debug(response.to_s + response.code)

   #response = RestClient.get 'http://fh.thomassennekamp.de/server/Message',
     #               {:params => {
    #                     :identity  => @rest_web_client.username,
      #                   :timestamp => Time.now.to_i,
       #                  :signature => 'hbtsthbtbsthbs3'
        #              }
         #       }



    @messages = response['messages']
    #array.each_with_index {|val, index| puts "#{val} => #{index}" }

    recipient         =response['recipient']
    if(recipient==username)
      then
      cipher            =response['cipher']
      iv                =response['iv']
      key_recipient_enc =response['key_recipient_enc']
      #key_recipient entschluesseln

      #cipher entschluesseln
    else
      redirect_to action: 'afterlogin', alert: 'Falscher Empfaenger'
    end



  end


  def sendMessageAction

    @rest_web_client = RestWebClient.new(rest_web_client_params)
    logger.debug("SendMessage_Action:"+@rest_web_clients.to_s)
    identity = @rest_web_client.username
    password = @rest_web_client.password
    message  = @rest_web_client.msg
    receiver  = @rest_web_client.receiver


    logger.debug("User: "+identity+",Password: "+password+",Message: "+message+",Empfänger: "+receiver)


    # Erhalte den Sender PubKey vom Server

    url = 'http://fh.thomassennekamp.de/server/PubKey'
    response = JSON.parse(RestClient.put url, {:identity => identity}.to_json, :content_type => :json, :accept => :json)

    statuscode = response["status_code"].to_i

    if statuscode>399

      redirect_to action: "sendMessage",  alert: "Error User fehler "
    end


    # Pubkey User auslesen
    pubkey_user       = response['pubkey_user'].to_s
    salt_masterkey    = response['salt_masterkey'].to_s
    privkey_user_enc  = response['privkey_user_enc'].to_s


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



    # Pubkey des Empfängers abrufen
    #response = RestClient.get 'http://fh.thomassennekamp.de/server/User', {:params => {:identity => 'thomas07'}}
    url = 'http://fh.thomassennekamp.de/server/PubKey'
    response    = JSON.parse(RestClient.get url, {:params => {identity => receiver}})
    statuscode  = response["status_code"].to_i

    if statuscode>399

      redirect_to action: "afterlogin",  alert: "Error User fehler "
    end
    pubkey_recipient = response["pubkey_user"].to_s
    statuscode        = response["status_code"].to_s
    logger.debug("Ausgabe : "+statuscode+" Pubkey: "+pubkey_recipient)


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
                             {:innerMessage  => {:sender              => identity,
                                                   :cipher                => Base64.encode64(cipher.to_s),
                                                   :iv                    => Base64.encode64(iv),
                                                   :key_recipient_enc     => Base64.encode64(key_recipient_enc),
                                                   :sig_recipient         => sig_recipient},
                              :recipient    => recipient,
                              :timestamp    => timestamp,
                              :pubkey_user  => pubkey_recipient,
                              :sig_service  => sig_service
                             }.to_json)

    logger.debug(response.code.to_s)
    logger.debug(response['status_code'].to_s)


    redirect_to action: "index",  alert: "Nachricht verschickt"
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
