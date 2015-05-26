
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

    salt_masterkey= OpenSSL::Random.random_bytes 64

    # Masterkey erzeugen

    masterkey = PBKDF2.new(:password=>@rest_web_client.password, :salt=>salt_masterkey, :iterations=>10000)

    logger.debug(masterkey.bin_string)


    # RSA Keys erzeugen

    rsakeys = OpenSSL::PKey::RSA.new(2048)
    privkey_user = rsakeys.to_pem
    pubkey_user  = rsakeys.public_key

    # privkey verschlüsseln
    aes = OpenSSL::Cipher::AES.new(128, :ECB)
    aes.encrypt
    aes.key = masterkey.bin_string
    crypt = aes.update(privkey_user) + aes.final

    # Für internen  Client-Test
    privkey_user_enc =  (Base64.encode64(crypt))
    pubkey_user_test =  (Base64.encode64(pubkey_user))
    salt_masterkey_test = (Base64.encode64(salt_masterkey))

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
                                   :pubkey_user       => pubkey_user_test,
                                   :salt_masterkey    => salt_masterkey_test
                               }
                             # Reihenfolge nicht relevant
    )



    logger.debug(response.to_s + " CODE : " + response.code.to_s)
    #logger.debug(response2.to_s + " CODE : " + response2.code.to_s)
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
    response = RestClient.get 'http://webengproject.herokuapp.com/'+identity
    #response = RestClient.get 'http://fh.thomassennekamp.de/server/User', {:params => {:identity => 'thomas06'}}
    response.code

    logger.debug("Code : "+response.code.to_s)
    # RestClient::NotImplemented: 501 Not Implemen
    # Pubkey User auslesen

    pubkey_user = response['pubkey_user']
    salt_masterkey = response['salt_masterkey']
    privkey_user_enc = response['privkey_user_enc']
    # Masterkey genieren mit PDKDF default: sha 256


    logger.debug("Pubkey:"+pubkey_user+" Salt_Masterkey:"+salt_masterkey+" Privkey"+privkey_user_enc)
    masterkey = PBKDF2.new do |p|
      p.password = password
      p.salt = salt_masterkey
      p.iterations = 10000
    end


    #Entschlüsslung privkey_user_enc

    cipher = OpenSSL::Cipher.new('AES-128-ECB')
    cipher.decrypt()
    cipher.key = masterkey.bin_string
    tempkey = Base64.decode64(privkey_user_enc)

    redirect_to @rest_web_client, notice: 'Rest web client  successfully .'
  end


  def receive
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
