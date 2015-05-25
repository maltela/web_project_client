
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

    privkey_user_enc =  (Base64.encode64(crypt))

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
                                   :salt_masterkey    => salt_masterkey,
                                   :privkey_user_enc  => privkey_user_enc,
                                   :pubkey_user       => pubkey_user
                               }
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
