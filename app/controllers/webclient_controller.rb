

require 'rest-client'

class WebclientController < ActionController::Base
  # Prevent CSRF attacks by raising an exception.
  # For APIs, you may want to use :null_session instead.
  protect_from_forgery with: :exception


  require 'rubygems'
  require 'rest_client'


  def register

    response =RestClient.create 'http://fh.thomassennekamp.de/server/user' , {:params => {:identity => 'TestWEB',:salt_masterkey => 12345679876543,:pubkey_user => 123456765432,:privkey_user_enc => 123456765432 }}
    response.code
  end


  def getInfo
    RestClient.get 'http://fh.thomassennekamp.de/server/User', {:params => {:identity => 'thomas06'}}
   # RestClient::NotImplemented: 501 Not Implemen


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
