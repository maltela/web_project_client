json.array!(@rest_web_clients) do |rest_web_client|
  json.extract! rest_web_client, :id, :username, :password
  json.url rest_web_client_url(rest_web_client, format: :json)
end
