require 'test_helper'

class RestWebClientsControllerTest < ActionController::TestCase
  setup do
    @rest_web_client = rest_web_clients(:one)
  end

  test "should get index" do
    get :index
    assert_response :success
    assert_not_nil assigns(:rest_web_clients)
  end

  test "should get new" do
    get :new
    assert_response :success
  end

  test "should create rest_web_client" do
    assert_difference('RestWebClient.count') do
      post :create, rest_web_client: { password: @rest_web_client.password, username: @rest_web_client.username }
    end

    assert_redirected_to rest_web_client_path(assigns(:rest_web_client))
  end

  test "should show rest_web_client" do
    get :show, id: @rest_web_client
    assert_response :success
  end

  test "should get edit" do
    get :edit, id: @rest_web_client
    assert_response :success
  end

  test "should update rest_web_client" do
    patch :update, id: @rest_web_client, rest_web_client: { password: @rest_web_client.password, username: @rest_web_client.username }
    assert_redirected_to rest_web_client_path(assigns(:rest_web_client))
  end

  test "should destroy rest_web_client" do
    assert_difference('RestWebClient.count', -1) do
      delete :destroy, id: @rest_web_client
    end

    assert_redirected_to rest_web_clients_path
  end
end
