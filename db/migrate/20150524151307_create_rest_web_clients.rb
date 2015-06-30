class CreateRestWebClients < ActiveRecord::Migration
  def change
    create_table :rest_web_clients do |t|
      t.string :username
      t.string :password
      t.string :msg
      t.string :receiver

      t.timestamps
    end
  end
end
