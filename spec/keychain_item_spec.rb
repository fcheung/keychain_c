require 'spec_helper'

describe Keychain::Item do 
  before(:each) do
    @keychain = Keychain.new(File.join(Dir.tmpdir, "keychain_spec_#{Time.now.to_i}_#{Time.now.usec}_#{rand(1000)}.keychain"), 'pass')
    @keychain.add_generic_password 'some-service', 'some-account', 'some-password'
  end

  after(:each) do
    @keychain.delete
  end

  subject {@keychain.search :service => 'some-service'}

  describe 'password' do
    it 'should retrieve the password' do
      subject.password.should == 'some-password'
    end
  end

  describe 'service' do
    it 'should retrieve the service' do
      subject.service.should == 'some-service'
    end
  end

  describe 'account' do
    it 'should retrieve the account' do
      subject.account.should == 'some-account'
    end
  end
end