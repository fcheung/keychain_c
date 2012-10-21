require 'spec_helper'

describe Keychain::Item do 
  before(:each) do
    @keychain = Keychain.new(File.join(Dir.tmpdir, "keychain_spec_#{Time.now.to_i}_#{Time.now.usec}_#{rand(1000)}.keychain"), 'pass')
    @keychain.generic_passwords.add :service => 'some-service', :account => 'some-account', :password => 'some-password'
  end

  after(:each) do
    @keychain.delete
  end

  subject {@keychain.generic_passwords.find :first, :conditions => {:service => 'some-service'}}

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

  describe 'created_at' do
    it 'should retrieve the item creation date' do
      subject.created_at.should be_within(2).of(Time.now)
    end
  end

  describe 'save' do
    it 'should update attributes and password' do
      subject.password = 'new-password'
      subject.account = 'new-account'
      subject.save

      fresh = @keychain.generic_passwords.find :first, :conditions => {:service => 'some-service'}
      fresh.password.should == 'new-password'
      fresh.account.should == 'new-account'
    end
  end
end