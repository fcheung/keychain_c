require 'spec_helper'

describe Keychain do
  describe 'default' do
    it "should return the login keychain" do
      Keychain.default.path.should == File.expand_path(File.join(ENV['HOME'], 'Library','Keychains', 'login.keychain'))
    end
  end

  describe 'new' do
    it 'should allow constructing a keychain from a path' do
      keychain = Keychain.new(File.join(ENV['HOME'], 'Library','Keychains', 'login.keychain'))
      keychain.path.should == Keychain.default.path
    end
  end
end