require 'spec_helper'
require 'tmpdir'
describe Keychain do
  describe 'default' do
    it "should return the login keychain" do
      Keychain.default.path.should == File.expand_path(File.join(ENV['HOME'], 'Library','Keychains', 'login.keychain'))
    end
  end

  describe 'open' do
    it 'should create a keychain reference to a path' do
      keychain = Keychain.open(File.join(ENV['HOME'], 'Library','Keychains', 'login.keychain'))
      keychain.path.should == Keychain.default.path
    end
  end

  describe 'new' do
    it 'should create the keychain' do
      keychain = Keychain.new(File.join(Dir.tmpdir, "other_keychain_spec_#{Time.now.to_i}_#{Time.now.usec}_#{rand(1000)}.keychain"),
                            'password');
      File.exists?(keychain.path).should be_true
      keychain.delete
    end
  end

  describe 'search' do
    before(:each) do
      @keychain_1 = Keychain.new(File.join(Dir.tmpdir, "other_keychain_spec_#{Time.now.to_i}_#{Time.now.usec}_#{rand(1000)}.keychain"), 'pass')
      @keychain_2 = Keychain.new(File.join(Dir.tmpdir, "keychain_2_#{Time.now.to_i}_#{Time.now.usec}_#{rand(1000)}.keychain"), 'pass')
      @keychain_3 = Keychain.new(File.join(Dir.tmpdir, "keychain_3_#{Time.now.to_i}_#{Time.now.usec}_#{rand(1000)}.keychain"), 'pass')

      @keychain_1.add_generic_password('aservice-1', 'anaccount', 'some-password-1')
      @keychain_2.add_generic_password('aservice-2', 'anaccount', 'some-password-2')
      @keychain_3.add_generic_password('aservice-3', 'anaccount', 'some-password-3')
    end

    context 'when no search chain is given' do
      it 'should search the defaults' do
        item = Keychain.search( :service => 'aservice-1')
        item.password.should == 'some-password-1'
      end
    end

    context 'when an array of keychains is given' do
      it 'should search the specified keychains' do
        Keychain.search([@keychain_2], :service => 'aservice-2').password.should == 'some-password-2'
      end

      it 'should not return results from other keychains' do
        Keychain.search([@keychain_2], :service => 'aservice-1').should be_nil
      end
    end
  
    after(:each) do
      @keychain_1.delete
      @keychain_2.delete
      @keychain_3.delete
    end
  end

  context 'with a temporary keychain' do
    before(:each) do
      @keychain = Keychain.new(File.join(Dir.tmpdir, "keychain_spec_#{Time.now.to_i}_#{Time.now.usec}_#{rand(1000)}.keychain"), 'pass')
    end

    describe('add_generic_password') do
      it 'should store passwords' do
        item = @keychain.add_generic_password('aservice', 'anaccount', 'some-password')
        item.should be_a(Keychain::Item)
        item.password.should == 'some-password'
      end
    end

    describe('search') do
      context 'when the keychain does contains a matching item' do
        it 'should return nil' do
          @keychain.search( :service => 'doesntexist').should be_nil
        end
      end

      context 'when the keychain contains a matching item' do
        before(:each) do
          item = @keychain.add_generic_password('aservice', 'anaccount', 'some-password')
        end
  
        it 'should find it' do
          item = @keychain.search( :service => 'aservice')
          item.should be_a(Keychain::Item)
          item.password.should == 'some-password'
        end
      end

      context 'when a different keychain contains a matching item' do
        before(:each) do
          @other_keychain = Keychain.new(File.join(Dir.tmpdir, "other_keychain_spec_#{Time.now.to_i}_#{Time.now.usec}_#{rand(1000)}.keychain"), 'pass')
          item = @other_keychain.add_generic_password('aservice', 'anaccount', 'some-password')
        end

        it 'should not find it' do
          @keychain.search( :service => 'aservice').should be_nil
        end

        after(:each) do
          @other_keychain.delete
        end
      end
    end

    after(:each) do
      @keychain.delete
    end
  end
end