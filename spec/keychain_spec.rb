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
      begin
        keychain = Keychain.new(File.join(Dir.tmpdir, "other_keychain_spec_#{Time.now.to_i}_#{Time.now.usec}_#{rand(1000)}.keychain"),
                            'password');
        File.exists?(keychain.path).should be_true
      ensure
       keychain.delete
      end
    end
  end

  
  
  shared_examples_for 'item collection' do

    before(:each) do
      @keychain_1 = Keychain.new(File.join(Dir.tmpdir, "other_keychain_spec_#{Time.now.to_i}_#{Time.now.usec}_#{rand(1000)}.keychain"), 'pass')
      @keychain_2 = Keychain.new(File.join(Dir.tmpdir, "keychain_2_#{Time.now.to_i}_#{Time.now.usec}_#{rand(1000)}.keychain"), 'pass')
      @keychain_3 = Keychain.new(File.join(Dir.tmpdir, "keychain_3_#{Time.now.to_i}_#{Time.now.usec}_#{rand(1000)}.keychain"), 'pass')

      add_fixtures
    end

    after(:each) do
      @keychain_1.delete
      @keychain_2.delete
      @keychain_3.delete
    end
    
    describe('add') do
      it 'should add a password' do
        item =  @keychain_1.send(subject).add(create_arguments)
        item.should be_a(Keychain::Item)
        item.kind.should == expected_kind
        item.password.should == 'some-password'
      end

      it 'should be findable' do        
        @keychain_1.send(subject).add(create_arguments)
        item = @keychain_1.send(subject).find(:first, :conditions => search_for_created_arguments)
        item.password.should == 'some-password'
      end

      context 'when a duplicate item exists' do
        before(:each) do
          @keychain_1.send(subject).add(create_arguments)
        end

        it 'should raise Keychain::DuplicateItemError' do
          expect {@keychain_1.send(subject).add(create_arguments)}.to raise_error(Keychain::DuplicateItemError)
        end
      end
    end

    describe('find :all') do

      context 'when the keychain does not contains a matching item' do
        it 'should return []' do
          @keychain_1.send(subject).find(:all, :conditions => search_arguments_with_no_results).should == []
        end
      end

      it 'should return an array of results' do
        item = @keychain_1.send(subject).find(:all, :conditions => search_arguments).first
        item.should be_a(Keychain::Item)
        item.password.should == 'some-password-1'
      end

      context 'searching all keychains' do
        context 'when the keychain does contains matching items' do
          it 'should return all of them' do
            Keychain.send(subject).find(:all, :conditions => search_arguments_with_multiple_results).length.should == 3
          end
        end

        context 'when the limit is option is set' do
          it 'should limit the return set' do
            Keychain.send(subject).find(:all, :conditions => search_arguments_with_multiple_results, :limit => 1).length.should == 1
          end
        end

        context 'when a subset of keychains is specified' do
          it 'should return items from those keychains' do
            Keychain.send(subject).find(:all, :conditions => search_arguments_with_multiple_results, :keychains => [@keychain_1, @keychain_2]).length.should == 2
          end
        end
      end
    end
    describe 'find :first' do
      context 'when the keychain does not contain a matching item' do
        it 'should return nil' do
          item = @keychain_1.send(subject).find(:first, :conditions => search_arguments_with_no_results).should be_nil
        end
      end

      context 'when the keychain does contain a matching item' do
        it 'should find it' do
          item = @keychain_1.send(subject).find(:first, :conditions => search_arguments)
          item.should be_a(Keychain::Item)
          item.password.should == 'some-password-1'
        end
      end

      context 'when a different keychain contains a matching item' do
        before(:each) do
          item = @keychain_1.send(subject).add(create_arguments)
        end

        it 'should not find it' do
          @keychain_2.send(subject).find(:first, :conditions => search_arguments).should be_nil
        end
      end
    end
  end

  describe 'generic_passwords' do
    subject { :generic_passwords }
    let(:create_arguments){{:service => 'aservice', :account => 'anaccount-foo', :password =>'some-password'}}
    let(:search_for_created_arguments){{:service => 'aservice'}}

    let(:search_arguments){{:service => 'aservice-1'}}
    let(:search_arguments_with_no_results){{:service => 'doesntexist'}}
    let(:search_arguments_with_multiple_results){{:account => 'anaccount'}}
    let(:expected_kind) {'genp'}

    def add_fixtures
      @keychain_1.generic_passwords.add(:service => 'aservice-1', :account => 'anaccount', :password => 'some-password-1')
      @keychain_2.generic_passwords.add(:service => 'aservice-2', :account => 'anaccount', :password => 'some-password-2')
      @keychain_3.generic_passwords.add(:service => 'aservice-2', :account => 'anaccount', :password => 'some-password-3')
    end
    it_behaves_like 'item collection'
  end

  describe 'internet_passwords' do
    subject { :internet_passwords }
    let(:create_arguments){{:server => 'dressipi.example.com', :account => 'anaccount-foo', :password =>'some-password', :protocol => Keychain::Protocols::HTTP}}
    let(:search_for_created_arguments){{:server => 'dressipi.example.com', :protocol => Keychain::Protocols::HTTP}}
    let(:search_arguments){{:server => 'dressipi-1.example.com', :protocol => Keychain::Protocols::HTTP}}
    let(:search_arguments_with_no_results){{:server => 'dressipi.example.com'}}
    let(:search_arguments_with_multiple_results){{:account => 'anaccount'}}
    let(:expected_kind) {'inet'}

    def add_fixtures
      @keychain_1.internet_passwords.add(:server => 'dressipi-1.example.com', :account => 'anaccount', :password => 'some-password-1', :protocol => Keychain::Protocols::HTTP)
      @keychain_2.internet_passwords.add(:server => 'dressipi-2.example.com', :account => 'anaccount', :password => 'some-password-2', :protocol => Keychain::Protocols::HTTP)
      @keychain_3.internet_passwords.add(:server => 'dressipi-3.example.com', :account => 'anaccount', :password => 'some-password-3', :protocol => Keychain::Protocols::HTTP)
    end
    it_behaves_like 'item collection'
  end
end