class Keychain
  class Proxy
    def initialize(kind, keychain=nil)
      @kind = kind
      @limit = nil
      @keychains = [keychain].compact
      @conditions = {}
    end

    def where(conditions)
      @conditions.merge! conditions
      self
    end

    def limit value
      @limit = value
      self
    end

    def in *keychains
      @keychains = keychains.flatten
      self
    end

    def first
      do_find :first
    end

    def all
      do_find :all
    end


    # @return [Keychain::Item]
    def create(attributes)
      keychain = @keychains.first || Keychain.default
      keychain.add_password @kind, attributes
    end
    private

    def do_find first_or_all
      query = {:conditions => @conditions}
      query = query.merge(:keychains => @keychains) if @keychains.any?
      query = query.merge(:limit => @limit) if @limit
      Keychain.find first_or_all, @kind,  query
    end

  end

  class Error < StandardError
    attr_accessor :code
    def initialize(message, code)
      self.code = code
      super message
    end
  end
  class DuplicateItemError < Error; end
  class NoSuchKeychainError < Error; end
  class AuthFailedError < Error; end

  def inspect
    "<Keychain 0x#{self.object_id.to_s(16)}: #{path}>"
  end

  def generic_passwords
    Proxy.new(Item::Classes::GENERIC, self)
  end

  def internet_passwords
    Proxy.new(Item::Classes::INTERNET,self)
  end

  def self.generic_passwords
    Proxy.new(Item::Classes::GENERIC)
  end

  def self.internet_passwords
    Proxy.new(Item::Classes::INTERNET)
  end


  # Returns whether the keychain is locked
  # @return [Boolean]
  def locked?
    (status & (1 << 0)).zero?
  end

  # Returns whether the keychain is readable
  # @return [Boolean]
  def readable?
    (status & (1 << 1)).nonzero?
  end

  # Returns whether the keychain is writable
  # @return [Boolean]
  def writeable?
    (status & (1 << 2)).nonzero?
  end
     
  def exists?
    begin
      readable?
      true
    rescue NoSuchKeychainError
      false
    end
  end


end

require 'keychain/keychain'

class Keychain::Item

  Keychain::KEYCHAIN_MAP.each do |ruby_name, attr_name|
    unless method_defined?(ruby_name)
      define_method ruby_name do
        @attributes[attr_name]
      end
      define_method ruby_name.to_s+'=' do |value|
        @attributes[attr_name] = value
      end
    end
  end

  def password=(new_password)
    @unsaved_password = new_password
  end
end
