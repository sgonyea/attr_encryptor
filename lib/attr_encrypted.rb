require 'encryptor'
require 'attr_encrypted/adapters/active_record' if defined?(ActiveRecord::Base)
require 'attr_encrypted/adapters/data_mapper'   if defined?(DataMapper)
require 'attr_encrypted/adapters/sequel'        if defined?(Sequel)
require 'attr_encrypted/version'
require 'ostruct'

# Adds attr_accessors that encrypt and decrypt an object's attributes
module AttrEncrypted
  def default_options
    {
      :prefix           => 'encrypted_',
      :suffix           => '',
      :if               => proc { true  },
      :unless           => proc { false },
      :encode?          => false,
      :encoding         => 'm',
      :marshal?         => false,
      :marshal          => :marshal_handler.to_proc,
      :cryptor          => :crypto_handler.to_proc,
      :decryptor        => :decryptor.to_proc,
      :encryptor        => :encryptor.to_proc
    }
  end

  def self.extended(base) # :nodoc:
    base.class_eval do
      include InstanceMethods
      attr_writer :attr_encrypted_options
      @attr_encrypted_options, @encrypted_attributes = {}, {}
    end
  end

  # Generates attr_accessors that encrypt and decrypt attributes transparently
  # @example You can pass your own options, overriding the defaults
  #
  #   class User
  #     # now all attributes will be encoded and marshaled by default
  #     attr_encrypted_options.merge!(:encode => true, :marshal => true, :some_other_option => true)
  #     attr_encrypted :configuration, :key => 'my secret key'
  #   end
  #
  # @example Usage from within a class
  #   class User
  #     attr_encrypted :email, :credit_card, :key => 'some secret key'
  #     attr_encrypted :configuration, :key => 'some other secret key', :marshal => true
  #   end
  #   @user = User.new
  #
  # @example Instance methods
  #   @user.encrypted_email #=> nil
  #   @user.email?          #=> false
  #   @user.email = 'test@example.com'
  #   @user.email?          #=> true
  #   @user.encrypted_email #=> returns the encrypted version of 'test@example.com'
  #
  # @overload attr_encrypted(attributes)
  #   @param [Array<Symbol>] attributes A list of attributes that should be encrypted
  # @overload attr_encrypted(attributes, opts)
  #   @param [Array<Symbol>] attributes A list of attributes that should be encrypted
  #   @param [Hash] opts Overrides to the default options, for the encryption of the given attributes
  #   @see #handle_options!
  def attr_encrypted(*attributes)
    options = handle_options!(attributes)

    attributes.each do |attr|
      attribute = options.attribute ||= "#{options.prefix}#{attr}#{options.suffix}"

      unless respond_to? attribute
        class_eval <<-RB
          def #{attribute}
            decrypt @#{attribute}
          end

          def #{attribute}?
            attr = self.#{attribute}
            if attr.respond_to?(:empty)
              !attr.empty?
            else
              !!attr
            end
          end
        RB
      end

      unless respond_to? "#{attribute}="
        class_eval <<-RB
          def #{attribute}=(val)
            @#{attribute}= encrypt(val)
          end
        RB
      end
    end

    encrypted_attributes[attr] = options.marshal_dump
  end
  alias_method :attr_encryptor, :attr_encrypted

  # @param [Array<..., Hash>] attributes The attributes, as passed into the attr_encrypted entry method. Destructive.
  #   @option opts [String] :attribute        The name of the referenced encrypted attribute. This is useful when defining one attribute to encrypt at a time or when the :prefix and :suffix options aren't enough.
  #   @option opts [String] :prefix           The attributes prefix, as stored internally.
  #   @option opts [String] :suffix           The attributes suffix, as stored internally.
  #   @option opts [boolean, #call] :if       Encryption will happen if this returns true
  #   @option opts [boolean, #call] :unless   Encryption will happen unless this returns true
  #   @option opts [String] :encoding         How to encode the data, if desired.
  #   @option opts [boolean] :marshal?        Whether or not to marshal the data, before passing to the encode method encryption
  #   @option opts [boolean] :encode?         Whether or not to encode the data, before passing to the encryption method encryption
  #   @option opts [#call]   :dump_method     If the default Marshal#dump is not desirable, pass in a Proc (or something that responds to #call)
  #   @option opts [#call]   :load_method     If the default Marshal#load is not desirable, pass in a Proc (or something that responds to #call)
  #   @option opts [#call]   :encrypt_method  If the default encryption is not desirable, pass in a Proc (or something that responds to #call)
  #   @option opts [#call]   :decrypt_method  If the default decryption is not desirable, pass in a Proc (or something that responds to #call)
  #   @option opts [String, Symbol] :key
  # @return [OpenStruct] Merged options, handles all deprecations
  def handle_options!(attributes)
    options = default_options
    options.merge!(attr_encrypted_options)

    if attributes.last.is_a?(Hash)
      options.merge!(attributes.pop)

      unless options[:unless].respond_to?(:call)
        options[:unless] = proc { options[:unless] }
      end

      unless options[:if].respond_to?(:call)
        options[:if] = proc { options[:if] }
      end

      if options.has_key?(:encode)
        options[:encode?] = options.delete :encode
      end

      if options.has_key?(:marshal) and not options[:marshal].is_a?(Proc)
        options[:marshal?]  = options.delete :marshal
        options[:marshal]   = DEFAULT_OPTIONS[:marshal]
        STDERR.puts "DEPRECATED: Please specify :marshal?, instead of :marshal"
      end

      if options.has_key?(:encryptor)
        options[:cryptor] = options.delete :encryptor
        STDERR.puts "DEPRECATED: Please specify :cryptor, instead of :encryptor"
      end
    end

    OpenStruct.new options
  end

  # Default options to use with calls to <tt>attr_encrypted</tt>
  #
  # It will inherit existing options from its superclass
  def attr_encrypted_options
    @attr_encrypted_options ||= superclass.attr_encrypted_options.dup
  end

  # Checks if an attribute is configured with <tt>attr_encrypted</tt>
  #
  # Example
  #
  #   class User
  #     attr_accessor :name
  #     attr_encrypted :email
  #   end
  #
  #   User.attr_encrypted?(:name)  # false
  #   User.attr_encrypted?(:email) # true
  def attr_encrypted?(attribute)
    encrypted_attributes.has_key?(attribute.to_sym)
  end

  # Decrypts a value for the attribute specified
  #
  # Example
  #
  #   class User
  #     attr_encrypted :email
  #   end
  #
  #   email = User.decrypt(:email, 'SOME_ENCRYPTED_EMAIL_STRING')

  def decrypt(attribute, encrypted_value)
    options = encrypted_attributes[attribute]

    if should_encrypt?(value, options)
      encrypted = encrypted_value.unpack(options.encoding).first if options.encode?
      value = options[:encryptor].send(options[:decrypt_method], options.merge!(:value => encrypted))
      value = options[:marshaler].send(options[:load_method], value) if options[:marshal]
      value
    else
      encrypted_value
    end
  end

  # Encrypts a value for the attribute specified
  #
  # Example
  #
  #   class User
  #     attr_encrypted :email
  #   end
  #
  #   encrypted_email = User.encrypt(:email, 'test@example.com')
  def encrypt(attribute, value)
    options = encrypted_attributes[attribute]

    if should_encrypt?(value, options)
      marshalled  = options[:marshal].call(value) if options[:marshal?] ? options[:marshaler].send(options[:dump_method], value) : value.to_s
      encrypted   = options[:encryptor].send(options[:encrypt_method], options.merge!(:value => value))
      encrypted   = encode(encrypted, options)
      encrypted
    else
      value
    end
  end

  def should_encrypt?(value, options)
    return false if     value.nil?
    return false unless value.is_a?(String) and not value.empty?
    return false if     options.unless.call(value, options)
    return false unless options.if.call(value, options)


    return true
  end
  alias :should_decrypt? :should_encrypt?

  def encode(value, options)
    if options[:encode]
      [value].pack(options[:default_encode])
    else
      value
    end
  end

  # Contains a hash of encrypted attributes with virtual attribute names as keys
  # and their corresponding options as values
  #
  # Example
  #
  #   class User
  #     attr_encrypted :email, :key => 'my secret key'
  #   end
  #
  #   User.encrypted_attributes # { :email => { :attribute => 'encrypted_email', :key => 'my secret key' } }
  def encrypted_attributes
    @encrypted_attributes ||= superclass.encrypted_attributes.dup
  end

  # Forwards calls to :encrypt_#{attribute} or :decrypt_#{attribute} to the corresponding encrypt or decrypt method
  # if attribute was configured with attr_encrypted
  #
  # Example
  #
  #   class User
  #     attr_encrypted :email, :key => 'my secret key'
  #   end
  #
  #   User.encrypt_email('SOME_ENCRYPTED_EMAIL_STRING')
  def method_missing(method, *arguments, &block)
    if method.to_s =~ /^((en|de)crypt)_(.+)$/ && attr_encrypted?($3)
      send($1, $3, *arguments)
    else
      super
    end
  end

  module InstanceMethods
    # Decrypts a value for the attribute specified using options evaluated in the current object's scope
    #
    # Example
    #
    #  class User
    #    attr_accessor :secret_key
    #    attr_encrypted :email, :key => :secret_key
    #
    #    def initialize(secret_key)
    #      self.secret_key = secret_key
    #    end
    #  end
    #
    #  @user = User.new('some-secret-key')
    #  @user.decrypt(:email, 'SOME_ENCRYPTED_EMAIL_STRING')
    def decrypt(attribute, encrypted_value)
      self.class.decrypt(attribute, encrypted_value, evaluated_attr_encrypted_options_for(attribute))
    end

    # Encrypts a value for the attribute specified using options evaluated in the current object's scope
    #
    # Example
    #
    #  class User
    #    attr_accessor :secret_key
    #    attr_encrypted :email, :key => :secret_key
    #
    #    def initialize(secret_key)
    #      self.secret_key = secret_key
    #    end
    #  end
    #
    #  @user = User.new('some-secret-key')
    #  @user.encrypt(:email, 'test@example.com')
    def encrypt(attribute, value)
      self.class.encrypt(attribute, value, evaluated_attr_encrypted_options_for(attribute))
    end

    protected

      # Returns attr_encrypted options evaluated in the current object's scope for the attribute specified
      def evaluated_attr_encrypted_options_for(attribute)
        self.class.encrypted_attributes[attribute.to_sym].inject({}) { |hash, (option, value)| hash.merge!(option => evaluate_attr_encrypted_option(value)) }
      end

      # Evaluates symbol (method reference) or proc (responds to call) options
      #
      # If the option is not a symbol or proc then the original option is returned
      def evaluate_attr_encrypted_option(option)
        if option.is_a?(Symbol) && respond_to?(option)
          send(option)
        elsif option.respond_to?(:call)
          option.call(self)
        else
          option
        end
      end
  end
end

Object.extend AttrEncrypted
