# -*- encoding: utf-8 -*-
$:.push File.expand_path("../lib", __FILE__)
require "attr_encrypted/version"

Gem::Specification.new do |s|
  s.name        = 'attr_encrypted'
  s.version     = AttrEncrypted::VERSION
  s.platform    = Gem::Platform::RUBY

  s.summary     = 'Encrypt and decrypt attributes'
  s.description = 'Generates attr_accessors that encrypt and decrypt attributes transparently'

  s.author   = 'Sean Huber'
  s.email    = 'shuber@huberry.com'
  s.homepage = 'http://github.com/shuber/attr_encrypted'

  s.has_rdoc = true

  s.add_dependency 'encryptor', '~>1.1.1'
  s.add_dependency 'yard',      '~>0.6'

  s.add_development_dependency 'activerecord', '~>2.3'
  s.add_development_dependency 'datamapper'
  s.add_development_dependency 'mocha'
  s.add_development_dependency 'sequel'

  s.add_development_dependency 'rspec', '~>2.4'

  s.files         = `git ls-files`.split("\n")
  s.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  s.require_paths = ["lib"]
end
