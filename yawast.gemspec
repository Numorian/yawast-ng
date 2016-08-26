$:.push File.expand_path("../lib", __FILE__)
require File.expand_path("../lib/yawast", __FILE__)

Gem::Specification.new do |s|
  s.name              = 'yawast'
  s.version           = Yawast::VERSION
  s.platform          = Gem::Platform::RUBY
  s.summary           = "The YAWAST Antecedent Web Application Security Toolkit"
  s.description       = "YAWAST is an application meant to simplify initial analysis and information gathering for penetration testers and security auditors."
  s.authors           = ["Adam Caudill"]
  s.email             = 'adam@adamcaudill.com'
  s.homepage          = 'https://github.com/adamcaudill/yawast'
  s.license           = 'MIT'
  s.rubyforge_project = "yawast"

  s.bindir            = 'bin'
  s.files             = `git ls-files`.split("\n")
  s.test_files        = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.executables       = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  s.require_path      = ["lib"]
end
