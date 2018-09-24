Pod::Spec.new do |s|
  s.name         = "OneTimePassword"
  s.version      = "3.1.5"
  s.summary      = "A small library for generating TOTP and HOTP one-time passwords."
  s.homepage     = "https://github.com/mattrubin/OneTimePassword"
  s.license      = "MIT"
  s.author       = "Matt Rubin"
  s.swift_version             = "4.0"
  s.ios.deployment_target     = "8.0"
  s.watchos.deployment_target = "2.0"
  s.source       = { :git => "https://github.com/mattrubin/OneTimePassword.git", :tag => s.version }
  s.source_files = "Sources/*.{swift}"
  s.requires_arc = true
  s.dependency "Base32", "~> 1.1.2"
  s.preserve_paths = "CommonCrypto/*.sh"
  s.script_phase = { :name => "CommonCrypto", :script => "sh $SRCROOT/OneTimePassword/CommonCrypto/commonCrypto.sh", :execution_position => :before_compile }
end
