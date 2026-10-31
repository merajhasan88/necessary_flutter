#
# To learn more about a Podspec see http://guides.cocoapods.org/syntax/podspec.html.
# Run `pod lib lint necessary.podspec` to validate before publishing.
#
Pod::Spec.new do |s|
  s.name             = 'necessary'
  s.version          = '0.1.5'
  s.summary          = 'Device integrity for Flutter apps: a device-bound key the plugin never exports, signed measurements, request proofs.'
  s.description      = <<-DESC
The iOS half of the necessary plugin: the installation and step-up keys in the Secure
Enclave (a Keychain software key where it declines), the integrity collector, and screen
protection. The app's backend decides.
                       DESC
  s.homepage         = 'https://github.com/merajhasan88/necessary_flutter'
  s.license          = { :type => 'Apache-2.0', :file => '../LICENSE' }
  s.author           = 'Meraj Hasan'
  s.source           = { :path => '.' }
  s.source_files = 'necessary/Sources/necessary/**/*'
  s.dependency 'Flutter'
  s.platform = :ios, '15.0'

  # Flutter.framework does not contain a i386 slice.
  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES', 'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'i386' }
  s.swift_version = '5.0'

  # If your plugin requires a privacy manifest, for example if it uses any
  # required reason APIs, update the PrivacyInfo.xcprivacy file to describe your
  # plugin's privacy impact, and then uncomment this line. For more information,
  # see https://developer.apple.com/documentation/bundleresources/privacy_manifest_files
  # s.resource_bundles = {'necessary_privacy' => ['necessary/Sources/necessary/PrivacyInfo.xcprivacy']}
end
