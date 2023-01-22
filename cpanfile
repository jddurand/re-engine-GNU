# This file is generated by Dist::Zilla::Plugin::CPANFile v6.030
# Do not edit this file directly. To change prereqs, edit the `dist.ini` file.

requires "XSLoader" => "0";
requires "perl" => "5.010000";
requires "strict" => "0";
requires "warnings" => "0";

on 'test' => sub {
  requires "ExtUtils::MakeMaker" => "0";
  requires "File::Spec" => "0";
  requires "IO::Handle" => "0";
  requires "IPC::Open3" => "0";
  requires "Test::More" => "0";
  requires "Thread" => "0";
  requires "perl" => "5.010000";
};

on 'test' => sub {
  recommends "CPAN::Meta" => "2.120900";
};

on 'configure' => sub {
  requires "Capture::Tiny" => "0";
  requires "Config::AutoConf" => "0.311";
  requires "ExtUtils::MakeMaker" => "0";
  requires "File::Spec" => "0";
  requires "File::Temp" => "0";
  requires "POSIX" => "0";
  requires "diagnostics" => "0";
  requires "perl" => "5.010000";
  requires "strict" => "0";
};

on 'develop' => sub {
  requires "Dist::Zilla" => "5";
  requires "Dist::Zilla::Plugin::Authority" => "0";
  requires "Dist::Zilla::Plugin::AutoMetaResources" => "0";
  requires "Dist::Zilla::Plugin::AutoPrereqs" => "0";
  requires "Dist::Zilla::Plugin::CPANFile" => "0";
  requires "Dist::Zilla::Plugin::DynamicPrereqs" => "0";
  requires "Dist::Zilla::Plugin::FileFinder::ByName" => "0";
  requires "Dist::Zilla::Plugin::Git::Contributors" => "0";
  requires "Dist::Zilla::Plugin::Git::NextVersion" => "0";
  requires "Dist::Zilla::Plugin::GitHub::Meta" => "0";
  requires "Dist::Zilla::Plugin::MetaTests" => "0";
  requires "Dist::Zilla::Plugin::MinimumPerl" => "0";
  requires "Dist::Zilla::Plugin::MojibakeTests" => "0";
  requires "Dist::Zilla::Plugin::OurPkgVersion" => "0";
  requires "Dist::Zilla::Plugin::PodCoverageTests" => "0";
  requires "Dist::Zilla::Plugin::PodWeaver" => "0";
  requires "Dist::Zilla::Plugin::Prereqs" => "0";
  requires "Dist::Zilla::Plugin::Prereqs::AuthorDeps" => "0";
  requires "Dist::Zilla::Plugin::Test::CPAN::Changes" => "0";
  requires "Dist::Zilla::Plugin::Test::CPAN::Meta::JSON" => "0";
  requires "Dist::Zilla::Plugin::Test::EOL" => "0";
  requires "Dist::Zilla::Plugin::Test::Kwalitee" => "0";
  requires "Dist::Zilla::Plugin::Test::MinimumVersion" => "0";
  requires "Dist::Zilla::Plugin::Test::NoTabs" => "0";
  requires "Dist::Zilla::Plugin::Test::Perl::Critic" => "0";
  requires "Dist::Zilla::Plugin::Test::Pod::LinkCheck" => "0";
  requires "Dist::Zilla::Plugin::Test::Portability" => "0";
  requires "Dist::Zilla::Plugin::Test::Synopsis" => "0";
  requires "Dist::Zilla::Plugin::Test::Version" => "0";
  requires "Dist::Zilla::PluginBundle::Starter::Git" => "0";
  requires "Pod::Coverage::TrustPod" => "0";
  requires "Pod::Weaver::PluginBundle::RJBS" => "0";
  requires "Software::License::Perl_5" => "0";
  requires "Test::CPAN::Changes" => "0.19";
  requires "Test::CPAN::Meta" => "0";
  requires "Test::CPAN::Meta::JSON" => "0.16";
  requires "Test::EOL" => "0";
  requires "Test::Kwalitee" => "1.21";
  requires "Test::MinimumVersion" => "0";
  requires "Test::Mojibake" => "0";
  requires "Test::More" => "0.96";
  requires "Test::NoTabs" => "0";
  requires "Test::Perl::Critic" => "0";
  requires "Test::Pod" => "1.41";
  requires "Test::Pod::Coverage" => "1.08";
  requires "Test::Pod::LinkCheck" => "0";
  requires "Test::Portability::Files" => "0";
  requires "Test::Synopsis" => "0";
  requires "Test::Version" => "1";
};
