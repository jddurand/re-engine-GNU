#!perl
use 5.010000;
use strict;
use diagnostics;
use Config::AutoConf;
use POSIX qw/EXIT_SUCCESS/;
use ExtUtils::MakeMaker;
use File::Spec;

my $config = 'config_autoconf.h';
my $log = 'config.log';

my $ac = Config::AutoConf->new(logfile => $log);
$ac->check_cc;
$ac->check_default_headers;
ac_c_inline($ac);
ac_c_restrict($ac);
$ac->check_func('malloc', { action_on_false => sub {die "No malloc()"} });
$ac->check_func('realloc', { action_on_false => sub {die "No realloc()"} });
$ac->check_type('mbstate_t', { action_on_false => sub {die "No mbstate_t"}, prologue => '#include <wchar.h>' });
$ac->check_funcs([qw/isblank iswctype/]);
$ac->check_decl('isblank', { action_on_true => sub { $ac->define_var('HAVE_DECL_ISBLANK', 1) }, prologue => '#include <ctype.h>' });
$ac->define_var('_REGEX_INCLUDE_LIMITS_H', 1);
$ac->define_var('_REGEX_LARGE_OFFSETS', 1);
$ac->define_var('re_syntax_options', 'rpl_re_syntax_options');
$ac->define_var('re_set_syntax', 'rpl_re_set_syntax');
$ac->define_var('re_compile_pattern', 'rpl_re_compile_pattern');
$ac->define_var('re_compile_fastmap', 'rpl_re_compile_fastmap');
$ac->define_var('re_search', 'rpl_re_search');
$ac->define_var('re_search_2', 'rpl_re_search_2');
$ac->define_var('re_match', 'rpl_re_match');
$ac->define_var('re_match_2', 'rpl_re_match_2');
$ac->define_var('re_set_registers', 'rpl_re_set_registers');
$ac->define_var('re_comp', 'rpl_re_comp');
$ac->define_var('re_exec', 'rpl_re_exec');
$ac->define_var('regcomp', 'rpl_regcomp');
$ac->define_var('regexec', 'rpl_regexec');
$ac->define_var('regerror', 'rpl_regerror');
$ac->define_var('regfree', 'rpl_regfree');
$ac->write_config_h($config);

WriteMakefile(
    NAME              => 're::engine::GNU',
    VERSION_FROM      => 'lib/re/engine/GNU.pm',
    PREREQ_PM         => {},
    ABSTRACT_FROM     => 'lib/re/engine/GNU.pm', # retrieve abstract from module
    AUTHOR            => 'Jean-Damien.Durand@free.fr>',
    LICENSE           => 'gpl',
    LIBS              => [''],
    DEFINE            => '',
    INC               => '-I' . File::Spec->curdir,
);

exit(EXIT_SUCCESS);

sub ac_c_inline {
  my ($ac) = @_;

  my $inline = ' ';
  foreach (qw/inline __inline__ __inline/) {
    my $candidate = $_;
    $ac->msg_checking("keyword $candidate");
    my $program = $ac->lang_build_program("
$candidate int testinline() {
  return 1;
}
", 'testinline');
    my $rc = $ac->compile_if_else($program);
    $ac->msg_result($rc ? 'yes' : 'no');
    if ($rc) {
      $inline = $candidate;
      last;
    }
  }
  if ($inline ne 'inline') {
    #
    # This will handle the case where inline is not supported -;
    #
    $ac->define_var('inline', $inline);
  }
}

sub ac_c_restrict {
  my ($ac) = @_;

  my $restrict = ' ';
  foreach (qw/restrict __restrict __restrict__ _Restrict/) {
    my $candidate = $_;
    $ac->msg_checking("keyword $candidate");
    my $program = $ac->lang_build_program("
typedef int * int_ptr;
int foo (int_ptr ${candidate} ip) {
  return ip[0];
}
int testrestrict() {
  int s[1];
  int * ${candidate} t = s;
  t[0] = 0;
  return foo(t);
}
", 'testrestrict');
    my $rc = $ac->compile_if_else($program);
    $ac->msg_result($rc ? 'yes' : 'no');
    if ($rc) {
      $restrict = $candidate;
      last;
    }
  }
  if ($restrict ne 'restrict') {
    #
    # This will handle the case where restrict is not supported -;
    #
    $ac->define_var('restrict', $restrict);
  }
}
