#!perl
use strict;
use diagnostics;
use Config::AutoConf 0.310;
BEGIN {
  no warnings 'redefine';
  *Config::AutoConf::check_member = \&my_check_member;
  *Config::AutoConf::check_members = \&my_check_members;
}
use POSIX qw/EXIT_SUCCESS/;
use File::Spec;
#
# config for gnu regex
#
do_config_GNU();


exit(EXIT_SUCCESS);

sub do_config_GNU {
    my $config = File::Spec->catfile('config_autoconf.h');
    my $log = File::Spec->catfile('config_autoconf.log');

    print STDERR "...\n";
    print STDERR "... GNU REGEX configuration\n";
    print STDERR "...\n";
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
}

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

#
# Until this is fixed in Config::AutoConf
#
no warnings 'redefine';
sub my_check_member {
    my $options = {};
    scalar @_ > 2 and ref $_[-1] eq "HASH" and $options = pop @_;
    my ( $self, $member ) = @_;
    $self = $self->_get_instance();
    defined($member)   or return croak("No type to check for");
    ref($member) eq "" or return croak("No type to check for");

    $member =~ m/^([^.]+)\.([^.]+)$/ or return croak("check_member(\"struct foo.member\", \%options)");
    my $type = $1;
    $member = $2;

    my $cache_name = $self->_cache_type_name( "$type.$member" );
    my $check_sub = sub {

        my $body = <<ACEOF;
  static $type check_aggr;
  if( check_aggr.$member )
    return 0;
ACEOF
        my $conftest = $self->lang_build_program( $options->{prologue}, $body );

        my $have_member = $self->compile_if_else(
            $conftest,
            {
                ( $options->{action_on_true}  ? ( action_on_true  => $options->{action_on_true} )  : () ),
                ( $options->{action_on_false} ? ( action_on_false => $options->{action_on_false} ) : () )
            }
        );
        $self->define_var(
            Config::AutoConf::_have_member_define_name("$type.$member"),
            $have_member ? $have_member : undef,
            "defined when $type.$member is available"
        );
        $have_member;
    };

    $self->check_cached(
        $cache_name,
        "for $type.$member",
        $check_sub,
        {
            ( $options->{action_on_cache_true}  ? ( action_on_true  => $options->{action_on_cache_true} )  : () ),
            ( $options->{action_on_cache_false} ? ( action_on_false => $options->{action_on_cache_false} ) : () )
        }
    );
};

sub my_check_members {
    my $options = {};
    scalar @_ > 2 and ref $_[-1] eq "HASH" and $options = pop @_;
    my ( $self, $members ) = @_;
    $self = $self->_get_instance();

    my %pass_options;
    defined $options->{prologue}              and $pass_options{prologue}              = $options->{prologue};
    defined $options->{action_on_cache_true}  and $pass_options{action_on_cache_true}  = $options->{action_on_cache_true};
    defined $options->{action_on_cache_false} and $pass_options{action_on_cache_false} = $options->{action_on_cache_false};

    my $have_members = 1;
    foreach my $member (@$members)
    {
        $have_members &= !!(
            $self->check_member(
                $member,
                {
                    %pass_options,
                    (
                        $options->{action_on_member_true} && "CODE" eq ref $options->{action_on_member_true}
                        ? ( action_on_true => sub { $options->{action_on_member_true}->($member) } )
                        : ()
                    ),
                    (
                        $options->{action_on_member_false} && "CODE" eq ref $options->{action_on_member_false}
                        ? ( action_on_false => sub { $options->{action_on_member_false}->($member) } )
                        : ()
                    ),
                }
            )
        );
    }

          $have_members
      and $options->{action_on_true}
      and ref $options->{action_on_true} eq "CODE"
      and $options->{action_on_true}->();

    $options->{action_on_false}
      and ref $options->{action_on_false} eq "CODE"
      and !$have_members
      and $options->{action_on_false}->();

    $have_members;
};

