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

my $DATA = do { local $/; <DATA>: };
$DATA //= '';
do_config_REGEXP();

exit(EXIT_SUCCESS);

sub do_config_REGEXP {
    my $config_wrapped = File::Spec->catfile('config_REGEXP_wrapped.h');
    my $log_wrapped = File::Spec->catfile('config_REGEXP_wrapped.log');
    my $config = File::Spec->catfile('config_REGEXP.h');

    my $ac = Config::AutoConf->new(logfile => $log_wrapped);

    print STDERR "...\n";
    print STDERR "... regexp structure configuration\n";
    print STDERR "... ------------------------------\n";
    $ac->check_cc;
    my @regexpMembers = qw/engine mother_re paren_names extflags minlen minlenret gofs substrs nparens intflags pprivate lastparen lastcloseparen swap offs subbeg saved_copy sublen suboffset subcoffset maxlen pre_prefix compflags prelen precomp wrapped wraplen seen_evals refcnt/;
    foreach (@regexpMembers) {
        $ac->check_member("regexp.$_", { prologue => "#include \"EXTERN.h\"
#include \"perl.h\"
#include \"XSUB.h\"

/* We are checking a structure member: it should never be a #define */
#undef $_

" });
    }
    print STDERR "...\n";
    print STDERR "... regexp_engine structure configuration\n";
    print STDERR "...\n";
    foreach (qw/comp exec intuit checkstr free numbered_buff_FETCH numbered_buff_STORE numbered_buff_LENGTH named_buff named_buff_iter qr_package dupe op_comp/) {
        $ac->check_member("regexp_engine.$_", { prologue => "#include \"EXTERN.h\"
#include \"perl.h\"
#include \"XSUB.h\"

/* We are checking a structure member: it should never be a #define */
#undef $_

" });
    }
    print STDERR "...\n";
    print STDERR "... regexp_engine perl functions\n";
    print STDERR "...\n";
    foreach (qw/Perl_reg_numbered_buff_fetch Perl_reg_numbered_buff_store Perl_reg_numbered_buff_length Perl_reg_named_buff Perl_reg_named_buff_iter/) {
        my $func = $_;
        $ac->check_decl($func, { action_on_true => sub {
            $ac->define_var('HAVE_' . uc($func), 1);
                                 },
                                 prologue => "#include \"EXTERN.h\"
#include \"perl.h\"
#include \"XSUB.h\"" });
    }
    print STDERR "...\n";
    print STDERR "... portability\n";
    print STDERR "...\n";
    foreach (qw/sv_pos_b2u_flags/) {
        my $func = $_;
        $ac->check_decl($func, { action_on_true => sub {
            $ac->define_var('HAVE_' . uc($func), 1);
                                 },
                                 prologue => "#include \"EXTERN.h\"
#include \"perl.h\"
#include \"XSUB.h\"" });
    }
    #
    # Generate structure wrappers
    #
    my $fh;
    open($fh, '>', $config) || die "Cannot open $config, $!";
    print $fh "#ifndef __CONFIG_REGEXP_H\n";
    print $fh "\n";
    print $fh "#define __CONFIG_REGEXP_H\n";
    print $fh "#include \"$config_wrapped\"\n";
    foreach (@regexpMembers) {
      my $can = "REGEXP_" . uc($_) . "_CAN";
      my $get = "REGEXP_" . uc($_) . "_GET";
      my $set = "REGEXP_" . uc($_) . "_SET";
      print $fh "\n";
      print $fh "#undef $can\n";
      print $fh "#undef $get\n";
      print $fh "#undef $set\n";
      print $fh "#ifdef HAVE_REGEXP_" . uc($_) . "\n";
      print $fh "#  define $can 1\n";
      print $fh "#  define $get(rx) ((struct regexp *) (rx))->$_\n";
      print $fh "#  define $set(rx, x) ((struct regexp *) (rx))->$_ = (x)\n";
      print $fh "#else\n";
      print $fh "#  define $can 0\n";
      print $fh "#  define $get(rx)\n";
      print $fh "#  define $set(rx, x)\n";
      print $fh "#endif\n";
    }
    #
    # Any eventual hardcoded stuff
    #
    print $fh "$DATA\n";
    print $fh "#endif /* __CONFIG_REGEXP_H */\n";
    close($fh) || warn "Cannot close $fh, $!";
    #
    # Generate wrapped config
    #
    $ac->write_config_h($config_wrapped);
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

__DATA__
/* Few compatibility issues */
#if PERL_VERSION > 10
#  define _RegSV(p) SvANY(p)
#else
#  define _RegSV(p) (p)
#endif

#ifndef PM_GETRE
#  define PM_GETRE(o) ((o)->op_pmregexp)
#endif

#ifndef PERL_UNUSED_VAR
#  define PERL_UNUSED_VAR(x) ((void)x)
#endif

#ifndef PERL_UNUSED_ARG
#  define PERL_UNUSED_ARG(x) PERL_UNUSED_VAR(x)
#endif

#ifndef sv_setsv_cow
#  define sv_setsv_cow(a,b) Perl_sv_setsv_cow(aTHX_ a,b)
#endif

#ifndef RX_MATCH_TAINTED_off
#  ifdef RXf_TAINTED_SEEN
#    ifdef NO_TAINT_SUPPORT
#      define RX_MATCH_TAINTED_off(x)
#    else
#      define RX_MATCH_TAINTED_off(x) (RX_EXTFLAGS_SET(x, RX_EXTFLAGS_GET(x) & ~RXf_TAINTED_SEEN))
#    endif
#  else
#    define RX_MATCH_TAINTED_off(x)
#  endif
#endif

#ifndef RX_MATCH_UTF8_set
#  ifdef RXf_MATCH_UTF8
#    define RX_MATCH_UTF8_set(x, t) ((t) ? (RX_EXTFLAGS_SET(x, RX_EXTFLAGS_GET(x) |= RXf_MATCH_UTF8)) :(RX_EXTFLAGS_SET(x, RX_EXTFLAGS_GET(x) &= ~RXf_MATCH_UTF8)))
#  else
#    define RX_MATCH_UTF8_set(x, t)
#  endif
#endif

#ifndef CopHINTHASH_get
#  define CopHINTHASH_get(c) ((c)->cop_hints_hash)
#endif

#ifndef cophh_fetch_pvs
#  ifdef STR_WITH_LEN
#    define cophh_fetch_pvs(cophh, key, flags) Perl_refcounted_he_fetch(aTHX_ cophh, NULL, key, sizeof(key) - 1, 0, flags)
#else
#    define cophh_fetch_pvs(cophh, key, flags) Perl_refcounted_he_fetch(aTHX_ cophh, NULL, STR_WITH_LEN(key), 0, flags)
#  endif
#endif

#ifdef PERL_STATIC_INLINE
#  define GNU_STATIC PERL_STATIC_INLINE
#else
# define GNU_STATIC static
#endif
