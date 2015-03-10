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

do_config_REGEXP();

exit(EXIT_SUCCESS);

sub do_config_REGEXP {
    my $config = File::Spec->catfile('config_REGEXP.h');
    my $log = File::Spec->catfile('config_REGEXP.log');

    my $ac = Config::AutoConf->new(logfile => $log);

    print STDERR "...\n";
    print STDERR "... regexp structure configuration\n";
    print STDERR "... ------------------------------\n";
    $ac->check_cc;
    my @members = qw/engine mother_re paren_names extflags minlen minlenret gofs substrs nparens intflags pprivate lastparen lastcloseparen swap offs subbeg saved_copy sublen suboffset subcoffset maxlen pre_prefix compflags prelen precomp wrapped wraplen seen_evals refcnt/;
    foreach (@members) {
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
    @members = qw/comp exec intuit checkstr free numbered_buff_FETCH numbered_buff_STORE numbered_buff_LENGTH named_buff named_buff_iter qr_package dupe op_comp/;
    foreach (@members) {
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
    my @funcs = qw/Perl_reg_numbered_buff_fetch Perl_reg_numbered_buff_store Perl_reg_numbered_buff_length Perl_reg_named_buff Perl_reg_named_buff_iter/;
    foreach (@funcs) {
        my $func = $_;
        $ac->check_decl($func, { action_on_true => sub {
            $ac->define_var('HAVE_' . uc($func), 1);
                                 },
                                 prologue => "#include \"EXTERN.h\"
#include \"perl.h\"
#include \"XSUB.h\"" });
    }
    $ac->write_config_h($config);
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

