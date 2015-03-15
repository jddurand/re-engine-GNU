package re::engine::GNU;
use strict;
use diagnostics;
use 5.010000;
use XSLoader ();

# ABSTRACT: GNU Regular Expression Engine

# AUTHORITY

# All engines should subclass the core Regexp package
our @ISA = 'Regexp';

BEGIN
{
  # VERSION
    XSLoader::load __PACKAGE__, $VERSION;
}

{
  no strict 'subs';
    our $RE_SYNTAX_AWK = RE_SYNTAX_AWK;
    our $RE_SYNTAX_ED = RE_SYNTAX_ED;
    our $RE_SYNTAX_EGREP = RE_SYNTAX_EGREP;
    our $RE_SYNTAX_EMACS = RE_SYNTAX_EMACS;
    our $RE_SYNTAX_GNU_AWK = RE_SYNTAX_GNU_AWK;
    our $RE_SYNTAX_GREP = RE_SYNTAX_GREP;
    our $RE_SYNTAX_POSIX_AWK = RE_SYNTAX_POSIX_AWK;
    our $RE_SYNTAX_POSIX_BASIC = RE_SYNTAX_POSIX_BASIC;
    our $RE_SYNTAX_POSIX_EGREP = RE_SYNTAX_POSIX_EGREP;
    our $RE_SYNTAX_POSIX_EXTENDED = RE_SYNTAX_POSIX_EXTENDED;
    our $RE_SYNTAX_POSIX_MINIMAL_BASIC = RE_SYNTAX_POSIX_MINIMAL_BASIC;
    our $RE_SYNTAX_POSIX_MINIMAL_EXTENDED = RE_SYNTAX_POSIX_MINIMAL_EXTENDED;
    our $RE_SYNTAX_SED = RE_SYNTAX_SED;
}

sub import
{
    my $class = shift;

    $^H{regcomp} = ENGINE;

    if (@_) {
      my %args = @_;
      if (exists $args{'-debug'}) {
        $^H{__PACKAGE__ . '/debug'} = $args{'-debug'};
      }
      if (exists $args{'-syntax'}) {
        $^H{__PACKAGE__ . '/syntax'} = $args{'-syntax'};
      }
    }

}

sub unimport
{
    my $class = shift;

    if (exists($^H{regcomp}) && $^H{regcomp} == ENGINE) {
      delete($^H{regcomp});
    }

}

1;

__END__

=head1 NAME

re::engine::GNU - Perl extension for GNU regular expressions

=head1 SYNOPSIS

  use re::engine::GNU;
  'test' =~ /\(tes\)t/ && print "ok 1\n";
  'test' =~ [ 0, '\(tes\)t' ] && print "ok 2\n";
  'test' =~ { syntax => 0, pattern => '\(tes\)t' } && print "ok 3\n";

=head1 DESCRIPTION

The GNU regular expression engine plugged into perl. The package can be "used" with the following pragmas:

=over

=item -debug => boolean

E.g. use re::engine::GNU -debug => 1;    # a true value will print on stderr

=item -syntax => bitwised value

E.g. use re::engine::GNU -syntax => 0;   # Default syntax. Useful for the // form.

=back

Regular expressions can be writen in three form:

=over

=item classic

e.g. qr/xxx/. The default syntax is then GNU Emacs.

=item array

e.g. [ syntax, 'xxx' ], where syntax is a bitwised value.

=item hash

e.g. { syntax => value, pattern => 'xxx' }, where value is bitwised, like in the array form.

=back

Bitwised value is fully documented in the file regex.h distributed with this package. The following convenient class variables are available:

=over

=item $re::engine::GNU::RE_SYNTAX_ED

=item $re::engine::GNU::RE_SYNTAX_EGREP

=item $re::engine::GNU::RE_SYNTAX_EMACS (default)

=item $re::engine::GNU::RE_SYNTAX_GNU_AWK

=item $re::engine::GNU::RE_SYNTAX_GREP

=item $re::engine::GNU::RE_SYNTAX_POSIX_AWK

=item $re::engine::GNU::RE_SYNTAX_POSIX_BASIC

=item $re::engine::GNU::RE_SYNTAX_POSIX_EGREP

=item $re::engine::GNU::RE_SYNTAX_POSIX_EXTENDED

=item $re::engine::GNU::RE_SYNTAX_POSIX_MINIMAL_BASIC

=item $re::engine::GNU::RE_SYNTAX_POSIX_MINIMAL_EXTENDED

=item $re::engine::GNU::RE_SYNTAX_SED

=back

Please refer to L<Gnulib Regular expression syntaxes|https://www.gnu.org/software/gnulib/manual/html_node/Regular-expression-syntaxes.html#Regular-expression-syntaxes> documentation.

The following perl modifiers are supported and applied to the chosen syntax:

=over

=item //m

This is triggering an internal flag saying that newline is an anchor.

=item //s

This is setting a bit in the syntax value, saying that "." can also match newline.

=item //i

This is making the regular expression case insensitive.

=back

The perl modifiers //xp are explicited dropped.

=head2 EXPORT

None by default.

=head1 NOTES

I18N is supported without collation.

=head1 SEE ALSO

http://www.regular-expressions.info/gnu.html

=cut
