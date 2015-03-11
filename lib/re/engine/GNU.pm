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

sub import
{
    my $class = shift;

    $^H{regcomp} = ENGINE;

    if (@_) {
      my %args = @_;
      if (exists $args{'-debug'}) {
        $^H{__PACKAGE__ . '::debug'} = $args{'-debug'};
      }
      if (exists $args{'-syntax'}) {
        $^H{__PACKAGE__ . '::syntax'} = $args{'-syntax'};
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

=item -debug

E.g. use re::engine::GNU -debug => 1;    # a true value will print on stderr

=item -syntax

E.g. use re::engine::GNU -syntax => 0;   # Default syntax. Useful for the // form.

=back

They can be writen in three form:

=over

=item classic

e.g. qr/xxx/. The default syntax is then GNU Emacs.

=item array

e.g. [ syntax, 'xxx' ], where syntax is a bitwised value.

=item hash

e.g. { syntax => value, pattern => 'xxx' }, where value is bitwised, like in the array form.

=back

Bitwised value is to be documented (brave people should read the file regex.h in this package).

=head2 EXPORT

None by default.

=head1 SEE ALSO

http://www.regular-expressions.info/gnu.html

=cut
