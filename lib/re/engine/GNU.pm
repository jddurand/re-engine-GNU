package re::engine::GNU;
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
    $^H{regcomp} = ENGINE;
}

sub unimport
{
    my $class = shift;

    if (exists($^H{regcomp}) && $^H{regcomp} == ENGINE) {
      delete($^H{regcomp});
    }

    if (@_) {
      my %args = @_;
      if (exists $args{'debug'}) {
        $^H{__PACKAGE__ . '::debug'} = $args{'debug'};
      }
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

The GNU regular expression engine plugged into perl.

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

=head1 AUTHOR

Jean-Damien Durand.

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2015 by Jean-Damien Durand.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.20.1 or,
at your option, any later version of Perl 5 you may have available.

=cut
