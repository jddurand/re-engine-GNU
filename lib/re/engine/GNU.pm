package re::engine::GNU;
use 5.010000;
use XSLoader ();

# AUTHORITY

# VERSION

# All engines should subclass the core Regexp package
our @ISA = 'Regexp';

BEGIN
{
    XSLoader::load __PACKAGE__, $VERSION;
}

sub import
{
    $^H{regcomp} = ENGINE;
}

sub unimport
{
    delete $^H{regcomp}
        if $^H{regcomp} == ENGINE;
}

1;

__END__
# Below is stub documentation for your module. You'd better edit it!

=head1 NAME

re::engine::GNU - Perl extension for blah blah blah

=head1 SYNOPSIS

  use re::engine::GNU;
  blah blah blah

=head1 DESCRIPTION

Stub documentation for re::engine::GNU, created by h2xs. It looks like the
author of the extension was negligent enough to leave the stub
unedited.

Blah blah blah.

=head2 EXPORT

None by default.



=head1 SEE ALSO

Mention other useful documentation such as the documentation of
related modules or operating system documentation (such as man pages
in UNIX), or any relevant external documentation such as RFCs or
standards.

If you have a mailing list set up for your module, mention it here.

If you have a web site set up for your module, mention it here.

=head1 AUTHOR

A. U. Thor, E<lt>a.u.thor@a.galaxy.far.far.awayE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2015 by A. U. Thor

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.20.1 or,
at your option, any later version of Perl 5 you may have available.


=cut
