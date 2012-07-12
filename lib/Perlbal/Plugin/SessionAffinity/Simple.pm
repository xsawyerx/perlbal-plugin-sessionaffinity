use strict;
use warnings;
package Perlbal::Plugin::SessionAffinity::Simple;
# ABSTRACT: Simple backend fetching

sub get_backend {
    my $backend = shift;
    return $backend->{'service'}{'pool'}{'nodes'}[0];
}

1;

