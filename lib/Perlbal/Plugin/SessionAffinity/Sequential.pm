use strict;
use warnings;
package Perlbal::Plugin::SessionAffinity::Sequential;
# ABSTRACT: Sequential backend IDs

my $ref = ref [];

sub get_backend {
    my $backend = shift;

    my @nodes = @{ $backend->{'service'}{'pool'}{'nodes'} };

    # find the id of the node
    # (index number, starting from 1)
    foreach my $i ( 0 .. scalar @nodes ) {
        # check if it was just removed
        # stupid race condition...
        defined $nodes[$i] && ref $nodes[$i] && ref $nodes[$i] eq $ref
            or next;

        my ( $ip, $port ) = @{ $nodes[$i] };

        if ( $backend->{'ipport'} eq "$ip:$port" ) {
            return [ $ip, $port ];
        }
    }

    # default to first backend in node list
    return $nodes[0];
}

1;

