use strict;
use warnings;
package Perlbal::Plugin::SessionAffinity::Sequential;
# ABSTRACT: Sequential backend IDs

use DDP;

sub get_backend_id {
    p @_;
    my ( $backend, $create_id ) = @_;
    my @nodes   = @{ $backend->{'service'}{'pool'}{'nodes'} };

    # find the id of the node
    # (index number, starting from 1)
    foreach my $i ( 0 .. scalar @nodes ) {
        my ( $ip, $port ) = @{ $nodes[$i] };

        if ( $backend->{'ipport'} eq "$ip:$port" ) {
            return $create_id->($ip);
        }
    }

    # default to first backend in node list
    return $create_id->( $nodes[0][0] );
}

1;

