use strict;
use warnings;
package Perlbal::Plugin::SessionAffinity;
# ABSTRACT: Sane session affinity (sticky sessions) for Perlbal

use Perlbal;
use CGI::Cookie;
use Digest::SHA 'sha1_hex';

sub load   {1}
sub unload {1}

my $cookie_hdr = 'X-SERVERID'; # FIXME: make this configurable

sub get_backend_id {
    my $backend = shift;
    my @nodes   = @{ $backend->{'service'}{'pool'}{'nodes'} };

    # find the id of the node
    # (index number, starting from 1)
    foreach my $i ( 0 .. scalar @nodes ) {
        my ( $ip, $port ) = @{ $nodes[$i] };

        if ( $backend->{'ipport'} eq "$ip:$port" ) {
            return $i + 1;
        }
    }

    # default to first backend in node list
    return 1;
}

# get the ip and port of the requested backend from the cookie
sub get_ip_port {
    my ( $svc, $req ) = @_;

    my $cookie  = $req->header('Cookie');
    my %cookies = ();

    if ( defined $cookie ) {
        %cookies = CGI::Cookie->parse($cookie);

        if ( defined $cookies{$cookie_hdr} ) {
            my $server_id = $cookies{$cookie_hdr}->value - 1;
            my $value     = $svc->{'pool'}{'nodes'}[$server_id];

            ref $value and return join ':', @{$value};
        }
    }

    return;
}

sub get_backend {
    my ( $svc, $req ) = @_;

    my $ip_port = get_ip_port( $svc, $req )
        or return;

    foreach my $backend ( @{ $svc->{'bored_backends'} } ) {
        $ip_port eq $backend->{'ipport'}
            and return [$backend];
    }

    return;
}

sub register {
    my ( $class, $gsvc ) = @_;

    my $check_cookie = sub {
        my $client = shift;
        my $req    = $client->{'req_headers'};

        defined $req or return 0;

        my $svc = $client->{'service'};

        if ( my $backend = get_backend( $svc, $req ) ) {
            $svc->{'bored_backends'} = $backend;
        }

        return 0;
    };

    my $set_cookie = sub {
        my $backend  = shift;
        my $res      = $backend->{'res_headers'};
        my $req      = $backend->{'req_headers'};

        defined $backend && defined $res
            or return 0;

        my $svc     = $backend->{'service'};
        my %cookies = ();

        if ( my $cookie = $req->header('Cookie') ) {
            %cookies = CGI::Cookie->parse($cookie);
        }

        my $backend_id = get_backend_id($backend);

        if ( ! defined $cookies{$cookie_hdr} ||
            $cookies{$cookie_hdr}->value != $backend_id ) {
            my $backend_cookie = CGI::Cookie->new(
                -name  => $cookie_hdr,
                -value => $backend_id,
            );

            if ( defined $res->header('set-cookie') ) {
                my $value = $res->header('set-cookie') .
                            "\r\nSet-Cookie: "         .
                            $backend_cookie->as_string;

                $res->header( 'Set-Cookie' => $value );
            } else {
                $res->header( 'Set-Cookie' => $backend_cookie );
            }
        }

        return 0;
    };

    $gsvc->register_hook(
        'SessionAffinity', 'start_proxy_request', $check_cookie,
    );

    $gsvc->register_hook(
        'SessionAffinity', 'modify_response_headers', $set_cookie,
    );

    return 1;
}

sub unregister {
    my ( $class, $svc ) = @_;

    $svc->unregister_hooks('SessionAffinity');
    $svc->unregister_setters('SessionAffinity');

    return 1;
}

1;

__END__

=head1 SYNOPSIS

=head1 DESCRIPTION

=head1 ATTRIBUTES

These are future attributes:

=head2 session_cookie_header

The name of the cookie header for the session. It's currently hardcoded
to B<X-SERVERID> but it will be configurable in the future.

=head1 SUBROUTINES/METHODS

=head2 register

=head2 unregister

=head2 get_backend_id

Get a backend ID number. This is currently simply sequential, but will be
very dynamic in the near future.

=head2 get_ip_port

Parses a request's cookies and finds the specific cookie relating to session
affinity and get the server via the ID in the cookie.

This is currently considered a security risk, since the ID is sequential and
substantially predictable.

=head2 get_backend

=head1 DEPENDENCIES

=head2 Perlbal

Obviously.

=head2 CGI::Cookies

To parse and create cookies.

=head2 Digest::SHA

To provide a SHA1 checksum in the future.

