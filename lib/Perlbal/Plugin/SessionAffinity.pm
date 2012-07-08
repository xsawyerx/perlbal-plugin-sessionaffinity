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
                $res->header( 'Set-Cookie' => $backend_cookie->as_string );
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

    $gsvc->register_hook(
        'SessionAffinity', 'backend_response_received', $set_cookie,
    );

    return 1;
}

sub unregister {
    my ( $class, $svc ) = @_;

    # TODO: are we using setters?
    $svc->unregister_hooks('SessionAffinity');
    $svc->unregister_setters('SessionAffinity');

    return 1;
}

1;

__END__

=head1 SYNOPSIS

    LOAD SessionAffinity

    CREATE POOL backends
      POOL backends ADD 10.20.20.100
      POOL backends ADD 10.20.20.101
      POOL backends ADD 10.20.20.102

    CREATE SERVICE balancer
      SET listen          = 0.0.0.0:80
      SET role            = reverse_proxy
      SET pool            = dynamic
      SET persist_client  = on
      SET persist_backend = on
      SET verify_backend  = on
      SET plugins         = sessionaffinity
    ENABLE balancer

=head1 DESCRIPTION

L<Perlbal> doesn't support session affinity (or otherwise known as "sticky
sessions") out of the box. There is a plugin on CPAN called
L<Perlbal::Plugin::StickySessions> but there's a few problems with it:

=over 4

=item * It only supports sticky sessions for files

It uses only one hook for adding cookies, which only applies to file fetching.
This means that if you want sticky sessions for anything other than file
fetching, you're fresh out of luck. :)

B<However, this plugin> uses proper hooks to accomplish sticky sessions on
each and every request.

=item * It requires patches

It depends on patches the author has prepared (that were not integrated) into
the Perlbal core distribution. This means you need to apply these patches on
every new version of Perlbal you're installing.

B<However, this plugin> doesn't require B<any> patches.

=item * It's outdated

At least one of the patches provided with it is simply unnecessary anymore
because the hook it adds was already added to Perlbal (at a little different
location, though). Clearly it hasn't been updated in a while.

B<However, this plugin> is up to date.

=item * It's overkill/breakable/copy-pasta/ZOMGWTF?!

It has a lot of code that is basically copy-pasted from some handling code in
L<Perlbal> itself. This means that any code that is changed, needs to be
updated in the module (every, single, time) which will suddenly become
incompatible with previous versions.

It's a lot of code that mostly likely isn't necessary and instead of
refactoring where needed, and submit that to Perlbal, it was simply copied
over, which is more than horrible.

B<However, this plugin> is very thin and slim, contains no copy-pasted code
and will not break future and previous versions every time Perlbal changes
code.

It does, however, plays with an attribute that isn't explicitly documented
as public, though fully accessible. However, if Perlbal does indeed change it,
this module should be successfully updated and might provide backwards
compatibility (even though the author considers Perlbal's compatibility
standards to be downright insane).

=item * Observed breakage

After looking into this, it seems as though gentleness is necessary, since
the connect-ahead doesn't seem to be cleaning up, and more and more closed
sessions are mounted.

B<However, this plugin> does not use the method and therefore Perlbal itself
is in charge and therefore does a proper job with closing and releasing
connections.

=item * Probable security risk

It sets a cookie with a backend ID that is relevant to the backend order in
the pool. By running enough requests you will eventually statistically find
all possible backends in a given pool.

You can also attack by a special-crafted cookie and measure the timings for
requests to find when it probably does additional processing (since the
backend is specified) to find how many backends exist in a given pool.

I'll leave finding of more ways to exploit this security risk as an exercise
to the reader.

B<However, this plugin> will provide various ways to provide a backend ID
(see below) in such a way that prevents a user from knowing how many backends
exist.

=item * Limited features

It does not provide the user with a way to control how the backend ID is given
to the user, nor does it give the user a way to fetch the backends. It only
gets them using Perlbal, without allowing the user some options on that.

B<However, this plugin> will give the user the ability to pick backends using
either randomly, via an external class or semi-random (for the lack of a better
name).

=back

=head1 ATTRIBUTES

These are future attributes:

=head2 session_cookie_header

The name of the cookie header for the session. It's currently hardcoded
to B<X-SERVERID> but it will be configurable in the future.

=head1 SUBROUTINES/METHODS

=head2 register

Registers two checks:

=over 4

=item * Cookie check

It searches for the backend using the service and the current request's cookie.
It then sets the possible backends list to what it found. It's a trick since
it's the C<bored_backends> list, which is reserved just for connect-ahead
backends, but it seems to work.

The theory is that apparently Perlbal always finds the desired backend from
that list even when the connect-ahead amount has been exhausted, so it should
work. However, I do not promise anything, triple, quadruple and quintuple check
it yourself.

The cookie check is scheduled in the B<start_proxy_request> hook.

=item * Cookie set

Sets the session affinity cookie.

The cookie set is scheduled in the B<modify_response_headers> and
B<backend_response_received> hooks.

=back

=head2 unregister

Unregister the hooks and setters.

=head2 get_backend_id

Get a backend ID number. This is currently simply sequential, but will be
very dynamic in the near future.

=head2 get_ip_port

Parses a request's cookies and finds the specific cookie relating to session
affinity and get the server via the ID in the cookie.

This is currently considered a security risk, since the ID is sequential and
substantially predictable.

=head2 get_backend

Gets the IP and port from a request's cookie and find the backend object we
want.

=head1 DEPENDENCIES

=head2 Perlbal

Obviously.

=head2 CGI::Cookies

To parse and create cookies.

=head2 Digest::SHA

To provide a SHA1 checksum in the future.

=head1 SEE ALSO

=head2 Perlbal::Plugin::StickySessions

Try it and see why you would probably prefer this one. :)

