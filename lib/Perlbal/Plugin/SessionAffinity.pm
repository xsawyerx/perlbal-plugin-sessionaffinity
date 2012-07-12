use strict;
use warnings;
package Perlbal::Plugin::SessionAffinity;
# ABSTRACT: Sane session affinity (sticky sessions) for Perlbal

use Carp;
use Perlbal;
use CGI::Cookie;
use Digest::SHA 'sha1_hex';

my $cookie_hdr     = 'X-SERVERID';
my $id_type        = 'Simple';
my $salt           = join q{}, map { $_ = rand 999; s/\.//; $_ } 1 .. 10;
my $arrayref       = ref [];
my %loaded_classes = ();

# get a full backend object
# and try to find a node in the backend's pool
sub find_node {
    my $backend = shift;
    my @nodes   = @{ $backend->{'service'}{'pool'}{'nodes'} };

    foreach my $node (@nodes) {
        defined $node && ref $node && ref $node eq $arrayref
            or next;

        my ( $ip, $port ) = @{$node};

        if ( $backend->{'ipport'} eq "$ip:$port" ) {
            return [ $ip, $port ];
        }
    }

    # explicit return FTW
    return;
}

# get the ip and port of the requested backend from the cookie
sub get_ip_port {
    my ( $svc, $req ) = @_;

    my $cookie  = $req->header('Cookie');
    my %cookies = ();

    if ( defined $cookie ) {
        %cookies = CGI::Cookie->parse($cookie);

        if ( defined $cookies{$cookie_hdr} ) {
            my $id      = $cookies{$cookie_hdr}->value || '';
            my $backend = find_backend_by_id( $svc, $id );

            ref $backend and return join ':', @{$backend};
        }
    }

    return;
}

# create an id from ip and optional port
sub create_id {
    my $ip   = shift;
    my $port = shift || '';
    return sha1_hex( $salt . $ip . $port );
}

# using an sha1 checksum id, find the matching backend
sub find_backend_by_id {
    my ( $svc, $id ) = @_;

    foreach my $backend ( @{ $svc->{'pool'}{'nodes'} } ) {
        my $bid = create_id( @{$backend} );

        if ( $bid eq $id ) {
            return $backend;
        }
    }

    return;
}

sub load {
    # the name of header in the cookie that stores the backend ID
    Perlbal::register_global_hook(
        'manage_command.affinity_cookie_header', sub {
            my $mc = shift->parse(qr/^affinity_cookie_header\s+=\s+(.+)\s*$/,
                      "usage: AFFINITY_COOKIE_HEADER = <name>");

            ($cookie_hdr) = $mc->args;

            return $mc->ok;
        },
    );

    Perlbal::register_global_hook(
        'manage_command.affinity_id_type', sub {
            my $mc = shift->parse(qr/^affinity_id_type\s+=\s+(.+)\s*$/,
                      "usage: AFFINITY_ID_TYPE = <type>");

            ($id_type) = $mc->args;

            return $mc->ok;
        },
    );

    Perlbal::register_global_hook(
        'manage_command.affinity_salt', sub {
            my $mc = shift->parse(qr/^affinity_salt\s+=\s+(.+)\s*$/,
                      "usage: AFFINITY_SALT = <salt>");

            ($salt) = $mc->args;

            return $mc->ok;
        },
    );

    return 1;
}

sub register {
    my ( $class, $gsvc ) = @_;

    my $check_cookie = sub {
        my $client = shift;
        my $req    = $client->{'req_headers'} or return 0;
        my $svc    = $client->{'service'};
        my $pool   = $svc->{'pool'};

        # make sure all nodes in this service have their own pool
        foreach my $node ( @{ $pool->{'nodes'} } ) {
            my ( $ip, $port ) = @{$node};

            # pool
            my $pid = create_id( $ip, $port );
            exists $Perlbal::pool{$pid} and next;

            my $nodepool = Perlbal::Pool->new($pid);
            $nodepool->add( $ip, $port );
            $Perlbal::pool{$pid} = $nodepool;

            # service
            my $sid = "${pid}_service";
            exists $Perlbal::service{$sid} and next;

            my $nodeservice = Perlbal->create_service($sid);
            my $svc_role    = $svc->{'role'};

            # role sets up constraints for the rest
            # so it goes first
            $nodeservice->set( role => $svc_role );

            foreach my $tunable_name ( keys %{$Perlbal::Service::tunables} ) {
                # skip role because we had already set it
                $tunable_name eq 'role' and next;

                # persist_client_timeout is DEPRECATED
                # but not marked anywhere as deprecated. :(
                # (well, nowhere we can actually predictably inspect)
                $tunable_name eq 'persist_client_timeout' and next; 

                # we skip the pool because we're gonna set it to a specific one
                $tunable_name eq 'pool' and next;

                # make sure svc has value for this tunable
                defined $svc->{$tunable_name} or next;

                my $tunable = $Perlbal::Service::tunables->{$tunable_name};
                my $role    = $tunable->{'check_role'};

                if ( $role eq '*' || $role eq $svc_role ) {
                    $nodeservice->set( $tunable_name, $svc->{$tunable_name} );
                }
            }

            $nodeservice->set( pool => $pid );

            $Perlbal::service{$sid} = $nodeservice;
        }

        my $ip_port = get_ip_port( $svc, $req )
            or return 0;

        my $req_pool_id = create_id( split /:/, $ip_port );
        my $req_svc     = $Perlbal::service{"${req_pool_id}_service"};
        $client->{'service'} = $req_svc;

        return 0;
    };

    my $set_cookie = sub {
        my $backend  = shift; # Perlbal::BackendHTTP
        my $res      = $backend->{'res_headers'};
        my $req      = $backend->{'req_headers'};

        defined $backend && defined $res
            or return 0;

        my $svc     = $backend->{'service'};
        my %cookies = ();

        if ( my $cookie = $req->header('Cookie') ) {
            %cookies = CGI::Cookie->parse($cookie);
        }

        my $class = "Perlbal::Plugin::SessionAffinity::$id_type";

        if ( ! exists $loaded_classes{$class} ) {
            local $@ = undef;
            eval "use $class";
            $@ and croak "Cannot load $class\n";

            $loaded_classes{$class}++;
        }

        # try to find that specific backend
        # or get a new one
        my $node = find_node($backend) ||
                   $class->can('get_backend')
                         ->($backend)
            or return 0;

        my $backend_id = create_id( @{$node} ) || '';

        if ( ! defined $cookies{$cookie_hdr} ||
             $cookies{$cookie_hdr}->value ne $backend_id ) {

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
      SET pool            = backends
      SET persist_client  = on
      SET persist_backend = on
      SET verify_backend  = on
      SET plugins         = sessionaffinity
    ENABLE balancer

=head1 DESCRIPTION

L<Perlbal> doesn't support session affinity (or otherwise known as "sticky
sessions") out of the box. There is a plugin on CPAN called
L<Perlbal::Plugin::StickySessions> but there's a few problems with it.

This plugin should be do a much better job. Go ahead and read why you should
use this one and how it works.

=head1 WHY YOU SHOULD USE IT

Here is a list of problems with the other implementation of sticky sessions:

=over 4

=item * It only supports sticky sessions for files

The hook it uses for adding cookies only applies to file fetching. This means
that if you want sticky sessions for anything other than file fetching, you're
fresh out of luck. :)

B<However, this plugin> uses (hopefully) the proper hook to accomplish sticky
sessions on each and every request.

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

=item * Observed breakage

After looking into this, it seems as though gentleness is necessary, since
the connect-ahead doesn't seem to be cleaning up, and more and more closed
sessions are mounted.

B<However, this plugin> does not use the method, keeping Perlbal itself in
charge and which allows proper closing and releasing of connections.

=item * Probable security risk

It sets a cookie with a backend ID that correlates to the backend order in
the pool. This means that you can simply run requests with different backend
IDs and easily find the number of backends in a pool.

You can also attack by a special-crafted cookie and measure the timings for
requests to find when it probably does additional processing (since the
backend is specified) to find how many backends exist in a given pool.

I'll leave finding of more ways to exploit this security risk as an exercise
to the reader.

B<However, this plugin> uses L<Digest::SHA> with a randomly-created salt
on each start-up (which the user can explicitly specify, if it seeks
predictability) to keep the backend ID value in the cookie.

By allowing you to change the cookie header name and the way the value is
presented, it would be more difficult for an attacker to understand what the
header represents, and how many backends exist (since there is no counter).

=item * Limited features

It does not provide the user with a way to control how the backend is picked.
It only gets them using Perlbal.

B<However, this plugin> will give the user the ability to pick backends using
either randomly, via an external class or others.

=back

=head1 HOW DOES IT WORK

=head2 Basic stuff

Basically, the module creates a SHA1 checksum for each backend node, and
provides the user with a cookie request. If the user provides that cookie in
return, it will try and find and provide the user with that specific node.

If the node is no longer in the service's pool, or the cookie matches a node
that doesn't exist, it will provide the user with a cookie again.

=head2 Advanced stuff

The plugin sets up dedicated pools and services for each service's node. This
is required since Perlbal has no way of actually allowing you to specify the
node a user will go to, only the service. Not to worry, this creation is done
lazily so it saves as much memory as it can. In the future it might save even
more.

When a user comes in with a cookie of a node that exist in the service's pool
it will create a pool for it (if one doesn't exist), and a matching service
for it (if one doesn't exist) and then direct to user to it.

The check against nodes and pools is done live and not against the static
configuration file. This means that if you're playing some trickery on pools
(changing them live), it will still work fine.

A new service is created using configurations from the existing service. The
more interesting details is that reuse is emphasized so no new sockets are
created and instead this new service uses the already existing sockets (along
with existing connections) instead of firing new ones. It doesn't open a new
listening or anything like that. This also means your SSL connections work
seamlessly. Yes, it's insanely cool, I know! :)

=head1 ATTRIBUTES

=head2 affinity_cookie_header

The name of the cookie header for the session.

Default: B<X-SERVERID>.

=head2 affinity_salt

The salt that is used to create the backend's SHA1 IDs.

Default: the following code is run when you load
L<Perlbal::Plugin::SessionAffinity> to create the salt on start up:

    join q{}, map { $_ = rand 999; s/\.//; $_ } 1 .. 10;

If you want predictability, you can override the salt.

=head1 SUBROUTINES/METHODS

=head2 register

Registers our events.

=head2 unregister

Unregister our hooks and setters events.

=head2 get_backend_id

Get a backend ID number. This is currently simply sequential, but will be
very dynamic in the near future.

=head2 get_ip_port

Parses a request's cookies and finds the specific cookie relating to session
affinity and get the backend details via the ID in the cookie.

=head2 find_backend_by_id

Given a SHA1 ID, find the correct backend to which it belongs.

=head1 DEPENDENCIES

=head2 Perlbal

Obviously.

=head2 CGI::Cookies

To parse and create cookies.

=head2 Digest::SHA

To provide a SHA1 checksum.

=head2 Carp

To provide croak. It's core, don't worry.

=head1 SEE ALSO

=head2 Perlbal::Plugin::StickySessions

Try it and see why you would probably prefer this one. :)

