#!perl

# this test checks the hostname-style srand trick
# we're using

use strict;
use warnings;

use Test::More;
use Perlbal::Plugin::SessionAffinity;

my %generated = ();
my @domains   = qw<foo.com bar.org baz.net quux.info>;

foreach my $idx ( 1 .. 30 ) {
    diag("Round $idx");

    foreach my $domain (@domains) {
        my $index = Perlbal::Plugin::SessionAffinity::domain_index(
            $domain, scalar @domains
        );

        my $rand = rand();
        diag("Random number for $domain: $index");

        ok(
            ( $index > 0 ) && ( $index <= $#domains ),
            'Index is in the correct range',
        );

        ok(
            length $rand > 1,
            "Random generation is back to normal: $rand",
        );

        exists $generated{$domain} or $generated{$domain} = $index;

        is(
            $index,
            $generated{$domain},
            "Index for $domain hasn't changed",
        );

        isnt(
            int rand $index,
            $generated{$domain},
            'Random generation still normal',
        );
    }
}

done_testing();
