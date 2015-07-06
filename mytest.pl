#!/usr/bin/env perl

use strict;
use warnings;
use lib 'lib';
use Bytes::Random::Secure::Tiny;

my $r = Bytes::Random::Secure::Tiny->new;

print ref $r, "\n";

my @array = (1..16);

for ( 1 .. 10 ) {
    my $aref = [@array];
    print "Shuffling ", scalar @$aref, " elements: (", join(", ", @$aref), ")\n";
    $r->shuffle($aref);
    print "Got       ", scalar @$aref, " elements: (", join(", ", @$aref), ")\n\n";
}


