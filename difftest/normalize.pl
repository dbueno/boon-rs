#!/usr/bin/env perl
# Read a boon / boon-rs report on stdin, emit a canonical sorted set of
# findings: one line "TIER | VAR | RANGES" per reported buffer.
# Ignores progress chatter, timing, CAVEATS, and the "<-" provenance traces
# (whose order differs between the two tools but whose content is not part of
# the verdict).
use strict; use warnings;
my @out;
my @lines = <STDIN>;
for my $i (0 .. $#lines) {
    my $l = $lines[$i];
    my ($tier, $var);
    if ($l =~ /^Almost certainly a buffer overflow in `(.+)':/)   { $tier = "ALMOST";   $var = $1; }
    elsif ($l =~ /^Possibly a buffer overflow in `(.+)':/)        { $tier = "POSSIBLE"; $var = $1; }
    elsif ($l =~ /^Slight chance of a buffer overflow in `(.+)':/){ $tier = "SLIGHT";   $var = $1; }
    else { next; }
    # next non-blank line holds the ranges
    my $ranges = "?";
    for my $j ($i+1 .. $i+3) {
        last if $j > $#lines;
        if ($lines[$j] =~ /([-\+\d\.Infinity]+ bytes allocated, [-\+\d\.Infinity]+ bytes used)/) {
            $ranges = $1; last;
        }
    }
    push @out, "$tier | $var | $ranges";
}
print "$_\n" for sort @out;
