#!/usr/bin/env perl
# Summarize the Juliet differential CSV: file,rs_bad,rs_good,orig_bad,orig_good
use strict; use warnings;
my ($n,%cwe);
my ($cmp_bad,$agree_bad,$cmp_good,$agree_good)=(0,0,0,0);
my (%conf_bad,%conf_good);
my ($orig_err_bad,$orig_err_good,$rs_err)=(0,0,0);
my @disagree;
while (<>) {
    chomp; next unless /,/;
    my ($f,$rb,$rg,$ob,$og)=split /,/;
    next unless defined $og;
    $n++;
    my ($cwe)= $f=~m{/(CWE\d+)_}; $cwe||="?"; $cwe{$cwe}++;
    $rs_err++ if $rb eq 'ERR' || $rg eq 'ERR';
    # OMITGOOD (bad) variant: detection
    if ($ob eq 'ERR'){ $orig_err_bad++ }
    elsif ($rb ne 'ERR'){ $cmp_bad++; $conf_bad{"$rb/$ob"}++; $agree_bad++ if $rb eq $ob; }
    # OMITBAD (good) variant: false positive
    if ($og eq 'ERR'){ $orig_err_good++ }
    elsif ($rg ne 'ERR'){ $cmp_good++; $conf_good{"$rg/$og"}++; $agree_good++ if $rg eq $og; }
    # record a disagreement only where both tools analyzed successfully
    if ($ob ne 'ERR' && $rb ne 'ERR' && $rb ne $ob) { push @disagree, "$f  OMITGOOD rs=$rb orig=$ob"; }
    if ($og ne 'ERR' && $rg ne 'ERR' && $rg ne $og) { push @disagree, "$f  OMITBAD  rs=$rg orig=$og"; }
}
sub pct { my($a,$b)=@_; $b? sprintf("%.2f%%",100*$a/$b):"n/a"; }
print "=== Juliet differential: boon-rs vs original BOON ===\n";
print "files compared        : $n\n";
print "by CWE                : ", join("  ", map {"$_=$cwe{$_}"} sort keys %cwe), "\n\n";

print "OMITGOOD (flawed build) — does boon-rs agree with BOON on detecting?\n";
print "  comparable (both analyzed): $cmp_bad\n";
print "  agree                     : $agree_bad  (", pct($agree_bad,$cmp_bad), ")\n";
print "  rs/orig confusion         : ", join("  ", map {"$_:$conf_bad{$_}"} sort keys %conf_bad), "\n";
print "  original errored          : $orig_err_bad\n\n";

print "OMITBAD (fixed build) — does boon-rs agree with BOON on staying clean?\n";
print "  comparable (both analyzed): $cmp_good\n";
print "  agree                     : $agree_good  (", pct($agree_good,$cmp_good), ")\n";
print "  rs/orig confusion         : ", join("  ", map {"$_:$conf_good{$_}"} sort keys %conf_good), "\n";
print "  original errored          : $orig_err_good\n\n";

my $tot_cmp=$cmp_bad+$cmp_good; my $tot_ag=$agree_bad+$agree_good;
print "OVERALL agreement on comparable variants: $tot_ag / $tot_cmp  (", pct($tot_ag,$tot_cmp), ")\n";
print "boon-rs errored variants  : $rs_err\n";
print "disagreements (both analyzed): ", scalar(@disagree), "\n";
if (@ARGV==0 && @disagree) {} # placeholder
if (@disagree) {
    print "\n--- disagreement detail (first 40) ---\n";
    print "$_\n" for @disagree[0..($#disagree<39?$#disagree:39)];
}
