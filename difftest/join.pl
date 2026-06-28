#!/usr/bin/env perl
# Join post-fix boon-rs verdicts (rs-results.csv: file,rs_bad,rs_good) with the
# original BOON verdicts from run 1 (juliet-results.csv: file,rs_bad,rs_good,
# orig_bad,orig_good). The original is unaffected by the boon-rs-only fix, so
# run-1's orig columns are authoritative. Produce the post-fix differential and
# show how it changed vs. run 1.
use strict; use warnings;
my (%orig_bad,%orig_good,%old_rs_bad,%old_rs_good);
open my $r1, '<', 'difftest/juliet-results.csv' or die;
while (<$r1>) { chomp; my @c=split /,/; next unless @c==5;
  $old_rs_bad{$c[0]}=$c[1]; $old_rs_good{$c[0]}=$c[2];
  $orig_bad{$c[0]}=$c[3]; $orig_good{$c[0]}=$c[4]; }
close $r1;

my ($cmp,$agree,$rs_err)=(0,0,0);
my (@new_dis,@fixed,@regress);
open my $r2,'<','difftest/rs-results.csv' or die;
while (<$r2>) { chomp; my @c=split /,/; next unless @c==3;
  my ($f,$rb,$rg)=@c;
  my ($ob,$og)=($orig_bad{$f},$orig_good{$f});
  next unless defined $ob;
  $rs_err++ if $rb eq 'ERR' || $rg eq 'ERR';
  for my $v (['OMITGOOD',$rb,$ob,$old_rs_bad{$f}],['OMITBAD',$rg,$og,$old_rs_good{$f}]) {
    my ($lbl,$rs,$or,$oldrs)=@$v;
    next if $or eq 'ERR' || $rs eq 'ERR';
    $cmp++;
    my $now = ($rs eq $or);
    $agree++ if $now;
    # did the comparison status change vs run 1?
    my $was = (defined $oldrs && $oldrs ne 'ERR') ? ($oldrs eq $or) : undef;
    if (!$now) { push @new_dis, "$f  $lbl rs=$rs orig=$or"; }
    if (defined $was) {
      push @fixed,   "$f $lbl" if !$was &&  $now;   # disagreement -> agreement
      push @regress, "$f $lbl rs:$oldrs->$rs" if $was && !$now; # agreement -> disagreement
    }
  }
}
close $r2;
sub pct { my($a,$b)=@_; $b? sprintf("%.3f%%",100*$a/$b):"n/a"; }
print "=== POST-FIX Juliet differential (post-fix boon-rs vs. run-1 original) ===\n";
print "comparable variants : $cmp\n";
print "agree               : $agree  (", pct($agree,$cmp), ")\n";
print "disagreements       : ", scalar(@new_dis), "\n";
print "boon-rs ERR variants: $rs_err\n\n";
print "vs run 1: disagreements fixed (now agree): ", scalar(@fixed), "\n";
print "vs run 1: NEW regressions (now disagree) : ", scalar(@regress), "\n";
if (@regress){ print "  REGRESSION DETAIL:\n"; print "    $_\n" for @regress; }
if (@new_dis){ print "\nremaining disagreements (".scalar(@new_dis)."):\n"; print "  $_\n" for @new_dis[0..($#new_dis<29?$#new_dis:29)]; }
