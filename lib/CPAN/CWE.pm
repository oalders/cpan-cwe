package CPAN::CWE;

# Shared helpers for the cpan-cwe scripts: load records and the editorial
# category map, and tally CWEs.

use v5.36;
use Exporter         qw(import);
use Cpanel::JSON::XS  qw(decode_json);
use Mojo::File        qw(path);

our @EXPORT_OK = qw(load_records load_categories cwe_counts categorize);

sub load_records ($file) {
    return decode_json( path($file)->slurp );
}

# Returns ( \%id_to_category, \@ordered_category_names ).
sub load_categories ($file) {
    my $data = decode_json( path($file)->slurp );
    my ( %of, @order );
    for my $cat ( sort keys %$data ) {
        next if $cat =~ /^_/;                 # skip _comment
        push @order, $cat;
        $of{"CWE-$_"} = $cat for @{ $data->{$cat} };
    }
    return ( \%of, \@order );
}

# Count how many CVEs carry each CWE (a CVE with N distinct CWEs adds to N).
# Returns ( \%count, \%name ), keyed by CWE id.
sub cwe_counts ($records) {
    my ( %count, %name );
    for my $r (@$records) {
        for my $c ( @{ $r->{cwes} } ) {
            $count{ $c->{id} }++;
            $name{ $c->{id} } //= $c->{name};
        }
    }
    return ( \%count, \%name );
}

sub categorize ( $of, $cwe_id ) {
    return $of->{$cwe_id} // 'Other';
}

1;
