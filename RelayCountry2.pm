=head1 NAME

RelayCountry2 - add message metadata indicating the country code of each relay

=head1 SYNOPSIS

  loadplugin     Mail::SpamAssassin::Plugin::RelayCountry2

=head1 DESCRIPTION

The RelayCountry2 plugin attempts to determine the domain country
codes of each relay used in the delivery path of messages and add that
information to the message metadata as "X-Relay-Countries", or 
the C<_RELAYCOUNTRY_> header markup.

=head1 REQUIREMENT

This plugin requires the Geo::IP module from CPAN. Don't enable both this
plugin and the original RelayCountry one as both will try and set the same
headers/metadata.

=cut

package Mail::SpamAssassin::Plugin::RelayCountry2;

use strict;
use warnings;
use bytes;
use re 'taint';

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
use NetAddr::IP 4.000;

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);

# Gleaned from RFC 3330 (IPv4) & RFC 5156 (IPv6)
my @private_networks = (
	"0.0.0.0/8",		# "This" Network (RFC 1700)
	"10.0.0.0/8",		# Private-Use Networks (RFC 1918)
	"127.0.0.0/8",		# Loopback (RFC 1700)
	"169.254.0.0/16",	# Link Local
	"172.16.0.0/12",	# Private-Use Networks (RFC 1918)
	"192.0.2.0/24",		# Test-Net
	"192.88.99.0/24",	# 6to4 Relay Anycast (RFC 3068)
	"192.168.0.0/16",	# Private-Use Networks (RFC 1918)
	"::1/128",		# Loopback (RFC 4291)
	"::ffff:0:0/96",	# IPv4-mapped Addresses
	"fe80::/10",		# Link Local Addresses
	"fec0::/10",		# Site Local Addresses
	"fc00::/7",		# Unique Local Addresses
	"2001::/32",		# Teredo (RFC 4380)
	"2001:db8::/32",	# Documentation Addresses (RFC 3849)
	"2002::/16",		# 6to4 (RFC 3056)
);

my @illegal_networks = (
	"14.0.0.0/8",		# Public-Data Networks (RFC 1700)
	"198.18.0.0/15",	# Network Interconnect (RFC 2544)
	"224.0.0.0/4",		# Multicast (RFC 3171)
	"240.0.0.0/4",		# Reserved (RFC 1700)
	"::/96",		# IPv4-compatible Addresses (RFC 4291)
	"2001:10::/28",		# ORCHID Addresses (RFC 4843)
	"ff00::/8",		# Multicast (RFC 4291)
);

my @networks = (
	( map { [ NetAddr::IP->new($_), "**" ] } @private_networks ),
	( map { [ NetAddr::IP->new($_), "--" ] } @illegal_networks ),
);

sub new {
	my ($class, $mailsa) = @_;

	$class = ref($class) || $class;
	my $self = $class->SUPER::new($mailsa);
	bless ($self, $class);

	return $self;
}

sub extract_metadata {
	my ($self, $opts) = @_;

	my $gi4;
	my $gi6;

	eval {
		require Geo::IP;
		$gi4 = Geo::IP->open_type(Geo::IP->GEOIP_COUNTRY_EDITION, Geo::IP->GEOIP_STANDARD);
		$gi6 = Geo::IP->open_type(Geo::IP->GEOIP_COUNTRY_EDITION_V6, Geo::IP->GEOIP_STANDARD);
		1;
	} or do {
		my $eval_stat = $@ ne '' ? $@ : "errno=$!"; chomp $eval_stat;
		dbg("metadata: failed to load 'Geo::IP', skipping: $eval_stat");
		return 1;
	};

	my $msg = $opts->{"msg"};
	my @countries;

	RELAY:
	foreach my $relay (@{$msg->{"metadata"}->{"relays_untrusted"}}) {
		my $ip = NetAddr::IP->new($relay->{"ip"});

		# Sort each relevant route in descending order of mask length,
		# so a more specific network matches first
		foreach my $network (sort { $b->[0]->masklen <=> $a->[0]->masklen } grep { $_->[0]->version == $ip->version } @networks) {
			if ($network->[0]->contains($ip)) {
				push @countries, $network->[1];
				next RELAY;
			}
		}

		my $country = ($ip->version == 4 and $gi4) ? $gi4->country_code_by_addr($ip->addr) || "XX"
		            : ($ip->version == 6 and $gi6) ? $gi6->country_code_by_addr_v6($ip->addr) || "XX"
		            :                                "XX"
		            ;

		push @countries, $country;
	}

	my $country_list = join q{ }, @countries;

	$msg->put_metadata("X-Relay-Countries", $country_list);
	dbg("metadata: X-Relay-Countries: $country_list");

	return 1;
}

sub parsed_metadata {
	my ($self, $opts) = @_;

	$opts->{permsgstatus}->set_tag("RELAYCOUNTRY", $opts->{"permsgstatus"}->get_message->get_metadata("X-Relay-Countries"));

	return 1;
}

1;
