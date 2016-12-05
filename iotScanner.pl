use AnyEvent::HTTP;
use Data::Dumper;
use MIME::Base64;
use Digest::SHA;
use JSON;

my $devs = {};
my $body;
my $headers = {};
my $devType = "";
my @ipList = ();
my $ptr = -1;
my $httpPort = 80;
my $debug = 0;
my $ip = $ARGV[0];
if ($ARGV[0] =~ /^\-?h/) {
	print "perl iotScanner.pl <ipRanges> [devCfgUrl=<devCfgUrl>]\n";
	exit;
}
my $devCfgUrl = "";
for ($i=1; $i<=$#ARGV; $i++) {
	if ($ARGV[$i] =~ /devCfgUrl=/) {
		$devCfgUrl = $';
	} elsif ($ARGV[$i] =~ /^debug/) {
		if ($' =~ /^\=/) {
			$debug = $';
		} else {
			$debug = 1;
		}
		print "debug=$debug\n";
	}
}
readDevices();

foreach $e (split(/\,/, $ARGV[0])) {
	if ($e =~ /\-/) {
		$start = $`;
		$end   = $';
		print "$start|$end|\n";
		for ($i = ip2num($start); $i<=ip2num($end); $i++) {
			push @ipList, num2ip($i);
		}
	} else {
		push @ipList, $e;
	}
}
my $numOfIps = scalar @ipList;
my $numOfResults = 0;
my $i;
my $w = AnyEvent->condvar; #

for ($i=0; $i<10; $i++) {
kickoff();
}

$w->recv;

sub kickoff {
	$ptr ++;
	if (! defined $ipList[$ptr]) { return; }
	check({ip => $ipList[$ptr], stage => ""});
}

sub check_login {
	my $ctx = shift;
	my $url = composeURL($ctx);
	$headers = {};
	my $dev = $ctx->{dev};
	if ($dev->{auth}->[0] eq "basic") {
		if ($dev->{auth}->[1] eq "") {
			http_get $url, sub {
				my $status = $_[1]->{Status};
				if ($status == 200) {
					print "device $ctx->{ip} is of type $ctx->{devType} still has default password\n";
				} else {
					print "device $ctx->{ip} of type $ctx->{devType} has changed password\n";
				}
				$numOfResults ++; if ($numOfResults == $numOfIps) { exit;} else {kickoff();}
			};
			return;
		}
		$tmp = "Basic " . encode_base64($dev->{auth}->[1]); # am9objpyYXBpZDc=\r\n
		chomp($tmp);
		$headers->{Authorization} = $tmp;
	} elsif ($dev->{auth}->[0] eq "form") {
		my $subtype = $dev->{auth}->[1];
		my $postdata = $dev->{auth}->[2];
		if (defined $dev->{extractFormData}) {
			foreach $e (@{$dev->{extractFormData}}) {
				if ($body =~ /$e/) {
					if (! defined $ctx->{extractedData}) { $ctx->{extractedData} = [];}
					push @{$ctx->{extractedData}}, $1;
				}
			}
		}
		if ($subtype =~ /^sub/) {
			$subtype = "";
			$postdata = substitute($postdata, $ctx->{extractedData});
		}
		if ($subtype eq "") {
			http_post $url, $postdata, sub {
				#print "body=$_[0]\n";
				my $status = $_[1]->{Status};
				my $body = $_[0];
				if ($dev->{auth}->[3] eq "body") {
					if ($dev->{auth}->[4] eq "regex") {
						$pattern = $dev->{auth}->[5];
						if ($body =~ /$pattern/) {
							print "device $ctx->{ip} is of type $ctx->{devType} still has default password\n";
						} else {
							print "device $ctx->{ip} of type $ctx->{devType} has changed password\n";
						}
						$numOfResults ++; if ($numOfResults == $numOfIps) { exit;} else {kickoff();}
					} elsif ($dev->{auth}->[4] eq "!substr") {
						if (index($body, $dev->{auth}->[5]) < 0) {
							print "device $ctx->{ip} is of type $ctx->{devType} still has default password\n";
						} else {
							print "device $ctx->{ip} of type $ctx->{devType} has changed password\n";
						}
						$numOfResults ++; if ($numOfResults == $numOfIps) { exit;} else {kickoff();}
					}
				} 
			};
		} 
		
		return;
	}
	
	if ($debug) {print "checking login on $url\n";}
	http_get $url, headers=> $headers, sub {
		my $status = $_[1]->{Status};
		if ($debug) {print "check_login status=$status\n";}
		if ($status == 200) {
			if ($ctx->{dev}->{auth}->[0] eq "basic") {
				print "device $ctx->{ip} is of type $ctx->{devType} still has default password\n";
			} elsif ($ctx->{dev}->{auth}->[0] eq "expect200") {
				print "device $ctx->{ip} is of type $ctx->{devType}  doesnot have any password\n";
			}
		} elsif ($status == 301 || $status == 302) {
			print "device $ctx->{ip} is of type $ctx->{devType} still has default password\n";
		} elsif ($status == 401 && $ctx->{dev}->{auth}->[0] eq "basic") {
			print "device $ctx->{ip} is of type $ctx->{devType} has changed password\n";
		} else {
			print "device $ctx->{ip}: unexpected resp code $status\n";
		}
		$numOfResults ++; if ($numOfResults == $numOfIps) { exit;} else {kickoff();}
	};
}

sub composeURL {
	my $ctx = shift;
	my $portStr = ($httpPort != 80)? ":$httpPort" : "";
	if (! defined $ctx->{url}) {
		return "http://$ctx->{ip}$portStr/";
	} elsif ($ctx->{url} =~ /^https?:/) {
		return $ctx->{url};
	} elsif ($ctx->{url} =~ /^\//) {
		return "http://$ctx->{ip}$portStr$ctx->{url}";
	} elsif ($ctx->{url} =~ /^\//) {
		print "unexpected partial url $ctx->{url}\n";
		return;
	}
}

sub search4devType { #with $body and $header
	my $e;
	my $i;
	my $j;
	my $len;
	my $len2;
	my $p;
	my $q;
	foreach $e (keys %{$devs}) {
		$p = $devs->{$e}->{devTypePattern};
		#$len = scalar @{$devs->{$e}->{devTypePattern}};
		if ($p->[0]->[0] eq "header") {
			$tmp = $headers->{$p->[0]->[1]};
		} elsif ($p->[0]->[0] eq "body") {
			if ($p->[0]->[1] eq "") {
				$tmp = $body;
			} else {
				$pattern = "<$p->[0]->[1]>(.*?)</$p->[0]->[1]>";
				if ($body =~ /$pattern/) {
					$tmp = $1;
				} else {
					#print "didnot find pattern $pattern\n";
					next;
				}
			}
		}
		$p = $devs->{$e}->{devTypePattern}->[1];
		$len = scalar @{$p};
		if ($p->[0] eq "==") {
			if ($tmp eq $p->[1]) {
				return $e;
			}
		} elsif ($p->[0] =~ /^regex/) {
			for ($i=1; $i < $len; $i++) {
				$pattern = $p->[$i];
				if ($tmp !~ /$pattern/) { last; }
			}
			if ($i == $len) { return $e;}
		} elsif ($p->[0] eq "substr") {
			if (index($tmp,$p->[1]) >= 0) {
				return $e;
			}
		}
	}
	return "";
}

sub check {
	my $ctx = shift;
	my $url = composeURL($ctx);
	if ($ctx->{stage} eq "initialClickLoginPage") {
		return check_init_login($ctx);
	}
	http_get $url,  sub {
		($body, $headers) = @_;
		my $status = $headers->{Status};
		if ($debug) {print "got status=$status for $url\n";}
		if ($status == 301 || $status == 302) {
			if ($debug) {print "http redirect to $headers->{location}\n";}
			$ctx->{url} = $headers->{location};
			return check($ctx);
		} elsif ($status == 401) {
			$devType = search4devType();
			if ($devType eq "") {
				print "$ctx->{ip}: didnot find dev type after trying all devices\n";
				$numOfResults ++; if ($numOfResults == $numOfIps) { exit;} else {kickoff();}
				kickoff();
				return;
			}
			if ($debug) {print "devType=$devType\n";}
			$ctx->{devType} = $devType;
			$ctx->{url} = $url;
			$ctx->{dev} = $devs->{$devType};
			return check_login($ctx);
		} elsif ($status == 200) {
			$devType = search4devType();
			if ($devType ne "") {
				if ($debug) {print "devType=$devType\n";}
				$ctx->{dev} = $devs->{$devType};
				$ctx->{devType} = $devType;
				goto gotoCheckLogin;
			} elsif ($ctx->{stage} eq "look4LoginPage") { #come from refreshUrl
				#pass through
			} elsif ($ctx->{stage} eq "") {
				$url = getRefreshUrl($ctx->{url});
				#print "url=$url\n";
				if ($url ne "") {
					$ctx->{url} = $url;
					$ctx->{stage} = "look4LoginPage";
					return check($ctx);
				}
			}
		} elsif ($status == 404) {
			print "canot find dev type for $ctx->{ip} due to 404 response\n";
			$numOfResults ++; if ($numOfResults == $numOfIps) { exit;} else {kickoff();}
			return;
		} else {
			if ($status == 595) {
				print "device $ctx->{ip}: failed to establish TCP connection\n";
			} else {
				print "unexpected status code $status for ip $ctx->{ip}\n";
			}
			$numOfResults ++; if ($numOfResults == $numOfIps) { exit;} else {kickoff();}
			return;
		}
		$devType = search4devType();
		if ($devType eq "") {
			print "$ctx->{ip}: didnot find dev type after trying all devices\n";
			$numOfResults ++; if ($numOfResults == $numOfIps) { exit;} else {kickoff();}
			kickoff();
			return;
		}
		#print "devType=$devType\n";
		$ctx->{dev} = $devs->{$devType};
		$ctx->{devType} = $devType;
		if ($status == 401) {
			$ctx->{url}   = $url;
			return check_login($ctx);
		}
gotoCheckLogin:
		if (defined $ctx->{dev}->{loginUrlPattern}) {
			$pattern = $ctx->{dev}->{loginUrlPattern};
			if ($body =~ /$pattern/) {
				$ctx->{url}   = $1;
				#print "url=$1\n";
				return check_login($ctx);
			}
		} else {#nextUrl
			$tmp = $ctx->{dev}->{nextUrl};
			if ($tmp->[0] eq "string") {
				if ($tmp->[1] ne "") {
					$ctx->{url}   = $tmp->[1];
				} else {
					$ctx->{url} = $url;
				}
			}
		}
		#$ctx->{url} = $ctx->{dev}->{nextUrl};
		check_login($ctx);
	};
}

sub getRefreshUrl {
	my $prevUrl = shift;
	my $newUrl;
	my $tmpBody = $body;
	while($tmpBody =~ /\<META\s+[^\>]*url=(.*?)>/i) {
		$tmpBody = $';
		$tmp = $1;
		if ($tmp =~ /^[\"\'](.*?)[\"\']/) {
			$newUrl = $1; last;
		} elsif ($tmp =~ /^(.*?)[\>\"\s]/) {
			$newUrl = $1; last;
		}
	}
	#print "newUrl=$newUrl\n";
	if ($newUrl ne "" && $newUrl ne $prevUrl) {
		return $newUrl;
	} else {
		return "";
	}
}

sub match {
	my $title;
	if ($body !~ /<title>(.*?)<\/title>/) {
		return "";
	}
	$title = $1;
	my $e;
	my $f;
	foreach $e (keys %{$devs}) {
		my $patterns = $devs->{$e}->{devTypePattern};
		my $isMatch = 1;
		#print "e=$e\n";
		foreach $f (@{$patterns}) {
			#print "f=$f\n";
			if ($title !~ /$f/) {
				$isMatch = 0; last;
			}
		}
		if ($isMatch) { return $e; }
	}
	return "";
}

sub search4login {
	my $ctx = shift;
	$devType = match();
	#print "devType=$devType|\n";
	if ($devType eq "") { 
		print "didnot find devType for $ctx->{ip}\n";
		$numOfResults ++; if ($numOfResults == $numOfIps) { exit;} else {kickoff();}
		return; }
	my $pattern = $devs->{$devType}->{loginUrlPattern};
	#printf "%d pattern=$pattern\n", length($body);
	if ($body =~ /$pattern/) {
		#print "found url\n";
		return $1;
	}
	return "";
}

sub readDevices {
	#open FD, "devices.cfg" || die "Failed to open devices.cfg $!\n";
	if ($devCfgUrl ne "") {
		#partially from http://www.perlmonks.org/?node_id=1078704
		my $ua = new LWP::UserAgent;
		$ua->agent('Mozilla/5.0');
		$ua->ssl_opts( verify_hostname => 0 ,SSL_verify_mode => 0x00);
		my $req = new HTTP::Request('GET',$devCfgUrl);
		my $res = $ua->request($req);
		$buff = $res->{_content};
	} else {
		open FD, "devices.cfg" || die "Failed to open devices.cfg $!\n";
		read FD, $buff, 0x100000;
		close FD;
	}
	$devs = decode_json($buff);
}
sub substitute {
	my ($str, $p) = @_;
	my $ret;
	while ($str =~ /\$(\d+)/) {
		$ret .= $` . $p->[$1 - 1];
		$str = $';
	}
	$ret .= $str;
	return $ret;
}

sub ip2num {
	my @a = split(/\./, $_[0]);
	return ($a[0]<<24) + ($a[1] << 16) + ($a[2] << 8) + $a[3];
}

sub num2ip {
	my $n = shift;
	return sprintf("%d.%d.%d.%d", ($n >> 24), ($n >> 16) & 0xff, ($n >> 8) & 0xff, $n & 0xff);
}

__END__
--- to handle page 404
