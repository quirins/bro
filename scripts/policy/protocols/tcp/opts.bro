##! Detect browser plugins as they leak through requests to Omniture
##! advertising servers.

##! @load base/protocols/tcp

module TCP;

export {
	redef enum Notice::Type += {
		## Generated if a login originates or responds with a host where
		## the reverse hostname lookup resolves to a name matched by the
		## :bro:id:`SSH::interesting_hostnames` regular expression.
		Interesting_Hostname_Login,
	};
}

event tcp_option(c: connection, is_orig: bool, opt: count, optlen: count, optval: string)
	{
		## NOTICE([	$note=Interesting_Hostname_Login,
		##					$msg=fmt("TCP opt val %s.", optval),
		##				]);
		print fmt("optval: %s", optval);

	}