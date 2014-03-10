
module DumpEvents;

export {
	# If true, include event argument in output.
	const include_args = T &redef;

	# Only include events matching the given pattern into output.
	const include = /.*/ &redef;
}

event new_event(name: string, args: call_argument_vector)
	{
	if ( include !in name )
		return;

	if ( ! include_args || |args| == 0 )
		return;

	print fmt("%.6f %s", network_time(), name);

	for ( i in args )
		{
		local a = args[i];
		
		local proto = fmt("%s: %s", a$name, a$type_name);
		
		if ( a?$value )
			print fmt("                  [%d] %-15s = %s", i, proto, a$value);
		else
			print fmt("                  | %-15s = %s [default]", proto, a$value);
		}

	print "";
	}