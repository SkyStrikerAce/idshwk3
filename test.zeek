global IP_User : table[addr] of set[string] = {};

event http_header (c: connection, is_orig: bool, name: string, value: string)
{
    if(name == "USER-AGENT")
    {
        if(c$id$orig_h !in IP_User)
        {
            IP_User[c$id$orig_h] = set(to_lower(value));
        }
        else
        {
            if(to_lower(value) !in IP_User[c$id$orig_h])
            {
                add IP_User[c$id$orig_h][to_lower(value)];
            }
        }
    }
}

event zeek_done()
{
	local temp: int = 0;
	for (IP in IP_User)
	{
		temp = 0;
		for (User in IP_User[IP])
		{
			temp += 1;
		}
		if(temp >= 2)
		{
			print fmt("%s is a proxy",IP);
		}
	}
}
