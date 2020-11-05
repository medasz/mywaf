--get client ip
function get_client_ip()
	local client_ip = ngx.req.get_headers()["x_real_ip"]
	if not client_ip then
		client_ip = ngx.req.get_headers()['x_forwarded_for']
	end
	if not client_ip then
		client_ip = ngx.var.remote_addr
	end
	if not client_ip then
		client_ip = "unknow"
	end
	return client_ip
end

--get rule
function get_rule(filename)
	local fd = io.open(config_waf_rules_path.."/"..filename,"r")
	if not fd then
		return
	end
	local t = {}
	for line in fd:lines() do
		table.insert(t,line)
	end
	fd:close()
	return t
end