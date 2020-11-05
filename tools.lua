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
		client_ip = "unknown"
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

--log record
function log_record(action,uri,data,rule)
	local cjson = require('cjson.safe')
	uri = ngx.unescape_uri(uri)
	local client_ip = get_client_ip()
	local local_time = ngx.localtime()
	local server_name = ngx.var.server_name
	local user_agent = ngx.var.http_user_agent
	local msg = {
		client_ip 	= client_ip,
		local_time	= local_time,
		action		= action,
		server_name	= server_name,
		uri 		= uri,
		user_agent 	= user_agent,
		data		= data,
		rule 		= rule
	}
	local msg = cjson.encode(msg)
	local filename = ngx.today().."_waf.log"
	local log_file = config_waf_logs_path.."/"..filename
	local fd = io.open(log_file,"a")
	if not fd then
		return
	end
	fd:write(msg.."\n")
	fd:flush()
	fd:close()
end

--waf output
function waf_output()
	if config_waf_output == "redirect" then
		ngx.redirect("http://www.baidu.com",301)
	else
		ngx.header['content_type']="text/html"
		ngx.status=ngx.HTTP_FORBIDDEN
		ngx.say(config_waf_output_html)
		ngx.exit(ngx.status)
end