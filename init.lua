require 'config'
require 'tools'

--white ip check
function white_ip_check()
	if config_white_ip_status == "on" then
		local client_ip 	= 	get_client_ip()
		local white_ip_rule	=	get_rule("white_ip.rule")
		if white_ip_rule ~= nil then
			for _,rule in ipairs(white_ip_rule) do
				if rule ~= "" and client_ip == rule then
					log_record("white ip",ngx.var.request_uri,client_ip,rule)
					return true
				end
			end
		end
	end
end

--black ip check
function black_ip_check()
	if config_black_ip_status == "on" then
		local client_ip = get_client_ip()
		local black_ip_rule = get_rule("black_ip.rule")
		if black_ip_rule ~= nil then
			for _,rule in ipairs(black_ip_rule) do
				if rule ~= "" and client_ip == rule then
					log_record("black ip",ngx.var.request_uri,client_ip,rule)
					if config_waf_status == "on" then
						ngx.exit(403)
					end
				end
			end
		end
	end
end

--user agent check
function black_user_agent_check()
	if config_user_agent_status == "on" then
		local user_agent = ngx.var.http_user_agent
		local black_user_agent_rule = get_rule("black_user_agent.rule")
		if black_user_agent_rule ~= nil then
			for _,rule in ipairs(black_user_agent_rule) do
				if rule ~= "" and ngx.re.match(user_agent,rule,"isjo") then
					log_record("black user_agent",ngx.var.request_uri,user_agent,rule)
					if config_waf_status == "on" then
						waf_output()
					end
				end
			end
		end
	end
end

--cc deny
function cc_deny()
	if config_cc_deny_status == "on" then
		local client_ip = get_client_ip()
		local token = client_ip..ngx.var.uri
		local ccCount = tonumber(string.match(config_cc_deny_rate,"(.*)/"))
		local ccTime = tonumber(string.match(config_cc_deny_rate,"/(.*)"))
		local limit = ngx.shared.limit
		if limit then
			local curCount = limit:get(token)
			if curCount then
				if curCount >= ccCount then
					log_record("cc deny",ngx.var.request_uri,"-","-")
					if config_waf_status == "on" then
						ngx.exit(403)
					end
				else
					limit:incr(token,1)
				end
			else
				limit:set(token,1,ccTime)
			end
		end
	end
end

--black cookie check
function black_cookie_check()
	if config_black_cookie_status == "on" then
		local cookie = ngx.var.http_cookie
		local black_cookie_rule = get_rule("black_cookie.rule")
		if black_cookie_rule ~= nil then
			for _,rule in ipairs(black_cookie_rule) do
				if rule ~= "" and ngx.re.match(cookie,rule,"isjo") then
					log_record("black cookie",ngx.var.request_uri,cookie,rule)
					if config_waf_status == "on" then
						waf_output()
					end
				end
			end
		end
	end
end

--white uri check
function white_uri_check()
	if config_white_uri_status == "on" then
		
	end
end