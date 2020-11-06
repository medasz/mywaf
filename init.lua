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
		local request_uri = ngx.var.request_uri
		local white_uri_rule = get_rule("white_uri.rule")
		if white_uri_rule ~= nil then
			for _,rule in ipairs(white_uri_rule) do
				if rule ~= "" and ngx.re.match(request_uri,rule,"isjo") then
					log_record("white uri",ngx.var.request_uri,request_uri,rule)
					return true
				end
			end
		end
	end
end

--black uri check
function black_uri_check()
	if config_black_uri_status == "on" then
		local request_uri = ngx.var.request_uri
		local black_uri_rule = get_rule("black_uri.rule")
		if black_uri_rule ~= nil then
			for _,rule in ipairs(black_uri_rule) do
				if rule ~= "" and ngx.re.match(request_uri,rule,"isjo") then
					log_record("black uri",ngx.var.request_uri,request_uri,rule)
					if config_waf_status == "on" then
						waf_output()
					end
				end
			end
		end
	end
end

--black get args check
function black_get_args_check()
	if config_black_get_args_status == "on" then
		local args = ngx.req.get_uri_args()
		local black_get_args_rule = get_rule("black_get_args.rule")
		for key,val in pairs(args) do
			local data
			if type(val) == "table" then
				data = clear_list(val)
			elseif type(val) == "boolean" then

			else
				data = val
			end
			if data and data ~= "" and match_rules(data,black_get_args_rule) then
				log_record("black get_args",ngx.var.request_uri,data,rule)
				if config_waf_status == "on" then
					waf_output()
				end
			end
		end
	end
end

--black post check
function black_post_check()
	if config_black_post_status == "on" then
		local boundary = get_boundary()
		if boundary then
			black_post_file_check()
		else
			black_post_args_check()
		end
	end
end

--black post args check
function black_post_args_check()
	--同步读取客户端请求体，不阻塞nginx事件循环
	ngx.req.read_body()
	--返回table，读取uri的所有查询参数
	local args = ngx.req.get_uri_args()
	if not args then
		return
	end
	for key,val in pairs(args) do
		if type(val) == "table" then

		end
	end
end

--black post file check
function black_post_file_check()
	
end