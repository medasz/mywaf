-- 加载配置文件
local config = require('config')

-- 加载功能函数
local tools	= require('tools')

local _M = {
	--[[
	{
		"white_ip.rule":{'','',''},
		"black_ip.rule":{'','',''}
	}
	]]
	rules_table = {}
}

-- 加载规则到内存
function _M.load_rules()
	_M.rules_table = tools.get_rules(config.config_rule_dir)
	for k,v in pairs(_M.rules_table) do
		ngx.log(ngx.INFO,"filename:"..k..';rules:'..table.concat(v,";"))
	end
end

-- 获取规则
function _M.get_rule(filename)
	return _M.rules_table[filename]
end

-- IP白名单检测
function _M.white_ip_check()
	if config.config_white_ip == "on" then
		local client_ip = tools.get_client_ip()
		local rule_list = _M.get_rule("white_ip.rule")
		if rule_list then
			for _,rule in ipairs(rule_list) do
				if rule ~= "" and ngx.re.match(client_ip,rule,"isjo") then
					tools.log_record(config.config_log_dir,"white_ip",ngx.var.request_uri,client_ip,rule)
					return true
				end
			end
		end
	end
end

-- IP黑名单检测
function _M.black_ip_check()
	if config.config_black_ip == "on" then
		local client_ip = tools.get_client_ip()
		local rule_list = _M.get_rule("black_ip.rule")
		if rule_list then
			for _,rule in ipairs(rule_list) do
				if rule ~= "" and ngx.re.match(client_ip,rule,"isjo") then
					tools.log_record(config.config_log_dir,"black_ip",ngx.var.request_uri,client_ip,rule)
					if config.config_waf_status == "on" then
						ngx.exit(403)
					end
				end
			end 
		end
	end
end

-- 黑名单user_agent检测
function _M.black_user_agent_check()
	if config.config_user_agent == "on" then
		local user_agent = ngx.var.http_user_agent
		local rule_list = _M.get_rule("black_user_agent.rule")
		if rule_list then
			for _,rule in ipairs(rule_list) do
				if rule ~= "" and ngx.re.match(user_agent,rule,"sjo") then
					tools.log_record(config.config_log_dir,"black_user_agent",ngx.var.request_uri,"-",rule)
					if config.config_waf_status == "on" then
						tools.waf_output()
					end
				end
			end
		end
	end
end

-- uri白名单检测
function _M.white_uri_check()
	if config.config_white_uri == "on" then
		local req_uri = ngx.var.request_uri
		local rule_list = _M.get_rule("white_uri.rule")
		if rule_list then
			for _,rule in ipairs(rule_list) do
				if rule ~= "" and ngx.re.match(req_uri,rule,"sjo") then
					tools.log_record(config.config_log_dir,"white_uri",req_uri,"-",rule)
					return true
				end
			end
		end
	end
end

-- uri黑名单检测
function _M.black_uri_check()
	if config.config_black_uri == "on" then
		local req_uri = ngx.var.request_uri
		local rule_list = _M.get_rule("black_uri.rule")
		if rule_list then
			for _,rule in ipairs(rule_list) do
				if rule ~= "" and ngx.re.match(req_uri,rule,"sjo") then
					tools.log_record(config.config_log_dir,"black_uri",req_uri,"-",rule)
					if config.config_waf_status == "on" then
						tools.waf_output()
					end
				end
			end
		end
	end
end

-- cc防御
function _M.cc_check()
	if config.config_cc == "on" then
		local total_count = tonumber(string.match(config.config_cc_rate,"(.+)/"))
		local exp_time = tonumber(string.match(config.config_cc_rate,"/(.+)"))
		local limit = ngx.shared.limit
		local client_ip =tools.get_client_ip()
		local token = client_ip..ngx.var.uri
		if limit == nil then
			return
		end
		local cur_count = limit:get(token)
		if cur_count then
			if cur_count < total_count then
				limit:incr(token,1)
			else
				tools.log_record(config.config_log_dir,"cc_deny",ngx.var.request_uri,cur_count,total_count)
				if config.config_waf_status == "on" then
					ngx.exit(403)
				end
			end
		else
			limit:set(token,1,exp_time)
		end
	end	
end

-- cookie黑名单检测
function _M.black_cookie_check()
	if config.config_black_cookie == "on" then
		local cookie = ngx.var.http_cookie
		local rule_list = _M.get_rule("black_cookie.rule")
		if rule_list then
			for _,rule in ipairs(rule_list) do
				if rule ~= "" and ngx.re.match(cookie,rule,"sjo") then
					tools.log_record(config.config_log_dir,"black_cookie",ngx.var.request_uri,cookie,rule)
					if config.config_waf_status == "on" then
						tools.waf_output()
					end
				end
			end
		end
	end
end

-- get参数黑名单检测
function _M.black_get_args_check()
	if config.config_black_get_args == "on" then
		local args = ngx.req.get_uri_args()
		local rule_list = _M.get_rule("black_get_args.rule")
		for k,v in pairs(args) do
			local data
			if type(v) == "table" then
				data = table.concat(v," ")
			elseif type(v) == "boolean" then
			else
				data = v
			end
			if rule_list then
				for _,rule in ipairs(rule_list) do
					if rule ~= "" and ngx.re.match(data,rule,"sjo") then
						tools.log_record(config.config_log_dir,"black_get_args",ngx.var.request_uri,data,rule)
						if config.config_waf_status == "on" then
							tools.waf_output()
						end
					end 
				end
			end
		end
	end
end

-- post请求参数黑名单检测
function _M.black_post_args_check()
	ngx.req.read_body()
	local args = ngx.req.get_post_args()
	local rule_list = _M.get_rule("black_post.rule")
	if args == nil then
		return
	end
	for k,v in pairs(args) do
		local data
		if type(v) == "table" then
			data = string.format("%s:%s",k,table.concat(v," "))
		elseif type(v) == "boolean" then
			data = k
		else
			data = v
		end
		if data then 
			local flag,rule = tools.ruleMatch(ngx.unescape_uri(data),rule_list)
			if flag then
				tools.log_record(config.config_log_dir,"black_post_args",ngx.var.request_uri,ngx.unescape_uri(data),rule)
				if config.config_waf_status == "on" then
					tools.waf_output()
				end
			end
		end
	end
end

-- 文件后缀名黑名单检测
-- 文件上传数据格式样例
--[[
-----------------------------2243723649166645011495177173
Content-Disposition: form-data; name="MAX_FILE_SIZE"

100000
-----------------------------2243723649166645011495177173
Content-Disposition: form-data; name="uploaded"; filename="test.txt"
Content-Type: text/plain

abc

-----------------------------2243723649166645011495177173
Content-Disposition: form-data; name="Upload"

Upload
-----------------------------2243723649166645011495177173
Content-Disposition: form-data; name="user_token"

a1ef7f34ab38ec1a83951a5b1e06a283
-----------------------------2243723649166645011495177173--

]]
function _M.file_ext_check(data)
	local rule_list = _M.get_rule("black_file_ext.rule")
	local m = ngx.re.match(data,"Content-Disposition: form-data;(.+)filename=\"(.+)\\.(.+)\"","jo")
	if m == nil then
		return
	end
	local flag,rule = tools.ruleMatch(m[3],rule_list)
	if flag then
		tools.log_record(config.config_log_dir,"black_file_ext",ngx.var.request_uri,data,rule)
		if config.config_waf_status == "on" then
			tools.waf_output()
		end
	end
end

-- 文件内容黑名单检测
function _M.file_content_check(data)
	local rule_list = _M.get_rule("black_post.rule")
	local flag,rule = tools.ruleMatch(data,rule_list)
	if flag then
		tools.log_record(config.config_log_dir,"black_file_ext",ngx.var.request_uri,data,rule)
		if config.config_waf_status == "on" then
			tools.waf_output()
		end
	end
end

-- post请求内容黑名单检测
function _M.black_post_content_check()
	local rule_list = _M.get_rule("black_post.rule")
	-- 创建一个包含下游连接的socket对象
	local sock = ngx.req.socket()
	if sock == nil then
		return
	end
	sock:settimeout(0)
	-- 创建当前请求的新请求体，并初始化缓冲区大小
	ngx.req.init_body(128*1024)
	local size = 4096
	local content_length = tonumber(ngx.req.get_headers()['content_length'])
	local curSize = 0
	while curSize < content_length do
		local data,err,partial = sock:receive(size)
		data = data or partial
		-- 向新请求体中添加数据
		ngx.req.append_body(data)
		data = ngx.unescape_uri(data)
		-- 文件后缀名黑名单检测
		_M.file_ext_check(data)

		-- 文件内容黑名单检测
		_M.file_content_check(data)

		-- 根据剩余数据大小调整获取数据大小
		curSize = curSize + size
		local less = content_length - curSize
		if less < size then
			size = less
		end
	end
	ngx.req.finish_body()
	sock:close()
end

-- post请求体黑名单检测
function _M.black_post_check()
	if config.config_black_post == "on" then
		local boundary = tools.get_boundary()
		if boundary then
			_M.black_post_content_check()
		else
			_M.black_post_args_check()
		end
	end
end

-- 规则检查
function _M.check()
	if _M.white_ip_check() then
	elseif _M.black_ip_check() then
	elseif _M.black_user_agent_check() then
	elseif _M.white_uri_check() then
	elseif _M.black_uri_check() then
	elseif _M.cc_check() then
	elseif _M.black_cookie_check() then
	elseif _M.black_get_args_check() then
	elseif _M.black_post_check() then
	else
		return
	end
end

return _M