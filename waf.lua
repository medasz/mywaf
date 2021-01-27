-- 加载mysql数据库连接
local mysql = require("resty.mysql")

-- 加载md5库
local md5 = require("resty.md5")

-- 加载配置文件
-- local config = require('config')
local config = {}

-- 加载功能函数
local tools	= require('tools')

-- 加载进程库
local process = require('ngx.process')

-- 加载http库
local http = require('resty.http')

-- 加载cjson
local cjson = require('cjson.safe')

-- 配置uuid
local config_uuid

-- 规则uuid
local rule_uuid

local _M = {
	--[[
	{
		"white_ip.rule":{'','',''},
		"black_ip.rule":{'','',''}
	}
	]]
	rules_table = {}
}

-- 启动特权进程
function _M.start_agent()
	local ok,err = process.enable_privileged_agent()
	if not ok then
		ngx.log(ngx.ERR,err)
	end
end

-- agent特权进程
function agent()
	local db,err = mysql:new()
	if err then
	    ngx.log(ngx.ERR,err)
		ngx.timer.at(10,agent)
		return
	end
	db:set_timeout(1000)
	local options={
	    host="127.0.0.1",
	    port=3306,
	    database="mywaf",
	    user="admin",
	    password="password",
	}
	local ok,err=db:connect(options)
	if not ok then
		ngx.log(ngx.ERR,err)
	    db:close()
	    ngx.timer.at(10,agent)
	    return
	end
	local flag_sql = "select * from flag"
	local flag,err,errcode,sqlstate=db:query(flag_sql)
	if not flag then
	    ngx.log(ngx.ERR,err)
	    db:close()
	    ngx.timer.at(10,agent)
	    return
	end
	local resConfigStr = nil
	local resRuleStr = nil
	local cycle = 10
	for x,y in ipairs(flag) do
	    if y.name == "config" then
	        local get_config_sql = "select * from waf_config"
	        local waf_config,err,errcode,sqlstate = db:query(get_config_sql)
	        if not waf_config then
	            ngx.log(ngx.ERR,err)
	            db:close()
	            ngx.timer.at(10,agent)
	            return
	        end
	        local resConfig = {}
	        for k,v in ipairs(waf_config) do
	            resConfig[v.name_key]=v.value
	        end
	        if not next(resConfig) then
	            resConfig.result='false'
	            db:close()
	            ngx.timer.at(10,agent)
	            return
	        else
	            resConfig.result='true'
	            resConfig.uuid=y.uuid
	        end
	        if resConfig.config_update_cycle ~= tostring(cycle) then
	        	local tmp_number = tonumber(resConfig.config_update_cycle)
	        	if tmp_number then
	        		cycle = tmp_number
	        	end
	        end
	        resConfigStr = cjson.encode(resConfig)
			if not resConfigStr then
				db:close()
				ngx.timer.at(10,agent)
				return
			end
	    else
	        local rules,err,errcode,sqlstate = db:query("select * from rule")
	        if not rules then
	            ngx.log(ngx.ERR,err)
	            db:close()
	            ngx.timer.at(10,agent)
	            return
	        end
	        local tmp = {}
	        for x,y in ipairs(rules) do
	            if not tmp[y.rule_type..".rule"] then
	                tmp[y.rule_type..".rule"]={y.rule_item}
	            else
	                table.insert(tmp[y.rule_type..".rule"],y.rule_item)
	            end
	        end
	        local resRule = {}
	        if not next(tmp) then
	            resRule.result="false"
	            db:close()
	            ngx.timer.at(10,agent)
	        else
	            resRule.result="true"
	            resRule.rules=tmp
	            resRule.uuid=y.uuid
	        end
	        resRuleStr = cjson.encode(resRule)
			if not resRuleStr then
				db:close()
				ngx.timer.at(10,agent)
				return
			end
	    end
	end
	-- local httpc = http.new()
	-- httpc:set_timeouts(5000,5000,10000)
	-- httpc:connect("127.0.0.1",5600)
	-- local resConfig,err = httpc:request({
	-- 	method="GET",
	-- 	path="/json/config",
	-- })
	-- if not resConfig then
	-- 	ngx.log(ngx.ERR,err)
	-- 	ngx.timer.at(10,agent)
	-- 	return
	-- end
	-- local resConfigStr,err=resConfig:read_body()
	-- if not resConfigStr then
	-- 	ngx.log(ngx.ERR,err)
	-- 	ngx.timer.at(10,agent)
	-- 	return
	-- end
	-- local wafConfig = cjson.decode(resConfigStr)
	-- if not wafConfig or wafConfig.result=="false" then
	-- 	ngx.timer.at(10,agent)
	-- 	return
	-- end






	local loadConfig = ngx.shared.loadConfig
	local success,err,forcible=loadConfig:set("config",resConfigStr)--wafConfig)
	if err then
		ngx.log(ngx.ERR,err)
		db:close()
		ngx.timer.at(10,agent)
		return
	end
	

	-- local resRule,err = httpc:request({
	-- 	method="GET",
	-- 	path="/json/rule",
	-- })
	-- if not resRule then
	-- 	ngx.log(ngx.ERR,err)
	-- 	ngx.timer.at(10,agent)
	-- 	return
	-- end
	-- local resRuleStr=resRule:read_body()
	-- local wafRule = cjson.decode(resRuleStr)
	-- if not wafRule or wafRule.result=="false" then
	-- 	ngx.timer.at(10,agent)
	-- 	return
	-- end

	success,err,forcible=loadConfig:set("rule",resRuleStr)--wafConfig)
	if err then
		ngx.log(ngx.ERR,err)
		db:close()
		ngx.timer.at(10,agent)
		return
	end
	db:close()
	ngx.timer.at(cycle,agent)
end

-- worker进程
function worker()
	local err
	local loadConfig=ngx.shared.loadConfig
	local wafConfigStr,err=loadConfig:get("config")
	if not wafConfigStr then
		ngx.log(ngx.ERR,err)
		ngx.timer.at(10,worker)
		return
	end
	local wafConfig,err=cjson.decode(wafConfigStr)
	if not wafConfig then
		ngx.log(ngx.ERR,err)
		ngx.timer.at(10,worker)	
	end
	if not config_uuid or wafConfig.uuid ~= config_uuid then
		config=wafConfig
		config_uuid=wafConfig.uuid
	end
	

	local wafRuleStr,err=loadConfig:get("rule")
	if not wafRuleStr then
		ngx.log(ngx.ERR,err)
		ngx.timer.at(10,worker)
		return
	end
	local wafRule,err=cjson.decode(wafRuleStr)
	if not wafRule then
		ngx.log(ngx.ERR,err)
		ngx.timer.at(10,worker)	
	end
	if not rule_uuid or wafRule.uuid ~= rule_uuid then
		_M.rules_table=wafRule.rules
		rule_uuid=wafRule.uuid
	end
	local cycle = 10
	if config.config_reload_cycle ~= tostring(cycle) then
    	local tmp_number = tonumber(config.config_reload_cycle)
    	if tmp_number then
    		cycle = tmp_number
    	end
    end
	ngx.timer.at(cycle,worker)
end

-- 定时任务
function _M.init_worker()
	local process_type = process.type()
	if process_type == "privileged agent" then
		ngx.timer.at(0,agent)
	elseif process_type == 'worker' then
		ngx.timer.at(0,worker)
	end
end

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
					----tools.log_record(config.config_log_dir,"white_ip",ngx.var.request_uri,client_ip,rule)
					ngx.ctx.waf_log={}
					ngx.ctx.waf_log["attack_type"]="white_ip"
					ngx.ctx.waf_log["rule"]=rule
					ngx.ctx.waf_log["data"]=client_ip
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
					----tools.log_record(config.config_log_dir,"black_ip",ngx.var.request_uri,client_ip,rule)
					ngx.ctx.waf_log={}
					ngx.ctx.waf_log["attack_type"]="black_ip"
					ngx.ctx.waf_log["rule"]=rule
					ngx.ctx.waf_log["data"]=client_ip
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
					--tools.log_record(config.config_log_dir,"black_user_agent",ngx.var.request_uri,"-",rule)
					ngx.ctx.waf_log={}
					ngx.ctx.waf_log["attack_type"]="black_user_agent"
					ngx.ctx.waf_log["rule"]=rule
					ngx.ctx.waf_log["data"]="-"
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
					--tools.log_record(config.config_log_dir,"white_uri",req_uri,"-",rule)
					ngx.ctx.waf_log={}
					ngx.ctx.waf_log["attack_type"]="white_uri"
					ngx.ctx.waf_log["rule"]=rule
					ngx.ctx.waf_log["data"]="-"
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
					--tools.log_record(config.config_log_dir,"black_uri",req_uri,"-",rule)
					ngx.ctx.waf_log={}
					ngx.ctx.waf_log["attack_type"]="black_uri"
					ngx.ctx.waf_log["rule"]=rule
					ngx.ctx.waf_log["data"]="-"
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
		local token = client_ip..ngx.var.host..ngx.var.uri
		token = md5.sumhexa(token)
		if limit == nil then
			return
		end
		local cur_count = limit:get(token)
		if cur_count then
			if cur_count < total_count then
				limit:incr(token,1)
			else
				--tools.log_record(config.config_log_dir,"cc_deny",ngx.var.request_uri,cur_count,total_count)
				ngx.ctx.waf_log={}
				ngx.ctx.waf_log["attack_type"]="cc_deny"
				ngx.ctx.waf_log["rule"]=string.format("%s",total_count)
				ngx.ctx.waf_log["data"]=string.format("%s",cur_count)
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
					--tools.log_record(config.config_log_dir,"black_cookie",ngx.var.request_uri,cookie,rule)
					ngx.ctx.waf_log={}
					ngx.ctx.waf_log["attack_type"]="black_cookie"
					ngx.ctx.waf_log["rule"]=rule
					ngx.ctx.waf_log["data"]=cookie
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
						--tools.log_record(config.config_log_dir,"black_get_args",ngx.var.request_uri,data,rule)
						ngx.ctx.waf_log={}
						ngx.ctx.waf_log["attack_type"]="black_get_args"
						ngx.ctx.waf_log["rule"]=rule
						ngx.ctx.waf_log["data"]=data
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
				--tools.log_record(config.config_log_dir,"black_post_args",ngx.var.request_uri,ngx.unescape_uri(data),rule)
				ngx.ctx.waf_log={}
				ngx.ctx.waf_log["attack_type"]="black_post_args"
				ngx.ctx.waf_log["rule"]=rule
				ngx.ctx.waf_log["data"]=ngx.unescape_uri(data)
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
		--tools.log_record(config.config_log_dir,"black_file_ext",ngx.var.request_uri,data,rule)
		ngx.ctx.waf_log={}
		ngx.ctx.waf_log["attack_type"]="black_file_ext"
		ngx.ctx.waf_log["rule"]=rule
		ngx.ctx.waf_log["data"]=data
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
		--tools.log_record(config.config_log_dir,"black_file_content",ngx.var.request_uri,data,rule)
		ngx.ctx.waf_log={}
		ngx.ctx.waf_log["attack_type"]="black_file_content"
		ngx.ctx.waf_log["rule"]=rule
		ngx.ctx.waf_log["data"]=data
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

-- 获取是否自动开启添加黑名单的开关值
function _M.get_config_cc_black_ip()
	return config.config_cc_black_ip
end

return _M