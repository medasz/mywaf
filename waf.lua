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
					tools.log_record(config.config_log_dir,"white_uri",req_uri,req_uri,rule)
					return true
				end
			end
		end
	end
end

-- 规则检查
function _M.check()
	if _M.white_ip_check() then
	elseif _M.black_ip_check() then
	elseif _M.black_user_agent_check() then
	elseif _M.white_uri_check() then
	else
		ngx.exit(403)
		return
	end
end

return _M