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
	if next(_M.rules_table) == nil then
		return
	end
end

-- 获取规则
function _M.get_rule(filename)
	return _M.[filename]
end
function _M.white_ip_check()
	if config.config_white_ip == "on" then
		local client_ip = tools.get_client_ip()
		local rules_list = _M.get_rule("white_ip.rule")
		if rules_list then
			for _,rule in ipairs(rules_list) do
				if rule ~= "" and ngx.re.match(client_ip,rule,"isjo") then
					return true
				end
			end
		end
	end
end
-- 规则检查
function _M.check()
	if _M.white_ip_check() then
	else
		ngx.exit(403)
		return
	end
end

return _M