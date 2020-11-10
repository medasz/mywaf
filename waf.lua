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
	rules_table={}
}

-- 加载规则到内存
function _M.load_rules()
	local _M.rules_table = tools.get_rules(config.config_rule_dir)
	if next(_M.rules_table) == nil then
		return
	end
end

-- 规则检查
function _M.check()
	
end

return _M