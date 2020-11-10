local _M = {
	-- 规则目录
	config_rule_dir = "/opt/openresty/nginx/conf/mywaf/rules",
	-- 日志记录目录
	config_log_dir 	= "/tmp",
	-- 白名单规则检测
	config_white_ip = "on",
}
return _M