local _M = {
	-- waf拦截
	config_waf_status = "on",
	-- 规则目录
	config_rule_dir = "/opt/openresty/nginx/conf/mywaf/rules",
	-- 日志记录目录
	config_log_dir 	= "/tmp",
	-- ip白名单规则检测
	config_white_ip = "on",
	-- ip黑名单规则检测
	config_black_ip = "on",

}
return _M