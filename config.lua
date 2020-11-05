--waf config file

--waf rules path
config_waf_rules_path	=	"/opt/openresty/mywaf/rules"

--waf logs path
config_waf_logs_path	=	"/opt/openresty/mywaf/logs"

--waf status
config_waf_status		=	"on"

--white ip status
config_white_ip_status	= 	"on"

--black ip status
config_black_ip_status	=	"on"

--user agent status
config_user_agent_status=	"on"

--waf output
config_waf_output		=	"html"

--waf output html
config_waf_output_html	=	[[
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta http-equiv="Content-Language" content="zh-cn" />
<title>OpsAny｜Web应用防火墙</title>
</head>
<body>
<h1 align="center"> 欢迎白帽子进行授权安全测试，安全漏洞请联系QQ：57459267
</body>
</html>
]]

--waf CC deny
config_cc_deny_status	=	"on"

--waf CC rate
config_cc_deny_rate		=	"6/60"