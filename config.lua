local _M = {
	-- waf拦截
	config_waf_status    = "on",
	-- 规则目录
	config_rule_dir      = "/opt/openresty/nginx/conf/mywaf/rules",
	-- 日志记录目录
	config_log_dir 	     = "/tmp",
	-- ip白名单规则检测
	config_white_ip      = "on",
	-- ip黑名单规则检测
	config_black_ip      = "on",
	-- user_agent黑名单检测
	config_user_agent    = "on",
  -- uri白名单检测
  config_white_uri     = "on",

	-- waf拦截模式(redirect/html)
	config_waf_mode      = "html",
	-- 跳转网址
	config_redirect_uri  = "http://github.com/medasz",
	-- 拦截界面
	config_output_html   = [[
	<html>
    <head>
    <meta charset="UTF-8">
    <title>MIDUN WAF</title>
    </head>
      <body>
        <div>
      <div class="table">
        <div>
          <div class="cell">
            您的IP为: %s
          </div>
          <div class="cell">
            欢迎在遵守白帽子道德准则的情况下进行安全测试。
          </div>
          <div class="cell">
            联系方式：http://xsec.io
          </div>
        </div>
      </div>
    </div>
      </body>
    </html>
	]],

}
return _M