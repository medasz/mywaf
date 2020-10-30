--导入配置文件
require 'config'

--设置局部变量
local whiteIpButton	=	optionIsOn(whiteIpButton)
local remoteIp 		= 	nil
--获取远程IP地址
function getRemoteIp()
	remoteIp=ngx.var.remote_addr
	if not remoteIp then
		remoteIp = "unknow"
	end
end
getRemoteIp()


--判断开关状态
function optionIsOn(option)
	-- body
	return option == "on"
end


--IP白名单检测
function checkWhiteIp()
	if whiteIpButton then
		for _,v in ipairs(whiteIpList) do
			if v==remoteIp then
				return true
			end
		end
	end
	return false
end