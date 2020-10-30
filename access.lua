--获取远程IP地址
local remoteIp = ngx.var.remote_addr
--修改响应头
ngx.header['Server']=wafName
--IP白名单检测
if checkWhiteIp() then

else
	return
end