# mywaf
对loveshell/ngx_lua_waf进行一些小修改
# Install
```shell
1.安装openresty
2.git clone https://github.com/medasz/mywaf.git
3.cp -r mywaf /path/to/your/openresty/
4.配置nginx配置文件nginx.conf,在http字段中添加以下配置
<font color=red>asd</fond>
#指定lua库路径
lua_package_path "/path/to/your/openresty/mywaf/?.lua;/path/to/your/openresty/lualib/?.lua;;";
#创建共享缓存区块
lua_shared_dict limit 10m;
#初始化lua脚本执行
init_by_lua_file /path/to/your/openresty/mywaf/init.lua;
#访问lua脚本执行
access_by_lua_file /path/to/your/openresty/mywaf/waf.lua;
#隐藏版本信息
server_tokens off;
#开启lua缓存
lua_code_cache on;
#反向代理需要保护的服务器
在server字段中添加
location / {
	proxy_pass http://x.x.x.x:xx;
}
5.修改config.lua的RulePath(代表规则目录)和logdir(日志目录)
6.检测nginx配置是否正确
nginx -t
7.启动nginx
nginx
```
# Check
```shell
检测是否安装成功：
响应头中带有server:mywaf，表示waf配置成功。
```
