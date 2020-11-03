# mywaf
一个简单的waf

# Install
```shell
1.安装openresty
2.git clone https://github.com/medasz/mywaf.git
3.cp -r mywaf /path/to/your/openresty/
4.配置nginx配置文件nginx.conf,在http字段中添加以下配置
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
6.给logs和rules目录读写权限
chown -R nobody /path/to/your/openresty/mywaf/logs
chown -R nobody /path/to/your/openresty/mywaf/rules
7.检测nginx配置是否正确
nginx -t
8.启动nginx
nginx
```
# Check
```shell
检测是否安装成功：
响应头中带有server:mywaf，表示waf配置成功。
```
# History
1. 第一个版本
对[ngx_lua_waf](https://github.com/loveshell/ngx_lua_waf)进行一些小的修改
2. 第二个版本
上传了ngx_lua_waf的流程模块
3. 第三个版本
修改一些函数实现
4. 第四个版本
修改整体设计

# TODO
1. 规则存储到数据库
2. waf管理界面
3. 结果展示

# About
1. 第一，二，三个版本是基于loveshell的ngx_lua_waf修改的
2. 第四个版本是基于unixhot的waf修改的
3. 第五个版本是基于xsec-lab的x-waf和x-waf-admin修改的
