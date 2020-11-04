# mywaf
一个简单的waf，完成unixhot的waf中post请求体检查部分

# 安装
```shell
1.安装openresty
2.git clone https://github.com/medasz/mywaf.git
3.cp -r mywaf /path/to/your/openresty/
4.配置nginx配置文件nginx.conf,在http字段中添加以下配置
5.修改config.lua的RulePath(代表规则目录)和logdir(日志目录)
6.给logs和rules目录读写权限
chown -R nobody /path/to/your/openresty/mywaf/logs
chown -R nobody /path/to/your/openresty/mywaf/rules
7.检测nginx配置是否正确
nginx -t
8.启动nginx
nginx
```
# 检查
```shell
检测是否安装成功：
响应头中带有server:mywaf，表示waf配置成功。
```

# 配置文件讲解


# 历史版本说明
1. 第一个版本
对[ngx_lua_waf](https://github.com/loveshell/ngx_lua_waf)进行一些小的修改
2. 第二个版本
上传了ngx_lua_waf的流程模块
3. 第三个版本
修改一些函数实现
4. 第四个版本
修改整体设计，主要是根据[unixhot的waf](https://github.com/unixhot/waf.git)

# TODO
1. 规则存储到数据库
2. waf管理界面
3. 结果展示
4. unixhot的waf中没有

# About
1. 第一，二，三个版本是基于loveshell的ngx_lua_waf修改的
2. 第四个版本是基于unixhot的waf修改的
3. 第五个版本是基于xsec-lab的x-waf和x-waf-admin修改的
