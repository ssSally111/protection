# 通过 HOOK OpenProcess实现r3层进程保护
> 环境：Windows11 23H2

### 这里只测试过x64任务管理器

1.将 protection.dll 注入到任务管理器

2.任务管理器结束受保护程序会错误提示：无法完成该操作。未指定的错误
