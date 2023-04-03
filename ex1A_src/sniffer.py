import threading
import tkinter
from tkinter.constants import *
from tkinter import *
from tkinter import font, filedialog
from tkinter.messagebox import askyesno
from tkinter.scrolledtext import ScrolledText
from tkinter.ttk import Treeview
from scapy.layers.inet import *
from scapy.layers.l2 import *
from scapy.all import *
from nic_check import OPTIONS

stop_sending = threading.Event()
track_id = -1
id = 1#数据包的编号
packet_time_list = []#抓包的时间
packet_list = []#抓取到的数据包
packet_track_list = []#流追踪的数据包
NIC = None
#各种事件的标志，True表示发生过，false表示尚未发生
flag_start = False
flag_save = False
flag_stop = False
flag_track = False
ip1 = NONE
ip2 = NONE
port1 = NONE
port2 = NONE
class StatusBar(Frame):
    def __init__(self, master):
        Frame.__init__(self, master)# 初始化Frame对象。master为Frame的父控件，默认为None
        self.label = Label(self, bd=1, relief=SUNKEN, anchor=W)# 标签控件，bd为背景色，relief表示边框样式，anchor表示文本或图像在背景内容区的位置
        self.label.pack(fill=X)# 标签布局
    def set(self, fmt, *args):
        self.label.config(text=fmt % args)
        self.label.update_idletasks()# 确保窗口实时更新
    def clear(self):
        self.label.config(text="")
        self.label.update_idletasks()


def click_packet_list_treeview(event):#当点击数据包列表中的任意一行时，展开该数据包的详细信息
    # event.widget获取Treeview对象，调用selection获取选择对象名称,返回结果为字符型元组
    selected_item = event.widget.selection()
    # 清空packet_dissect_tree上现有的内容------------------------
    packet_dissect_tree.delete(*packet_dissect_tree.get_children())
    # 设置协议解析区的宽度
    packet_dissect_tree.column('Dissect', width=packet_list_frame.winfo_width())
    # 转换为整型
    packet_id = int(selected_item[0])-1
    print('编号',packet_id+1)
    # 取出要分析的数据包
    packet = packet_list[packet_id]
    lines = (packet.show(dump=True)).split('\n')  # dump=True返回字符串，不打出，\n换行符
    last_tree_entry = None
    #print(lines)
    for line in lines:
        if line.startswith('#'):
            line = line.strip('# ')  # 删除#
            last_tree_entry = packet_dissect_tree.insert('', 'end', text=line)  # 第一个参数为空表示根节点
        else:
            packet_dissect_tree.insert(last_tree_entry, 'end', text=line)
        col_width = font.Font().measure(line)
        packet_dissect_tree.column('Dissect', width=500)



    # 在hexdump区显示此数据包的十六进制内容，不用修改
    hexdump_scrolledtext['state'] = 'normal'
    hexdump_scrolledtext.delete(1.0, END)
    hexdump_scrolledtext.insert(END, hexdump(packet, dump=True))
    hexdump_scrolledtext['state'] = 'disabled'


def packet_capture():#抓取数据包
    global packet_list
    packet_list.clear()#重置数据包列表为空
    stop_sending.clear()#重置停止抓包的条件
    filters = fitler_entry.get()#从窗口中提取过滤条件
    print('过滤条件：'+ filters)
    #sniff函数抓取数据包(filter:过滤条件，prn：每个数据包的回调函数，stop_filter:停止抓包的条件)
    print("当前网卡：",NIC)
    sniff(prn=(lambda x: packet_manage(x)), filter=filters, stop_filter=(lambda x: stop_sending.is_set()),iface=NIC)

def packet_manage(packet):#处理抓取到的数据包
    global packet_list,id
    packet_list.append(packet)#先将数据包存储到列表中
    packet_time = packet.time#记录数据包抓取的时间
    packet_time_list.append(packet_time)
    timeArray = time.localtime(packet_time)
    Time = time.strftime("%Y-%m-%d %H:%M:%S", timeArray)
    length = len(packet)  # 记录数据包长度
    info = packet.summary()  # 记录数据包info信息
    types = {0x0800:'IPv4',0x0806:'ARP',0x86dd:"IPv6",0x880b:"PPP",0x814c:'SNMP'}
    type = packet[Ether].type#记录以太网的类型
    src = packet[Ether].src#记录MAC地址
    dst = packet[Ether].dst
    if type in types:
        proto_ether = types[type]
    else:
        proto_ether = "Other"  #如果该数据包含有上述字典中没有的协议，则设置为other
        protocol = proto_ether
    if proto_ether == 'IPv4':#如果数据包是IPv4类型，就继续判断更细化的协议
        prots = {1:'ICMP',2:'IGMP',4:'IP',6:'TCP',8:'EGP',9:'IGP',17:'UDP',41:'IPv6',50:'ESP',89:'OSPF'}
        #字典记录IPv4报文携带的是哪一种协议
        src=packet[IP].src#将源地址和目的地址更新为IP地址
        dst=packet[IP].dst
        if packet[IP].proto in prots:#分析是ipv4下的哪一种协议
            proto_ip = prots[packet[IP].proto]
        else:
            proto_ip = 'other'
        if proto_ip == 'ICMP':#如果是icmp
            #print("是icmp报文")
            types_icmp = {0: 'echo reply' , 3:'Destination unreachable',5: 'router redirect', 8: 'echo request',
                          11: 'time-to-live exceeded',13: 'timestamp request',14: 'timestamp reply' }
            if packet[ICMP].type in types_icmp:
                type_icmp = types_icmp[packet[ICMP].type]#现在知道了是哪一种icmp报文
                print(type_icmp)
                if type_icmp == 'echo reply':
                    info = 'echo reply    ' + 'id=' + str(packet[ICMP].id) + ',seq=' + str(packet[ICMP].seq) + ', ttl=' + str(packet[IP].ttl)
                elif type_icmp == 'Destination unreachable':
                    info = "Destination unreachable"
                elif type_icmp == 'echo request':
                    info = 'echo request  ' + 'id=' + str(packet[ICMP].id) + ',seq=' + str(packet[ICMP].seq) + ', ttl=' + str(packet[IP].ttl)
                elif type_icmp == 'time-to-live exceeded':
                    info = "time-to-live exceeded"
                else:
                    info = type_icmp
                packet_list_treeview.insert("", 'end', id, text=id,values=(id, Time, src, dst, "ICMP", length, info))
            else:
                packet_list_treeview.insert("", 'end', id, text=id, values=(id, Time, src, dst, proto_ip, length, info))
            #if proto_ip == 'TCP':  # 如果是tcp
        elif proto_ip == 'TCP':
            flag = ''
            print(packet[TCP].dport)
            if 'U' in packet[TCP].flags:
                flag = flag + 'URG'
            if 'A' in packet[TCP].flags:
                if flag != '':
                    flag = flag + ','
                flag = flag + 'ACK'
            if 'P' in packet[TCP].flags:
                if flag != '':
                    flag = flag + ','
                flag = flag + 'PSH'
            if 'R' in packet[TCP].flags:
                if flag != '':
                    flag = flag + ','
                flag = flag + 'RST'
            if 'S' in packet[TCP].flags:
                if flag != '':
                    flag = flag + ','
                flag = flag + 'SYN'
            if 'F' in packet[TCP].flags:
                if flag != '':
                    flag = flag + ','
                flag = flag + 'FIN'
            info = str(packet[TCP].sport) + '  -->  ' + str(packet[TCP].dport)  + ' [' +flag +'] ' + \
                   ' Seq=' + str(packet[TCP].seq) + ' Ack=' + str(packet[TCP].ack) + ' Win=' + str(packet[TCP].window)
            #print(info)
            packet_list_treeview.insert("", 'end', id, text=id, values=(id, Time, src, dst, "TCP", length, info))
        elif proto_ip == 'UDP':
            info = str(packet[UDP].sport) + '  -->  ' + str(packet[UDP].dport) + ' LEN=' + str(packet[UDP].len)
            packet_list_treeview.insert("", 'end', id, text=id, values=(id, Time, src, dst, "UDP", length, info))
        else:
            packet_list_treeview.insert("", 'end', id, text=id, values=(id, Time, src, dst, proto_ip, length, info))
    elif proto_ether == 'ARP':
        if packet[ARP].op == 1:
            dst = "Broadcast"
            info = "Who has " + packet[ARP].pdst + "?\tTell " + packet[ARP].psrc
        elif packet[ARP].op == 2:
            info = packet[ARP].psrc + " is at " + packet[Ether].dst
        packet_list_treeview.insert("", 'end', id, text=id, values=(id, Time, src, dst, "ARP", length, info))
    else:
        packet_list_treeview.insert("", 'end', id, text=id, values=(id, Time, src, dst, proto_ether, length, info))
    #将该数据包提取到的数据插入到数据包列表区
    packet_list_treeview.update_idletasks()
    id = id +1

def save():
    global flag_save
    flag_save = True
    filename = tkinter.filedialog.asksaveasfilename(title='保存捕获文件为',filetype=[('pcap','.pcap'),('pcapng','.pcapng')],initialfile='.pcap')
    if filename.find('.pcap') == -1:
        # 默认文件格式为 pcap
        filename = filename+'.pcap'
    wrpcap(filename, packet_list)

def start():#响应开始按钮
    global flag_stop,flag_save,id,packet_list #停止和保存的标志，true表示已经发生，false表示尚未发生
    if flag_stop == True and flag_save == False:#如果抓包停止了但还没有保存，要提醒用户保存
        save_or_not = tkinter.messagebox.askyesnocancel("Unsaved Packets...","您是否要保存已捕获的分组？若不保存，您已捕获的分组将会丢失")
        if save_or_not == True:#如果选择保存分组
            #提供pcapng格式的文件保存方式
            filename = tkinter.filedialog.asksaveasfilename(title='保存捕获文件为',filetype=[('pcap','.pcap'),('pcapng','.pcapng')],initialfile='.pcap')
            if filename.find('.pcap') == -1:
                # 默认文件格式为 pcap
                filename = filename + '.pcap'
            wrpcap(filename, packet_list)
        else:
            flag_stop = False
            return

    #开始正式运行抓包工作
    start_button['state']=DISABLED#开始、保存按钮不可用，停止按钮可用
    save_button['state']=DISABLED
    stop_button['state']=NORMAL
    flag_stop = False
    items = packet_list_treeview.get_children()
    for item in items:#清空数据包列表
        packet_list_treeview.delete(item)
    packet_list_treeview.clipboard_clear()#清除剪切板
    hexdump_scrolledtext['state'] = 'normal'
    hexdump_scrolledtext.delete(1.0, END)
    hexdump_scrolledtext['state'] = 'disabled'
    packet_list = []
    id = 1#id重置为1

    t = threading.Thread(target=packet_capture)#多线程调用抓包函数
    t.setDaemon(True)#设置为该线程为守护线程
    t.start()
    flag_save = False

def stop():
    global flag_stop
    # 终止线程，停止抓包
    stop_sending.set()
    # 设置开始按钮为可用，暂停按钮为不可用,保存为可用
    start_button['state'] = NORMAL
    save_button['state'] = NORMAL
    stop_button['state'] = DISABLED
    flag_stop = True

def quit():
    #终止线程，停止抓包
    stop_sending.set()
    # 已经暂停，或停止，需要提示保存在退出
    if flag_stop == True :
        # 没进行保存操作
        if flag_save == False:
            save_or_not = tkinter.messagebox.askyesnocancel("Unsaved Packets...","您是否要保存已捕获的分组？若不保存，您已捕获的分组将会丢失")
            if save_or_not is False:
                main_window.destroy()
            elif save_or_not is True:
                filename = tkinter.filedialog.asksaveasfilename(title='保存捕获文件为',filetype=[('pcap','.pcap'),('pcapng','.pcapng')],initialfile='*.pcap')
                if filename.find('.pcap') == -1:
                    # 默认文件格式为 pcap
                    filename = filename + '.pcap'
                wrpcap(filename, packet_list)
                main_window.destroy()
        else:
            main_window.destroy()
    else:
        main_window.destroy()
# ---------------------以下代码负责绘制GUI界面---------------------

def choose_nic(events):
    global NIC
    NIC = variable.get()
    print(NIC)
main_window = tkinter.Tk() # 创建根窗口
main_window.title("sniffer")
# 带水平分割条的主窗体
# PanedWindow是一个窗口布局管理的插件，可以包含一个或者多个子控件
main_panedwindow = PanedWindow(main_window, sashrelief=RAISED, sashwidth=5, orient=VERTICAL)

# 顶部的按钮及过滤条件区
toolbar = Frame(main_window) # 新建一个框架控件；在屏幕上显示一个矩形区域，用来作为容器
# 按钮控件；在程序中显示按钮
start_button = Button(toolbar, width=8, text="开始", command=start)
stop_button = Button(toolbar, width=8, text="停止", command=stop)
save_button = Button(toolbar, width=8, text="保存数据", command=save)
quit_button = Button(toolbar, width=8, text="退出", command=quit)
#下拉菜单：用于选择网卡
nic_text = Label(toolbar,width=8,text="网卡选择：")
variable = StringVar()
variable.set("尚未选择")
nic_choose = OptionMenu(toolbar, variable, *OPTIONS)
# 按钮状态
start_button['state'] = 'normal'
stop_button['state'] = 'disabled'
save_button['state'] = 'disabled'
quit_button['state'] = 'normal'
# 按钮及toolbar容器布局

# pack() 可接受参数
# side：控件停靠位置，可选left，top，right，bottom
# fill：填充方向，可选x，y，both，none
# expand：是否扩展，可选yes，no
# anchor：位置， n（北/上），e（东/右），s（南/下），w（西/左），center（中间）
# padx/pady:外边距
# ipadx/ipady：内边距
start_button.pack(side=LEFT, padx=5)
stop_button.pack(side=LEFT, after=start_button, padx=10, pady=10)
save_button.pack(side=LEFT, after=stop_button, padx=10, pady=10)
quit_button.pack(side=LEFT, after=save_button, padx=10, pady=10)
nic_text.pack(side=LEFT,after=quit_button,padx=10,pady=10)
nic_choose.pack(side=LEFT,after=nic_text, padx=10, pady=10)
toolbar.pack(side=TOP, fill=X)
nic_choose.bind('<Expose>', choose_nic)

toolbar1 = Frame(main_window)# 新建一个用来放置“过滤条件”的框架控件
filter_label = Label(toolbar1, width=10, text="过滤条件：")
fitler_entry = Entry(toolbar1)# 输入框
# 布局
filter_label.pack(side=LEFT, padx=5, pady=5)
fitler_entry.pack(side=LEFT, after=filter_label, padx=5, pady=5, fill=X, expand=YES)
toolbar1.pack(side=TOP, fill=X)
# 数据包列表区
packet_list_frame = Frame()
packet_list_sub_frame = Frame(packet_list_frame)    # 创建第二层框架frame
# 创建一个树状结构和表格的结合体，第一列为树状结构，后几列为列表，每一行表示一个item，即为一个报文数据
packet_list_treeview = Treeview(packet_list_sub_frame, selectmode='browse')   # “selectmode1=browse” 定义只能选一行进行解析
packet_list_treeview.bind('<<TreeviewSelect>>', click_packet_list_treeview)   # 事件绑定，代表 选择变化是发生
# 数据包列表垂直滚动条
# orient为滚动条的方向, command=packet_list_treeview.yview 将滚动条绑定到treeview控件的Y轴
packet_list_vscrollbar = Scrollbar(packet_list_sub_frame, orient="vertical", command=packet_list_treeview.yview)
packet_list_vscrollbar.pack(side=RIGHT, fill=Y, expand=YES, anchor='e')
packet_list_treeview.configure(yscrollcommand=packet_list_vscrollbar.set)    # 给treeview添加垂直滚动条 配置
packet_list_sub_frame.pack(side=TOP, fill=BOTH, expand=YES)
# 数据包列表水平滚动条
packet_list_hscrollbar = Scrollbar(packet_list_frame, orient="horizontal", command=packet_list_treeview.xview)
packet_list_hscrollbar.pack(side=BOTTOM, fill=X, expand=YES, anchor='s')
packet_list_treeview.configure(xscrollcommand=packet_list_hscrollbar.set)  # 给treeview添加水平滚动条配置
# 数据包列表区列标题
packet_list_treeview["columns"] = ("No.", "Time", "Source", "Destination", "Protocol", "Length", "Info")
packet_list_column_width = [100, 180, 160, 160, 100, 100, 542]
packet_list_treeview['show'] = 'headings'
# 设置数据包列表区的列
for column_name, column_width in zip(packet_list_treeview["columns"], packet_list_column_width):
    packet_list_treeview.column(column_name, width=column_width)
    packet_list_treeview.heading(column_name, text=column_name)
# treeview及主框架布局
packet_list_treeview.pack(side=LEFT, fill=BOTH, expand=YES)
packet_list_frame.pack(side=LEFT, fill=BOTH, padx=5, pady=5, expand=YES, anchor='n')
# 将数据包列表区加入到主窗体
main_panedwindow.add(packet_list_frame)

"""
协议解析区
"""
packet_dissect_frame = Frame()
packet_dissect_sub_frame = Frame(packet_dissect_frame)
packet_dissect_tree = Treeview(packet_dissect_sub_frame, selectmode='browse')


packet_dissect_tree["columns"] = ("Dissect",)
#packet_dissect_tree.column('Dissect',width=500)
packet_dissect_tree.heading('#0', text='数据报解析区')
packet_dissect_tree.pack(side=TOP, fill=BOTH, expand=YES)
# 协议解析区垂直滚动条
packet_dissect_vscrollbar = Scrollbar(packet_dissect_sub_frame, orient="vertical", command=packet_dissect_tree.yview)
packet_dissect_vscrollbar.pack(side=RIGHT, fill=Y)      # 滚动条布局
packet_dissect_tree.configure(yscrollcommand=packet_dissect_vscrollbar.set)
packet_dissect_sub_frame.pack(side=TOP, fill=BOTH, expand=YES)
# 协议解析区水平滚动条
packet_dissect_hscrollbar = Scrollbar(packet_dissect_frame, orient="horizontal", command=packet_dissect_tree.xview)
packet_dissect_hscrollbar.pack(side=BOTTOM, fill=X)
packet_dissect_tree.configure(xscrollcommand=packet_dissect_hscrollbar.set)
packet_dissect_frame.pack(side=LEFT, fill=BOTH, padx=5, pady=5, expand=YES)
# 将协议解析区加入到主窗体
main_panedwindow.add(packet_dissect_frame)

# hexdump区
hexdump_scrolledtext = ScrolledText(height=10)   # 新建一个滚动文本框
hexdump_scrolledtext['state'] = 'disabled'
# 将hexdump区区加入到主窗体
main_panedwindow.add(hexdump_scrolledtext)

# 主窗体布局
main_panedwindow.pack(fill=BOTH, expand=1)

# 从Frame类派生出状态栏StatusBar类（继承自Label组件本身，使用set和clear方法去扩展它）
status_bar = StatusBar(main_window)
status_bar.pack(side=BOTTOM, fill=X)
# 调用主循环，显示窗口，同时开始tkinter的事件循环
main_window.mainloop()