import threading
import tkinter
from tkinter.constants import *
from tkinter import *
from tkinter import font, filedialog
from tkinter.messagebox import askyesno
from tkinter.scrolledtext import ScrolledText
from tkinter.ttk import Treeview
from nic_check import *

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
# ---------------------以下代码负责绘制GUI界面---------------------
def draw_GUI():
    tk = tkinter.Tk() # 创建根窗口
    # w, h = tk.maxsize()
    # tk.geometry("{}x{}".format(w,h))
    tk.title("嗅探器")
    # 带水平分割条的主窗体
    # PanedWindow是一个窗口布局管理的插件，可以包含一个或者多个子控件
    main_panedwindow = PanedWindow(tk, sashrelief=RAISED, sashwidth=5, orient=VERTICAL)

    # 顶部的按钮及过滤条件区
    toolbar = Frame(tk) # 新建一个框架控件；在屏幕上显示一个矩形区域，用来作为容器
    # 按钮控件；在程序中显示按钮
    start_button = Button(toolbar, width=8, text="开始")
    stop_button = Button(toolbar, width=8, text="停止")
    save_button = Button(toolbar, width=8, text="保存数据")
    quit_button = Button(toolbar, width=8, text="退出")
    nic_text = Label(toolbar,width=8,text="网卡选择：")
    variable = StringVar()
    variable.set(OPTIONS[0])
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

    toolbar1 = Frame(tk)# 新建一个用来放置“过滤条件”的框架控件
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
    #packet_list_treeview.bind('<<TreeviewSelect>>', click_packet_list_treeview)   # 事件绑定，代表 选择变化是发生
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
    packet_dissect_tree.column('Dissect', anchor='w')
    # packet_dissect_tree.heading('#0', text='数据报解析区', anchor='w')
    packet_dissect_tree.pack(side=LEFT, fill=BOTH, expand=YES)
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
    status_bar = StatusBar(tk)
    status_bar.pack(side=BOTTOM, fill=X)
    # 调用主循环，显示窗口，同时开始tkinter的事件循环
    tk.mainloop()