/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cn.edu.shu.ipv6sniffer.model;

import java.io.IOException;
import java.util.ArrayList;

import org.apache.log4j.Logger;

import cn.edu.shu.ipv6sniffer.control.Ipv6SnifferControl;
import jpcap.JpcapCaptor;
import jpcap.JpcapSender;
import jpcap.NetworkInterface;
import jpcap.PacketReceiver;
import jpcap.packet.IPPacket;
import jpcap.packet.Packet;

/**
 *
 * @author 祥文
 */
public class Ipv6SnifferModel implements PacketReceiver {

	private static Logger logger = Logger.getLogger(Ipv6SnifferModel.class);

	private Ipv6SnifferControl ipv6SnifferControl;
	private NetworkInterface[] devices;// 存储所有网卡
	private NetworkInterface device;// 需要监控的网卡
	private int deviceIndex = 0;// 监控的网卡对应的索引
	private boolean isNonBlockingMode = true;
	private int snaplen = 65535;// 每次捕获的数据包最大长度（设置为IP包最大长度即可）
	private boolean promisc = false;// 是否过滤（Mac地址不是当前网卡的IP数据包）
	private int timeout = 10000;// 设置超时为10秒
	private JpcapCaptor jpcap;
	private JpcapSender sender;
	private ArrayList<Packet> packetList = new ArrayList<Packet>(100);// 存储抓取到的包

	/**
	 * 通过捕捉器捕获数据有两种方式： 1.回调方法
	 * 1.1.实现一个方法处理器接口的类PacketReceiver，并将该类的一个对象，注册到捕获器中。（回调方法的实现, 其实就是监听器模型）
	 * 1.2.将消息处理器（PacketReceiver） 注册到捕获器（JpcapCaptor）有两种方式
	 */
	private PacketReceiver packetReceiver;

	private volatile long bytesTotal = 0;// 总流量
	private volatile int packetTotal = 0;// 总包数
	private volatile int ipv4Total = 0;// 总ipv4数
	private volatile int ipv6Total = 0;// 总ipv6数
	private volatile int tcpTotal = 0;// 总tcp数
	private volatile int udpTotal = 0;// 总udp数

	public Ipv6SnifferModel(Ipv6SnifferControl ipv6SnifferControl) {
		super();
		this.ipv6SnifferControl = ipv6SnifferControl;
		this.packetReceiver = this;
		// TODO Auto-generated constructor stub
	}

	/**
	 * @decription 获取所有的网卡
	 * @return 所有网卡列表
	 */
	public NetworkInterface[] getDevices() {
		devices = JpcapCaptor.getDeviceList(); // 获得设备列表
		return this.devices;
	}

	/**
	 * @decription 打开连接
	 * @return 所用的网卡
	 */
	private NetworkInterface openDevice() throws IOException {

		jpcap = JpcapCaptor.openDevice(this.device, this.snaplen, this.promisc,
				this.timeout); // 打开与设备的连接
		jpcap.setNonBlockingMode(this.isNonBlockingMode);
		// 只监听IP数据包
		//jpcap.setFilter("ip", true); // 只监听B的IP数据包
		sender = jpcap.getJpcapSenderInstance();
		return device;
	}

	/**
	 * @decription 抓包前的准备：关闭上一个jpcap，打开新的网卡连接，清空列表
	 * @return
	 */
	public void beforeCapture() {
		// 关闭原来的captor
		if (this.jpcap != null) {
			this.jpcap.close();
			this.jpcap = null;
		}

		// 打开新的设备
		try {
			this.openDevice();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		// 清空包列表中的包
		this.packetList.clear();
		this.packetList.ensureCapacity(100);
	}

	/**
	 * @decription 开始抓包
	 * @return
	 */
	public boolean startCapture() {
		
		System.out.println("监控的网卡是：" + this.device.description);
		// 声明一个IPPacket类
		// IPPacket ipPacket = null;

		// if (this.timeout == -1) {
		this.jpcap.loopPacket(-1, this.packetReceiver);
		// 通知controller抓包结束
		// this.myCtrl.finishCap();
		// } else {
		// this.jpcap.processPacket(-1, this.packetReceiver);
		// }
		return true;
	}

	/**
	 * @decription 停止抓包
	 * @return
	 */
	public boolean stopCapture() {
		this.jpcap.breakLoop();
		this.jpcap.close();
		return true;
	}

	/**
	 * @decription 通过序号得到包
	 * @param index
	 *            包的序号
	 * @return
	 * @throws Exception
	 */
	public Packet getPacketByIndex(int index) throws Exception {
		if (index >= this.packetList.size() || index < 0)
			throw new Exception("包的序号大于包数目");
		return this.packetList.get(index);
	}

	/**
	 * @decription 统计置0
	 */
	public void resetTotal() {
		bytesTotal = 0;// 总流量
		packetTotal = 0;// 总包数
		ipv4Total = 0;// 总ipv4数
		ipv6Total = 0;// 总ipv6数
		tcpTotal = 0;// 总tcp数
		udpTotal = 0;// 总udp数

	}

	/**
	 * @decription 实现PacketReceiver接口必须实现的函数，用于对接收的包进行处理
	 * @param packet 捕获的包
	 * @return
	 */
	@Override
	public void receivePacket(Packet packet) {
		// TODO Auto-generated method stub
		if (packet == null)// 没有包，返回
			return;
		// 更新统计数据
		this.jpcap.updateStat();
		this.bytesTotal += packet.len;
		this.packetTotal++;

		if (packet instanceof IPPacket) {

			if (((IPPacket) packet).version == 4) {
				this.ipv4Total++;//ipv4包
				//System.out.println("ipv4包");
			}

			if (((IPPacket) packet).version == 6) {
				this.ipv6Total++;//ipv6包
				// 传递给controller
				this.packetList.add(packet);
				//获得新的包，刷新view层表格
				this.ipv6SnifferControl.addNewPacket(this.packetList.size() - 1, packet);
			}

			switch (((IPPacket) packet).protocol) {
			case IPPacket.IPPROTO_TCP:
				this.tcpTotal++;//tcp报文
				break;
			case IPPacket.IPPROTO_UDP:
				this.udpTotal++;//udp报文
				break;

			}
		}

		System.out.println("捕获的报文数据： " + packet);
	}

	public int getDeviceIndex() {
		return deviceIndex;
	}

	public void setDeviceIndex(int deviceIndex) {
		this.device = this.devices[deviceIndex];
		this.deviceIndex = deviceIndex;
	}

	public ArrayList<Packet> getPacketList() {
		return packetList;
	}

	public long getBytesTotal() {
		return bytesTotal;
	}

	public void setBytesTotal(long bytesTotal) {
		this.bytesTotal = bytesTotal;
	}

	public int getPacketTotal() {
		return packetTotal;
	}

	public void setPacketTotal(int packetTotal) {
		this.packetTotal = packetTotal;
	}

	public int getIpv4Total() {
		return ipv4Total;
	}

	public void setIpv4Total(int ipv4Total) {
		this.ipv4Total = ipv4Total;
	}

	public int getIpv6Total() {
		return ipv6Total;
	}

	public void setIpv6Total(int ipv6Total) {
		this.ipv6Total = ipv6Total;
	}

	public int getTcpTotal() {
		return tcpTotal;
	}

	public void setTcpTotal(int tcpTotal) {
		this.tcpTotal = tcpTotal;
	}

	public int getUdpTotal() {
		return udpTotal;
	}

	public void setUdpTotal(int udpTotal) {
		this.udpTotal = udpTotal;
	}
	
}
