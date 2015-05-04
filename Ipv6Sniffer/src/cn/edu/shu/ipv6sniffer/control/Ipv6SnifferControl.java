/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cn.edu.shu.ipv6sniffer.control;

import java.util.Arrays;
import java.util.Date;

import javax.swing.DefaultComboBoxModel;
import javax.swing.table.DefaultTableModel;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;

import cn.edu.shu.ipv6sniffer.model.Ipv6SnifferModel;
import cn.edu.shu.ipv6sniffer.util.DateUtil;
import jpcap.NetworkInterface;
import jpcap.packet.ARPPacket;
import jpcap.packet.IPPacket;
import jpcap.packet.Packet;
import jpcap.packet.TCPPacket;
import jpcap.packet.UDPPacket;

/**
 * 
 * @author 祥文
 */
public class Ipv6SnifferControl {

	public static int totalPacket = 0;// 总包数

	private Ipv6SnifferModel ipv6SnifferModel = new Ipv6SnifferModel(this);// model层组件，用于抓包

	private javax.swing.JLabel ipv6Total;// 用于显示ipv6总数
	private javax.swing.JLabel bytesTotal;// 用于显示流量总数
	private javax.swing.JLabel packetTotal;// 用于显示流量总数
	private boolean ipv6Only = true;// 是否解析其他协议
	private javax.swing.JTree detailPacketTree;// 树，用于列出详细的包
	private javax.swing.JComboBox<String> networkInterface;// 下拉列表，用于选择网卡
	private javax.swing.JTable packetTable;// 表格，用于显示包的简略信息
	private javax.swing.JButton startButton;// 按钮，用于开始或停止抓包
	private javax.swing.JPanel totalPanel;// 面板，total的父组件
	private javax.swing.JRadioButton ipv6OnlyButton;// 是否解析其他协议

	private boolean startOrStop = false;// 用于控制按钮是开始还是结束
	private Thread captureThread = null;// 抓包线程
	private TotalThread totalThread = null;// 更新统计线程
	private Object[] title = new Object[] { "序号", "捕获时间", "源地址", "目的地址", "协议类型" };

	private DefaultComboBoxModel<String> networkComboBoxModel = new DefaultComboBoxModel<String>();// 用于存储下拉列表的值
	private volatile DefaultTableModel packetTableModel = new DefaultTableModel(
			title, 0);// 用于存储表格的值
	private DefaultTreeModel detailPacketTreeModel;// 用于存储包的详细信息

	/**
	 * @decription 初始化各种组件
	 */
	public void initAllComponents() {
		// TODO Auto-generated method stub
		// 设置网卡下拉列表
		this.networkInterface.setModel(networkComboBoxModel);
		NetworkInterface[] devices = this.ipv6SnifferModel.getDevices();
		for (NetworkInterface device : devices) {
			this.networkComboBoxModel
					.addElement(new String(device.description));
		}
		this.packetTable.setModel(packetTableModel);
		this.detailPacketTreeModel = new DefaultTreeModel(null);
		this.detailPacketTree.setModel(this.detailPacketTreeModel);
	}

	/**
	 * @decription 调用model的开始或停止来实现抓包
	 * @return 是否启动成功
	 */
	public boolean startOrStopCapture() {
		// 如果已经启动，则停止
		if (!this.startOrStop) {
			// 开始抓包
			this.startCapture();
		} else {
			this.stopCapture();
		}
		return true;
	}

	/**
	 * @decription 多线程实现调用model的开始实现抓包
	 */
	public void startCapture() {
		java.awt.EventQueue.invokeLater(new Runnable() {

			@Override
			public void run() {
				// TODO Auto-generated method stub
				// 清空list和tree的内容
				detailPacketTreeModel.setRoot(null);
				packetTableModel.setNumRows(0);
				networkInterface.setEnabled(false);
				ipv6OnlyButton.setEnabled(false);
				startButton.setText("停止");
			}

		});
		// 获取选择的网卡索引
		this.ipv6SnifferModel.setDeviceIndex(this.networkInterface
				.getSelectedIndex());

		// 是否只分析Ipv6
		this.ipv6Only = !this.ipv6OnlyButton.getModel().isSelected();
		this.ipv6SnifferModel.setIpv6Only(!this.ipv6OnlyButton.getModel()
				.isSelected());

		// 多线程抓包
		this.captureThread = new Thread(new Runnable() {
			@Override
			public void run() {
				// TODO Auto-generated method stub
				ipv6SnifferModel.beforeCapture();
				ipv6SnifferModel.resetTotal();
				ipv6SnifferModel.startCapture();
			}
		});

		this.totalThread = new TotalThread();

		this.captureThread.setDaemon(true);
		this.captureThread.start();
		this.totalThread.start();

		this.startOrStop = true;
	}

	/**
	 * @decription 多线程调用model的stopCapture停止抓包
	 */
	public void stopCapture() {
		this.ipv6SnifferModel.stopCapture();

		// disable 按钮，直到后台抓包线程停止
		this.startButton.setEnabled(false);

		// 不断检测线程状态，直到抓包线程结束
		while (this.captureThread != null && this.captureThread.isAlive()) {
			try {
				Thread.sleep(100);
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}

		java.awt.EventQueue.invokeLater(new Runnable() {
			@Override
			public void run() {
				networkInterface.setEnabled(true);
				ipv6OnlyButton.setEnabled(true);
				startButton.setEnabled(true);
				startButton.setText("开始");
			}
		});

		this.totalThread.stopUpdate();
		this.startOrStop = false;
	}

	/**
	 * @decription 由于jpcap未提供隧道ipv6的封装，故专门写一函数，针对ipv4中作为负荷的ipv6内容的字节流进行解析
	 * @param ipp
	 * @return 树中一个结点
	 */
	private DefaultMutableTreeNode parseTunnelIpv6(IPPacket ip) {
		byte[] ipv6byte = ip.data;
		if (ipv6byte.length <= 40) {
			return null;
		}

		DefaultMutableTreeNode ipv6Node = new DefaultMutableTreeNode("隧道IPv6报文");

		// 版本号
		int version = ipv6byte[0] >>> 4;
		ipv6Node.add(new DefaultMutableTreeNode("版本（version）：" + version));

		// 通信流类别
		int trafficClass = ipv6byte[0] << 4 + ipv6byte[1] >>> 4;
		ipv6Node.add(new DefaultMutableTreeNode("通信流类别（Traffic Class）："
				+ trafficClass));

		// 流标签
		String flowLabel = "0x" + (ipv6byte[1] & 0x0f) + (ipv6byte[2] >>> 4)
				+ (ipv6byte[2] & 0x0f) + (ipv6byte[3] >>> 4)
				+ (ipv6byte[3] & 0x0f);
		ipv6Node.add(new DefaultMutableTreeNode("流标签（Flow Label）：" + flowLabel));

		// 有效载荷长度
		int payloadLength = ipv6byte[4] << 8 + ipv6byte[5] & 0xff;
		ipv6Node.add(new DefaultMutableTreeNode("有效载荷长度（Payload Length）："
				+ payloadLength));

		// 下一头部
		int nextHeader = ipv6byte[6] & 0xff;
		DefaultMutableTreeNode nextHeaderNode = this
				.getIpv6NextHeader((short) nextHeader);
		// nextHeaderNode.add(this.getIpv6Option(ipv6byte[6]));
		ipv6Node.add(nextHeaderNode);

		// 跳数限制
		int hopLimit = ipv6byte[7] & 0xff;
		ipv6Node.add(new DefaultMutableTreeNode("跳数限制（Hop Limit）：" + hopLimit));

		String sourceAddr = ip.src_ip.toString();
		String destAddr = ip.dst_ip.toString();
		ipv6Node.add(new DefaultMutableTreeNode("源地址（Source Address）："
				+ sourceAddr));

		ipv6Node.add(new DefaultMutableTreeNode("目的地址（Destination Address）："
				+ destAddr));

		return ipv6Node;
	}

	/**
	 * @decription 得到ipv6下一头部
	 * @param nextheader
	 *            下一ipv6头部
	 * @return 树中结点
	 */
	private DefaultMutableTreeNode getIpv6NextHeader(short nextheader) {
		DefaultMutableTreeNode nextHeaderNode;
		switch (nextheader) {
		case IPPacket.IPPROTO_TCP:
			nextHeaderNode = new DefaultMutableTreeNode("下一报头（next header）：TCP"
					+ "(" + nextheader + ")");
			break;
		case IPPacket.IPPROTO_UDP:
			nextHeaderNode = new DefaultMutableTreeNode("下一报头（next header）：UDP"
					+ "(" + nextheader + ")");
			break;
		case IPPacket.IPPROTO_HOPOPT:
			nextHeaderNode = new DefaultMutableTreeNode(
					"下一报头（next header）：IPv6 hop-by-hop" + "(" + nextheader
							+ ")");
			break;
		case IPPacket.IPPROTO_IPv6_Frag:
			nextHeaderNode = new DefaultMutableTreeNode(
					"下一报头（next header）：fragment header for IPv6" + "("
							+ nextheader + ")");
			break;
		case IPPacket.IPPROTO_IPv6_ICMP:
			nextHeaderNode = new DefaultMutableTreeNode(
					"下一报头（next header）：IPv6 ICMP" + "(" + nextheader + ")");
			break;
		case IPPacket.IPPROTO_IPv6_NoNxt:
			nextHeaderNode = new DefaultMutableTreeNode(
					"下一报头（next header）：no next header header for IPv6" + "("
							+ nextheader + ")");
			break;
		case IPPacket.IPPROTO_IPv6_Opts:
			nextHeaderNode = new DefaultMutableTreeNode(
					"下一报头（next header）：destination option for IPv6" + "("
							+ nextheader + ")");
			break;
		case IPPacket.IPPROTO_IPv6_Route:
			nextHeaderNode = new DefaultMutableTreeNode(
					"下一报头（next header）：routing header for IPv6" + "("
							+ nextheader + ")");
			break;
		default:
			nextHeaderNode = new DefaultMutableTreeNode(
					"下一报头（next header）：未知IPV6报头" + "(" + nextheader + ")");
		}

		return nextHeaderNode;
	}

	/**
	 * @decription 有新的ipv6包，更新表格
	 * @param index
	 * @param packet
	 */
	public void ipv6Packet(int index, Packet packet) {
		IPPacket ip = (IPPacket) packet;
		String sourceAddr = ip.src_ip.toString();
		String destAddr = ip.dst_ip.toString();
		System.out.println("ipv6数据 : " + ip.toString());
		this.packetTableModel.addRow(new Object[] { index,
				DateUtil.getLongDate(new Date()),
				sourceAddr.substring(1, sourceAddr.length()),
				destAddr.substring(1, destAddr.length()), "IPV6" });
	}

	/**
	 * @decription 有新的ipv4包，更新表格
	 * @param index
	 * @param packet
	 */
	public void ipv4Packet(int index, Packet packet) {
		IPPacket ip = (IPPacket) packet;
		System.out.println("ipv4数据 : " + ip.toString());
		this.packetTableModel.addRow(new Object[] { index,
				DateUtil.getLongDate(new Date()), ip.src_ip.getHostAddress(),
				ip.dst_ip.getHostAddress(), "IPV4" });
	}

	/**
	 * @decription 有新的arp包，更新表格
	 * @param index
	 * @param packet
	 */
	public void arpPacket(int index, Packet packet) {
		ARPPacket arp = (ARPPacket) packet;
		System.out.println("arp数据 : " + arp.toString());
		this.packetTableModel.addRow(new Object[] { index,
				DateUtil.getLongDate(new Date()),
				arp.getSenderHardwareAddress(), arp.getTargetHardwareAddress(),
				"ARP" });
	}

	/**
	 * @decription 有新的arp包，更新表格
	 * @param index
	 * @param packet
	 */
	public void unknowPacket(int index, Packet packet) {
		System.out.println("未知数据 : " + packet.toString());
		this.packetTableModel.addRow(new Object[] { index,
				DateUtil.getLongDate(new Date()), "unknow", "unknow", "未知" });
	}

	/**
	 * @decription 有新的包，更新表格
	 * @param index
	 * @param packet
	 */
	public synchronized void addNewPacket(int index, Packet packet) {
		synchronized (packetTableModel) {
			if (packet instanceof IPPacket) {
				if (((IPPacket) packet).version == 4) {
					if (!this.ipv6Only) {
						ipv4Packet(index, packet);// ipv4
					}
				}
				if (((IPPacket) packet).version == 6) {
					ipv6Packet(index, packet);// ipv6
				}
			} else if (packet instanceof ARPPacket) {
				if (!this.ipv6Only) {
					arpPacket(index, packet);// arp
				}
			} else {
				unknowPacket(index, packet);// 未知类型
			}
		}
	}

	/**
	 * @decription tcp刷新树
	 * @param packet
	 *            显示的包
	 */
	private void tcpUpdate(Packet packet, DefaultMutableTreeNode node) {
		if (packet instanceof TCPPacket) {
			TCPPacket tcp = (TCPPacket) packet;
			DefaultMutableTreeNode destNode = new DefaultMutableTreeNode(
					"目的端口：" + tcp.dst_port);
			DefaultMutableTreeNode srcNode = new DefaultMutableTreeNode("源端口："
					+ tcp.src_port);
			DefaultMutableTreeNode sequenceNode = new DefaultMutableTreeNode(
					"序号：" + tcp.sequence);
			DefaultMutableTreeNode ack_numNode = new DefaultMutableTreeNode(
					"确认号：" + tcp.ack_num);
			DefaultMutableTreeNode urgNode = new DefaultMutableTreeNode("URG位："
					+ tcp.urg);
			DefaultMutableTreeNode ackNode = new DefaultMutableTreeNode("ACK位："
					+ tcp.ack);
			DefaultMutableTreeNode pshNode = new DefaultMutableTreeNode("PSH位："
					+ tcp.psh);
			DefaultMutableTreeNode rstNode = new DefaultMutableTreeNode("RST位："
					+ tcp.rst);
			DefaultMutableTreeNode synNode = new DefaultMutableTreeNode("SYN位："
					+ tcp.syn);
			DefaultMutableTreeNode finNode = new DefaultMutableTreeNode("FIN位："
					+ tcp.fin);
			DefaultMutableTreeNode windowsNode = new DefaultMutableTreeNode(
					"窗口：" + tcp.window);
			DefaultMutableTreeNode urgent_pointerNode = new DefaultMutableTreeNode(
					"紧急指针：" + tcp.urgent_pointer);
			DefaultMutableTreeNode optionNode = new DefaultMutableTreeNode(
					"可选项：" + tcp.option);
			node.add(destNode);
			node.add(srcNode);
			node.add(sequenceNode);
			node.add(ack_numNode);
			node.add(urgNode);
			node.add(ackNode);
			node.add(pshNode);
			node.add(rstNode);
			node.add(synNode);
			node.add(finNode);
			node.add(windowsNode);
			node.add(urgent_pointerNode);
			node.add(optionNode);
		}
	}

	/**
	 * @decription udp刷新树
	 * @param packet
	 *            显示的包
	 */
	private void udpUpdate(Packet packet, DefaultMutableTreeNode node) {
		if (packet instanceof UDPPacket) {
			UDPPacket udp = (UDPPacket) packet;
			DefaultMutableTreeNode destNode = new DefaultMutableTreeNode(
					"目的端口:" + udp.dst_port);
			DefaultMutableTreeNode lengthNode = new DefaultMutableTreeNode(
					"报文长度:" + udp.length);
			DefaultMutableTreeNode srcNode = new DefaultMutableTreeNode("源端口:"
					+ udp.src_port);
			node.add(destNode);
			node.add(lengthNode);
			node.add(srcNode);
		}
	}

	/**
	 * @decription ipv6刷新树
	 * @param packet
	 *            显示的包
	 */
	private void ipv6Update(Packet packet) {
		// TODO Auto-generated method stub
		IPPacket ip = (IPPacket) packet;
		// 根节点
		DefaultMutableTreeNode root = new DefaultMutableTreeNode("IPV6包：");
		this.detailPacketTreeModel.setRoot(root);
		// 头部数据
		DefaultMutableTreeNode header = new DefaultMutableTreeNode("头部数据："
				+ Arrays.toString(ip.header));
		this.detailPacketTreeModel.insertNodeInto(header, root, 0);
		// IP报文
		DefaultMutableTreeNode ipNode = new DefaultMutableTreeNode("IP报文");
		// IP版本号
		DefaultMutableTreeNode versionNode = new DefaultMutableTreeNode(
				"版本（version）：" + ip.version);
		// 通信类别
		DefaultMutableTreeNode trafficClassNode = new DefaultMutableTreeNode(
				"通信流类别（traffic class）：" + ip.priority);
		// 流标签
		DefaultMutableTreeNode flowLabelNode = new DefaultMutableTreeNode(
				"流标签（flow label）：" + ip.flow_label);
		// 负荷长度
		DefaultMutableTreeNode payloadLengthNode = new DefaultMutableTreeNode(
				"负荷长度（payload length）：" + ip.length);

		// 下一头部
		DefaultMutableTreeNode nextHeaderNode = this
				.getIpv6NextHeader(ip.protocol);
		// 跳数
		DefaultMutableTreeNode hoplimitNode = new DefaultMutableTreeNode(
				"跳数（hop limit）：" + ip.hop_limit);

		ipNode.add(versionNode);
		ipNode.add(trafficClassNode);
		ipNode.add(flowLabelNode);
		ipNode.add(payloadLengthNode);
		ipNode.add(nextHeaderNode);
		ipNode.add(hoplimitNode);

		// ip地址
		DefaultMutableTreeNode srcNode = new DefaultMutableTreeNode("源IP地址："
				+ ip.src_ip.getHostAddress());
		DefaultMutableTreeNode dstNode = new DefaultMutableTreeNode("目的IP地址："
				+ ip.dst_ip.getHostAddress());

		// 加入ip结点
		ipNode.add(srcNode);
		ipNode.add(dstNode);

		// 加入根节点
		this.detailPacketTreeModel.insertNodeInto(ipNode, root, 1);
	}

	/**
	 * @decription ipv4刷新树
	 * @param packet
	 *            显示的包
	 */
	private void ipv4Update(Packet packet) {
		// TODO Auto-generated method stub
		IPPacket ip = (IPPacket) packet;
		// 根节点
		DefaultMutableTreeNode root = new DefaultMutableTreeNode("IPV4包：");
		this.detailPacketTreeModel.setRoot(root);
		// 头部数据
		DefaultMutableTreeNode header = new DefaultMutableTreeNode("头部数据："
				+ Arrays.toString(ip.header));
		this.detailPacketTreeModel.insertNodeInto(header, root, 0);
		// IP报文
		DefaultMutableTreeNode ipNode = new DefaultMutableTreeNode("IP报文");
		// IP版本号
		DefaultMutableTreeNode versionNode = new DefaultMutableTreeNode(
				"版本（version）：" + ip.version);
		// 服务类型
		DefaultMutableTreeNode tosNode = new DefaultMutableTreeNode(
				"服务类型（TOS）：" + ip.rsv_tos);
		// 总长度
		DefaultMutableTreeNode lengthNode = new DefaultMutableTreeNode(
				"总长度（total length）：" + ip.length);
		// 标识
		DefaultMutableTreeNode identNode = new DefaultMutableTreeNode(
				"标识（Identification）：" + ip.ident);
		// flags
		String flags = "0";
		String temp = "";
		if (ip.dont_frag) {
			flags = flags + "0";
			temp = temp + "不分段；";
		} else {
			flags = flags + "1";
			temp = temp + "分段；";
		}
		if (ip.more_frag) {
			flags = flags + "0";
			temp = temp + "后续分段";
		} else {
			flags = flags + "1";
			temp = temp + "无后续分段";
		}
		flags = flags + " " + temp;
		// 标识位
		DefaultMutableTreeNode flagsNode = new DefaultMutableTreeNode(
				"标记位（flags）：" + flags);

		// 片偏移
		DefaultMutableTreeNode offsetNode = new DefaultMutableTreeNode(
				"片段偏移量（fragment offset）:" + ip.offset);
		// 生存时间
		DefaultMutableTreeNode hoplimitNode = new DefaultMutableTreeNode(
				"生存时间(TTL)：" + ip.hop_limit);

		// 上层协议
		DefaultMutableTreeNode protocolNode;
		switch (ip.protocol) {

		case IPPacket.IPPROTO_ICMP:
			protocolNode = new DefaultMutableTreeNode("协议类型（Protocol）：ICMP"
					+ "(" + ip.protocol + ")");
			break;
		case IPPacket.IPPROTO_IGMP:
			protocolNode = new DefaultMutableTreeNode("协议类型（Protocol）：IGMP"
					+ "(" + ip.protocol + ")");
			break;
		case IPPacket.IPPROTO_IP:
			protocolNode = new DefaultMutableTreeNode(
					"协议类型（Protocol）：IP OVER IP" + "(" + ip.protocol + ")");
			break;
		case IPPacket.IPPROTO_IPv6:
			protocolNode = new DefaultMutableTreeNode("协议类型（Protocol）：IPv6"
					+ "(" + ip.protocol + ")");
			break;

		case IPPacket.IPPROTO_TCP:
			protocolNode = new DefaultMutableTreeNode("传输层协议类型（Protocol）：TCP"
					+ "(" + ip.protocol + ")");
			tcpUpdate(packet, protocolNode);
			break;
		case IPPacket.IPPROTO_UDP:
			protocolNode = new DefaultMutableTreeNode("传输层协议类型（Protocol）：UDP"
					+ "(" + ip.protocol + ")");
			udpUpdate(packet, protocolNode);
			break;
		default:
			protocolNode = new DefaultMutableTreeNode("传输层协议类型（Protocol）：未知"
					+ "(" + ip.protocol + ")");
			break;
		}

		// 可选项
		DefaultMutableTreeNode optionNode = null;
		if (ip.option == null) {
			optionNode = new DefaultMutableTreeNode("选项(Option)：无");
		} else {
			optionNode = new DefaultMutableTreeNode("选项(Option)Option："
					+ Arrays.toString(ip.option));
		}

		// 加入ip结点
		ipNode.add(versionNode);
		ipNode.add(tosNode);
		ipNode.add(lengthNode);
		ipNode.add(identNode);
		ipNode.add(flagsNode);
		ipNode.add(offsetNode);
		ipNode.add(hoplimitNode);
		ipNode.add(protocolNode);
		ipNode.add(optionNode);

		// 如果是隧道ipv6，则需专门处理
		if (ip.protocol == IPPacket.IPPROTO_IPv6) {
			ipNode.add(this.parseTunnelIpv6(ip));
		}

		// ip地址
		DefaultMutableTreeNode srcNode = new DefaultMutableTreeNode("源IP地址："
				+ ip.src_ip.getHostAddress());
		DefaultMutableTreeNode dstNode = new DefaultMutableTreeNode("目的IP地址："
				+ ip.dst_ip.getHostAddress());

		// 加入ip结点
		ipNode.add(srcNode);
		ipNode.add(dstNode);

		// 加入根节点
		this.detailPacketTreeModel.insertNodeInto(ipNode, root, 1);
	}

	/**
	 * @decription arp刷新树
	 * @param packet
	 *            显示的包
	 */
	private void arpUpdate(Packet packet) {
		// TODO Auto-generated method stub
		ARPPacket arp = (ARPPacket) packet;
		// 根节点
		DefaultMutableTreeNode root = new DefaultMutableTreeNode("ARP数据包：");
		this.detailPacketTreeModel.setRoot(root);
		// 头部数据
		DefaultMutableTreeNode header = new DefaultMutableTreeNode("ARP头部数据："
				+ Arrays.toString(packet.header));
		this.detailPacketTreeModel.insertNodeInto(header, root, 0);
		DefaultMutableTreeNode arpNode = new DefaultMutableTreeNode("ARP报文");

		// 各种地址
		DefaultMutableTreeNode senderMacAddrNode = new DefaultMutableTreeNode(
				"发送方MAC地址：" + arp.getSenderHardwareAddress());
		String srcAddr = String.valueOf(arp.getSenderProtocolAddress());
		srcAddr = srcAddr.substring(1, srcAddr.length());
		DefaultMutableTreeNode senderProAddrNode = new DefaultMutableTreeNode(
				"发送方网络地址：" + srcAddr);

		DefaultMutableTreeNode targetMacAddrNode = new DefaultMutableTreeNode(
				"目的MAC地址：" + arp.getTargetHardwareAddress());
		String destAddr = String.valueOf(arp.getTargetProtocolAddress());
		destAddr = destAddr.substring(1, destAddr.length());
		DefaultMutableTreeNode targetProAddrNode = new DefaultMutableTreeNode(
				"目的网络地址：" + destAddr);

		DefaultMutableTreeNode prototype = new DefaultMutableTreeNode(
				"网络层协议类型："
						+ (arp.prototype == ARPPacket.PROTOTYPE_IP ? "IP"
								: "未知"));

		// ARP类型
		DefaultMutableTreeNode operation;
		if (arp.operation == ARPPacket.ARP_REQUEST)
			operation = new DefaultMutableTreeNode("ARP类型：ARP请求");
		else if (arp.operation == ARPPacket.ARP_REPLY)
			operation = new DefaultMutableTreeNode("ARP类型：ARP应答");
		else
			operation = new DefaultMutableTreeNode("ARP类型：未知");

		// 数据链路帧类型
		DefaultMutableTreeNode hardtype;
		if (arp.hardtype == ARPPacket.HARDTYPE_ETHER)
			hardtype = new DefaultMutableTreeNode("数据链路层类型：以太网");
		else if (arp.hardtype == ARPPacket.HARDTYPE_FRAMERELAY)
			hardtype = new DefaultMutableTreeNode("数据链路层类型：帧中继");
		else if (arp.hardtype == ARPPacket.HARDTYPE_IEEE802)
			hardtype = new DefaultMutableTreeNode("数据链路层类型：IEEE802");
		else
			hardtype = new DefaultMutableTreeNode("数据链路层类型：未知");

		// 加入ARP结点
		arpNode.add(senderMacAddrNode);
		arpNode.add(senderProAddrNode);
		arpNode.add(targetMacAddrNode);
		arpNode.add(targetProAddrNode);
		arpNode.add(prototype);
		arpNode.add(operation);
		arpNode.add(hardtype);
		// 加入根节点
		this.detailPacketTreeModel.insertNodeInto(arpNode, root, 1);
	}

	/**
	 * @decription 根据选中的表格行刷新树
	 * @param selectedRow
	 *            被选中的表格行
	 */
	public void updateDetailPacketTree(int packetIndex) {
		// TODO Auto-generated method stub
		Packet packet = null;
		try {
			packet = this.ipv6SnifferModel.getPacketByIndex(packetIndex);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			System.out.println("包的序号不存在");
			e.printStackTrace();
		}
		if (packet != null)
			// 根据不同协议选择刷新树类型
			if (packet instanceof IPPacket) {
				if (((IPPacket) packet).version == 4) {
					if (!this.ipv6Only) {
						ipv4Update(packet);// ipv4
					}
				}
				if (((IPPacket) packet).version == 6) {
					ipv6Update(packet);// ipv6
				}
			} else if (packet instanceof ARPPacket) {
				if (!this.ipv6Only) {
					arpUpdate(packet);// arp
				}
			}
	}

	/**
	 * @decription 内部线程类，用来更新total信息
	 * @author 祥文
	 *
	 */
	class TotalThread extends Thread {

		private boolean update = true;

		@Override
		public void run() {
			// TODO Auto-generated method stub
			while (update) {
				packetTotal.setText("" + ipv6SnifferModel.getPacketTotal());// 用于显示总包数
				ipv6Total.setText("" + ipv6SnifferModel.getIpv6Total());// 用于显示ipv6总数
				bytesTotal.setText("" + ipv6SnifferModel.getBytesTotal());// 用于显示总流量
			}
		}

		public void stopUpdate() {
			this.update = false;
		}
	}

	public javax.swing.JLabel getIpv6Total() {
		return ipv6Total;
	}

	public void setIpv6Total(javax.swing.JLabel ipv6Total) {
		this.ipv6Total = ipv6Total;
	}

	public javax.swing.JLabel getBytesTotal() {
		return bytesTotal;
	}

	public void setBytesTotal(javax.swing.JLabel bytesTotal) {
		this.bytesTotal = bytesTotal;
	}

	public javax.swing.JLabel getPacketTotal() {
		return packetTotal;
	}

	public void setPacketTotal(javax.swing.JLabel packetTotal) {
		this.packetTotal = packetTotal;
	}

	public boolean isIpv6Only() {
		return ipv6Only;
	}

	public void setIpv6Only(boolean ipv6Only) {
		this.ipv6Only = ipv6Only;
	}

	public javax.swing.JTree getDetailPacketTree() {
		return detailPacketTree;
	}

	public void setDetailPacketTree(javax.swing.JTree detailPacketTree) {
		this.detailPacketTree = detailPacketTree;
	}

	public javax.swing.JComboBox<String> getNetworkInterface() {
		return networkInterface;
	}

	public void setNetworkInterface(
			javax.swing.JComboBox<String> networkInterface) {
		this.networkInterface = networkInterface;
		this.networkInterface.setModel(networkComboBoxModel);
	}

	public javax.swing.JTable getPacketTable() {
		return packetTable;
	}

	public void setPacketTable(javax.swing.JTable packetTable) {
		this.packetTable = packetTable;
	}

	public javax.swing.JButton getStartButton() {
		return startButton;
	}

	public void setStartButton(javax.swing.JButton startButton) {
		this.startButton = startButton;
	}

	public javax.swing.JPanel getTotalPanel() {
		return totalPanel;
	}

	public void setTotalPanel(javax.swing.JPanel totalPanel) {
		this.totalPanel = totalPanel;
	}

	public javax.swing.JRadioButton getIpv6OnlyButton() {
		return ipv6OnlyButton;
	}

	public void setIpv6OnlyButton(javax.swing.JRadioButton ipv6OnlyButton) {
		this.ipv6OnlyButton = ipv6OnlyButton;
	}

}
