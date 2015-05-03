/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cn.edu.shu.ipv6sniffer.control;

import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.Date;

import javax.swing.DefaultComboBoxModel;
import javax.swing.table.DefaultTableModel;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;

import org.apache.log4j.Logger;

import cn.edu.shu.ipv6sniffer.model.Ipv6SnifferModel;
import cn.edu.shu.ipv6sniffer.util.DateUtil;
import jpcap.NetworkInterface;
import jpcap.packet.IPPacket;
import jpcap.packet.Packet;

/**
 * 
 * @author 祥文
 */
public class Ipv6SnifferControl {

	private static Logger logger = Logger.getLogger(Ipv6SnifferControl.class);

	public static int totalPacket = 0;

	private Ipv6SnifferModel ipv6SnifferModel = new Ipv6SnifferModel(this);// model层组件，用于抓包

	private javax.swing.JLabel ipv6Total;// 用于显示ipv6总数
	private javax.swing.JLabel bytesTotal;// 用于显示流量总数
	private javax.swing.JLabel packetTotal;// 用于显示流量总数
	private javax.swing.JTree detailPacketTree;// 树，用于列出详细的包
	private javax.swing.JComboBox<String> networkInterface;// 下拉列表，用于选择网卡
	private javax.swing.JTable packetTable;// 表格，用于显示包的简略信息
	private javax.swing.JButton startButton;// 按钮，用于开始或停止抓包
	private javax.swing.JPanel totalPanel;// 面板，total的父组件

	private boolean startOrStop = false;// 用于控制按钮是开始还是结束
	private Thread captureThread = null;
	private TotalThread totalThread = null;
	private Object[] title = new Object[]{"序号","捕获时间","源地址","目的地址"};

	private DefaultComboBoxModel<String> networkComboBoxModel = new DefaultComboBoxModel<String>();// 用于存储下拉列表的值
	private DefaultTableModel packetTableModel = new DefaultTableModel(title,0);// 用于存储表格的值
	private DefaultTreeModel detailPacketTreeModel;// 用于存储包的详细信息

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
				startButton.setText("停止");
			}

		});
		// 获取选择的网卡索引
		this.ipv6SnifferModel.setDeviceIndex(this.networkInterface
				.getSelectedIndex());

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
				startButton.setText("开始");
				startButton.setEnabled(true);
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
	private DefaultMutableTreeNode parseTunnelIpv6(IPPacket ipp) {
		byte[] ipv6byte = ipp.data;
		if (ipv6byte.length <= 40) {
			return null;
		}

		DefaultMutableTreeNode ipv6Node = new DefaultMutableTreeNode("隧道IPv6报文");

		// version
		int version = ipv6byte[0] >>> 4;
		ipv6Node.add(new DefaultMutableTreeNode("版本（version）：" + version));

		// Traffic Class
		int trafficClass = ipv6byte[0] << 4 + ipv6byte[1] >>> 4;
		ipv6Node.add(new DefaultMutableTreeNode("通信流类别（Traffic Class）："
				+ trafficClass));

		// flow label
		String flowLabel = "0x" + (ipv6byte[1] & 0x0f) + (ipv6byte[2] >>> 4)
				+ (ipv6byte[2] & 0x0f) + (ipv6byte[3] >>> 4)
				+ (ipv6byte[3] & 0x0f);
		ipv6Node.add(new DefaultMutableTreeNode("流标签（Flow Label）：" + flowLabel));

		// Payload
		int payloadLength = ipv6byte[4] << 8 + ipv6byte[5] & 0xff;
		ipv6Node.add(new DefaultMutableTreeNode("有效载荷长度（Payload Length）："
				+ payloadLength));

		// next header
		int nextHeader = ipv6byte[6] & 0xff;
		DefaultMutableTreeNode nextHeaderNode = this
				.getIpv6NextHeader((short) nextHeader);
		// nextHeaderNode.add(this.getIpv6Option(ipv6byte[6]));
		ipv6Node.add(nextHeaderNode);

		// hop limit
		int hopLimit = ipv6byte[7] & 0xff;
		ipv6Node.add(new DefaultMutableTreeNode("跳数限制（Hop Limit）：" + hopLimit));

		// source address
		byte[] sourceAddByte = Arrays.copyOfRange(ipv6byte, 8, 24);
		String sourceAdd;
		try {
			sourceAdd = InetAddress.getByAddress(sourceAddByte).toString();
		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			sourceAdd = "0::0";
		}
		ipv6Node.add(new DefaultMutableTreeNode("源地址（Source Address）："
				+ sourceAdd));

		// target address
		byte[] destAddByte = Arrays.copyOfRange(ipv6byte, 24, 40);
		String destAdd;
		try {
			destAdd = InetAddress.getByAddress(destAddByte).toString();
		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			destAdd = "0::0";
		}
		ipv6Node.add(new DefaultMutableTreeNode("目的地址（Destination Address）："
				+ destAdd));

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
	 * @decription 有新的包，更新表格
	 * @param index
	 * @param packet
	 */
	public void addNewPacket(int index, Packet packet) {
		// 更新表格
		byte[] ipv6byte = packet.data;
		// source address
		byte[] sourceAddByte = Arrays.copyOfRange(ipv6byte, 8, 24);
		String sourceAdd;
		try {
			sourceAdd = InetAddress.getByAddress(sourceAddByte).toString();
		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			sourceAdd = "0::0";
		}

		// target address
		byte[] destAddByte = Arrays.copyOfRange(ipv6byte, 24, 40);
		String destAdd;
		try {
			destAdd = InetAddress.getByAddress(destAddByte).toString();
		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			destAdd = "0::0";
		}
		this.packetTableModel.addRow(new Object[] { index,
				DateUtil.getLongDate(new Date()), sourceAdd.substring(1, sourceAdd.length() -1 ), destAdd.substring(1, destAdd.length() -1) });
	}

	/**
	 * @decription 根据选中的表格行刷新树
	 * @param selectedRow
	 *            被选中的表格行
	 */
	public void getSelectPacketTable(int packetIndex) {
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
			this.updatedetailPacketTree(packet);

	}

	/**
	 * @decription 根据包的信息更新树
	 * @param packet
	 */
	private void updatedetailPacketTree(Packet packet) {
		// TODO Auto-generated method stub

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

}
