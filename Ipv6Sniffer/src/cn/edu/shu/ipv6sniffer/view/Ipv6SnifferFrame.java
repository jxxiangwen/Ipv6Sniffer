/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cn.edu.shu.ipv6sniffer.view;

import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;

import cn.edu.shu.ipv6sniffer.control.Ipv6SnifferControl;

/**
 *
 * @author 祥文
 */
public class Ipv6SnifferFrame extends javax.swing.JFrame {

	/**
	 * 
	 */
	private static final long serialVersionUID = -7160835837632290482L;
	private Ipv6SnifferControl ipv6SnifferControl = new Ipv6SnifferControl();

	/**
	 * Creates new form Ipv6SnifferFrame
	 */
	public Ipv6SnifferFrame() {
		initComponents();
		ipv6SnifferControl.setBytesTotal(bytesTotal);
		ipv6SnifferControl.setIpv6Total(ipv6Total);
		ipv6SnifferControl.setPacketTotal(packetTotal);
		ipv6SnifferControl.setIpv6OnlyButton(ipv6OnlyButton);
		ipv6SnifferControl.setDetailPacketTree(detailPacketTree);
		ipv6SnifferControl.setNetworkInterface(networkInterface);
		ipv6SnifferControl.setPacketTable(packetTable);
		ipv6SnifferControl.setStartButton(startButton);
		ipv6SnifferControl.setTotalPanel(totalPanel);
		ipv6SnifferControl.setPacketTable(packetTable);

		ipv6SnifferControl.initAllComponents();
	}

	/**
	 * This method is called from within the constructor to initialize the form.
	 * WARNING: Do NOT modify this code. The content of this method is always
	 * regenerated by the Form Editor.
	 */
	// <editor-fold defaultstate="collapsed"
	// desc="Generated Code">//GEN-BEGIN:initComponents
	private void initComponents() {

		jPanel1 = new javax.swing.JPanel();
		jLabel1 = new javax.swing.JLabel();
		networkInterface = new javax.swing.JComboBox<String>();
		jScrollPane1 = new javax.swing.JScrollPane();
		packetTable = new javax.swing.JTable();
		startButton = new javax.swing.JButton();
		jScrollPane2 = new javax.swing.JScrollPane();
		detailPacketTree = new javax.swing.JTree();
		totalPanel = new javax.swing.JPanel();
		jLabel2 = new javax.swing.JLabel();
		ipv6Total = new javax.swing.JLabel();
		jLabel4 = new javax.swing.JLabel();
		jLabel3 = new javax.swing.JLabel();
		bytesTotal = new javax.swing.JLabel();
		jLabel5 = new javax.swing.JLabel();
		jLabel6 = new javax.swing.JLabel();
		packetTotal = new javax.swing.JLabel();
		jLabel7 = new javax.swing.JLabel();
		ipv6OnlyButton = new javax.swing.JRadioButton();

		setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);

		jLabel1.setFont(new java.awt.Font("宋体", 0, 18)); // NOI18N
		jLabel1.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
		jLabel1.setText("请选择需要监控的网卡");

		networkInterface.setFont(new java.awt.Font("宋体", 0, 18)); // NOI18N
		networkInterface
				.setModel(new javax.swing.DefaultComboBoxModel<String>());
		networkInterface.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				networkInterfaceActionPerformed(evt);
			}
		});

		packetTable.setModel(new javax.swing.table.DefaultTableModel() {
			/**
			 * 
			 */
			private static final long serialVersionUID = 616040251973729541L;
			boolean[] canEdit = new boolean[] { false, false, false, false };

			public boolean isCellEditable(int rowIndex, int columnIndex) {
				return canEdit[columnIndex];
			}
		});
		packetTable.getSelectionModel().addListSelectionListener(
				new ListSelectionListener() {
					@Override
					public void valueChanged(ListSelectionEvent e) {
						// TODO Auto-generated method stub
						tableSelectActionPerformed(e);
					}
				});
		jScrollPane1.setViewportView(packetTable);

		startButton.setFont(new java.awt.Font("宋体", 0, 18)); // NOI18N
		startButton.setText("开始");
		startButton.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				startButtonActionPerformed(evt);
			}
		});

		jScrollPane2.setViewportView(detailPacketTree);

		jLabel2.setFont(new java.awt.Font("宋体", 0, 18)); // NOI18N
		jLabel2.setText("其中IPV6：");

		ipv6Total.setFont(new java.awt.Font("宋体", 0, 18)); // NOI18N
		ipv6Total.setText("0");

		jLabel4.setFont(new java.awt.Font("宋体", 0, 18)); // NOI18N
		jLabel4.setText("个");

		jLabel3.setFont(new java.awt.Font("宋体", 0, 18)); // NOI18N
		jLabel3.setText("总流量：");

		bytesTotal.setFont(new java.awt.Font("宋体", 0, 18)); // NOI18N
		bytesTotal.setText("0");

		jLabel5.setFont(new java.awt.Font("宋体", 0, 18)); // NOI18N
		jLabel5.setText("字节");

		jLabel6.setFont(new java.awt.Font("宋体", 0, 18)); // NOI18N
		jLabel6.setText("共捕获包：");

		packetTotal.setFont(new java.awt.Font("宋体", 0, 18)); // NOI18N
		packetTotal.setText("0");

		jLabel7.setFont(new java.awt.Font("宋体", 0, 18)); // NOI18N
		jLabel7.setText("个");

		javax.swing.GroupLayout totalPanelLayout = new javax.swing.GroupLayout(
				totalPanel);
		totalPanel.setLayout(totalPanelLayout);
		totalPanelLayout
				.setHorizontalGroup(totalPanelLayout
						.createParallelGroup(
								javax.swing.GroupLayout.Alignment.LEADING)
						.addGroup(
								javax.swing.GroupLayout.Alignment.TRAILING,
								totalPanelLayout
										.createSequentialGroup()
										.addGap(36, 36, 36)
										.addComponent(
												jLabel6,
												javax.swing.GroupLayout.PREFERRED_SIZE,
												99,
												javax.swing.GroupLayout.PREFERRED_SIZE)
										.addGap(18, 18, 18)
										.addComponent(
												packetTotal,
												javax.swing.GroupLayout.PREFERRED_SIZE,
												85,
												javax.swing.GroupLayout.PREFERRED_SIZE)
										.addPreferredGap(
												javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
										.addComponent(
												jLabel7,
												javax.swing.GroupLayout.PREFERRED_SIZE,
												71,
												javax.swing.GroupLayout.PREFERRED_SIZE)
										.addGap(43, 43, 43)
										.addComponent(
												jLabel2,
												javax.swing.GroupLayout.PREFERRED_SIZE,
												139,
												javax.swing.GroupLayout.PREFERRED_SIZE)
										.addGap(18, 18, 18)
										.addComponent(
												ipv6Total,
												javax.swing.GroupLayout.PREFERRED_SIZE,
												85,
												javax.swing.GroupLayout.PREFERRED_SIZE)
										.addPreferredGap(
												javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
										.addComponent(
												jLabel4,
												javax.swing.GroupLayout.PREFERRED_SIZE,
												71,
												javax.swing.GroupLayout.PREFERRED_SIZE)
										.addGap(75, 75, 75)
										.addComponent(
												jLabel3,
												javax.swing.GroupLayout.PREFERRED_SIZE,
												99,
												javax.swing.GroupLayout.PREFERRED_SIZE)
										.addGap(18, 18, 18)
										.addComponent(
												bytesTotal,
												javax.swing.GroupLayout.PREFERRED_SIZE,
												85,
												javax.swing.GroupLayout.PREFERRED_SIZE)
										.addPreferredGap(
												javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
										.addComponent(
												jLabel5,
												javax.swing.GroupLayout.PREFERRED_SIZE,
												71,
												javax.swing.GroupLayout.PREFERRED_SIZE)
										.addContainerGap(
												javax.swing.GroupLayout.DEFAULT_SIZE,
												Short.MAX_VALUE)));
		totalPanelLayout
				.setVerticalGroup(totalPanelLayout
						.createParallelGroup(
								javax.swing.GroupLayout.Alignment.LEADING)
						.addGroup(
								totalPanelLayout
										.createSequentialGroup()
										.addGap(21, 21, 21)
										.addGroup(
												totalPanelLayout
														.createParallelGroup(
																javax.swing.GroupLayout.Alignment.LEADING)
														.addGroup(
																totalPanelLayout
																		.createParallelGroup(
																				javax.swing.GroupLayout.Alignment.BASELINE)
																		.addComponent(
																				jLabel3,
																				javax.swing.GroupLayout.PREFERRED_SIZE,
																				42,
																				javax.swing.GroupLayout.PREFERRED_SIZE)
																		.addComponent(
																				bytesTotal,
																				javax.swing.GroupLayout.PREFERRED_SIZE,
																				42,
																				javax.swing.GroupLayout.PREFERRED_SIZE)
																		.addComponent(
																				jLabel5,
																				javax.swing.GroupLayout.PREFERRED_SIZE,
																				44,
																				javax.swing.GroupLayout.PREFERRED_SIZE))
														.addGroup(
																totalPanelLayout
																		.createParallelGroup(
																				javax.swing.GroupLayout.Alignment.BASELINE)
																		.addComponent(
																				jLabel2,
																				javax.swing.GroupLayout.PREFERRED_SIZE,
																				42,
																				javax.swing.GroupLayout.PREFERRED_SIZE)
																		.addComponent(
																				ipv6Total,
																				javax.swing.GroupLayout.PREFERRED_SIZE,
																				42,
																				javax.swing.GroupLayout.PREFERRED_SIZE)
																		.addComponent(
																				jLabel4,
																				javax.swing.GroupLayout.PREFERRED_SIZE,
																				44,
																				javax.swing.GroupLayout.PREFERRED_SIZE)
																		.addGroup(
																				totalPanelLayout
																						.createParallelGroup(
																								javax.swing.GroupLayout.Alignment.BASELINE)
																						.addComponent(
																								jLabel6,
																								javax.swing.GroupLayout.PREFERRED_SIZE,
																								42,
																								javax.swing.GroupLayout.PREFERRED_SIZE)
																						.addComponent(
																								packetTotal,
																								javax.swing.GroupLayout.PREFERRED_SIZE,
																								42,
																								javax.swing.GroupLayout.PREFERRED_SIZE)
																						.addComponent(
																								jLabel7,
																								javax.swing.GroupLayout.PREFERRED_SIZE,
																								44,
																								javax.swing.GroupLayout.PREFERRED_SIZE))))
										.addContainerGap(156, Short.MAX_VALUE)));

		ipv6OnlyButton.setFont(new java.awt.Font("宋体", 0, 18)); // NOI18N
		ipv6OnlyButton.setText("分析其他协议");

		javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(
				jPanel1);
		jPanel1.setLayout(jPanel1Layout);
		jPanel1Layout
				.setHorizontalGroup(jPanel1Layout
						.createParallelGroup(
								javax.swing.GroupLayout.Alignment.LEADING)
						.addGroup(
								javax.swing.GroupLayout.Alignment.TRAILING,
								jPanel1Layout
										.createSequentialGroup()
										.addContainerGap()
										.addGroup(
												jPanel1Layout
														.createParallelGroup(
																javax.swing.GroupLayout.Alignment.TRAILING)
														.addComponent(
																totalPanel,
																javax.swing.GroupLayout.DEFAULT_SIZE,
																javax.swing.GroupLayout.DEFAULT_SIZE,
																Short.MAX_VALUE)
														.addComponent(
																jScrollPane2)
														.addComponent(
																jScrollPane1)
														.addGroup(
																jPanel1Layout
																		.createSequentialGroup()
																		.addComponent(
																				jLabel1,
																				javax.swing.GroupLayout.DEFAULT_SIZE,
																				205,
																				Short.MAX_VALUE)
																		.addGap(18,
																				18,
																				18)
																		.addComponent(
																				networkInterface,
																				javax.swing.GroupLayout.PREFERRED_SIZE,
																				862,
																				javax.swing.GroupLayout.PREFERRED_SIZE)
																		.addGap(18,
																				18,
																				18)
																		.addComponent(
																				ipv6OnlyButton,
																				javax.swing.GroupLayout.PREFERRED_SIZE,
																				147,
																				javax.swing.GroupLayout.PREFERRED_SIZE)
																		.addGap(26,
																				26,
																				26)
																		.addComponent(
																				startButton,
																				javax.swing.GroupLayout.PREFERRED_SIZE,
																				128,
																				javax.swing.GroupLayout.PREFERRED_SIZE)))
										.addGap(25, 25, 25)));
		jPanel1Layout
				.setVerticalGroup(jPanel1Layout
						.createParallelGroup(
								javax.swing.GroupLayout.Alignment.LEADING)
						.addGroup(
								jPanel1Layout
										.createSequentialGroup()
										.addGap(32, 32, 32)
										.addGroup(
												jPanel1Layout
														.createParallelGroup(
																javax.swing.GroupLayout.Alignment.BASELINE)
														.addComponent(
																jLabel1,
																javax.swing.GroupLayout.PREFERRED_SIZE,
																49,
																javax.swing.GroupLayout.PREFERRED_SIZE)
														.addComponent(
																networkInterface,
																javax.swing.GroupLayout.PREFERRED_SIZE,
																49,
																javax.swing.GroupLayout.PREFERRED_SIZE)
														.addComponent(
																startButton,
																javax.swing.GroupLayout.PREFERRED_SIZE,
																49,
																javax.swing.GroupLayout.PREFERRED_SIZE)
														.addComponent(
																ipv6OnlyButton,
																javax.swing.GroupLayout.DEFAULT_SIZE,
																51,
																Short.MAX_VALUE))
										.addPreferredGap(
												javax.swing.LayoutStyle.ComponentPlacement.UNRELATED,
												11, Short.MAX_VALUE)
										.addComponent(
												jScrollPane1,
												javax.swing.GroupLayout.PREFERRED_SIZE,
												189,
												javax.swing.GroupLayout.PREFERRED_SIZE)
										.addGap(18, 18, 18)
										.addComponent(
												jScrollPane2,
												javax.swing.GroupLayout.PREFERRED_SIZE,
												227,
												javax.swing.GroupLayout.PREFERRED_SIZE)
										.addGap(18, 18, 18)
										.addComponent(
												totalPanel,
												javax.swing.GroupLayout.DEFAULT_SIZE,
												javax.swing.GroupLayout.DEFAULT_SIZE,
												Short.MAX_VALUE)
										.addContainerGap()));

		javax.swing.GroupLayout layout = new javax.swing.GroupLayout(
				getContentPane());
		getContentPane().setLayout(layout);
		layout.setHorizontalGroup(layout.createParallelGroup(
				javax.swing.GroupLayout.Alignment.LEADING).addComponent(
				jPanel1, javax.swing.GroupLayout.DEFAULT_SIZE,
				javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE));
		layout.setVerticalGroup(layout.createParallelGroup(
				javax.swing.GroupLayout.Alignment.LEADING).addComponent(
				jPanel1, javax.swing.GroupLayout.DEFAULT_SIZE,
				javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE));

		pack();
	}// </editor-fold>//GEN-END:initComponents

	private void networkInterfaceActionPerformed(java.awt.event.ActionEvent evt) {
		// TODO add your handling code here:
	}

	private void startButtonActionPerformed(java.awt.event.ActionEvent evt) {
		// TODO add your handling code here:
		this.ipv6SnifferControl.startOrStopCapture();
	}

	private void tableSelectActionPerformed(ListSelectionEvent e) {
		// TODO add your handling code here:
		if (!e.getValueIsAdjusting()) {
			Object selected = this.packetTable.getModel().getValueAt(
					this.packetTable.getSelectedRow(), 0);
			System.out.println("被选择的值为： " + selected);
			this.ipv6SnifferControl.updateDetailPacketTree(Integer
					.valueOf(selected + ""));
		}
	}

	/**
	 * @param args
	 *            the command line arguments
	 */
	public static void main(String args[]) {
		/* Set the Nimbus look and feel */
		// <editor-fold defaultstate="collapsed"
		// desc=" Look and feel setting code (optional) ">
		/*
		 * If Nimbus (introduced in Java SE 6) is not available, stay with the
		 * default look and feel. For details see
		 * http://download.oracle.com/javase
		 * /tutorial/uiswing/lookandfeel/plaf.html
		 */
		try {
			for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager
					.getInstalledLookAndFeels()) {
				if ("Nimbus".equals(info.getName())) {
					javax.swing.UIManager.setLookAndFeel(info.getClassName());
					break;
				}
			}
		} catch (ClassNotFoundException ex) {
			java.util.logging.Logger
					.getLogger(Ipv6SnifferFrame.class.getName()).log(
							java.util.logging.Level.SEVERE, null, ex);
		} catch (InstantiationException ex) {
			java.util.logging.Logger
					.getLogger(Ipv6SnifferFrame.class.getName()).log(
							java.util.logging.Level.SEVERE, null, ex);
		} catch (IllegalAccessException ex) {
			java.util.logging.Logger
					.getLogger(Ipv6SnifferFrame.class.getName()).log(
							java.util.logging.Level.SEVERE, null, ex);
		} catch (javax.swing.UnsupportedLookAndFeelException ex) {
			java.util.logging.Logger
					.getLogger(Ipv6SnifferFrame.class.getName()).log(
							java.util.logging.Level.SEVERE, null, ex);
		}
		// </editor-fold>

		/* Create and display the form */
		java.awt.EventQueue.invokeLater(new Runnable() {
			public void run() {
				new Ipv6SnifferFrame().setVisible(true);
			}
		});
	}

	// Variables declaration - do not modify//GEN-BEGIN:variables
	private javax.swing.JLabel bytesTotal;
	private javax.swing.JTree detailPacketTree;
	private javax.swing.JRadioButton ipv6OnlyButton;
	private javax.swing.JLabel ipv6Total;
	private javax.swing.JLabel packetTotal;
	private javax.swing.JLabel jLabel1;
	private javax.swing.JLabel jLabel2;
	private javax.swing.JLabel jLabel3;
	private javax.swing.JLabel jLabel4;
	private javax.swing.JLabel jLabel5;
	private javax.swing.JLabel jLabel6;
	private javax.swing.JLabel jLabel7;
	private javax.swing.JPanel jPanel1;
	private javax.swing.JScrollPane jScrollPane1;
	private javax.swing.JScrollPane jScrollPane2;
	private javax.swing.JComboBox<String> networkInterface;
	private javax.swing.JTable packetTable;
	private javax.swing.JButton startButton;
	private javax.swing.JPanel totalPanel;
	// End of variables declaration//GEN-END:variables
}
