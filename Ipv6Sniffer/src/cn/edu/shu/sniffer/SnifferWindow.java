package cn.edu.shu.sniffer;

import org.eclipse.jface.dialogs.MessageDialog;
import org.eclipse.swt.events.SelectionAdapter;
import org.eclipse.swt.events.SelectionEvent;
import org.eclipse.swt.events.SelectionListener;
import org.eclipse.swt.graphics.Point;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Display;
import org.eclipse.swt.widgets.Layout;
import org.eclipse.swt.widgets.Shell;
import org.eclipse.swt.widgets.Text;
import org.eclipse.swt.SWT;
import org.eclipse.swt.widgets.Label;
import org.eclipse.swt.widgets.Button;
import org.eclipse.ui.internal.layout.LayoutUtil;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.layout.FillLayout;
import org.eclipse.swt.layout.RowLayout;
import org.eclipse.swt.layout.FormLayout;
import org.eclipse.swt.layout.FormData;
import org.eclipse.swt.layout.FormAttachment;
import org.eclipse.swt.custom.StackLayout;
import org.eclipse.wb.swt.SWTResourceManager;
import org.eclipse.swt.widgets.List;
import org.eclipse.swt.widgets.Table;
import org.eclipse.jface.viewers.TableViewer;
import org.eclipse.swt.widgets.ToolBar;
import org.eclipse.swt.widgets.Slider;
import org.eclipse.swt.custom.CLabel;
import org.eclipse.swt.custom.StyledText;

public class SnifferWindow {
	protected Shell shell;
	private Button btnTcp_1;

	/**
	 * Launch the application.
	 * 
	 * @param args
	 */
	public static void main(String[] args) {
		SnifferWindow snifferWindow = new SnifferWindow();
		snifferWindow.open();
		
	}

	/** */
	/**
	 * 　　 * Open the window 　　
	 */
	public void open() {
		final Display display = Display.getDefault();
		createContents();
		shell.open();
		shell.layout();
		while (!shell.isDisposed()) {
			if (!display.readAndDispatch()) {
				display.sleep();
			}
		}
	}
	/** */
	/**
	 * 　　 * Create contents of the window 　　
	 */
	protected void createContents() {
		shell = new Shell();
		shell.setBackground(SWTResourceManager.getColor(SWT.COLOR_WIDGET_LIGHT_SHADOW));
		shell.setSize(951, 697);
		shell.setText("Ipv6Sniffer");
		shell.setLayout(null);
		
		Button btnIpv = new Button(shell, SWT.BORDER | SWT.FLAT | SWT.CHECK);
		btnIpv.setSelection(true);
		btnIpv.setFont(SWTResourceManager.getFont("Microsoft YaHei UI", 16, SWT.NORMAL));
		btnIpv.addSelectionListener(new SelectionAdapter() {
			@Override
			public void widgetSelected(SelectionEvent e) {
			}
		});
		btnIpv.setBounds(266, 137, 92, 44);
		btnIpv.setText("Ipv6");
		
		Button btnTcp = new Button(shell, SWT.BORDER | SWT.FLAT | SWT.CHECK);
		btnTcp.setFont(SWTResourceManager.getFont("Microsoft YaHei UI", 16, SWT.NORMAL));
		btnTcp.setBounds(521, 137, 92, 44);
		btnTcp.setText("UDP");
		
		btnTcp_1 = new Button(shell, SWT.BORDER | SWT.FLAT | SWT.CHECK);
		btnTcp_1.addSelectionListener(new SelectionAdapter() {
			@Override
			public void widgetSelected(SelectionEvent e) {
			}
		});
		btnTcp_1.setText("TCP");
		btnTcp_1.setFont(SWTResourceManager.getFont("Microsoft YaHei UI", 16, SWT.NORMAL));
		btnTcp_1.setBounds(398, 137, 92, 44);
		
		Button btnNewButton = new Button(shell, SWT.NONE);
		btnNewButton.setFont(SWTResourceManager.getFont("Microsoft YaHei UI", 16, SWT.NORMAL));
		btnNewButton.setBounds(692, 137, 80, 44);
		btnNewButton.setText("开始");
		
		Button button = new Button(shell, SWT.NONE);
		button.setFont(SWTResourceManager.getFont("Microsoft YaHei UI", 16, SWT.NORMAL));
		button.addSelectionListener(new SelectionAdapter() {
			@Override
			public void widgetSelected(SelectionEvent e) {
			}
		});
		button.setText("停止");
		button.setBounds(821, 137, 80, 44);
		
		List list = new List(shell, SWT.BORDER);
		list.setBounds(97, 26, 722, 44);
		
		Label label = new Label(shell, SWT.CENTER);
		label.setFont(SWTResourceManager.getFont("Microsoft YaHei UI", 16, SWT.NORMAL));
		label.setBounds(666, 616, 92, 32);
		label.setText("共捕获");
		
		Label label_1 = new Label(shell, SWT.CENTER);
		label_1.setFont(SWTResourceManager.getFont("Microsoft YaHei UI", 16, SWT.NORMAL));
		label_1.setText("个包");
		label_1.setBounds(850, 616, 61, 32);
		
		Label lblNewLabel = new Label(shell, SWT.CENTER);
		lblNewLabel.setFont(SWTResourceManager.getFont("Microsoft YaHei UI", 12, SWT.NORMAL));
		lblNewLabel.setText("0");
		lblNewLabel.setBounds(764, 616, 80, 32);
	}
}
