package cn.edu.shu.ipv6sniffer.util;

import java.util.Date;

public class TableEntity {
	private int number;
	private Date receiveTime;
	private String sourceAddr;
	private String destinationAddr;
	public int getNumber() {
		return number;
	}
	public void setNumber(int number) {
		this.number = number;
	}
	public Date getReceiveTime() {
		return receiveTime;
	}
	public void setReceiveTime(Date receiveTime) {
		this.receiveTime = receiveTime;
	}
	public String getSourceAddr() {
		return sourceAddr;
	}
	public void setSourceAddr(String sourceAddr) {
		this.sourceAddr = sourceAddr;
	}
	public String getDestinationAddr() {
		return destinationAddr;
	}
	public void setDestinationAddr(String destinationAddr) {
		this.destinationAddr = destinationAddr;
	}
}
