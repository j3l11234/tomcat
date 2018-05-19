//*************************************************************************************************
//
// Copyright © 2016 Open Text. All Rights Reserved.
// Trademarks owned by Open Text.
//
//*************************************************************************************************

package org.apache.tomcat.util.net;

import java.net.InetAddress;

public class ProxyProtocolInfo {
    private final InetAddress srcAddress;
    private final int srcPort;
    private final InetAddress dstAddress;
    private final int dstPort;

    public ProxyProtocolInfo(InetAddress srcAddress, int srcPort, InetAddress dstAddress, int dstPort) {
        this.srcAddress = srcAddress;
        this.srcPort = srcPort;
        this.dstAddress = dstAddress;
        this.dstPort = dstPort;
    }

    public InetAddress getSourceAddress() {
        return srcAddress;
    }

    public String getSourceAddressAsString() {
        return (srcAddress == null) ? "null" : srcAddress.getHostAddress();
    }

    public int getSourcePort() {
        return srcPort;
    }

    public InetAddress getDestinationAddress() {
        return dstAddress;
    }

    public int getDestinationPort() {
        return dstPort;
    }

    public String getDestinationAddressAsString() {
        return (dstAddress == null) ? "null" : dstAddress.getHostAddress();
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof ProxyProtocolInfo))
            return false;
        ProxyProtocolInfo that = (ProxyProtocolInfo)obj;
        return this.srcPort == that.srcPort && this.dstPort == that.dstPort
                && this.getSourceAddressAsString().equals(that.getSourceAddressAsString())
                && this.getDestinationAddressAsString().equals(that.getDestinationAddressAsString());
    }

    @Override
    public int hashCode() {
        return this.srcPort ^ this.dstPort ^ this.srcAddress.hashCode() ^ this.dstAddress.hashCode();
    }

    @Override
    public String toString() {
        return getSourceAddressAsString() + ":" + getSourcePort() + " " + getDestinationAddressAsString() + ":" + getDestinationPort();
    }
}
