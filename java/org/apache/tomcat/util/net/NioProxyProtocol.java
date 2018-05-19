//*************************************************************************************************
//
// Copyright © 2016 Open Text. All Rights Reserved.
// Trademarks owned by Open Text.
//
//*************************************************************************************************

package org.apache.tomcat.util.net;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;

import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;


public class NioProxyProtocol {
    private static final Log log = LogFactory.getLog(NioProxyProtocol.class);

    public enum ConfigEnum {

        OFF("off"),             // Proxy Protocol is not enabled, and the PROXY header is not expected for new connections.
        ON("on"),               // Proxy Protocol is enabled, and the PROXY header is required on new connections.
        OPTIONAL("optional");   // Proxy Protocol is enabled, and the PROXY header is optional on new connections.

        private final String mValue;

        ConfigEnum(String val) {
            mValue = val;
        }
        public String value() {
            return mValue;
        }
        public static ConfigEnum fromValue(String val) {
            for (ConfigEnum a : ConfigEnum.values()) {
                if (a.value().equals(val)) {
                    return a;
                }
            }
            throw new IllegalArgumentException(val);
        }

        @Override
        public String toString() {
            return this.value();
        }
    }

    // From http://www.haproxy.org/download/1.5/doc/proxy-protocol.txt
    // So a 108-byte buffer is always enough to store all the line and a trailing zero
    static final int MAX_PROXY_HEADER_LENGTH = 108;

    // Regexes used for valiation.  These aren't precise, but do provide the level of sanity checking we need to verify we got a properly formatted PROXY protocol header.
    static final String IP4_REGEX = "^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$";
    static final String IP6_REGEX = "^[0-9a-fA-F:]+$";
    static final String PORT_REGEX = "^\\d{1,5}$";

    protected ByteBuffer netInBuffer;

    protected ProxyProtocolInfo proxyProtocolInfo;

    protected boolean bReadFromSocket = false;

    public boolean getReadFromSocket() {
        return bReadFromSocket;
    }

    public void setReadFromSocket(boolean bReadFromSocket) {
        this.bReadFromSocket = bReadFromSocket;
    }

    public ByteBuffer getNetInBuffer() {
        if (netInBuffer == null)
            netInBuffer = ByteBuffer.allocateDirect(MAX_PROXY_HEADER_LENGTH);
        return netInBuffer;
    }

    public ProxyProtocolInfo getProxyProtocolInfo() {
        return proxyProtocolInfo;
    }

    /**
     * Reads a sequence of bytes from this object's optional input buffer into the given buffer.
     *
     * @param dst The buffer into which bytes are to be transferred
     * @return The number of bytes read, possibly zero.
     */
    public int read(ByteBuffer dst) {
        if (netInBuffer.position() > 0) {
            netInBuffer.flip();    // limit = position, position = 0
            int remaining = Math.min(netInBuffer.remaining(), dst.remaining());
            byte[] bytes = new byte[remaining];
            netInBuffer.get(bytes, 0, bytes.length);
            dst.put(bytes, 0, bytes.length);
            netInBuffer.position(remaining);
            netInBuffer.compact(); // position = limit - position, limit = capacity
            return remaining;
        }
        return 0;
    }

    public void reset() throws IOException {
        if (netInBuffer != null)
            netInBuffer.clear();
        proxyProtocolInfo = null;
        bReadFromSocket = false;
    }

    private static String formatBytesForLog(byte[] bytes) {
        return DatatypeConverter.printHexBinary(bytes);
    }

    // For debugging / troubleshooting, output the proxy bytes. But only do this at a very low log level, so they are not logged by default.
    private IOException handleProxyProtocolError(String msg, byte[] proxyBytes) {
        if (log.isTraceEnabled())
            log.trace(msg + ": " + formatBytesForLog(proxyBytes));
        return new IOException(msg);
    }

    private String validateProtocolToken(String token, String regex, String err, byte[] proxyBytes) throws IOException {
        if (!token.matches(regex))
            throw handleProxyProtocolError("malformed PROXY protocol header. " + err, proxyBytes);
        return token;
    }

    private InetAddress parseAddress(String token, String regex, String err, byte[] proxyBytes) throws IOException {
        token = validateProtocolToken(token, regex, err, proxyBytes);
        try {
            return InetAddress.getByName(token);
        } catch (IOException e) {
            throw handleProxyProtocolError("malformed PROXY protocol header. " + err, proxyBytes);
        }
    }

    private int parsePort(String token, String regex, String err, byte[] proxyBytes) throws IOException {
        token = validateProtocolToken(token, regex, err, proxyBytes);
        int port = Integer.parseInt(token);
        if (port < 0 || port >= 65536)
            throw handleProxyProtocolError("malformed PROXY protocol header. " + err, proxyBytes);
        return port;
    }

    @SuppressWarnings("pmd:EmptyIfStmt")
    public void handleProxyProtocol(ByteBuffer inBuffer, boolean bReadReady, boolean bRequired) throws IOException {

        // Our PROXY protocol might be optional, so create a read-only buffer to read from.
        ByteBuffer proxyBuffer = inBuffer.asReadOnlyBuffer();
        if (!bReadReady)
            proxyBuffer.flip();
        int remaining = Math.min(proxyBuffer.remaining(), MAX_PROXY_HEADER_LENGTH);
        byte[] proxyBytes = new byte[remaining];
        proxyBuffer.get(proxyBytes, 0, remaining);
        int proxyPos = 0;

        // Verify the header starts with "PROXY "
        if (proxyBytes.length < 6) {
            if (bRequired)
                throw handleProxyProtocolError("underflow for required PROXY protocol header", proxyBytes);
        } else if (proxyBytes[0] != 'P' || proxyBytes[1] != 'R' || proxyBytes[2] != 'O' || proxyBytes[3] != 'X' || proxyBytes[4] != 'Y' || proxyBytes[5] != ' ') {
            if (bRequired)
                throw handleProxyProtocolError("missing required PROXY protocol header", proxyBytes);
        } else {
            // Find the PROXY protocol's ending CRLF.
            for (proxyPos = 6; proxyPos < proxyBytes.length; ++proxyPos) {
                if (proxyBytes[proxyPos] == '\r' && proxyPos + 1 < proxyBytes.length && proxyBytes[proxyPos + 1] == '\n') {
                    break;
                }
            }
            if (proxyPos >= proxyBytes.length)
                throw handleProxyProtocolError("malformed PROXY protocol header. No trailing CRLF", proxyBytes);
        }

        // No PROXY protocol header was detected, and it was optional.  Do nothing.
        if (proxyPos == 0)
            return;

        // Consume all bytes b/ween 0 and proxyPos -- they're part of the PROXY protocol header.
        if (!bReadReady)
            inBuffer.flip();
        inBuffer.position(proxyPos + 2);    // + 2 to capture the trailing CRLF
        if (!bReadReady)
            inBuffer.compact();

        // At this point, we have a header of the form "PROXY ...\r\n".  Let's parse it.
        InetAddress srcAddress, dstAddress;
        int srcPort, dstPort;
        String proxyHeader = new String(proxyBytes, 6, proxyPos - 6, StandardCharsets.US_ASCII);
        String[] proxyHeaders = proxyHeader.split(" ");

        // From http://www.haproxy.org/download/1.5/doc/proxy-protocol.txt
        //
        //unknown connection (short form)
        // PROXY UNKNOWN\r\n
        //worst case (optional fields set to 0xff) :
        //PROXY UNKNOWN ffff:f...f:ffff ffff:f...f:ffff 65535 65535\r\n
        // If the announced transport protocol is "UNKNOWN", then the receiver knows that
        // the sender speaks the correct PROXY protocol with the appropriate version, and
        // SHOULD accept the connection and use the real connection's parameters as if
        // there were no PROXY protocol header on the wire.
        if (proxyHeaders[0].equals("UNKNOWN")) {
        }

        else if (proxyHeaders.length != 5) {
            throw handleProxyProtocolError("malformed PROXY protocol header", proxyBytes);
        }

        // TCP/IPv4 :
        // PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n
        else if (proxyHeaders[0].equals("TCP4")) {
            srcAddress = parseAddress(proxyHeaders[1], IP4_REGEX, "Invalid src address", proxyBytes);
            dstAddress = parseAddress(proxyHeaders[2], IP4_REGEX, "Invalid dst address", proxyBytes);
            srcPort = parsePort(proxyHeaders[3], PORT_REGEX, "Invalid src port", proxyBytes);
            dstPort = parsePort(proxyHeaders[4], PORT_REGEX, "Invalid dst port", proxyBytes);
            proxyProtocolInfo = new ProxyProtocolInfo(srcAddress, srcPort, dstAddress, dstPort);
        }

        // TCP/IPv6 :
        // "PROXY TCP6 ffff:f...f:ffff ffff:f...f:ffff 65535 65535\r\n"
        else if (proxyHeaders[0].equals("TCP6")) {
            srcAddress = parseAddress(proxyHeaders[1], IP6_REGEX, "Invalid src address", proxyBytes);
            dstAddress = parseAddress(proxyHeaders[2], IP6_REGEX, "Invalid dst address", proxyBytes);
            srcPort = parsePort(proxyHeaders[3], PORT_REGEX, "Invalid src port", proxyBytes);
            dstPort = parsePort(proxyHeaders[4], PORT_REGEX, "Invalid dst port", proxyBytes);
            proxyProtocolInfo = new ProxyProtocolInfo(srcAddress, srcPort, dstAddress, dstPort);
        }

        else {
            throw handleProxyProtocolError("malformed PROXY protocol header. Invalid protocol", proxyBytes);
        }
    }
}

