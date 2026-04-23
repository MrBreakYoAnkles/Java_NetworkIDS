import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import java.net.InetAddress;
import java.time.LocalDateTime;
import java.util.List;
import java.util.HashMap;
import java.util.Map;

/*
 * Alex Stanford
 * Security Disaster Prep
 *
 * PacketSniffer.java
 * IDS prototype that:
 *  - Captures live packets using Pcap4J
 *  - Detects TCP port scans (unique destination ports within a time window)
 *  - Prints ICMP activity as a periodic summary (not every packet)
 *
 * Demo tips to remember!
 *  - TCP demo: set filter to "tcp" and run in VM:    nmap -p 1-200 127.0.0.1
 *  - ICMP demo: set filter to "icmp" and run in VM:  ping 127.0.0.1
 *  - CTRL + C in ubuntu to stop pings
 */

public class PacketSniffer {

  // ===================== IDS SETTINGS =====================

  // Port-scan detection window and threshold
  private static final long WINDOW_MS = 10_000;       // 10 seconds
  private static final int PORT_SCAN_THRESHOLD = 20;  // unique destination ports

  // Tracks ports per source IP: Map<srcIp, Map<dstPort, lastSeenMs>>
  private static final Map<String, Map<Integer, Long>> portsSeenBySrc = new HashMap<>();

  // Global cooldown to avoid alert spam during a single demo test run
  private static long lastPortScanAlertMs = 0;
  private static final long GLOBAL_ALERT_COOLDOWN_MS = 15_000; // 15 seconds

  // ICMP output control (summary instead of printing every packet) makes it easy for analysis when demoing
  private static int icmpCount = 0;
  private static long lastIcmpSummaryMs = 0;
  private static final long ICMP_SUMMARY_INTERVAL_MS = 2_000; // 2 seconds
  //private static final long ICMP_SUMMARY_INTERVAL_MS = 5000; //use this for demo

  // Optional debug toggles
  private static final boolean DEBUG_TCP_PACKETS = true; // set true if you want to print some TCP packets
  private static final boolean DEBUG_IPV6 = false;
  private static final boolean DEBUG_ARP = false;

  // ===================== CAPTURE SETTINGS =====================

  private static final int SNAPLEN = 65536;       // bytes per packet to capture
  private static final int READ_TIMEOUT_MS = 10;  // read timeout (ms)
  private static final int PACKET_COUNT = 0;      // 0 = infinite
  

  public static void main(String[] args) throws Exception {

    // 1) List available interfaces
    List<PcapNetworkInterface> allDevs = Pcaps.findAllDevs();
    if (allDevs == null || allDevs.isEmpty()) {
      System.err.println("No network interfaces found.");
      return;
    }

    System.out.println("Available network interfaces:");
    for (int i = 0; i < allDevs.size(); i++) {
      PcapNetworkInterface nif = allDevs.get(i);
      System.out.printf("[%d] %s (%s)%n", i, nif.getName(), nif.getDescription());
      nif.getAddresses().forEach(addr -> {
        if (addr.getAddress() != null) {
          System.out.println("     IP: " + addr.getAddress());
        }
      });
    }

    // 2) Pick an interface 
    // 7 = VirtualBox Host-Only Adapter
    // 8 = Physical Ethernet adapter
    // 9 = Loopback adapter for localhost testing
    
    PcapNetworkInterface nif = allDevs.get(8);
    
    //ICMP test on VM = ping 192.168.1.205
    //TCP test on VM = sudo nmap -sS -p 1-200 192.168.1.205
    //turn off windows firewall defender to test 
    

    if (nif == null) {
      System.err.println("Could not select the interface at current index. Pick a valid index from the list.");
      return;
    }
    
    
    System.out.println("\nCapturing on: " + nif.getName() + " (" + nif.getDescription() + ")");
    System.out.println("Tip (Windows): ping -n 3 127.0.0.1");
    System.out.println("Tip (TCP scan): nmap -p 1-200 127.0.0.1");

    // 3) Open a live capture handle
    PcapHandle handle = nif.openLive(
        SNAPLEN,
        PcapNetworkInterface.PromiscuousMode.PROMISCUOUS,
        READ_TIMEOUT_MS
    );

    //  FILTER CONTROL 
    //these filter only tcp or icmp traffic
    // TCP demo (port scan): nmap -p 1-200 127.0.0.1
    //  handle.setFilter("tcp", BpfProgram.BpfCompileMode.OPTIMIZE);

    // ICMP demo (ping): ping -n 3 127.0.0.1
    // handle.setFilter("icmp", BpfProgram.BpfCompileMode.OPTIMIZE);
 
    // Both:
     handle.setFilter("tcp or icmp", BpfProgram.BpfCompileMode.OPTIMIZE);

    // 4) Listener runs once per captured packet
    PacketListener listener = packet -> {
      LocalDateTime now = LocalDateTime.now();

      IpV4Packet ipv4 = packet.get(IpV4Packet.class);
      IpV6Packet ipv6 = packet.get(IpV6Packet.class);

      // ---------- IPv4 ----------
      if (ipv4 != null) {
        InetAddress src = ipv4.getHeader().getSrcAddr();
        InetAddress dst = ipv4.getHeader().getDstAddr();

        // ---------- TCP ----------
        TcpPacket tcp = packet.get(TcpPacket.class);
        if (tcp != null) {
          TcpPacket.TcpHeader th = tcp.getHeader();
          int sport = th.getSrcPort().valueAsInt();
          int dport = th.getDstPort().valueAsInt();

          String srcIp = src.getHostAddress();
          long nowMs = System.currentTimeMillis();

          // Get or create the map of destination ports for this source IP
          Map<Integer, Long> portMap = portsSeenBySrc.computeIfAbsent(srcIp, k -> new HashMap<>());

          // Remove entries outside the time window
          portMap.entrySet().removeIf(e -> (nowMs - e.getValue()) > WINDOW_MS);

          // Record that we saw this destination port now
          portMap.put(dport, nowMs);

          // Detect port scan if the number of unique ports in the window is high
          if (portMap.size() >= PORT_SCAN_THRESHOLD) {
            long nowAlertMs = System.currentTimeMillis();

            // Global cooldown prevents repeated alerts during a single scan burst
            if ((nowAlertMs - lastPortScanAlertMs) >= GLOBAL_ALERT_COOLDOWN_MS) {
              System.out.printf(
                  "[ALERT] Possible port scan from %s: %d unique ports in last %d ms%n",
                  srcIp, portMap.size(), WINDOW_MS
              );
              lastPortScanAlertMs = nowAlertMs;
            }

            // Clear so it doesn't instantly re-trigger on the same burst
            portMap.clear();
          }

          // Optional: print limited TCP details (off by default)
          if (DEBUG_TCP_PACKETS && th.getSyn() && !th.getAck()) {
            System.out.printf("[%s] TCP SYN %s:%d -> %s:%d%n", now, src, sport, dst, dport);
          }

          return;
        }

        // ---------- ICMP ----------
        IcmpV4CommonPacket icmp = packet.get(IcmpV4CommonPacket.class);
        if (icmp != null) {
        	System.out.println("[ICMP] Packet received from " + src.getHostAddress() + " to " + dst.getHostAddress());
          icmpCount++;

          long nowMs = System.currentTimeMillis();

          // Print a summary periodically instead of every packet
          if ((nowMs - lastIcmpSummaryMs) >= ICMP_SUMMARY_INTERVAL_MS) {
            System.out.printf(
                "[INFO] ICMP activity: %d packets seen in the last %d ms%n",
                icmpCount, ICMP_SUMMARY_INTERVAL_MS
            );
            icmpCount = 0;
            lastIcmpSummaryMs = nowMs;
          }

          return;
        }

        // Other IPv4 packets are ignored for a clean demo output
        return;
      }

      // ---------- IPv6 ----------
      if (ipv6 != null) {
        if (DEBUG_IPV6) {
          InetAddress src = ipv6.getHeader().getSrcAddr();
          InetAddress dst = ipv6.getHeader().getDstAddr();
          System.out.printf("[%s] IPv6 %s -> %s%n", now, src, dst);
        }
        return;
      }
    };

    // 5) Start capture loop
    try {
      handle.loop(PACKET_COUNT, listener);
    } catch (InterruptedException e) {
      System.out.println("\nCapture interrupted.");
    } finally {
      if (handle != null && handle.isOpen()) handle.close();
    }
  }
  
  //below finds and returns the network interface that matches the given IP address.
  //returns null if no matching interface is found.
  private static PcapNetworkInterface pickByIp(List<PcapNetworkInterface> allDevs, String ip) {
	  for (PcapNetworkInterface nif : allDevs) {
	    for (PcapAddress addr : nif.getAddresses()) {
	      if (addr.getAddress() != null && addr.getAddress().getHostAddress().equals(ip)) {
	        return nif;
	      }
	    }
	  }
	  return null;
	}
}