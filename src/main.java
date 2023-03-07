import javax.imageio.ImageIO;
import javax.swing.*;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.Style;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyleContext;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;

import org.jnetpcap.*;
import org.jnetpcap.packet.AbstractMessageHeader;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.application.Html;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.lan.IEEE802dot1q;
import org.jnetpcap.protocol.lan.IEEE802dot3;
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;
import org.jnetpcap.protocol.voip.Rtcp;
import org.jnetpcap.protocol.vpn.L2TP;
import org.jnetpcap.winpcap.WinPcap;

public class main extends JFrame {

    public static textarea logs = new textarea();
    public static textarea2 logs2 = new textarea2();

    StringBuilder ERR = new StringBuilder();
    public static List<PcapIf> NICS = new ArrayList<PcapIf>();
    int code = Pcap.findAllDevs(NICS, ERR);
    public static int snaplen = 64 * 1024;
    public static int flags = Pcap.MODE_PROMISCUOUS;
    public static int timeout = 100;
    public static String r = "\n";
    public static int iterator = 0;
    public static String p_number = null;

    public static String layer_1;
    public static String layer_2;
    public static String layer_3;
    public static String layer_4;
    public static String layer_5;
    public static String layer_8;

    public static String HISTORY_PATH_NAME = "C://SPROTOTYPE_FILE/Historique/Historique du " + date.FileDate() + ".txt";

    /*--------------------------------------------*/

    public static int ok;

    public static class network{

        // Affichage des interfaces dispo

        public static void NICS_DISPO() throws IOException {
            Thread.currentThread().setName("Affichage des cartes réseaux");
            logs.append(date.date() + "Interfaces disponibles: " + r);

            logs.append(r);
            for(int i = 0 ; i < NICS.size() ; i++ )
            {
                var nic = NICS.get(i);
                logs.append(i + ": " + nic.getDescription() + " - " + nic.getName() + r);

                if(!nic.getAddresses().isEmpty())
                {
                    var int_infos = nic.getAddresses().get(0);
                    byte[] ad = NICS.get(i).getHardwareAddress();
                    logs.append("Adresse IP: " + org.jnetpcap.packet.format.FormatUtils.ip(int_infos.getAddr().getData()) + r + "Masque: " + org.jnetpcap.packet.format.FormatUtils.ip(int_infos.getNetmask().getData()) + r + "Broadcast: " + org.jnetpcap.packet.format.FormatUtils.ip(int_infos.getBroadaddr().getData()) + r );
                    if (NICS.get(i).getHardwareAddress() != null)
                    {
                        logs.append("Adresse MAC: " + org.jnetpcap.packet.format.FormatUtils.mac(ad));
                    }

                } else {
                  logs.append("Aucune information sur cette interface.");
                }
                logs.append(r + "________________________________________________________________________________");
                logs.append(r + r);
            }
            logs.append(r);
        }
    }

    public main()
    {

        Thread.currentThread().setName("Ceci est la conf du panel");
        try {UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
            } catch (ClassNotFoundException e) {
            e.printStackTrace();
        } catch (InstantiationException e) {
            e.printStackTrace();
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        } catch (UnsupportedLookAndFeelException e) {
            e.printStackTrace();
        }

        this.setTitle("S-Prototype");
        this.setExtendedState(this.getExtendedState() | JFrame.MAXIMIZED_BOTH);
        this.setResizable(true);
        this.setSize(sys1.getw(), sys1.geth());
        setMinimumSize(new Dimension(sys1.getw(),sys1.geth()));
        this.setLocationRelativeTo(null);
        this.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        this.add(new panel());

        try {
            Image ico = ImageIO.read(new File("img/ico.png"));
            setIconImage(ico);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public class panel extends JPanel
    {
        public panel()
        {
            Thread.currentThread().setName("Elements et actions du panel");
            this.setBackground(Color.white);

            // MENUBAR

            JMenuBar mbar = new JMenuBar();
            mbar.setBorderPainted(true);
            setJMenuBar(mbar);

            JMenu Analysis = new JMenu("Commandes");


            // FILE
            JMenu FILE = new JMenu("Fichier");
            JMenuItem SAVE_LOGS = new JMenuItem("Enregistrer sous");
            JMenu SEND_LOGS = new JMenu("Envoyer");
            JMenu PRINT_LOGS = new JMenu("Imprimer");

            FILE.add(SAVE_LOGS);
            FILE.add(SEND_LOGS);
            FILE.add(PRINT_LOGS);

            // PROTOC COMPONENTS
            JMenu ARP = new JMenu("ARP");
            JMenu ICMP = new JMenu("ICMP");
            JMenu TCP = new JMenu("TCP");
            JMenu UDP = new JMenu("UDP");
            JMenu SCANS = new JMenu("Scans");
            JMenu IP = new JMenu("IP");
            JMenu HTTP_S = new JMenu("HTTP");
            JMenu VOIP = new JMenu("VoIP");
            JMenu VPN = new JMenu("VPN");
            JMenu VLAN = new JMenu("VLAN");
            JMenu DNS = new JMenu("DNS");
            JMenu DHCP = new JMenu("DHCP");
            JMenu SMB = new JMenu("SMB");

            // OTHER
            JMenu HELP = new JMenu("Aide");
            JMenu LOGS = new JMenu("Logs");
            JMenu INTERFACES = new JMenu("Interfaces");
            JMenu About = new JMenu("À Propos");

            mbar.add(FILE);
            mbar.add(INTERFACES);
            mbar.add(ICMP);
            mbar.add(ARP);
            mbar.add(IP);
            mbar.add(TCP);
            mbar.add(UDP);
            mbar.add(SCANS);
            mbar.add(HTTP_S);
            mbar.add(VOIP);
            mbar.add(VPN);
            mbar.add(VLAN);
            mbar.add(DNS);
            mbar.add(DHCP);
            mbar.add(SMB);
            mbar.add(LOGS);
            mbar.add(Analysis);
            mbar.add(HELP);
            mbar.add(About);

            // --------------------------- Analayse (INFOS) ------------------------------------ //

            JMenu Wifi = new JMenu("Wi-Fi");
            Analysis.add(Wifi);
            JMenu ARP_INFOS = new JMenu("ARP");
            JMenuItem ARP_TABLE = new JMenuItem("Table ARP (arp -a)");
            ARP_INFOS.add(ARP_TABLE);
            Analysis.add(ARP_INFOS);

            JMenuItem Infos = new JMenuItem("Points d'accès disponibles (netsh)");
            Wifi.add(Infos);

            Infos.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    String com = "netsh wlan show networks mode=Bssid";

                    try {

                        Process proc = Runtime.getRuntime().exec(com);
                        BufferedReader reader = new BufferedReader(new InputStreamReader(proc.getInputStream()));
                        String out;

                        logs.append(date.date() + "[ netsh command ]" + r);

                        while ((out = reader.readLine()) != null)
                        {

                            if(out.contains("r�seau"))
                            {
                                logs.append(out.replace("r�seau", "réseau") + r);
                            } else
                                {
                                logs.append(out.replace('�',' ') + r);
                            }
                        }
                        logs.append(r);
                    } catch (IOException ioException) {
                        ioException.printStackTrace();
                    }
                }
            });


            ARP_TABLE.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    String com = "arp -a";

                    try {

                        Process proc = Runtime.getRuntime().exec(com);
                        BufferedReader reader = new BufferedReader(new InputStreamReader(proc.getInputStream()));
                        String out;

                        logs.append(date.date() + "[ Table ARP ]" + r);

                        while ((out = reader.readLine()) != null)
                        {
                            if(out.contains("Interface�"))
                            {
                                logs.append(out.replace("Interface�", "Interface") + r);
                            } else {
                                if (out.contains("Internet")) {
                                    logs.append(out.replace("Internet", "IP      ") + r);
                                } else {
                                    logs.append(out + r);
                                }
                            }

                        }

                        logs.append(r);

                    } catch (IOException ioException) {
                        ioException.printStackTrace();
                    }
                }
            });

            // ArrayList<String> bssid = new ArrayList<String>();
            // String com = "chcp 65001 && netsh wlan show networks mode=Bssid";

            // TODO
            // JMenuItem WLANS1 = new JMenuItem("Réseaux");
            // Wifi.add(WLANS1);

            // --------------------------- ARP ------------------------------------ //

            JCheckBoxMenuItem ARP_CAP_ALL_AND_SHOW = new JCheckBoxMenuItem("Afficher la capture");
            JCheckBoxMenuItem ARP_DETECT_SPOOFING = new JCheckBoxMenuItem("Détection - ARP Spoofing");
            JCheckBoxMenuItem ARP_DETECT_MAC_SPOOFING = new JCheckBoxMenuItem("Détection - MAC Spoofing");
            JCheckBoxMenuItem ARP_DETECT_SCAN = new JCheckBoxMenuItem("Détection - Scan ARP");
            JCheckBoxMenuItem ARP_DETECT_NETCUT = new JCheckBoxMenuItem("Détection - Netcut");

            ARP.add(ARP_CAP_ALL_AND_SHOW);
            ARP.add(ARP_DETECT_SPOOFING);
            ARP.add(ARP_DETECT_MAC_SPOOFING);
            ARP.add(ARP_DETECT_SCAN);
            ARP.add(ARP_DETECT_NETCUT);

            // --------------------------- ICMP ------------------------------------ //
            JCheckBoxMenuItem ICMP_CAP_ALL_AND_SHOW = new JCheckBoxMenuItem("Afficher la capture");
            JCheckBoxMenuItem ICMP_DETECT_TUNNEL = new JCheckBoxMenuItem("Détection - Tunnel ICMP");
            JCheckBoxMenuItem ICMP_DETECT_PING_SCAN = new JCheckBoxMenuItem("Détection - Ping Scan");

            ICMP.add(ICMP_CAP_ALL_AND_SHOW);
            ICMP.add(ICMP_DETECT_TUNNEL);
            ICMP.add(ICMP_DETECT_PING_SCAN);

            // --------------------------- IP --------------------------------------- //

            JCheckBoxMenuItem IP_DETECT_SPOOFING = new JCheckBoxMenuItem("Détection - IP Spoofing");
            JCheckBoxMenuItem IP_DETECT_FRAGMENT = new JCheckBoxMenuItem("Détection - Fragmentation IP");

            IP.add(IP_DETECT_SPOOFING);
            IP.add(IP_DETECT_FRAGMENT);

            // --------------------------- TCP ------------------------------------- //

            JCheckBoxMenuItem TCP_CAP_ALL_AND_SHOW = new JCheckBoxMenuItem("Afficher la capture");

            TCP.add(TCP_CAP_ALL_AND_SHOW);

            // --------------------------- UDP ------------------------------------- //

            JCheckBoxMenuItem UDP_CAP_ALL_AND_SHOW = new JCheckBoxMenuItem("Afficher la capture");
            UDP.add(UDP_CAP_ALL_AND_SHOW);

            // --------------------------- SCAAAAAANNNSS ----------------------------- //

            JMenu SCAN_DETECT_CUSTOM_PORTS = new JMenu("Détection de scans sur");
            JMenu SCAN_DETECT_ALL = new JMenu("Détecter tous les scans");

            JCheckBoxMenuItem SCAN_DETECT_FTP = new JCheckBoxMenuItem("FTP");
            JCheckBoxMenuItem SCAN_DETECT_TFTP = new JCheckBoxMenuItem("TFTP");
            JCheckBoxMenuItem SCAN_DETECT_FTPS = new JCheckBoxMenuItem("FTPS");
            JCheckBoxMenuItem SCAN_DETECT_SSH = new JCheckBoxMenuItem("SSH");
            JCheckBoxMenuItem SCAN_DETECT_TELNET = new JCheckBoxMenuItem("TELNET");
            JCheckBoxMenuItem SCAN_DETECT_SMTP = new JCheckBoxMenuItem("SMTP");
            JCheckBoxMenuItem SCAN_DETECT_SMTPS = new JCheckBoxMenuItem("SMTPS");
            JCheckBoxMenuItem SCAN_DETECT_IMAP = new JCheckBoxMenuItem("IMAP");
            JCheckBoxMenuItem SCAN_DETECT_POP3 = new JCheckBoxMenuItem("POP3");
            JCheckBoxMenuItem SCAN_DETECT_DHCP = new JCheckBoxMenuItem("DHCP");
            JCheckBoxMenuItem SCAN_DETECT_LDAP = new JCheckBoxMenuItem("LDAP");
            JCheckBoxMenuItem SCAN_DETECT_MS_SQL = new JCheckBoxMenuItem("MS SQL");
            JCheckBoxMenuItem SCAN_DETECT_MYSQL = new JCheckBoxMenuItem("MY SQL");
            JCheckBoxMenuItem SCAN_DETECT_POSTGRESQL = new JCheckBoxMenuItem("POSTGRESQL");
            JCheckBoxMenuItem SCAN_DETECT_ORACLE_DB = new JCheckBoxMenuItem("ORACLE DATABASE");
            JCheckBoxMenuItem SCAN_DETECT_RDP = new JCheckBoxMenuItem("RDP");
            JCheckBoxMenuItem SCAN_DETECT_VPN_PPTP = new JCheckBoxMenuItem("VPN PPTP");
            JCheckBoxMenuItem SCAN_DETECT_SNMP = new JCheckBoxMenuItem("SNMP");
            JCheckBoxMenuItem SCAN_DETECT_IRC = new JCheckBoxMenuItem("IRC");
            JCheckBoxMenuItem SCAN_DETECT_NETBIOS = new JCheckBoxMenuItem("NETBIOS");
            JCheckBoxMenuItem SCAN_DETECT_DNS = new JCheckBoxMenuItem("DNS");
            JCheckBoxMenuItem SCAN_DETECT_DNS_OVER_TLS = new JCheckBoxMenuItem("DNS (SSL/TLS)");
            JCheckBoxMenuItem SCAN_DETECT_BIND = new JCheckBoxMenuItem("BIND");
            JCheckBoxMenuItem SCAN_DETECT_HTTP = new JCheckBoxMenuItem("HTTP");
            JCheckBoxMenuItem SCAN_DETECT_HTTPS = new JCheckBoxMenuItem("HTTPS");
            JCheckBoxMenuItem SCAN_DETECT_TACACS = new JCheckBoxMenuItem("TACACS+");
            JCheckBoxMenuItem SCAN_DETECT_KERBEROS = new JCheckBoxMenuItem("KEBEROS");
            JCheckBoxMenuItem SCAN_DETECT_NTP = new JCheckBoxMenuItem("NTP");
            JCheckBoxMenuItem SCAN_DETECT_MICROSOFT_DS_ACTIVE_DIR = new JCheckBoxMenuItem("MICROSOFT DS ACTIVE DIRECTORY");
            JCheckBoxMenuItem SCAN_DETECT_DS_SMB = new JCheckBoxMenuItem("MICROSOFT DS SMB FILE SHARING");

            SCAN_DETECT_CUSTOM_PORTS.add(SCAN_DETECT_FTP);
            SCAN_DETECT_CUSTOM_PORTS.add(SCAN_DETECT_TFTP);
            SCAN_DETECT_CUSTOM_PORTS.add(SCAN_DETECT_FTPS);
            SCAN_DETECT_CUSTOM_PORTS.add(SCAN_DETECT_SSH);
            SCAN_DETECT_CUSTOM_PORTS.add(SCAN_DETECT_TELNET);
            SCAN_DETECT_CUSTOM_PORTS.add(SCAN_DETECT_SMTP);
            SCAN_DETECT_CUSTOM_PORTS.add(SCAN_DETECT_SMTPS);
            SCAN_DETECT_CUSTOM_PORTS.add(SCAN_DETECT_IMAP);
            SCAN_DETECT_CUSTOM_PORTS.add(SCAN_DETECT_POP3);
            SCAN_DETECT_CUSTOM_PORTS.add(SCAN_DETECT_DHCP);
            SCAN_DETECT_CUSTOM_PORTS.add(SCAN_DETECT_LDAP);
            SCAN_DETECT_CUSTOM_PORTS.add(SCAN_DETECT_MS_SQL);
            SCAN_DETECT_CUSTOM_PORTS.add(SCAN_DETECT_MYSQL);
            SCAN_DETECT_CUSTOM_PORTS.add(SCAN_DETECT_POSTGRESQL);
            SCAN_DETECT_CUSTOM_PORTS.add(SCAN_DETECT_ORACLE_DB);
            SCAN_DETECT_CUSTOM_PORTS.add(SCAN_DETECT_RDP);
            SCAN_DETECT_CUSTOM_PORTS.add(SCAN_DETECT_VPN_PPTP);
            SCAN_DETECT_CUSTOM_PORTS.add(SCAN_DETECT_SNMP);
            SCAN_DETECT_CUSTOM_PORTS.add(SCAN_DETECT_IRC);
            SCAN_DETECT_CUSTOM_PORTS.add(SCAN_DETECT_NETBIOS);
            SCAN_DETECT_CUSTOM_PORTS.add(SCAN_DETECT_DNS);
            SCAN_DETECT_CUSTOM_PORTS.add(SCAN_DETECT_DNS_OVER_TLS);
            SCAN_DETECT_CUSTOM_PORTS.add(SCAN_DETECT_BIND);
            SCAN_DETECT_CUSTOM_PORTS.add(SCAN_DETECT_HTTP);
            SCAN_DETECT_CUSTOM_PORTS.add(SCAN_DETECT_HTTPS);
            SCAN_DETECT_CUSTOM_PORTS.add(SCAN_DETECT_TACACS);
            SCAN_DETECT_CUSTOM_PORTS.add(SCAN_DETECT_KERBEROS);
            SCAN_DETECT_CUSTOM_PORTS.add(SCAN_DETECT_NTP);
            SCAN_DETECT_CUSTOM_PORTS.add(SCAN_DETECT_DS_SMB);

            SCANS.add(SCAN_DETECT_CUSTOM_PORTS);

            // --------------------------- HTTP ------------------------------------- //

            JMenu HTTP = new JMenu("HTTP");
            JMenu HTTPS = new JMenu("HTTPS");

            JCheckBoxMenuItem HTTP_CAP_ALL_AND_SHOW = new JCheckBoxMenuItem("Afficher la capture");
            JCheckBoxMenuItem HTTP_CAP_HTML = new JCheckBoxMenuItem("Afficher les données HTML");
            HTTP.add(HTTP_CAP_ALL_AND_SHOW);
            HTTP.add(HTTP_CAP_HTML);

            HTTP_S.add(HTTP);
            HTTP_S.add(HTTPS);

            // --------------------------- VoIP ------------------------------------- //


            // --------------------------- VPN ------------------------------------- //


            // --------------------------- VLan ------------------------------------- //


            // --------------------------- Exploits ------------------------------------- //


            // --------------------------- A PROPOS -------------------------------- //

            JMenuItem LICENSE = new JMenuItem("License");
            JMenuItem CONTRAT = new JMenuItem("Contrat");
            JMenuItem RELOAD = new JMenuItem("Relancer");
            About.add(RELOAD);
            About.add(CONTRAT);
            About.add(LICENSE);

            // --------------------------- LOGS ------------------------------------ //

            JCheckBoxMenuItem IP_TO_DOMAIN = new JCheckBoxMenuItem("<html>Résoudre les Adresse IP<br>en noms de domaine");
            JCheckBoxMenuItem SHOW_ID = new JCheckBoxMenuItem("<html>Afficher les numéros<br>de paquets");

            final JMenu FONT_COLOR = new JMenu("Couleur de fond");
            final JMenu TEXT_COLOR = new JMenu("Couleur de texte");
            final JMenu FONT_FAMILY = new JMenu("Police d'écriture");
            final JMenuItem DELETE = new JMenuItem("Effacer");

            // FONT_COLOR
            final JMenuItem BLACK_FONT = new JMenuItem("Noir");
            final JMenuItem GREY_1_FONT = new JMenuItem("Gris clair");
            final JMenuItem GREY_2_FONT = new JMenuItem("Gris foncé");
            final JMenuItem WHITE_FONT = new JMenuItem("Blanc");
            // TEXT_COLOR
            final JMenuItem BLACK_TEXT = new JMenuItem("Noir");
            final JMenuItem  WHITE_TEXT = new JMenuItem("Blanc");
            final JMenuItem BLUE_TEXT = new JMenuItem("Bleu");
            final JMenuItem GREEN_TEXT = new JMenuItem("Hacker Green");
            final JMenuItem RED_PIRATE = new JMenuItem("Rouge Pirate");

            // FONT_FAMILY TODO

            LOGS.add(IP_TO_DOMAIN);
            LOGS.add(SHOW_ID);
            LOGS.add(Analysis);

            LOGS.add(FONT_FAMILY);

            FONT_COLOR.add(BLACK_FONT);
            FONT_COLOR.add(GREY_1_FONT);
            FONT_COLOR.add(GREY_2_FONT);
            FONT_COLOR.add(WHITE_FONT);
            LOGS.add(FONT_COLOR);

            TEXT_COLOR.add(BLACK_TEXT);
            TEXT_COLOR.add(BLUE_TEXT);
            TEXT_COLOR.add(WHITE_TEXT);
            TEXT_COLOR.add(GREEN_TEXT);
            TEXT_COLOR.add(RED_PIRATE);
            LOGS.add(TEXT_COLOR);
            LOGS.add(DELETE);

            // --------------------- NICS --------------------------- //
            JMenuItem INFO_NICS = new JMenuItem("Infos interfaces");

            INTERFACES.add(INFO_NICS);

            for(int interf_to_select = 0; interf_to_select < NICS.size() ; interf_to_select++ )
            {

                JCheckBoxMenuItem INTERF_TO_LISTEN = new JCheckBoxMenuItem(interf_to_select + " - " + NICS.get(interf_to_select).getDescription());
                if (!NICS.get(interf_to_select).getAddresses().isEmpty())
                {
                    var ip_addr_associated = NICS.get(interf_to_select).getAddresses().get(0).getAddr();
                    INTERF_TO_LISTEN.setText(interf_to_select + " - " + NICS.get(interf_to_select).getDescription() + " - " + org.jnetpcap.packet.format.FormatUtils.ip(ip_addr_associated.getData()));
                }

                INTERFACES.add(INTERF_TO_LISTEN);
                INTERF_TO_LISTEN.addActionListener(new ActionListener() {

                    public void actionPerformed(ActionEvent e) {
                        AbstractButton abutton = (AbstractButton) e.getSource();
                        boolean selected = abutton.getModel().isSelected();

                            try{
                                int result = Integer.parseInt(abutton.getActionCommand().substring(0,1));
                                Pcap pcap;

                                // TODO Tester si la capture a été initialisée au dépard ou pas

                                pcap = Pcap.openLive(NICS.get(result).getName(), snaplen, flags, timeout, ERR);



                                if (pcap == null) { System.out.println("Erreur: " + ERR.toString()); return; }

                                    Thread CAAP = new Thread(new Runnable() {
                                        public void run() {
                                            while (true) {
                                               /* try {
                                                    Thread.sleep(1);
                                                } catch (InterruptedException interruptedException) {
                                                    interruptedException.printStackTrace();
                                                }
                                                */ if (ok == 1) {

                                                    PcapPacketHandler icmp_1 = new PcapPacketHandler() {
                                                        @Override
                                                        public void nextPacket(PcapPacket pcapPacket, Object o) {

                                                            if (pcapPacket.iterator().hasNext())
                                                            {
                                                                ++iterator;
                                                                if (options_var.SHOW_ID)
                                                                {
                                                                    p_number = iterator + ". ";
                                                                }
                                                                if (!options_var.SHOW_ID)
                                                                {
                                                                    p_number = "";
                                                                }
                                                            }


                                                            Icmp icmp = new Icmp();
                                                            Arp arp = new Arp();
                                                            Http http = new Http();
                                                            L2TP vpn_l2tp = new L2TP();
                                                            Ethernet ether = new Ethernet();
                                                            Tcp tcp = new Tcp();
                                                            Udp udp = new Udp();
                                                            Html html = new Html();
                                                            IEEE802dot3 ieee802dot3 = new IEEE802dot3();


                                                            IEEE802dot1q vlan_dot1q = new IEEE802dot1q();
                                                            Ip4 ip4 = new Ip4();

                                                            // Ip6 ip6 = new Ip6();

                                                            if (pcapPacket.hasHeader(icmp) && pcapPacket.hasHeader(ip4) && pcapPacket.hasHeader(ether) && options_var.ICMP_CAPTURE_ALL_THE_SHIT) {
                                                                var sMAC = ether.source();
                                                                var dMAC = ether.destination();

                                                                String output = "";

                                                                if (options_var.IP_TO_DOMAIN)
                                                                {
                                                                    try {
                                                                        var sIP = Inet4Address.getByAddress(ip4.source()).getHostName();
                                                                        var dIP = Inet4Address.getByAddress(ip4.destination()).getHostName();
                                                                        output = p_number + "["+ result +"] " + "[" + icmp.getName().toUpperCase() + "] " + date.date() + "[" + org.jnetpcap.packet.format.FormatUtils.mac(sMAC) + " to " + org.jnetpcap.packet.format.FormatUtils.mac(dMAC) + "] " + "[" + icmp.typeEnum() + "] "  +  "[" + sIP + " to " + dIP + "] " + "[Code:" + icmp.code() + " Type:" + icmp.type() + "] [TTL:" + ip4.ttl()  + "] [Fragmenté: " + trad.vrai_faux(ip4.isFragmented()) + "] [Taille:" + pcapPacket.getCaptureHeader().hdr_len() + "] [Somme de contrôle: " + trad.valide(icmp.isChecksumValid()) + "]" + r + r;

                                                                    } catch (UnknownHostException unknownHostException) {
                                                                        unknownHostException.printStackTrace();
                                                                    }
                                                                }

                                                                if (!options_var.IP_TO_DOMAIN)
                                                                {
                                                                    var sIP = ip4.source();
                                                                    var dIP = ip4.destination();
                                                                    output = p_number + "["+ result +"] " + "[" + icmp.getName().toUpperCase() + "] " + date.date() + "[" + org.jnetpcap.packet.format.FormatUtils.mac(sMAC) + " to " + org.jnetpcap.packet.format.FormatUtils.mac(dMAC) + "] " + "[" + icmp.typeEnum() + "] "  +  "[" + org.jnetpcap.packet.format.FormatUtils.ip(sIP) + " to " + org.jnetpcap.packet.format.FormatUtils.ip(dIP) + "] " + "[Code:" + icmp.code() + " Type:" + icmp.type() + "] [TTL:" + ip4.ttl()  + "] [Fragmenté: " + trad.vrai_faux(ip4.isFragmented()) + "] [Taille:" + pcapPacket.getCaptureHeader().hdr_len() + "] [Somme de contrôle: " + trad.valide(icmp.isChecksumValid()) + "]" + r + r;
                                                                }

                                                                if(options_var.ICMP_CAPTURE_ALL_THE_SHIT)
                                                                {
                                                                    logs2.append(output);
                                                                }

                                                                try {

                                                                    File file = new File(HISTORY_PATH_NAME);
                                                                    FileWriter HISTO_WRITER = new FileWriter(file, true);
                                                                    HISTO_WRITER.write(output);
                                                                    HISTO_WRITER.close();

                                                                } catch (IOException ERROR_HISTO) {
                                                                    System.out.println("Erreur d'écriture");
                                                                    ERROR_HISTO.printStackTrace();
                                                                }
                                                            }

                                                            else {
                                                                if (pcapPacket.hasHeader(arp) && pcapPacket.hasHeader(ether) && options_var.ARP_CAPTURE_ALL_THE_SHIT) {


                                                                    var sMAC = ether.source();
                                                                    var dMAC = ether.destination();
                                                                    String output = p_number + "[" + result + "] " + "[" + arp.getName().toUpperCase()  + "] " + date.date() + "[" + org.jnetpcap.packet.format.FormatUtils.mac(sMAC) + " to " + org.jnetpcap.packet.format.FormatUtils.mac(dMAC) + "]"  + " [" + arp.operationDescription() + "] " + "[Sender Hardware Address:" + org.jnetpcap.packet.format.FormatUtils.mac(arp.sha()) + " - Sender Protocol Address:" + org.jnetpcap.packet.format.FormatUtils.ip(arp.spa()) + " - Target Hardware Address:" + org.jnetpcap.packet.format.FormatUtils.mac(arp.tha()) + " - Target Protocol address:" + org.jnetpcap.packet.format.FormatUtils.ip(arp.tpa()) + "]" + r;
                                                                    String output2 = "";

                                                                    if(arp.operation() == 1)
                                                                    {
                                                                        output2 = "[Je suis " + org.jnetpcap.packet.format.FormatUtils.ip(arp.spa()) + ", je veux l'adresse MAC de " + org.jnetpcap.packet.format.FormatUtils.ip(arp.tpa()) + "]" + r;
                                                                    }
                                                                    else
                                                                    {
                                                                        if (arp.operation() == 2)
                                                                        {
                                                                            output2 = "[Salut " + org.jnetpcap.packet.format.FormatUtils.ip(arp.tpa()) + ", je suis " + org.jnetpcap.packet.format.FormatUtils.ip(arp.spa()) + " et mon adresse MAC est: " + org.jnetpcap.packet.format.FormatUtils.mac(arp.sha()) + "]" + r;
                                                                        }
                                                                    }

                                                                    if(options_var.ARP_CAPTURE_ALL_THE_SHIT)
                                                                    {
                                                                        logs2.append(output);
                                                                        logs2.append(output2 + r);
                                                                    }


                                                                    try {
                                                                        File file = new File(HISTORY_PATH_NAME);
                                                                        FileWriter HISTO_WRITER = new FileWriter(file, true);
                                                                        HISTO_WRITER.write(output);
                                                                        HISTO_WRITER.write(output2 + r);
                                                                        HISTO_WRITER.close();

                                                                    } catch (IOException ERROR_HISTO) {
                                                                        System.out.println("Erreur d'écriture");
                                                                        ERROR_HISTO.printStackTrace();
                                                                    }
                                                                } else {
                                                                    if (pcapPacket.hasHeader(ether) && pcapPacket.hasHeader(ip4) && pcapPacket.hasHeader(http))
                                                                    {
                                                                        var sMAC = ether.source();
                                                                        var dMAC = ether.destination();
                                                                        String output = "";

                                                                        if (options_var.IP_TO_DOMAIN)
                                                                        {
                                                                            try {
                                                                                var sIP = Inet4Address.getByAddress(ip4.source()).getHostName();
                                                                                var dIP = Inet4Address.getByAddress(ip4.destination()).getHostName();
                                                                                output = p_number + "[" + result + "] [" + http.getName().toUpperCase() + "] " + date.date() + "[" + org.jnetpcap.packet.format.FormatUtils.mac(sMAC) + " to " + org.jnetpcap.packet.format.FormatUtils.mac(dMAC) + "] [Type: " + http.getMessageType() + "] [" + sIP + " to " + dIP + "]" + "[Taille de l'entête:" + http.getHeaderLength() + "]"  + r + " +Header: " + http.header();


                                                                            } catch (UnknownHostException unknownHostException) {
                                                                                unknownHostException.printStackTrace();
                                                                            }

                                                                        }

                                                                        if (!options_var.IP_TO_DOMAIN)
                                                                        {
                                                                            var sIP = ip4.source();
                                                                            var dIP = ip4.destination();
                                                                            output = p_number + "[" + result + "] [" + http.getName().toUpperCase() + "] " + date.date() + "[" + org.jnetpcap.packet.format.FormatUtils.mac(sMAC) + " to " + org.jnetpcap.packet.format.FormatUtils.mac(dMAC) + "] [Type: " + http.getMessageType() + "] [" + org.jnetpcap.packet.format.FormatUtils.ip(sIP) + " to " + org.jnetpcap.packet.format.FormatUtils.ip(dIP) + "]" + "[Taille de l'entête:" + http.getHeaderLength() + "]"  + r + " +Header: " + http.header();

                                                                        }

                                                                        String output2 = "";

                                                                        if (options_var.HTTP_CAPTURE_ALL_THE_SHIT)
                                                                        {
                                                                            logs2.append(output);
                                                                        }

                                                                        if(pcapPacket.hasHeader(html) && options_var.HTTP_CAPTURE_HTML)
                                                                        {
                                                                            output2 = "[" + html.getName().toUpperCase() + "] +Page: " + html.page()  + r;
                                                                            // ICI TODO POUR ACTIVER AFFICHAGE
                                                                            if(options_var.HTTP_CAPTURE_ALL_THE_SHIT)
                                                                            {
                                                                                logs2.append(output2);
                                                                            }

                                                                        }
                                                                        logs2.append(r);

                                                                        try {
                                                                            File file = new File(HISTORY_PATH_NAME);
                                                                            FileWriter HISTO_WRITER = new FileWriter(file, true);
                                                                            HISTO_WRITER.write(output);
                                                                            HISTO_WRITER.write(output2 + r);
                                                                            HISTO_WRITER.close();

                                                                        } catch (IOException ERROR_HISTO) {
                                                                            System.out.println("Erreur d'écriture");
                                                                            ERROR_HISTO.printStackTrace();
                                                                        }
                                                                    } else {
                                                                        if (pcapPacket.hasHeader(ether) && pcapPacket.hasHeader(ip4) && pcapPacket.hasHeader(tcp))
                                                                        {
                                                                            var sMAC = ether.source();
                                                                            var dMAC = ether.destination();
                                                                            var sPORT = tcp.source();
                                                                            var dPORT = tcp.destination();

                                                                            String output = "";

                                                                            String FLAGS = "";

                                                                            if(tcp.flags_SYN()) { FLAGS += " SYN"; }
                                                                            if(tcp.flags_ACK()) { FLAGS += " ACK"; }
                                                                            if(tcp.flags_PSH()) { FLAGS += " PSH"; }
                                                                            if(tcp.flags_CWR()) { FLAGS += " CWR"; }
                                                                            if(tcp.flags_RST()) { FLAGS += " RST"; }
                                                                            if(tcp.flags_URG()) { FLAGS += " URG"; }
                                                                            if(tcp.flags_ECE()) { FLAGS += " ECE"; }
                                                                            if(tcp.flags_FIN()) { FLAGS += " FIN"; }

                                                                            if (options_var.IP_TO_DOMAIN)
                                                                            {
                                                                                try {
                                                                                    var sIP = Inet4Address.getByAddress(ip4.source()).getHostName();
                                                                                    var dIP = Inet4Address.getByAddress(ip4.destination()).getHostName();
                                                                                    output = "[" + result + "] [" + tcp.getName().toUpperCase() + "] " + date.date() + "[" + org.jnetpcap.packet.format.FormatUtils.mac(sMAC) + " to " + org.jnetpcap.packet.format.FormatUtils.mac(dMAC) + "] [" + sPORT + " -> " + dPORT + "] [" + sIP + " to " + dIP + "] [Flags:" + FLAGS + "]" + r + r;

                                                                                } catch (UnknownHostException unknownHostException) {
                                                                                    unknownHostException.printStackTrace();
                                                                                }
                                                                            }

                                                                            if (!options_var.IP_TO_DOMAIN)
                                                                            {
                                                                                var sIP = ip4.source();
                                                                                var dIP = ip4.destination();
                                                                                output = p_number + "[" + result + "] [" + tcp.getName().toUpperCase() + "] " + date.date() + "[" + org.jnetpcap.packet.format.FormatUtils.mac(sMAC) + " to " + org.jnetpcap.packet.format.FormatUtils.mac(dMAC) + "] [" + sPORT + " -> " + dPORT + "] [" + org.jnetpcap.packet.format.FormatUtils.ip(sIP) + " to " + org.jnetpcap.packet.format.FormatUtils.ip(dIP) + "] [Flags:" + FLAGS + "]" + r + r;

                                                                            }

                                                                            if(options_var.TCP_CAPTURE_ALL_THE_SHIT)
                                                                            {
                                                                                logs2.append(output);
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    };

                                                    PrintStream out = System.out;
                                                    if (ok == 1) {
                                          /*            try {
                                                            Thread.sleep(775);
                                                        } catch (InterruptedException interruptedException) {
                                                            interruptedException.printStackTrace();
                                                        }

                                        */                pcap.loop(1, icmp_1, out); // TODO BUFFER PROBLEM
                                                    } else {
                                                        if (ok == 0)
                                                            pcap.breakloop();
                                                    }
                                                }
                                            }
                                        }
                                    });

                                if(selected)
                                {
                                    logs.append(date.date() + "Interface: " + "[" + result + "] " + NICS.get(result).getDescription() + " sur écoute." + r);
                                    ok = 1;

                                        CAAP.start();
                                        // CAAP_ARP.start();
                                }

                                if (!selected)
                                {
                                    logs.append(date.date() + "Interface: " + "[" + result + "] " + NICS.get(result).getDescription() + " n'est plus sur écoute." + r);
                                    ok = 0;

                                        CAAP.interrupt();
                                        // CAAP_ARP.interrupt();
                                        pcap.breakloop();
                                        pcap.breakloop();

                                        //logs.append("Capture and show desactivated");
                                }
                            } catch (NumberFormatException error)
                            {
                                error.printStackTrace();
                                return;
                            }
                            }


                });


            }


            // LOGS

            JScrollPane scroll = new JScrollPane(logs);
            scroll.setVisible(true);
            scroll.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
            this.add(scroll);

            JScrollPane scroll2 = new JScrollPane(logs2);
            scroll2.setVisible(true);
            scroll2.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
            this.add(scroll2);

            // EVENTS LOGS CUSTOMISATION
            BLACK_TEXT.addActionListener(e -> logs.setForeground(Color.BLACK));
            BLACK_TEXT.addActionListener(e -> logs2.setForeground(Color.BLACK));

            BLUE_TEXT.addActionListener(e -> logs.setForeground(Color.BLUE));
            BLUE_TEXT.addActionListener(e -> logs2.setForeground(Color.BLUE));

            WHITE_TEXT.addActionListener(e -> logs.setForeground(Color.WHITE));
            WHITE_TEXT.addActionListener(e -> logs2.setForeground(Color.WHITE));

            GREEN_TEXT.addActionListener(e -> logs.setForeground(Color.GREEN));
            GREEN_TEXT.addActionListener(e -> logs2.setForeground(Color.GREEN));

            RED_PIRATE.addActionListener(e -> logs.setForeground(Color.decode("#c71212")));
            RED_PIRATE.addActionListener(e -> logs2.setForeground(Color.decode("#c71212")));
            


            addWindowListener(new java.awt.event.WindowAdapter() {
                @Override
                public void windowClosing(java.awt.event.WindowEvent windowEvent) {
                   System.out.println("La fenetre a ete fermée brrrrr");

                   Long PID = sys1.getCurrentPid();
                   String PID_TO_STRING = Long.toString(PID);

                    ProcessBuilder builder = new ProcessBuilder("taskkill", "/F", "/PID", PID_TO_STRING);
                    builder.redirectErrorStream(true);
                    try {
                        Process p = builder.start();
                        BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
                        String line;
                        while (true)
                        {
                            line = r.readLine();
                            if(line == null) { break; }
                            System.out.println(line);
                        }
                    } catch (IOException e) {
                        e.printStackTrace();
                    }

                }
            });


            BLACK_FONT.addActionListener(e -> logs.setBackground(Color.BLACK));
            BLACK_FONT.addActionListener(e -> logs2.setBackground(Color.BLACK));

            GREY_1_FONT.addActionListener(e -> logs.setBackground(Color.GRAY));
            GREY_1_FONT.addActionListener(e -> logs2.setBackground(Color.GRAY));

            GREY_2_FONT.addActionListener(e -> logs.setBackground(Color.DARK_GRAY));
            GREY_2_FONT.addActionListener(e -> logs2.setBackground(Color.DARK_GRAY));

            WHITE_FONT.addActionListener(e -> logs.setBackground(Color.WHITE));
            WHITE_FONT.addActionListener(e -> logs2.setBackground(Color.WHITE));


            // EVENTS NICS
            INFO_NICS.addActionListener(e -> {
                try {
                    network.NICS_DISPO();
                } catch (IOException ioException) {
                    ioException.printStackTrace();
                }
            });

            DELETE.addActionListener(e -> logs.setText(""));
            DELETE.addActionListener(e -> logs2.setText(""));

            SHOW_ID.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    AbstractButton SHOW_ID_PLZ = (AbstractButton) e.getSource();
                    boolean SHOW_ID_SEL = SHOW_ID_PLZ.getModel().isSelected();

                    if(SHOW_ID_SEL)
                    {
                        options_var.SHOW_ID = true;
                    }

                    if(!SHOW_ID_SEL)
                    {
                        options_var.SHOW_ID = false;
                    }

                }
            });

            IP_TO_DOMAIN.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    AbstractButton IP_TO_DOMAIN_PLZ = (AbstractButton) e.getSource();
                    boolean IP_TO_DOMAIN_SEL = IP_TO_DOMAIN_PLZ.getModel().isSelected();
                    if (IP_TO_DOMAIN_SEL)
                    {
                        options_var.IP_TO_DOMAIN = true;
                        logs.append(date.date() + "Les noms de domaine s'affichent au lieu des adresses IP." + r);
                    }

                    if (!IP_TO_DOMAIN_SEL)
                    {
                        options_var.IP_TO_DOMAIN = false;
                        logs.append(date.date() + "Les adresses IP s'affichent au lieu des noms de domaine." + r);

                    }
                }
            });


            ICMP_CAP_ALL_AND_SHOW.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    AbstractButton ICMP_CAPTURE_ALL_THE_SHIT = (AbstractButton) e.getSource();
                    boolean ICMP_CAP_ALL_SHIT_SEL = ICMP_CAPTURE_ALL_THE_SHIT.getModel().isSelected();
                    if(ICMP_CAP_ALL_SHIT_SEL)
                    {
                        options_var.ICMP_CAPTURE_ALL_THE_SHIT = true;
                        logs.append(date.date() + "Affichage de tous les paquets ICMP activé." + r);

                    }

                    if(!ICMP_CAP_ALL_SHIT_SEL) {
                        options_var.ICMP_CAPTURE_ALL_THE_SHIT = false;
                        logs.append(date.date() + "Affichage de tous les paquets ICMP désactivé." + r);

                    }
                }
            });



            ARP_CAP_ALL_AND_SHOW.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    AbstractButton ARP_CAPTURE_ALL_THE_SHIT = (AbstractButton) e.getSource();
                    boolean ARP_CAP_ALL_SHIT_SEL = ARP_CAPTURE_ALL_THE_SHIT.getModel().isSelected();
                    if (ARP_CAP_ALL_SHIT_SEL)
                    {
                        options_var.ARP_CAPTURE_ALL_THE_SHIT = true;
                        logs.append(date.date() + "Affichage de tous les paquets ARP activé." + r);
                    }

                    if (!ARP_CAP_ALL_SHIT_SEL)
                    {
                        options_var.ARP_CAPTURE_ALL_THE_SHIT = false;
                        logs.append(date.date() + "Affichage de tous les paquets ARP désactivé." + r);
                    }

                }
            });



            TCP_CAP_ALL_AND_SHOW.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    AbstractButton TCP_CAPTURE_ALL_THE_SHIT = (AbstractButton) e.getSource();
                    boolean TCP_CAP_ALL_SHIT_SEL = TCP_CAPTURE_ALL_THE_SHIT.getModel().isSelected();
                    if (TCP_CAP_ALL_SHIT_SEL)
                    {
                        options_var.TCP_CAPTURE_ALL_THE_SHIT = true;
                        logs.append(date.date() + "Affichage de tous les paquets TCP activé." + r);
                    }

                    if (!TCP_CAP_ALL_SHIT_SEL)
                    {
                        options_var.TCP_CAPTURE_ALL_THE_SHIT = false;
                        logs.append(date.date() + "Affichage de tous les paquets TCP désactivé." + r);
                    }
                }
            });



            HTTP_CAP_ALL_AND_SHOW.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    AbstractButton HTTP_CAPTURE_ALL_THE_SHIT = (AbstractButton) e.getSource();
                    boolean HTTP_CAP_ALL_SHIT_SEL = HTTP_CAPTURE_ALL_THE_SHIT.getModel().isSelected();
                    if (HTTP_CAP_ALL_SHIT_SEL)
                    {
                        options_var.HTTP_CAPTURE_ALL_THE_SHIT = true;
                        logs.append(date.date() + "Affichage de tous les paquets HTTP activé." + r);
                    }

                    if (!HTTP_CAP_ALL_SHIT_SEL)
                    {
                        options_var.HTTP_CAPTURE_ALL_THE_SHIT = false;
                        logs.append(date.date() + "Affichage de tous les paquets HTTP désactivé." + r);
                    }
                }
            });

            HTTP_CAP_HTML.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    AbstractButton HTTP_CAPTURE_ALL_THE_HTML_SHIT = (AbstractButton) e.getSource();
                    boolean HTTP_CAP_ALL_HTML_SHIT_SEL = HTTP_CAPTURE_ALL_THE_HTML_SHIT.getModel().isSelected();
                    if (HTTP_CAP_ALL_HTML_SHIT_SEL)
                    {
                        options_var.HTTP_CAPTURE_HTML = true;
                        logs.append(date.date() + "Affichage du contenu HTML des paquets HTTP activé." + r);
                    }

                    if (!HTTP_CAP_ALL_HTML_SHIT_SEL)
                    {
                        options_var.HTTP_CAPTURE_HTML = false;
                        logs.append(date.date() + "Affichage du contenu HTML des paquets HTTP désactivé." + r);

                    }
                }
            });



        }
    }


    public static void main(String[] args) throws InterruptedException {

        String CD = System.getProperty("user.dir");
        System.out.println("Current working dir :" + CD);
        System.out.println(System.getProperty("os.arch"));
        System.out.println(System.getProperty("os.name"));
        System.out.println(System.getProperty("os.version"));

        Thread.currentThread().setName("Ceci est le main");

        sys0.GENERAL_DIRECTORY.CREATE_GENERAL_DIRECTORY();
        sys0.GENERAL_DIRECTORY.HISTORY_FILE();
        // sys1.WLAN_SSID_1();


        System.out.println(sys1.getCurrentPid());
        System.out.println(date.FileDate());


        System.out.println();

        main ma = new main();
        ma.setVisible(true);


    }
}