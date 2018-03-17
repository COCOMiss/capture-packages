using PacketDotNet;
using SharpPcap;
using System;
using System.Windows.Forms;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using TwzyProtocol;
using System.Linq;
using System.Windows.Shapes;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows.Threading;
using System.Threading;
using System.Text.RegularExpressions;
using System.Web;

namespace cocoCapture
{
    /// <summary>
    /// MainWindow.xaml 的交互逻辑
    /// </summary>
    public partial class MainWindow : Window
    {

        //  public int aaa;
        public ObservableCollection<PacketItem> packets { get; set; }
       //packet数据包
        public class PacketItem : INotifyPropertyChanged
        {
            private string t;
            private string len;
            private string prot;
            private string srcip;
            private string srcport;
            private string dstip;
            private string dstport;
            private Packet packet;
            private string inf;
            public string time { get { return t; } set { t = value; Notify("time"); } }
            public string length { get { return len; } set { len = value; Notify("length"); } }
            public string protocol { get { return prot; } set { prot = value; Notify("protocol"); } }
            public Packet Packet { get { return packet; } set { packet = value; Notify("Packet"); } }
            public string srcIp { get { return srcip; } set { srcip = value; Notify("srcIp"); } }
            public string srcPort { get { return srcport; } set { srcport = value; Notify("srcPort"); } }
            public string dstIp { get { return dstip; } set { dstip = value; Notify("dstIp"); } }
            public string dstPort { get { return dstport; } set { dstport = value; Notify("dstPort"); } }
            public string information { get { return inf; } set { inf = value; } }


            public event PropertyChangedEventHandler PropertyChanged;
            private void Notify(string propertyName)
            {
                if (PropertyChanged != null)
                {
                    PropertyChanged(this, new PropertyChangedEventArgs(propertyName));
                }
            }
        }


        SharpPcap.CaptureDeviceList devices = SharpPcap.CaptureDeviceList.Instance;




        ICaptureDevice device;
        bool keepCapturing = true;
        static string filterSelect = "";

        string filter = "";
        public MainWindow()
        {

            packets = new ObservableCollection<PacketItem>();
            //packets.Add(new PacketItem() { Info = "test" });
            InitializeComponent();

        }
        //选取网卡
        private void ComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (inters.SelectedIndex < 0)
            {
                return;
            }
            else
            {
                device = devices[inters.SelectedIndex];
            }
        }
        //获取网卡
        private void loadDevice()
        {
            try
            {
                foreach (var dev in devices)
                {
                    inters.Items.Add(dev.Description);
                }
                if (inters.Items.Count > 0)
                {
                    inters.SelectedIndex = 0;//自动选中第一个
                }
            }
            catch (Exception ex)
            {
                //System.Windows.MessageBox.Show(ex.Message);
                return;
            }

        }



        //选取过滤条件
        private void ComboBox_SelectionChanged_1(object sender, SelectionChangedEventArgs e)
        {



            if (selection.SelectedIndex >= 0)
            {

                filterSelect = selection.SelectedItem.ToString();
                Console.WriteLine(filterSelect + "select");
            }
            // Console.WriteLine(tranmissionSelect);
        }

        //添加过滤条件列表中的内容
        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            if (devices.Count < 1)
            {
                Console.WriteLine("No devices were found");
                return;
            }
            selection.Items.Add("tcp and udp");
            selection.Items.Add("Tcp");
            selection.Items.Add("UDP");
            selection.Items.Add("HTTP");
            selection.SelectedIndex = 0;
            filter = selection.SelectedItem.ToString();

            loadDevice();

        }
        //start
        private void start_Click(object sender, RoutedEventArgs e)
        {
            if (device == null || device.Started)
            {
                return;
            }
            try
            {
                device.OnPacketArrival += new PacketArrivalEventHandler(device_OnPacketArrival);
                int readTimeoutMillseconds = 1000;
                device.Open(DeviceMode.Normal, readTimeoutMillseconds);
                if (packetList.Items.Count > 0) {
                   // packetList.ItemsSource = null;
                    packets.Clear();
                }
                //packetList.Items.Clear();
                Console.WriteLine("statr capture");

            }
            catch (Exception ex)
            {
                //System.Windows.MessageBox.Show(ex.Message);
            }

            if (filterSelect == "tcp and udp")
            {
                try
                {
                    filter = "tcp and udp";
                    //device.Filter = filter;
                    device.StartCapture();
                    Console.WriteLine("start capture");
                }
                catch (Exception ex)
                {
                    //System.Windows.MessageBox.Show(ex.Message);
                }

            }
            if (filterSelect == "Tcp")
            {
                filter = "tcp";
                device.Filter = filter;
                device.StartCapture();

            }
            if (filterSelect == "UDP")
            {
                filter = "udp";
                device.Filter = filter;
                device.StartCapture();
            }else if(filterSelect == "HTTP"){
                filter = "tcp and port 80";
                device.Filter = filter;
                device.StartCapture();

            }



        }


        //将数据包加入listView中
        private void device_OnPacketArrival(object sender, CaptureEventArgs packet)
        {
            this.Dispatcher.BeginInvoke(DispatcherPriority.Normal,
            (ThreadStart)delegate()
            {
                //Console.WriteLine("packet caputure");
                AddPacketToList(packet);
            }
            );
        }

        private void AddPacketToList(CaptureEventArgs packet)
        {

            DateTime time = packet.Packet.Timeval.Date;
            int len = packet.Packet.Data.Length;


            //  解析
            try
            {
                var pac = PacketDotNet.Packet.ParsePacket(packet.Packet.LinkLayerType, packet.Packet.Data);
                TcpPacket tcpPacket = TcpPacket.GetEncapsulated(pac);
                UdpPacket udpPacket = UdpPacket.GetEncapsulated(pac);
                if (tcpPacket != null)
                {
                    var ipPacket = (PacketDotNet.IpPacket)tcpPacket.ParentPacket;
                    System.Net.IPAddress srcip = ipPacket.SourceAddress;
                    System.Net.IPAddress dstip = ipPacket.DestinationAddress;
                    int srcport = tcpPacket.SourcePort;
                    int dstport = tcpPacket.DestinationPort;
                    string tcpinf = String.Format("{0}:{1}:{2},{3} Len={4} {5}: {6}->{7}:{8} ", time.Hour, time.Minute, time.Second, "Tcp", len, srcip, srcport, dstip, dstport);
                    string t = String.Format("{0}:{1}:{2}", time.Hour, time.Minute, time.Second);
                    packets.Add(new PacketItem() { Packet = pac, time = t, length = len.ToString(), protocol = "Tcp", srcIp = srcip.ToString(), srcPort = srcport.ToString(), dstIp = dstip.ToString(), dstPort = dstport.ToString(), information = tcpinf });

                }
                if (udpPacket != null)
                {
                    var ipPacket = (PacketDotNet.IpPacket)udpPacket.ParentPacket;
                    System.Net.IPAddress srcip = ipPacket.SourceAddress;
                    System.Net.IPAddress dstip = ipPacket.DestinationAddress;
                    int srcport = udpPacket.SourcePort;
                    int dstport = udpPacket.DestinationPort;
                    string udpinf = String.Format("{0}:{1}:{2},{3} Len={4} {5}: {6}->{7}:{8} ", time.Hour, time.Minute, time.Second, "udp", len, srcip, srcport, dstip, dstport);
                    string t = String.Format("{0}:{1}:{2}", time.Hour, time.Minute, time.Second);
                    packets.Add(new PacketItem() { Packet = pac, time = t, length = len.ToString(), protocol = "udp", srcIp = srcip.ToString(), srcPort = srcport.ToString(), dstIp = dstip.ToString(), dstPort = dstport.ToString(), information = udpinf });
                    //packets.Add(new PacketItem() { Packet = pac, time =udpinf });
                }


            }
            catch (Exception ex)
            {
                //System.Windows.MessageBox.Show(ex.Message);
            }
            
            




        }
        //stop
        private void Button_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (device != null && device.Started)
                {
                    device.StopCapture();
                    device.Close();
                    Console.WriteLine("stop capture");
                }

            }
            catch (Exception ex)
            {
                //System.Windows.MessageBox.Show(ex.Message);
            }


        }




        //获取选定的packet
        private void packetList_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            PacketItem selectedItem = (PacketItem)packetList.SelectedItem;
            //Console.WriteLine("Selceted");
            //Console.WriteLine(selectedItem.Packet);
            ShowDetailTree(selectedItem.Packet,Int32.Parse(selectedItem.length));
        }





        //对选定的packet进行解析
        private void ShowDetailTree(Packet packet,int len)
        {
            
            packTreeView.Items.Clear();
            //add ethernet layer node
            var ethpack = PacketDotNet.EthernetPacket.GetEncapsulated(packet);
            TreeViewItem ethItem=new TreeViewItem() {Header = "Ethernet Layer"};
            ethItem.Items.Add(new TreeViewItem() {Header = "Src MAC:"+ethpack.SourceHwAddress});
            ethItem.Items.Add(new TreeViewItem() { Header ="dst MAC:"+ ethpack.DestinationHwAddress });
            ethItem.Items.Add(new TreeViewItem() { Header ="Layer type:" + ethpack.Type.ToString()});
            packTreeView.Items.Add(ethItem);
            //add over
            

            //ip
            var ip4pack = PacketDotNet.IPv4Packet.GetEncapsulated(packet);
            var ip6pack = PacketDotNet.IPv6Packet.GetEncapsulated(packet);
            Console.WriteLine("ip");
            if (ip4pack != null)
            {
                Console.WriteLine("get ipv4");
                TreeViewItem ipItem=new TreeViewItem() {Header = "Internet Protocol version layer"};
                ipItem.Items.Add(new TreeViewItem() { Header = "Source:" +ip4pack.SourceAddress});
                ipItem.Items.Add(new TreeViewItem() { Header = "Destination:" + ip4pack.DestinationAddress });
                ipItem.Items.Add(new TreeViewItem() {Header= " ip layer type:"+ ip4pack.Version.ToString()});
              
                ipItem.Items.Add(new TreeViewItem() { Header = " HeaderLength: " + ip4pack.HeaderLength });
                ipItem.Items.Add(new TreeViewItem() { Header = " TimeToLive:" + ip4pack.TimeToLive });
                ipItem.Items.Add(new TreeViewItem() { Header = " TotalLength: " + ip4pack.TotalLength });
                ipItem.Items.Add(new TreeViewItem() { Header = " transmission layer protocol: " + ip4pack.Protocol });
                ipItem.Items.Add(new TreeViewItem() { Header = " PayloadLength: " + ip4pack.PayloadLength });

                packTreeView.Items.Add(ipItem);
               // ip4pack.Version.ToString()
            }
            else if(ip6pack != null)
            {
                TreeViewItem ipItem = new TreeViewItem() { Header = "Internet Protocol version layer" };
                ipItem.Items.Add(new TreeViewItem() { Header = "Source:" + ip6pack.SourceAddress });
                ipItem.Items.Add(new TreeViewItem() { Header = "Destination:" + ip6pack.DestinationAddress });
                ipItem.Items.Add(new TreeViewItem() { Header = " ip layer type:" + ip6pack.Version.ToString() });

                ipItem.Items.Add(new TreeViewItem() { Header = " HeaderLength: " + ip6pack.HeaderLength });
                ipItem.Items.Add(new TreeViewItem() { Header = " TimeToLive:" + ip6pack.TimeToLive });
                ipItem.Items.Add(new TreeViewItem() { Header = " TotalLength: " + ip6pack.TotalLength });
                ipItem.Items.Add(new TreeViewItem() { Header = " transmission layer protocol: " + ip6pack.Protocol });
                ipItem.Items.Add(new TreeViewItem() { Header = " PayloadLength: " + ip6pack.PayloadLength });
                packTreeView.Items.Add(ipItem);
            }

            //transport

            var tranUDPpack = PacketDotNet.UdpPacket.GetEncapsulated(packet);
            var tranTCPpack = PacketDotNet.TcpPacket.GetEncapsulated(packet);
            if (tranUDPpack != null)
            {
                TreeViewItem tranItem=new TreeViewItem(){Header="transimssion control protovol"};
                tranItem.Items.Add(new TreeViewItem() { Header = "transimssion layer type:" + tranUDPpack.GetType().ToString() });
                tranItem.Items.Add(new TreeViewItem() { Header = "Source Port:" + tranUDPpack.SourcePort });
                tranItem.Items.Add(new TreeViewItem() { Header = "Destination Port:" + tranUDPpack.DestinationPort });
                tranItem.Items.Add(new TreeViewItem() { Header = "Segment Length:" + tranUDPpack.Length });
                tranItem.Items.Add(new TreeViewItem() { Header = "Checksum:" + tranUDPpack.Checksum });
                tranItem.Items.Add(new TreeViewItem() { Header = "HeaderLength: " + tranUDPpack.Header.Length });
                tranItem.Items.Add(new TreeViewItem() { Header = "PayloadDataLength: " + tranUDPpack.PayloadData.Length });
                tranItem.Items.Add(new TreeViewItem() { Header = "ValidChecksum: " + tranUDPpack.ValidChecksum });
                tranItem.Items.Add(new TreeViewItem() { Header = "ValidUDPChecksum: " + tranUDPpack.ValidUDPChecksum });

                packTreeView.Items.Add(tranItem);

            }

            if (tranTCPpack != null)
            {
                TreeViewItem tranItem = new TreeViewItem() { Header = "transimssion control protovol" };
                tranItem.Items.Add(new TreeViewItem() { Header = "transimssion layer type:" + tranTCPpack.GetType().ToString() });
                tranItem.Items.Add(new TreeViewItem() { Header = "Source Port:" + tranTCPpack.SourcePort });
                tranItem.Items.Add(new TreeViewItem() { Header = "Destination Port:" + tranTCPpack.DestinationPort });
                tranItem.Items.Add(new TreeViewItem() { Header = "Sequence Number:" + tranTCPpack.SequenceNumber });
                tranItem.Items.Add(new TreeViewItem { Header = "Window Size:" + tranTCPpack.WindowSize });
                tranItem.Items.Add(new TreeViewItem() { Header = "Checksum:" + tranTCPpack.Checksum });

                tranItem.Items.Add(new TreeViewItem() { Header = "HeaderLength: " + tranTCPpack.Header.Length });
                tranItem.Items.Add(new TreeViewItem() { Header = "PayloadDataLength: " + tranTCPpack.PayloadData.Length });
                tranItem.Items.Add(new TreeViewItem() { Header = "ValidChecksum: " + tranTCPpack.ValidChecksum });
                tranItem.Items.Add(new TreeViewItem() { Header = "ValidTCPChecksum: " + tranTCPpack.ValidTCPChecksum });
                tranItem.Items.Add(new TreeViewItem() { Header = "ACK: " + tranTCPpack.Ack });
                tranItem.Items.Add(new TreeViewItem() { Header = "ValidTCPChecksum: " + tranTCPpack.AcknowledgmentNumber });
                tranItem.Items.Add(new TreeViewItem() { Header = "SYN: " + tranTCPpack.Syn });
                tranItem.Items.Add(new TreeViewItem() { Header = "WindowSize: " + tranTCPpack.WindowSize });


                packTreeView.Items.Add(tranItem);

            }

            //application
            //get 

            if (tranTCPpack != null)
            {
                if (tranTCPpack.SourcePort == 80 || tranTCPpack.DestinationPort == 80)
                {
                    byte[] data=tranTCPpack.PayloadData;
                    String httpData = System.Text.Encoding.ASCII.GetString(data);
                    if (!String.IsNullOrEmpty(httpData))
                    {
                        HTTPParser(httpData);
                       
                    }

                }
            }

            // var applpac=PacketDotNet.
            //code end here:

            byte[] bytes=new byte[len];
            bytes = packet.Bytes;
            
            //show detail in the right side:
            packDetail.Text = "";
            packASCII.Text = "";
            int i = 0;


                while (i < len)
                {
                    packDetail.Text += String.Format("{0:x2} ", bytes[i]);
                    if (bytes[i] <= 126 && bytes[i] >= 32)
                    {
                        packASCII.Text += ((char)bytes[i]).ToString() + "";
                    }
                    else
                    {
                        packASCII.Text += ". ";
                    }
                    i++;
                    if (i % 4 == 0)
                    {
                        packDetail.Text += "\t";
                        packASCII.Text += " ";
                    }
                    if (i % 16 == 0)
                    {
                        packDetail.Text += "\n";
                        packASCII.Text += "\n";
                    }
                }
            
            
           

        }

        private String tempContent = "";

        //解析http数据
        private void HTTPParser(String httpdata) {
            TreeViewItem tranItem = new TreeViewItem() { Header = "HyperText transfer protocol" };
            int dataendIndex = -1;
            for (int i = 0; i < httpdata.Length-4; i++) {
                if (httpdata[i] == '\r' && httpdata[i + 1] == '\n'&&httpdata[i+2]=='\r'&&httpdata[i+3]=='\n') {
                    dataendIndex = i;
                }
            }
            string contentType = "";
            string charset = "";
            if (dataendIndex > 0)
            {
                String infoStr = httpdata.Substring(0, dataendIndex);
                String[] infos = infoStr.Split(new char[2] { '\r', '\n' });
                foreach (String info in infos)
                {
                    if (!String.IsNullOrEmpty(info))
                    {
                        tranItem.Items.Add(new TreeViewItem() { Header = info });
                        if (info.Length > 12) {
                            if (info.Substring(0, 12) == "Content-Type")
                             {
                        // string[]resultString=Regex.Split(content,small,RegexOptions.IgnoreCase)
                            string[] con= Regex.Split(info,": ",RegexOptions.IgnoreCase);

                            string[] content = Regex.Split(con[1], "; ", RegexOptions.IgnoreCase);
                              if (content.Length > 1)
                              {
                                  contentType = content[0];
                                 
                                //  string[] content2 = content[1].Split('=',' ');
                                  string[] content2 = Regex.Split(content[1], "=",RegexOptions.IgnoreCase);
                                  charset = content2[1];
                                  Console.WriteLine(contentType);
                                  Console.WriteLine(charset);

                              }
                              else
                              {
                                  contentType = content[0];
                              }
                        }
                       
                             
                        }
                    }
                }



                    if (dataendIndex + 4 <= httpdata.Length) 
                    {

                          if (contentType.Contains("text")&&charset=="utf-8" )
                            {

                                string httpContent = httpdata.Substring(dataendIndex + 4);
                                 byte[] srcBytes = GetBytes(httpContent);
                                
                       // string  httpContentgbk=Encoding.GetEncoding("GBK").GetString(Encoding.Default.GetBytes(httpContent));
                                byte[] dstBytes = Encoding.Convert(Encoding.Default, Encoding.UTF8, srcBytes);
                                httpContent = GetString(dstBytes);
                                tempContent = httpContent;
                                TreeViewItem contentItem = new TreeViewItem() { Header = "http content" };
                                contentItem.MouseDoubleClick += contentItem_MouseDoubleClick;
                                tranItem.Items.Add(contentItem);
                             }
                          else if (contentType.Contains("text") && charset == "gb2312")
                          {
                              string httpContent = httpdata.Substring(dataendIndex + 4);
                              string httpContentgbk = Encoding.GetEncoding("GBK").GetString(Encoding.Default.GetBytes(httpContent));
                              tempContent = httpContentgbk;
                              TreeViewItem contentItem = new TreeViewItem() { Header = "http content" +httpContentgbk};
                              contentItem.MouseDoubleClick += contentItem_MouseDoubleClick;
                              tranItem.Items.Add(contentItem);


                          }


                          else
                          {
                              string httpContent = httpdata.Substring(dataendIndex + 4);
                              tempContent = httpContent;
                              TreeViewItem contentItem = new TreeViewItem() { Header = "http content" };
                              contentItem.MouseDoubleClick += contentItem_MouseDoubleClick;
                              tranItem.Items.Add(contentItem);
                          }



                }
              
                
                
            }
            //Console.WriteLine(httpData);
            packTreeView.Items.Add(tranItem);
        }

        void contentItem_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            System.Windows.MessageBox.Show(tempContent, "Content");
        }

        static byte[] GetBytes(string str)
        {
            byte[] bytes = new byte[str.Length * sizeof(char)];
            System.Buffer.BlockCopy(str.ToCharArray(), 0, bytes, 0, bytes.Length);
            return bytes;
        }

        static string GetString(byte[] bytes)
        {
            char[] chars = new char[bytes.Length / sizeof(char)];
            System.Buffer.BlockCopy(bytes, 0, chars, 0, bytes.Length);
            return new string(chars);
        }

        private void treeview_httpContent(object sender, MouseButtonEventArgs e)
        {
            

            return;
        }
    
       
 
        

    }
}