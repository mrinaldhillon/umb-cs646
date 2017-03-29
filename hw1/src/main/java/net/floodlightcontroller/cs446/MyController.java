package net.floodlightcontroller.cs446;

import java.util.ArrayList;
import java.util.Collection;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentSkipListSet;

import org.projectfloodlight.openflow.protocol.OFFactory;
import org.projectfloodlight.openflow.protocol.OFFlowAdd;
import org.projectfloodlight.openflow.protocol.OFFlowMod;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFPacketOut;
import org.projectfloodlight.openflow.protocol.OFPortDesc;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.OFVersion;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
import org.projectfloodlight.openflow.protocol.action.OFActions;
import org.projectfloodlight.openflow.protocol.instruction.OFInstructionApplyActions;
import org.projectfloodlight.openflow.protocol.instruction.OFInstructions;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IPv4AddressWithMask;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.TableId;
import org.projectfloodlight.openflow.types.U64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.core.util.AppCookie;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPacket;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.util.FlowModUtils;
import net.floodlightcontroller.util.OFMessageDamper;
import net.floodlightcontroller.util.OFMessageUtils;

public class MyController implements IOFMessageListener, IFloodlightModule {

  protected IFloodlightProviderService floodlightProvider;

  protected static Logger logger;

  protected OFMessageDamper messageDamper;
  private int OFMESSAGE_DAMPER_CAPACITY = 10000;
  private int OFMESSAGE_DAMPER_TIMEOUT = 250; // ms
  public static final int FORWARDING_APP_ID = 446;

  private static final int MODFLOW_IDLE_TIMEOUT = 5;
  private static final int MODFLOW_HARD_TIMEOUT = 10;
  private static final int MODFLOW_PRIORITY = 1000;

  private int last_used_oport = -1;
  private static final String SW1_ID = "00:00:00:00:00:00:00:01";
  private static final String SW2_ID = "00:00:00:00:00:00:00:02";
  private static final String SW3_ID = "00:00:00:00:00:00:00:03";
  private static final String SW4_ID = "00:00:00:00:00:00:00:04";

  private static final String H1_IP = "10.0.0.1";
  private static final String H4_IP = "10.0.0.2";
  private static final String DEFAULT_FORWARDING_CONTROLLER_NAME = "forwarding";
  private static final String MY_FORWARDING_CONTROLLER_NAME = "forwarding";

  static {
    AppCookie.registerApp(FORWARDING_APP_ID, MY_FORWARDING_CONTROLLER_NAME);
  }
  protected static final U64 cookie = AppCookie.makeCookie(FORWARDING_APP_ID, 0);
  @Override
  public String getName() {
    // TODO Auto-generated method stub
    return MyController.class.getSimpleName();
  }

  @Override
  public boolean isCallbackOrderingPrereq(OFType type, String name) {
    // TODO Auto-generated method stub
    return false;
  }

  @Override
  public boolean isCallbackOrderingPostreq(OFType type, String name) {
    // Force "forwarding" controller to be handle packets after MyController.
    if (name.equals(DEFAULT_FORWARDING_CONTROLLER_NAME)) return true;
    return false;
  }

  @Override
  public Collection<Class<? extends IFloodlightService>> getModuleServices() {
    // TODO Auto-generated method stub
    return null;
  }

  @Override
  public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
    // TODO Auto-generated method stub
    return null;
  }

  @Override
  public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
    // TODO Auto-generated method stub
    Collection<Class<? extends IFloodlightService>> l =
      new ArrayList<Class<? extends IFloodlightService>>();
    l.add(IFloodlightProviderService.class);
    return l;
  }

  @Override
  public void init(FloodlightModuleContext context) throws FloodlightModuleException {
    // TODO Auto-generated method stub
    floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
    logger = LoggerFactory.getLogger(MyController.class);

    messageDamper = new OFMessageDamper(OFMESSAGE_DAMPER_CAPACITY,
        EnumSet.of(OFType.FLOW_MOD),
        OFMESSAGE_DAMPER_TIMEOUT);

  }

  @Override
  public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
    // TODO Auto-generated method stub
    floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);

  }

  private Match createMyMatchFromPacket(IOFSwitch sw, OFPort inPort, EthType ethType, 
      MacAddress srcMac, MacAddress destMac, IPv4Address srcIp, IPv4Address destIp) {
    Match.Builder mb = sw.getOFFactory().buildMatch()
      .setExact(MatchField.IN_PORT, inPort)
      .setExact(MatchField.ETH_TYPE, ethType)
      .setExact(MatchField.ETH_SRC, srcMac)
      .setExact(MatchField.ETH_DST, destMac)
      .setExact(MatchField.IPV4_SRC, srcIp)
      .setExact(MatchField.IPV4_DST, destIp);
    return mb.build();
  }

  private void writeMyFlowMod(IOFSwitch sw, Match match, OFPort outPort) {
    OFFactory myFactory=sw.getOFFactory();
    OFFlowMod.Builder fmb;
    OFActions actions = myFactory.actions();

    ArrayList<OFAction> actionList = new ArrayList<OFAction>();
    OFActionOutput output = actions.buildOutput()
      .setPort(outPort)
      .setMaxLen(0xFFffFFff)
      .build();
    actionList.add(output);

    fmb=myFactory.buildFlowAdd()
      .setMatch(match)
      .setCookie(cookie)
      .setIdleTimeout(MODFLOW_IDLE_TIMEOUT)
      .setHardTimeout(MODFLOW_HARD_TIMEOUT)
      .setPriority(MODFLOW_PRIORITY)
      .setBufferId(OFBufferId.NO_BUFFER)
      .setOutPort(outPort)
      .setActions(actionList);

    messageDamper.write(sw, fmb.build());
  }

  private void addMyFlow(IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx) throws UnsupportedOperationException {
    int oport = -1;
    OFPort inPort = (pi.getVersion().compareTo(OFVersion.OF_12) < 0 
        ? pi.getInPort() : pi.getMatch().get(MatchField.IN_PORT));

    Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, 
        IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
    MacAddress srcMac = eth.getSourceMACAddress();
    MacAddress destMac = eth.getDestinationMACAddress();
    IPv4 pkt = (IPv4) eth.getPayload();
    IPv4Address srcIp = pkt.getSourceAddress();
    IPv4Address destIp = pkt.getDestinationAddress();
    String srcIpString = pkt.getSourceAddress().toString();
    String destIpString = pkt.getDestinationAddress().toString();

    if (!srcIpString.equals(H1_IP) || !destIpString.equals(H4_IP)) {
      throw new UnsupportedOperationException("MyController does not handle flow from"
          + srcIpString + " to " + destIpString);
    }

    String swId = sw.getId().toString();
    switch(swId) {
      case SW1_ID:
               if (1 != inPort.getPortNumber()) {
                 throw new UnsupportedOperationException("MyController does not handle flow of Switch Id:" 
                     +  sw.getId().toString() + "InPort:" + inPort.getPortNumber());
               }
               oport = 2 == last_used_oport ? 3 : 2;
               logger.info("Last Used OutPort:{}", Integer.toString(last_used_oport));         
               // Set previous port
               last_used_oport = oport;
               break;
      case SW2_ID:
      case SW3_ID:
               if (1 != inPort.getPortNumber()) {
                 throw new UnsupportedOperationException("MyController does not handle flow of Switch Id:" 
                     +  sw.getId().toString() + "InPort:" + inPort.getPortNumber());
               }
               oport = 2;
               break;
      case SW4_ID:
               if (1 != inPort.getPortNumber() && 2 != inPort.getPortNumber()) {
                 throw new UnsupportedOperationException("MyController does not handle flow of Switch Id:" 
                     +  sw.getId().toString() + "InPort:" + inPort.getPortNumber());
               }
               oport = 3;
               break;
      default:
               throw new UnsupportedOperationException("MyController does not handle flow of Switch Id:" 
                   +  sw.getId().toString() + "InPort:" + inPort.getPortNumber());
    }

    logger.info("Switch Id:{}", swId);         
    logger.info("InPort:{}, OutPort:{}", Integer.toString(inPort.getPortNumber()), Integer.toString(oport));
    Match m = createMyMatchFromPacket(sw, inPort, EthType.IPv4, 
        srcMac, destMac, srcIp, destIp);
    writeMyFlowMod(sw, m, OFPort.of(oport));
  }

  @Override
  public net.floodlightcontroller.core.IListener.Command receive(IOFSwitch sw, OFMessage msg,
      FloodlightContext cntx) {
    Command cmd = Command.CONTINUE;
    try {
      switch(msg.getType()){
        case PACKET_IN:
          Ethernet eth =
            IFloodlightProviderService.bcStore.get(cntx,
                IFloodlightProviderService.CONTEXT_PI_PAYLOAD);

          MacAddress srcMac = eth.getSourceMACAddress();
          if(eth.getEtherType()==EthType.IPv4){
            IPv4 pkt = (IPv4) eth.getPayload();
            if(pkt.getProtocol()== IpProtocol.ICMP){
              logger.info("Src MAC:{}, Src IP:{}",
                  srcMac.toString(),
                  pkt.getSourceAddress().toString());
              logger.info("ip port:{}",
                  Integer.toString( ((OFPacketIn)msg).getInPort().getPortNumber() ));

              addMyFlow(sw, (OFPacketIn)msg, cntx);
              /* Stop this message from being handled by other PACKET_IN handlers i.e. Forwarding Controller.
               * This combined with making sure that "forwarding" Controller is called after MyController 
               *    (see isCallbackOrderingPostreq) completely disables Forwarding Controller for this message.
               *    */  
              cmd = Command.STOP;
            }
          }
          break;
        default:
          break;
      }
    } catch (UnsupportedOperationException e) {
      //logger.info(e.getMessage());
      /* Exception is thrown by addMyFlow if the packet flow is not handle by MyController 
       * For ex. response from H4 to H1 will come here. 
       * In such case only, should the forwarding controller be called other rules message rules are
       * exclusively set by by MyController. */
      cmd = Command.CONTINUE;
    } finally {
      return cmd;
    }
  }
}
