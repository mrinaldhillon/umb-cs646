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
  private int prev_oport = -1;
  public static final int FORWARDING_APP_ID = 446;
  static {
    AppCookie.registerApp(FORWARDING_APP_ID, "forwarding");
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
    // TODO Auto-generated method stub
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

  @Override
  public net.floodlightcontroller.core.IListener.Command receive(IOFSwitch sw, OFMessage msg,
      FloodlightContext cntx) {
    // TODO Auto-generated method stub
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
            if (sw.getId().toString().equals("00:00:00:00:00:00:00:01") 
                && pkt.getSourceAddress().toString().equals("10.0.0.1")) {
              addMyFlowSW1SrcH1(sw);
            } else {
              addMyFlow(sw);
            }
            // addMyFlow(sw);
            //return Command.STOP;
          }
        }
        break;
      default:
        break;
    }
    return Command.CONTINUE;
  }

  void addMyFlow(IOFSwitch sw){
    OFFlowMod.Builder fmb;
    OFFactory myFactory=sw.getOFFactory();
    fmb=myFactory.buildFlowAdd();

    Match myMatch = myFactory.buildMatch()
      .setExact(MatchField.IN_PORT, OFPort.of(1))
      .setExact(MatchField.ETH_TYPE, EthType.IPv4)
      .setMasked(MatchField.IPV4_SRC, IPv4AddressWithMask.of("10.0.0.1/24"))
      .setExact(MatchField.IP_PROTO, IpProtocol.TCP)
      //.setExact(MatchField.TCP_DST, TransportPort.of(80))
      .build();

    ArrayList<OFAction> actionList = new ArrayList<OFAction>();
    OFActions actions = myFactory.actions();

    OFActionOutput output = actions.buildOutput()
      .setMaxLen(0xFFffFFff)
      .setPort(OFPort.of(2))
      .build();
    actionList.add(output);

    fmb
      .setIdleTimeout(5)
      .setHardTimeout(5)
      .setBufferId(OFBufferId.NO_BUFFER)
      .setCookie(cookie)
      .setPriority(1)
      .setMatch(myMatch);

    FlowModUtils.setActions(fmb, actionList, sw);
    messageDamper.write(sw, fmb.build());
  }

  void addMyFlowSW1SrcH1(IOFSwitch sw){
    OFFlowMod.Builder fmb;
    OFFactory myFactory=sw.getOFFactory();
    fmb=myFactory.buildFlowAdd();

    Match myMatch = myFactory.buildMatch()
      .setExact(MatchField.IN_PORT, OFPort.of(1))
      .setExact(MatchField.ETH_TYPE, EthType.IPv4)
      .setExact(MatchField.IPV4_SRC, IPv4Address.of("10.0.0.1"))
      .setExact(MatchField.IPV4_DST, IPv4Address.of("10.0.0.2"))
      .setExact(MatchField.ETH_SRC, MacAddress.of("7e:57:ef:c6:ae:ce"))
      .setExact(MatchField.ETH_DST, MacAddress.of("12:c2:b9:83:6e:eb"))
    //  .setExact(MatchField.IP_PROTO, IpProtocol.TCP)
      //.setExact(MatchField.TCP_DST, TransportPort.of(80))
      .build();

    ArrayList<OFAction> actionList = new ArrayList<OFAction>();
    OFActions actions = myFactory.actions();

    int oport = 2 == prev_oport ? 3 : 2;
    System.out.println("Switch Id: " + sw.getId());
    System.out.println("Previous OutPort: " + prev_oport);
    System.out.println("Selected OutPort: " + oport);
    prev_oport = oport;

    OFActionOutput output = actions.buildOutput()
      .setMaxLen(0xFFffFFff)
      .setPort(OFPort.of(oport))
      .build();
    actionList.add(output);

    fmb
      .setIdleTimeout(5)
      .setHardTimeout(5)
      .setBufferId(OFBufferId.NO_BUFFER)
      .setCookie(cookie)
      .setPriority(1)
      .setMatch(myMatch);

    FlowModUtils.setActions(fmb, actionList, sw);
    messageDamper.write(sw, fmb.build());
  }
}
