package net.floodlightcontroller.dtguard;

import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.json.JSONArray;
import org.projectfloodlight.openflow.protocol.OFFlowMod;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.types.OFPort;

import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.util.FlowModUtils;
import net.floodlightcontroller.util.MatchUtils;
import net.floodlightcontroller.util.OFMessageDamper;

public class FlowGen {
	private int[] route;
	private String no2Dpid[];
	private Map<String, Map<String, Integer>> linkInfo; // Map<srcDpid, Map<dstDpid, srcPort>>
	private Map<String, DatapathId> dpid2Object;

	private IOFSwitchService switchService;
	protected OFMessageDamper messageDamper;

	private static int OFMESSAGE_DAMPER_CAPACITY = 10000;
	private static int OFMESSAGE_DAMPER_TIMEOUT = 250; // ms

	public FlowGen(int[] route, String[] no2Dpid) {
		this.route = route;
		this.no2Dpid = no2Dpid;
		linkInfo = new HashMap<String, Map<String, Integer>>();
		dpid2Object = new HashMap<String, DatapathId>();
		try {
			initLinks();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	protected void initLinks() throws Exception {
		ICHelper icLinks = new ICHelper(DTDetection.CONTROLLER_URL + "wm/topology/links/json");
		String dataLinks = icLinks.get();
		JSONArray jsonLinks = new JSONArray(dataLinks);
		System.out.println(dataLinks);
		for (int i = 0; i < jsonLinks.length(); ++i) {
			String srcDpid = jsonLinks.getJSONObject(i).getString("src-switch");
			String dstDpid = jsonLinks.getJSONObject(i).getString("dst-switch");
			int srcPort = jsonLinks.getJSONObject(i).getInt("src-port");
			Map<String, Integer> dstList;
			if (linkInfo.containsKey(srcDpid)) {
				dstList = linkInfo.get(srcDpid);
			} else {
				dstList = new HashMap<String, Integer>();
			}
			dstList.put(dstDpid, srcPort);
		}
	}

	public void init(FloodlightModuleContext context) {
		switchService = context.getServiceImpl(IOFSwitchService.class);
		messageDamper = new OFMessageDamper(OFMESSAGE_DAMPER_CAPACITY, EnumSet.of(OFType.FLOW_MOD),
				OFMESSAGE_DAMPER_TIMEOUT);
		for (DatapathId dpid : switchService.getAllSwitchDpids()) {
			for (String dp : no2Dpid) {
				if (dpid.toString().equals(dp)) {
					dpid2Object.put(dp, dpid);
				}
			}
		}
	}

	public void genFlow() {

		for (int i = 1; i < route.length; i++) {
			System.out.println(route[i] + " - " + i + "\t");
			String srcDpid = no2Dpid[route[i]];
			String dstDpid = no2Dpid[i];

			if (linkInfo.containsKey(srcDpid)) {
				Map<String, Integer> dstList = linkInfo.get(srcDpid);
				if (dstList.containsKey(dstDpid)) {
					int srcPort = dstList.get(dstDpid);
					// 下发流表
					OFFlowMod.Builder fmb;
					DatapathId switchDPID = dpid2Object.get(srcDpid);
					IOFSwitch sw = switchService.getSwitch(switchDPID);
					fmb = sw.getOFFactory().buildFlowAdd();

					OFActionOutput.Builder aob = sw.getOFFactory().actions().buildOutput();
					List<OFAction> actions = new ArrayList<>();
					Match match = null;
					Match.Builder mb = MatchUtils.convertToVersion(match, sw.getOFFactory().getVersion());

					// set input and output ports on the switch
					OFPort outPort = sw.getPort(String.valueOf(srcPort)).getPortNo();
					aob.setPort(outPort);
					aob.setMaxLen(Integer.MAX_VALUE);
					actions.add(aob.build());

					fmb.setMatch(mb.build()).setIdleTimeout(0).setHardTimeout(0).setBufferId(OFBufferId.NO_BUFFER)
							.setOutPort(outPort);

					FlowModUtils.setActions(fmb, actions, sw);
					messageDamper.write(sw, fmb.build());
				}
			}
		}
	}

}
