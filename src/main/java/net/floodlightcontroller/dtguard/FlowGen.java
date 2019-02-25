package net.floodlightcontroller.dtguard;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import org.json.JSONArray;
import org.json.JSONObject;

public class FlowGen {
	private int[] route;
	private String no2Dpid[];
	private Map<String, Map<String, Integer>> linkInfo; // Map<dstDpid, Map<srcDpid, dstPort>>

	public FlowGen(int[] route, String[] no2Dpid) {
		this.route = route;
		this.no2Dpid = no2Dpid;
		linkInfo = new HashMap<String, Map<String, Integer>>();
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

		for (int i = 0; i < jsonLinks.length(); ++i) {
			String srcDpid = jsonLinks.getJSONObject(i).getString("src-switch");
			String dstDpid = jsonLinks.getJSONObject(i).getString("dst-switch");
			int dstPort = jsonLinks.getJSONObject(i).getInt("src-port");
			Map<String, Integer> dstList;
			if (linkInfo.containsKey(dstDpid)) {
				dstList = linkInfo.get(dstDpid);
			} else {
				dstList = new HashMap<String, Integer>();
			}
			dstList.put(srcDpid, dstPort);
		}
	}

	public void genCommonFlow() throws IOException {
		for (int i = 1; i < no2Dpid.length; i++) {
			JSONObject params = new JSONObject();
			params.put("switch", no2Dpid[i]);
			params.put("tos-bits", "0xef");
			params.put("name", "dt-guard-c" + i);
			params.put("priority", "50");
			params.put("active", "true");
			ICHelper ic = new ICHelper(DTDetection.CONTROLLER_URL + "wm/staticflowentrypusher/json");
			ic.post(params.toString());
		}
	}

	public void genFlow() throws IOException {
		for (int i = 1; i < route.length; i++) {
			System.out.println(route[i] + " - " + i + "\t");
			String srcDpid = no2Dpid[route[i]];
			String dstDpid = no2Dpid[i];
			if (linkInfo.containsKey(dstDpid)) {
				Map<String, Integer> dstList = linkInfo.get(dstDpid);
				if (dstList.containsKey(srcDpid)) {
					int srcPort = dstList.get(srcDpid);
					JSONObject params = new JSONObject();
					params.put("switch", no2Dpid[i]);
					params.put("src-port", String.valueOf(srcPort));
					params.put("tos-bits", "0xef");
					params.put("name", "dt-guard-c" + i);
					params.put("priority", "1");
					params.put("active", "true");
					params.put("action", "output=flood");
					ICHelper ic = new ICHelper(DTDetection.CONTROLLER_URL + "wm/staticflowentrypusher/json");
					ic.post(params.toString());
				}
			}
		}
	}

}
