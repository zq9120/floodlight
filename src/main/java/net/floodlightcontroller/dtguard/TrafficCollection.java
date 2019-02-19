package net.floodlightcontroller.dtguard;

import java.util.HashMap;
import java.util.Map;

import org.json.JSONArray;
import org.json.JSONObject;

public class TrafficCollection {

	private int switchCount;
	private int topoMap[][];
	private String no2Dpid[];
	private Map<String, Integer> dpid2No;
	private Map<String, Map<String, Long>> portTraffic; // Map<dpid, Map<pordId, traffic>>
	private final static int QUANT_RATE = 1000;

	public TrafficCollection() {
		dpid2No = new HashMap<String, Integer>();
		portTraffic = new HashMap<String, Map<String, Long>>();
		try {
			initSwitch();
			getTraffic();
			initLinks();
			printTopoTraffic();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	protected void initSwitch() throws Exception {
		// 获取交换机列表
		ICHelper icSwList = new ICHelper(DTDetection.CONTROLLER_URL + "wm/core/controller/switches/json");
		String dataSwList = icSwList.get();
		JSONArray jsonSwList = new JSONArray(dataSwList);
		switchCount = jsonSwList.length();

		// 初始化拓扑
		topoMap = new int[switchCount][switchCount];
		for (int i = 0; i < switchCount; ++i)
			for (int j = 0; j < switchCount; ++j)
				topoMap[i][j] = 0;

		// 初始化no2Dpid、dpid2No
		no2Dpid = new String[switchCount];
		for (int i = 0; i < switchCount; ++i) {
			JSONObject sw = jsonSwList.getJSONObject(i);
			String dpid = sw.getString("switchDPID");
			no2Dpid[i] = dpid;
			dpid2No.put(dpid, i);
		}
	}

	protected void getTraffic() throws Exception {
		for (int i = 0; i < switchCount; ++i) {
			String dpid = no2Dpid[i];

			// 获取端口流量信息
			ICHelper icTraffic = new ICHelper(DTDetection.CONTROLLER_URL + "/wm/core/switch/" + dpid + "/port/json");
			String dataTraffic = icTraffic.get();
			JSONArray jsonTraffic = new JSONObject(dataTraffic).getJSONArray("port_reply").getJSONObject(0)
					.getJSONArray("port");
			Map<String, Long> portInfo = new HashMap<String, Long>();
			for (int j = 0; j < jsonTraffic.length(); ++j) {
				JSONObject jsonPort = jsonTraffic.getJSONObject(j);
				String portId = jsonPort.getString("port_number");
				long traffic = Long.valueOf(jsonPort.getLong("receive_packets"))
						+ Long.valueOf(jsonPort.getLong("transmit_packets"));
				portInfo.put(portId, traffic);
			}
			portTraffic.put(dpid, portInfo);
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
			int weight;
			try {
				weight = (int) (portTraffic.get(srcDpid).get(String.valueOf(srcPort)) / QUANT_RATE);
			} catch (Exception e) {
				weight = 1;
			}
			topoMap[dpid2No.get(srcDpid)][dpid2No.get(dstDpid)] = weight;
			topoMap[dpid2No.get(dstDpid)][dpid2No.get(srcDpid)] = weight;
		}
	}

	protected void printTopoTraffic() {
		System.out.println("============== TopoTraffic ==============");
		for (int i = 0; i < switchCount; ++i) {
			for (int j = 0; j < switchCount; ++j) {
				System.out.print(topoMap[i][j] + "\t");
			}
			System.out.println("\n");
		}
	}

	public int[][] getTopoMap() {
		return this.topoMap;
	}

	public String[] getNo2Dpid() {
		return no2Dpid;
	}

}
