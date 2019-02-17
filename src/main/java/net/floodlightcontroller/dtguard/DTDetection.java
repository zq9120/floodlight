package net.floodlightcontroller.dtguard;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Timer;
import java.util.TimerTask;

import org.json.JSONArray;
import org.json.JSONObject;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.types.EthType;
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
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;

public class DTDetection implements IOFMessageListener, IFloodlightModule {

	protected IFloodlightProviderService floodlightProvider;
	protected static Logger logger;
	protected static List<String> commAddrMap; // 存储格式 src_mac-dst_mac，用于计算对流比
	protected static int packetInCount = 0; // 收到packetIn数据包的数量，用于计算flood触发比例
	public static int floodCount = 0; // 执行了flood操作的packetIn数据包数量，用于计算flood触发比例
	public static int flowModCount = 0; // 下发流规则的数量，用于计算流包数均值
	public static int forwardPacketInCount = 0;
	protected static Map<String, List<String>> commAddrList; // Map<srcMac, List<dstMac>>，用于计算目的IP地址熵值
	protected static Map<String, List<String>> commAddrListFull;

	protected static int flowCount = 0;
	protected static int packetCount = 0;
	protected static int byteCount = 0;

	protected static int attackCount = 0;

	protected static final String CONTROLLER_URL = "http://127.0.0.1:8080/";
	protected static final String CONFIG_PATH = "/home/zhangziqi/Documents/scripts/config.txt";
	protected static final String OUTDATA_PATH = "/home/zhangziqi/Documents/scripts/statistic.csv";
	protected static final int PERIOD = 10000;
	protected static int ATTACK_RATE = 0;
	protected static int REPEAT_COUNT_LIMIT = 5;
	protected static int repeatCount = 0;

	@Override
	public void init(FloodlightModuleContext context) throws FloodlightModuleException {
		FileUtils.writeFile(CONFIG_PATH, "-1");
		FileUtils.writeFile(OUTDATA_PATH, "");
		floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
		logger = LoggerFactory.getLogger(DTDetection.class);
		commAddrMap = new ArrayList<String>();
		commAddrList = new HashMap<String, List<String>>();
		commAddrListFull = new HashMap<String, List<String>>();
		Timer timer = new Timer();
		timer.schedule(new StaticCalc(), PERIOD, PERIOD);
	}

	@Override
	public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IFloodlightProviderService.class);
		return l;
	}

	@Override
	public String getName() {
		return DTDetection.class.getSimpleName();
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		return false;
	}

	@Override
	public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		switch (msg.getType()) {
		case PACKET_IN:
			Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
			if (eth.getEtherType() != EthType.IPv4)
				break;

			IPv4 ipv4 = (IPv4) eth.getPayload();
			String srcIP = ipv4.getSourceAddress().toString();
			String dstIP = ipv4.getDestinationAddress().toString();

			String payload = new String(eth.getPayload().serialize());
			if (payload.contains("SDN_ATTACK_PAYLOAD"))
				attackCount++;

			String commAddrKey = srcIP + "-" + dstIP;
			if (!commAddrMap.contains(commAddrKey))
				commAddrMap.add(commAddrKey);

			List<String> dstList;
			if (commAddrList.containsKey(srcIP)) {
				dstList = commAddrList.get(srcIP);
			} else {
				dstList = new ArrayList<String>();
				commAddrList.put(srcIP, dstList);
			}
			if (!dstList.contains(dstIP))
				dstList.add(dstIP);

			List<String> dstListFull;
			if (commAddrListFull.containsKey(srcIP)) {
				dstListFull = commAddrListFull.get(srcIP);
			} else {
				dstListFull = new ArrayList<String>();
				commAddrListFull.put(srcIP, dstListFull);
			}
			dstListFull.add(dstIP);

			packetInCount++;
			break;
		default:
			break;
		}
		return Command.CONTINUE;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		return null;
	}

	class StaticCalc extends TimerTask {

		public void run() {
			try {
				logger.info("======== StaticCalc ========");

				ICHelper icSwList = new ICHelper(CONTROLLER_URL + "wm/core/controller/switches/json");
				String dataSwList = icSwList.get();
				JSONArray jsonSwList = new JSONArray(dataSwList);
				for (int i = 0; i < jsonSwList.length(); ++i) {
					JSONObject sw = jsonSwList.getJSONObject(i);
					String dpid = sw.getString("switchDPID");
					ICHelper icAggregate = new ICHelper(CONTROLLER_URL + "wm/core/switch/" + dpid + "/aggregate/json");
					String dataAggregate = icAggregate.get();
					JSONObject jsonAggregate = new JSONObject(dataAggregate);
					flowCount += jsonAggregate.getJSONObject("aggregate").getInt("flow_count");
					packetCount += jsonAggregate.getJSONObject("aggregate").getInt("packet_count");
					byteCount += jsonAggregate.getJSONObject("aggregate").getInt("byte_count");
				}

				int totalCommCount, interactionCommCount;
				synchronized (commAddrMap) {
					totalCommCount = commAddrMap.size(); // 总的流数量
					interactionCommCount = 0;
					for (int i = 0; i < commAddrMap.size(); ++i) {
						if (commAddrMap.get(i).contains("-")) {
							String items[] = commAddrMap.get(i).split("-");
							String key = items[1] + "-" + items[0];
							if (commAddrMap.contains(key))
								interactionCommCount++;
						}
					}
				}

				int totalSrcAddrCount, totalDstAddrCount;
				synchronized (commAddrList) {
					totalSrcAddrCount = commAddrList.size();
					totalDstAddrCount = 0;
					for (String key : commAddrList.keySet()) {
						totalDstAddrCount += commAddrList.get(key).size();
					}
				}

				// 攻击速率
				double attackRate = (float) attackCount / (PERIOD / 1000);

				// 流表匹配成功率 = 1 - PACKET_IN数量 / 数据包的数量 (攻击时减小)
				double flowTableMatchSuccessRate = 1 - ((float) packetInCount * 100 / packetCount);

				// 对流比 = 有交互的流数量 / 总的流数量 (攻击时减小)
				double interactionCommRate = (float) interactionCommCount / totalCommCount;

				// FLOOD触发比例 = 触发FLOOD操作的PACKET_IN数量 / PACKET_IN数量 (攻击时增大)
				double floodRate = (float) floodCount / forwardPacketInCount;

				// 平均通信主机数 = 目的IP地址数 / 源IP地址数 (攻击时增大)
				double avgCommHostCount = (float) totalDstAddrCount / totalSrcAddrCount;

				double entropy = entropy();

				// FLOW_MOD比例 = 下发流规则的数量 / PACKET_IN数量 (攻击时减小)
				double flowModRate = (float) flowModCount / packetInCount;

				// 流包数均值 = 下发流规则的数量 / 数据包的数量 (攻击时增大)
				double avgFlowPacket = (float) packetCount / flowCount;

				if (packetCount == 0)
					flowTableMatchSuccessRate = 0;

				if (totalCommCount == 0)
					interactionCommRate = 0;

				if (packetInCount == 0)
					floodRate = 0;

				if (totalSrcAddrCount == 0)
					avgCommHostCount = 0;

				if (packetInCount == 0)
					flowModRate = 0;

				if (packetInCount == 0)
					avgFlowPacket = 0;

				logger.info("attackRate = {} / ({} / 1000)", attackCount, PERIOD);
				logger.info("flowTableMatchSuccessRate = 1 - ({} / {})", packetInCount, packetCount);
				logger.info("interactionCommRate = {} / {}", interactionCommCount, totalCommCount);
				logger.info("floodRate = {} / {}", floodCount, forwardPacketInCount);
				logger.info("avgCommHostCount = {} / {}", totalDstAddrCount, totalSrcAddrCount);
				logger.info("flowModRate = {} / {}", flowModCount, packetInCount);
				logger.info("avgFlowPacket = {} / {}", packetCount, flowCount);

				logger.info("--------------------------------------------------------");

				logger.info("attackRate = {}", String.valueOf(attackRate));
				logger.info("flowTableMatchSuccessRate = {}", String.valueOf(flowTableMatchSuccessRate));
				logger.info("interactionCommRate = {}", String.valueOf(interactionCommRate));
				logger.info("floodRate = {}", String.valueOf(floodRate));
				logger.info("avgCommHostCount = {}", String.valueOf(avgCommHostCount));
				logger.info("entropy = {}", String.valueOf(entropy));
				logger.info("flowModRate = {}", String.valueOf(flowModRate));
				logger.info("avgFlowPacket = {}", String.valueOf(avgFlowPacket));

				synchronized (commAddrMap) {
					commAddrMap.clear();
				}
				packetInCount = 0;
				floodCount = 0;
				flowModCount = 0;
				forwardPacketInCount++;
				synchronized (commAddrList) {
					commAddrList.clear();
				}
				synchronized (commAddrListFull) {
					commAddrListFull.clear();
				}

				flowCount = 0;
				packetCount = 0;
				byteCount = 0;

				attackCount = 0;

				if (Integer.valueOf(FileUtils.readFile(CONFIG_PATH).trim()) >= 0) {
					String outData = String.format("%.2f,%.2f,%.2f,%.4f,%.2f,%.2f,%.2f,%.2f\n", attackRate,
							flowTableMatchSuccessRate, interactionCommRate, floodRate, avgCommHostCount, entropy,
							flowModRate, avgFlowPacket);

					FileUtils.writeFile(CONFIG_PATH, String.valueOf(ATTACK_RATE));
					FileUtils.writeFile(OUTDATA_PATH, FileUtils.readFile(OUTDATA_PATH) + outData);
					if (repeatCount++ == REPEAT_COUNT_LIMIT) {
						repeatCount = 0;
						ATTACK_RATE++;
						if (ATTACK_RATE >= 50)
							System.exit(0);
					}
				}
			} catch (IOException e) {
				e.printStackTrace();
			}
		}

		private double entropy() {
			try {
				double H_sum = 0, size = commAddrListFull.size();
				for (String key : commAddrListFull.keySet()) {
					List<String> dstListFull = commAddrListFull.get(key);
					Set<String> middleHashSet = new HashSet<String>(dstListFull);
					List<String> dstList = new ArrayList<String>(middleHashSet);

					double H = 0;
					for (int i = 0; i < dstList.size(); ++i) {
						String ip = dstList.get(i);
						int count = 0;
						for (int j = 0; j < dstListFull.size(); ++j) {
							if (ip.equals(dstListFull.get(j)))
								count++;
						}
						double p = (float) count / dstListFull.size();
						if (p > 0)
							H += -(p * Math.log(p) / Math.log(2));
					}
					H_sum += H;
				}
				return size == 0 ? 0 : H_sum / size;
			} catch (Exception e) {
				e.printStackTrace();
				return 0;
			}
		}
	}

}
