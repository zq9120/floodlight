package net.floodlightcontroller.dtguard;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.Proxy;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

public class ICHelper {
	private String requestURL;
	private String cookie = "";
	private HttpURLConnection conn;
	private URL url;
	private Proxy proxy = null;
	private Map<String, String> header;

	private int connTimeout;
	private int readTimeout;
	private String location;

	public ICHelper(String url) {
		this.requestURL = url;
		header = new HashMap<String, String>();
		connTimeout = 200000;
		readTimeout = 500000;
	}

	public void setTimeout(int connTimeout, int readTimeout) {
		this.connTimeout = connTimeout;
		this.readTimeout = readTimeout;
	}

	public String getUrl() {
		return requestURL;
	}

	public String getCookie() {
		return cookie;
	}

	public void setProxy(Proxy proxy) {
		this.proxy = proxy;
	}

	public void addHeader(String key, String value) {
		this.header.put(key, value);
	}

	public String getLocation() {
		return location;
	}

	public void setLocation(String location) {
		this.location = location;
	}

	public HttpURLConnection getConn() {
		return conn;
	}

	public void setConn(HttpURLConnection conn) {
		this.conn = conn;
	}

	private void connect() throws IOException {
		url = new URL(this.requestURL);
		if (proxy == null)
			conn = (HttpURLConnection) url.openConnection();
		else
			conn = (HttpURLConnection) url.openConnection(proxy);
		conn.setConnectTimeout(connTimeout);
		conn.setReadTimeout(readTimeout);
		conn.setDoOutput(true);
		conn.setUseCaches(false);
		conn.setInstanceFollowRedirects(false);
		for (String key : header.keySet()) {
			conn.setRequestProperty(key, header.get(key));
		}
	}

	public String get() throws IOException {
		connect();
		InputStream in = conn.getInputStream();
		StringBuilder responseMessage = new StringBuilder();
		BufferedReader br = new BufferedReader(new InputStreamReader(in, "UTF8"));

		int charCount = -1;
		while ((charCount = br.read()) != -1) {
			responseMessage.append((char) charCount);
		}

		in.close();

		location = conn.getHeaderField("location");
		if (location == null)
			location = conn.getHeaderField("Location");

		return responseMessage.toString();
	}

	public String post(String data) throws IOException {
		connect();

		OutputStream reqOut = conn.getOutputStream();
		reqOut.write(data.getBytes());
		reqOut.flush();
		reqOut.close();
		int charCount = -1;
		InputStream in = conn.getInputStream();
		StringBuilder responseMessage = new StringBuilder();

		BufferedReader br = new BufferedReader(new InputStreamReader(in, "UTF8"));
		while ((charCount = br.read()) != -1) {
			responseMessage.append((char) charCount);
		}
		in.close();
		location = conn.getHeaderField("location");
		if (location == null)
			location = conn.getHeaderField("Location");

		return responseMessage.toString();
	}

}
