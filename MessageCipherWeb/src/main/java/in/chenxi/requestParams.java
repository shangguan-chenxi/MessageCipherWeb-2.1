package in.chenxi;

public class requestParams {
	
	private String method;
	private String yourRsaPubKey;
	private String yourRsaPriKey;
	private String itsRsaPubKey;
	private String cryptedMessageAesKey;
	private String messageAesKey;
	private String plainText;
	private String cryptedText;
	private String protectionAesKey;
	private String clientRsaPublicKey;
	
	/** constructor */
	requestParams() {}
	
	/** toString Method */
	public String toString() {
		String str = "";
		str += "method -> " + this.method + "\n";
		str += "yourRsaPubKey -> " + this.yourRsaPubKey + "\n";
		str += "yourRsaPriKey -> " + this.yourRsaPriKey + "\n";
		str += "itsRsaPubKey -> " + this.itsRsaPubKey + "\n";
		str += "cryptedMessageAesKey -> " + this.cryptedMessageAesKey + "\n";
		str += "messageAesKey -> " + this.messageAesKey + "\n";
		str += "plainText -> " + this.plainText + "\n";
		str += "cryptedText ->" + this.cryptedText + "\n";
		str += "protectionAesKey -> " + this.protectionAesKey + "\n";
		str += "clientRsaPublicKey -> " + this.clientRsaPublicKey + "\n";
		return str;
	}
	
	/** getters */
	public String getMethod(){
		return this.method;
	}
	
	public String getYourRsaPubKey() {
		return this.yourRsaPubKey;
	}
	
	public String getYourRsaPriKey() {
		return this.yourRsaPriKey;
	}
	
	public String getItsRsaPubKey() {
		return this.itsRsaPubKey;
	}
	
	public String getCryptedMessageAesKey() {
		return this.cryptedMessageAesKey;
	}
	
	public String getMessageAesKey() {
		return this.messageAesKey;
	}
	
	public String getPlainText() {
		return this.plainText;
	}
	
	public String getCryptedText() {
		return this.cryptedText;
	}
	
	public String getProtectionAesKey() {
		return this.protectionAesKey;
	}
	
	public String getClientRsaPublicKey() {
		return this.clientRsaPublicKey;
	}
	
	
	/** setters */
	public void setMethod(String newStr){
		this.method = newStr;
	}
	
	public void setYourRsaPubKey(String newStr) {
		this.yourRsaPubKey = newStr;
	}
	
	public void setYourRsaPriKey(String newStr) {
		this.yourRsaPriKey = newStr;
	}
	
	public void setItsRsaPubKey(String newStr) {
		this.itsRsaPubKey = newStr;
	}
	
	public void setCryptedMessageAesKey(String newStr) {
		this.cryptedMessageAesKey = newStr;
	}
	
	public void setMessageAesKey(String newStr) {
		this.messageAesKey = newStr;
	}
	
	public void setPlainText(String newStr) {
		this.plainText = newStr;
	}
	
	public void setCryptedText(String newStr) {
		this.cryptedText = newStr;
	}
	
	public void setProtectionAesKey(String newStr) {
		this.protectionAesKey = newStr;
	}
	
	public void setClientRsaPublicKey(String newStr) {
		this.clientRsaPublicKey = newStr;
	}
}
