
package au.edu.esa.passthrough.managers.saml;

import java.util.List;

import org.apache.log4j.Logger;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.common.binding.decoding.SAMLMessageDecoder;
import org.opensaml.saml2.binding.encoding.HTTPRedirectDeflateEncoder;
import org.opensaml.saml2.binding.security.SAML2HTTPRedirectDeflateSignatureRule;
import org.opensaml.security.MetadataCriteria;
import org.opensaml.ws.message.MessageContext;
import org.opensaml.ws.security.SecurityPolicy;
import org.opensaml.ws.security.SecurityPolicyException;
import org.opensaml.ws.security.SecurityPolicyRule;
import org.opensaml.ws.security.provider.BasicSecurityPolicy;
import org.opensaml.ws.security.provider.StaticSecurityPolicyResolver;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.credential.CredentialResolver;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.security.criteria.UsageCriteria;
import org.opensaml.xml.security.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xml.signature.SignatureTrustEngine;
import org.opensaml.xml.signature.impl.ExplicitKeySignatureTrustEngine;
import org.opensaml.xml.util.DatatypeHelper;
import org.springframework.beans.factory.InitializingBean;

import au.edu.esa.passthrough.controllers.SAMLAuthenticationController;

public class RedirectBindingAdapter extends BindingAdapterImpl implements InitializingBean {

	private static final Logger LOG = Logger.getLogger(RedirectBindingAdapter.class);

	private final CredentialResolver credentialResolver;
	private SecurityPolicy securityPolicy;

	
	public RedirectBindingAdapter(SAMLMessageDecoder decoder,
			String issuingEntityName,
			CredentialResolver credentialResolver,
			List<SecurityPolicyRule> securityPolicyRules) throws Exception {
		
		super(decoder, issuingEntityName, null);
		DefaultBootstrap.bootstrap();
		this.credentialResolver = credentialResolver;
		this.securityPolicy = new SecurityPolicyDelegate(securityPolicyRules);
	}
	
	public void afterPropertiesSet() {
		encoder = new HTTPRedirectDeflateEncoder(); 
		
		KeyInfoCredentialResolver keyInfoCredResolver =
		Configuration.getGlobalSecurityConfiguration().getDefaultKeyInfoCredentialResolver();

		ExplicitKeySignatureTrustEngine trustEngine = new ExplicitKeySignatureTrustEngine(credentialResolver, keyInfoCredResolver);
		
		SecurityPolicyRule httpRedirectBindingSignatureRule = new ScootleSAML2HTTPRedirectDeflateSignatureRule(trustEngine);
		securityPolicy.getPolicyRules().add(httpRedirectBindingSignatureRule);
		
		securityPolicyResolver = new StaticSecurityPolicyResolver(securityPolicy);
	}
	
	public class ScootleSAML2HTTPRedirectDeflateSignatureRule extends SAML2HTTPRedirectDeflateSignatureRule {
		
		public ScootleSAML2HTTPRedirectDeflateSignatureRule(SignatureTrustEngine engine) {
			super(engine);
		}
		
		@Override
		protected CriteriaSet buildCriteriaSet(String entityID, SAMLMessageContext samlContext) throws SecurityPolicyException {
			
			CriteriaSet criteriaSet = new CriteriaSet();
		    if (!DatatypeHelper.isEmpty(entityID)) {
		        criteriaSet.add(new EntityIDCriteria(entityID));
		    }
		    
		    if (samlContext.getPeerEntityRole() != null) {
		    	LOG.info("buildCriteriaSet: PeerEntityRole: ["+ samlContext.getPeerEntityRole().toString() +"]. Create peer MetadataCriteria.");
		    	MetadataCriteria mdCriteria = new MetadataCriteria(samlContext.getPeerEntityRole(), samlContext
		    			.getInboundSAMLProtocol());
		    	criteriaSet.add(mdCriteria);
		    }
		
		    criteriaSet.add(new UsageCriteria(UsageType.SIGNING));
		
		    return criteriaSet;
		}
	}
	
	public class SecurityPolicyDelegate implements SecurityPolicy  {

		private final BasicSecurityPolicy basicSecurityPolicy;
		
		public SecurityPolicyDelegate(List<SecurityPolicyRule> securityPolicyRules) {
			super();
			basicSecurityPolicy = new BasicSecurityPolicy();
			basicSecurityPolicy.getPolicyRules().addAll(securityPolicyRules);
		}

		public void evaluate(MessageContext messageContext) throws SecurityPolicyException {
			basicSecurityPolicy.evaluate(messageContext);
		}

		public List<SecurityPolicyRule> getPolicyRules() {
			return basicSecurityPolicy.getPolicyRules();
		}
	}
}
