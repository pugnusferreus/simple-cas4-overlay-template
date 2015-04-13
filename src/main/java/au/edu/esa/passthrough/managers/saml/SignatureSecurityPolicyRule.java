
package au.edu.esa.passthrough.managers.saml;

import org.apache.log4j.Logger;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.Response;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.ws.message.MessageContext;
import org.opensaml.ws.security.SecurityPolicyException;
import org.opensaml.ws.security.SecurityPolicyRule;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.CredentialResolver;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.security.criteria.UsageCriteria;
import org.opensaml.xml.security.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xml.signature.impl.ExplicitKeySignatureTrustEngine;
import org.opensaml.xml.validation.ValidationException;
import org.springframework.beans.factory.InitializingBean;

/**
* The Rule to check that the message has been signed by an issuer that has credentials
* in the keystore.
*/
public class SignatureSecurityPolicyRule  implements InitializingBean, SecurityPolicyRule {

	private static final Logger LOG = Logger.getLogger(SignatureSecurityPolicyRule.class);
	
	private final CredentialResolver credentialResolver;	
	private final SAMLSignatureProfileValidator samlSignatureProfileValidator;
	private ExplicitKeySignatureTrustEngine trustEngine;
	
	public SignatureSecurityPolicyRule(CredentialResolver credentialResolver, SAMLSignatureProfileValidator samlSignatureProfileValidator) {
		super();
		
		this.credentialResolver = credentialResolver;
		this.samlSignatureProfileValidator = samlSignatureProfileValidator;
	}
	
	public void afterPropertiesSet() {

//		LOG.info("-----> " + Configuration.getGlobalSecurityConfiguration());
//		KeyInfoCredentialResolver keyInfoCredResolver = Configuration.getGlobalSecurityConfiguration().getDefaultKeyInfoCredentialResolver();
//
//		trustEngine = new ExplicitKeySignatureTrustEngine(credentialResolver,keyInfoCredResolver);		
	}

	public void evaluate(MessageContext messageContext) throws SecurityPolicyException {
		
		LOG.debug("evaluating signature of: "+ messageContext);
		
		if(!( messageContext.getInboundMessage() instanceof SignableSAMLObject)) {
			throw new SecurityPolicyException("Inbound Message is not a SignableSAMLObject");
		}
		
		BasicSAMLMessageContext basicSamlMegContext = (BasicSAMLMessageContext)messageContext;
		if (basicSamlMegContext.getInboundSAMLMessage() instanceof Response) {
			checkResponseSignature(messageContext);
		} else if (basicSamlMegContext.getInboundSAMLMessage() instanceof LogoutRequest) {
			checkLogoutRequestSignature(messageContext);
		}
	}
	
	private void checkLogoutRequestSignature(MessageContext messageContext) throws SecurityPolicyException {
		
		BasicSAMLMessageContext basicSamlMegContext = (BasicSAMLMessageContext)messageContext;
		LogoutRequest logoutRequest = (LogoutRequest) basicSamlMegContext.getInboundSAMLMessage();
		
		if( !logoutRequest.isSigned()) {
			LOG.error("evaluate: LogoutRequest was not signed!");
			throw new SecurityPolicyException("LogoutRequest was not signed.");
		}
		
		checkSignatureProfile(logoutRequest);

		checkMessageSignature(messageContext, logoutRequest);
	}
	
	private void checkResponseSignature(MessageContext messageContext) throws SecurityPolicyException {
		
		SignableSAMLObject samlMessage = (SignableSAMLObject) messageContext.getInboundMessage();
		
		if( !samlMessage.isSigned()) {
			/*
			 * Response signature is not mandatory by default. Unless specified 
			 * explicitly (saml.response.signature.required=true)
			 * in the application.properties
			 */
//			if (propertiesConfig.getBooleanParam(ConfigKey.Saml.SAML_RESPONSE_SIGNATURE_REQUIRED, false)) {
//				throw new SecurityPolicyException("SAML response message was not signed.");
//			} else {
				LOG.info("evaluate: Just FYI SAML response message was not signed. It's not required by default.");
				return;
			//}
		}
		
		checkSignatureProfile(samlMessage);

		checkMessageSignature(messageContext, samlMessage);
	}

	protected void checkMessageSignature(MessageContext messageContext,
			SignableSAMLObject samlMessage) throws SecurityPolicyException {
		CriteriaSet criteriaSet = new CriteriaSet();
		LOG.debug("Inbound issuer is: "+ messageContext.getInboundMessageIssuer());
		criteriaSet.add( new EntityIDCriteria(messageContext.getInboundMessageIssuer()));		
		criteriaSet.add( new UsageCriteria(UsageType.SIGNING) );

		try {
			if (!trustEngine.validate( samlMessage.getSignature(), criteriaSet)) {
				throw new SecurityPolicyException("Signature was either invalid or signing key could not be established as trusted");
			}
		} catch (SecurityException se) {
			throw new SecurityPolicyException("Error evaluating the signature",se);
		}
	}

	protected void checkSignatureProfile(SignableSAMLObject samlMessage)
			throws SecurityPolicyException {
		try {
			samlSignatureProfileValidator.validate(samlMessage.getSignature());
		} catch (ValidationException ve) {
		   
			throw new SecurityPolicyException("Signature did not conform to SAML Signature profile",ve);
		}
	}
}
