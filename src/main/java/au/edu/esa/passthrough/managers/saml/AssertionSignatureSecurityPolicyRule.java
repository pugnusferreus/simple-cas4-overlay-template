package au.edu.esa.passthrough.managers.saml;

import org.apache.log4j.Logger;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Response;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.ws.message.MessageContext;
import org.opensaml.ws.security.SecurityPolicyException;
import org.opensaml.xml.security.credential.CredentialResolver;

public class AssertionSignatureSecurityPolicyRule extends
		SignatureSecurityPolicyRule {

	private static final Logger LOG = Logger.getLogger(AssertionSignatureSecurityPolicyRule.class);

	public AssertionSignatureSecurityPolicyRule(
			CredentialResolver credentialResolver,
			SAMLSignatureProfileValidator samlSignatureProfileValidator) {
		
		super(credentialResolver, samlSignatureProfileValidator);
	}

	@Override
	public void evaluate(MessageContext messageContext)
			throws SecurityPolicyException {
		
		BasicSAMLMessageContext basicSamlMegContext = (BasicSAMLMessageContext)messageContext;
		
		/*
		 * Only interested in proceeding to evaluate the assertion signature 
		 * if the the inbound SAML message is an 
		 * org.opensaml.saml2.core.Response.
		 */
		if (basicSamlMegContext.getInboundSAMLMessage() instanceof Response) {
			Response smalInboundMeg = (Response)basicSamlMegContext.getInboundSAMLMessage();
			
			LOG.debug("evaluate: start evaluating the assertion signature...");
			checkAssertionSignature(messageContext, smalInboundMeg);
		}
	}
	
	private void checkAssertionSignature(MessageContext messageContext, Response smalInboundMeg) throws SecurityPolicyException {
		
		Assertion assertion = smalInboundMeg.getAssertions().get(0);
		
		if (!assertion.isSigned()) {
			/*
			 * Assertion signature is mandatory by default. Unless defined
			 * explicitly (saml.assertion.signature.required=false)
			 * in the application.properties
			 */
			//if (propertiesConfig.getBooleanParam(ConfigKey.Saml.SAML_ASSERTION_SIGNATURE_REQUIRED, true)) {
				throw new SecurityPolicyException("SAML Assertion was not signed.");
//			} else {
//				LOG.warn("SAML assertion is not signed!");
//				return;
//			}
		}
		
		LOG.info("checkAssertionSignature: "+ assertion.getSignatureReferenceID());
		checkSignatureProfile(assertion);
		checkMessageSignature(messageContext, assertion);
	}
}
