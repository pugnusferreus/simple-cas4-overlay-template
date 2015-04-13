package au.edu.esa.passthrough.managers.saml;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.common.binding.decoding.SAMLMessageDecoder;
import org.opensaml.common.binding.encoding.SAMLMessageEncoder;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.security.SecurityPolicyResolver;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.Credential;


public abstract class BindingAdapterImpl {
	
	public static final String SAML_REQUEST_POST_PARAM_NAME = "SAMLRequest";
	public static final String SAML_RESPONSE_POST_PARAM_NAME = "SAMLResponse";
	public static final String SAML_RELAY_STATE_PARAM_NAME = "RelayState";
	
	protected final SAMLMessageDecoder decoder;
	protected SAMLMessageEncoder encoder;	
	protected final String issuingEntityName;
	protected SecurityPolicyResolver securityPolicyResolver;
	
	
	public BindingAdapterImpl(SAMLMessageDecoder decoder,
			String issuingEntityName, SecurityPolicyResolver securityPolicyResolver) {
		
		this.decoder = decoder;
		this.issuingEntityName = issuingEntityName;
		this.securityPolicyResolver = securityPolicyResolver;
	}

	public void sendSAMLMessage(SignableSAMLObject samlMessage,
				Endpoint endpoint, 
				Credential signingCredential,
				HttpServletRequest request,
				HttpServletResponse response) throws MessageEncodingException {
		
		String relayStateParam = extractRelayStateParam(request);

		HttpServletResponseAdapter outTransport = new HttpServletResponseAdapter(response, false);
		
		BasicSAMLMessageContext messageContext = new BasicSAMLMessageContext();
		
		messageContext.setOutboundMessageTransport(outTransport);
		messageContext.setPeerEntityEndpoint(endpoint);
		messageContext.setOutboundSAMLMessage(samlMessage);
		messageContext.setOutboundMessageIssuer(issuingEntityName);
		messageContext.setOutboundSAMLMessageSigningCredential(signingCredential);
		
		// Pass on the RelayState param if it's in the request. 
		if (StringUtils.isNotBlank(relayStateParam)) {
			messageContext.setRelayState(relayStateParam);
		}
		
		encoder.encode(messageContext);
	}

	public SAMLMessageContext extractSAMLMessageContext(HttpServletRequest request) throws MessageDecodingException, SecurityException {
		
		BasicSAMLMessageContext messageContext = new BasicSAMLMessageContext();
		
		messageContext.setInboundMessageTransport(new HttpServletRequestAdapter(request));
		messageContext.setSecurityPolicyResolver(securityPolicyResolver);

		decoder.decode(messageContext);
		
		return	messageContext;
	}

	public String extractSAMLRequestParam(HttpServletRequest request) {
	    String value = request.getParameter(SAML_REQUEST_POST_PARAM_NAME);
	    
		if(StringUtils.isNotBlank(value)) {
			return value;
		}
		
		return null;
	}

	public String extractSAMLResponseParam(HttpServletRequest request) {
	    String value = request.getParameter(SAML_RESPONSE_POST_PARAM_NAME);
	    
		if(StringUtils.isNotBlank(value)) {
			return value;
		}
		
		return null;
	}
	
	public String extractRelayStateParam(HttpServletRequest request) {
		String value = request.getParameter(SAML_RELAY_STATE_PARAM_NAME);
		
		if(StringUtils.isNotBlank(value)) {
			return value;
		}
		
		return null;
	}
}
