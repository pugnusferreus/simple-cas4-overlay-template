
package au.edu.esa.passthrough.managers.saml;

import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.VelocityEngine;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.common.binding.decoding.SAMLMessageDecoder;
import org.opensaml.saml2.binding.encoding.HTTPPostSimpleSignEncoder;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.security.SecurityPolicyResolver;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Required;


public class PostBindingAdapter extends BindingAdapterImpl implements InitializingBean {

	private VelocityEngine velocityEngine;
	
	
	public PostBindingAdapter(SAMLMessageDecoder decoder,
			String issuingEntityName, SecurityPolicyResolver resolver) {
		super(decoder, issuingEntityName, resolver);
	}

	@Required
	public void setVelocityEngine(
			VelocityEngine velocityEngine) {
		this.velocityEngine = velocityEngine;
	}
	
	public void afterPropertiesSet() {
		encoder = new ScootleHTTPPostSimpleSignEncoder(velocityEngine,
		        "/templates/saml2-post-simplesign-binding.vm", true); 
	}
	
	public class ScootleHTTPPostSimpleSignEncoder extends HTTPPostSimpleSignEncoder {

		public ScootleHTTPPostSimpleSignEncoder(VelocityEngine engine,
				String templateId) {
			super(engine, templateId);
		}

		public ScootleHTTPPostSimpleSignEncoder(VelocityEngine engine,
				String templateId, boolean signXMLProtocolMessage) {
			super(engine, templateId, signXMLProtocolMessage);
		}
		
		/**
	     * Populate the Velocity context instance which will be used to render the POST body.
	     * 
	     * @param velocityContext the Velocity context instance to populate with data
	     * @param messageContext the SAML message context source of data
	     * @param endpointURL endpoint URL to which to encode message
	     * @throws MessageEncodingException thrown if there is a problem encoding the message
	     */
	    @SuppressWarnings("rawtypes")
		protected void populateVelocityContext(VelocityContext velocityContext, SAMLMessageContext messageContext,
	            String endpointURL) throws MessageEncodingException {
	    	super.populateVelocityContext(velocityContext, messageContext, endpointURL);
	    	
	    	/*
	    	 * Replace the encodedEndpointURL with endpointURL. For some reason
	    	 * the action URL rendered in the post redirect form gets some
	    	 * gibberish if encodedEndpointURL was used.
	    	 */
	    	velocityContext.put("action", endpointURL);
	    	
	    }
	}
}
