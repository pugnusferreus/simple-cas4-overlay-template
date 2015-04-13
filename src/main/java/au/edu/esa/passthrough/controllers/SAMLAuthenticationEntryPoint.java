package au.edu.esa.passthrough.controllers;

import java.io.IOException;
import java.util.UUID;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.namespace.QName;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.Validate;
import org.apache.log4j.Logger;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameIDType;
import org.opensaml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.SingleSignOnService;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.CredentialResolver;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.security.criteria.UsageCriteria;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Required;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.RequestMethod;

import au.edu.esa.passthrough.managers.saml.KeyStoreCredentialResolverDelegate;
import au.edu.esa.passthrough.managers.saml.PostBindingAdapter;
import au.edu.esa.passthrough.managers.saml.RedirectBindingAdapter;


/**
 *
 */
public class SAMLAuthenticationEntryPoint implements InitializingBean {

	private static final Logger LOG = Logger.getLogger(SAMLAuthenticationEntryPoint.class);
	
	private final TimeService timeService = new TimeService();
	
	private final IDService idService = new IDService();
	
	private PostBindingAdapter postBindingAdapter;
	
	private RedirectBindingAdapter redirectBindingAdapter;

	private EndpointGenerator endpointGenerator;
	
	private KeyStoreCredentialResolverDelegate keyStoreCredentialResolverDelegate;
	
	private AuthnRequestGenerator authnRequestGenerator;
	private final String sPEntityId = "https://localhost:8443/cas";
	//private final String sPEntityId = "http://localhost:8080/ec";
	private final String keyStoreAlias = "scootle";
	private String singleSignOnServiceURL;
	private String assertionConsumerServiceURL = "https://localhost:8443/cas/saml/consume";
	//private String assertionConsumerServiceURL = "http://localhost:8080/ec/ssosaml/consumer";
	
	private Credential signingCredential;

	public SAMLAuthenticationEntryPoint() {
		super();
	}

	public void setSingleSignOnServiceURL(String singleSignOnServiceURL) {
		this.singleSignOnServiceURL = singleSignOnServiceURL;
	}

	@Autowired
	public void setPostBindingAdapter(PostBindingAdapter postBindingAdapter) {
		this.postBindingAdapter = postBindingAdapter;
	}

	@Autowired
	public void setRedirectBindingAdapter(RedirectBindingAdapter redirectBindingAdapter) {
		this.redirectBindingAdapter = redirectBindingAdapter;
	}

	@Autowired
	public void setKeyStoreCredentialResolverDelegate(KeyStoreCredentialResolverDelegate keyStoreCredentialResolverDelegate) {
		this.keyStoreCredentialResolverDelegate = keyStoreCredentialResolverDelegate;
	}

	public void sendAuthRequest(HttpServletRequest request,
            HttpServletResponse response, RequestMethod method) throws IOException, ServletException {
		
		Endpoint endpoint = endpointGenerator.generateEndpoint(SingleSignOnService.DEFAULT_ELEMENT_NAME, singleSignOnServiceURL, assertionConsumerServiceURL);
		LOG.info("endpoint: "+ endpoint.getResponseLocation());
		
		AuthnRequest authnReqeust =  authnRequestGenerator.generateAuthnRequest(singleSignOnServiceURL,assertionConsumerServiceURL);
		
		LOG.info("Sending authnRequest to: "+ singleSignOnServiceURL );
		
		try {
			if (method == RequestMethod.POST) {
				LOG.info("Sending authnRequest via POST method");
				postBindingAdapter.sendSAMLMessage(authnReqeust, endpoint, signingCredential, request, response);
			} else if (method == RequestMethod.GET) {
				LOG.info("Sending authnRequest via GET method");
				redirectBindingAdapter.sendSAMLMessage(authnReqeust, endpoint, signingCredential, request, response);
			} else {
				LOG.error("sendAuthRequest: Unsupported binding method: "+ method);
			}
		} catch (MessageEncodingException mee) {
			LOG.error("Could not send authnRequest to Identity Provider.", mee);
			response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
		}
	}

	public void afterPropertiesSet() throws SecurityException {
		
		LOG.debug("afterPropertiesSet: sPEntityId: "+ sPEntityId);
		
		authnRequestGenerator = new AuthnRequestGenerator(sPEntityId,timeService,idService);
		endpointGenerator = new EndpointGenerator();
		

		CriteriaSet criteriaSet = new CriteriaSet();
		criteriaSet.add(new EntityIDCriteria(keyStoreAlias));
		criteriaSet.add(new UsageCriteria(UsageType.SIGNING));

		signingCredential = keyStoreCredentialResolverDelegate.resolveSingle(criteriaSet);
		
		try{
			Validate.notNull(signingCredential);
		} catch (IllegalArgumentException ex) {
			String msg = "Could NOT find the key with the alias of ["+ keyStoreAlias +"] in the keystore";
			LOG.error(msg);
			throw new IllegalArgumentException(msg, ex);
		}
	}
	
	@Component(value="timeService")
	public class TimeService {

		public DateTime getCurrentDateTime() {
			return new DateTime();
		}
		
	}
	

	@Component(value="idService")
	public class IDService {
	
		public String generateID() {
			return UUID.randomUUID().toString();
		}
	}
	
	public class EndpointGenerator {

		private XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
		
		public Endpoint generateEndpoint(QName service, String location, String responseLocation) {
			
			LOG.debug("end point service:: "+ service);
			LOG.debug("end point location:: "+ location);
			LOG.debug("end point responseLocation:: "+ responseLocation);
			
			SAMLObjectBuilder<Endpoint> endpointBuilder = (SAMLObjectBuilder<Endpoint>) builderFactory.getBuilder(service);
			Endpoint samlEndpoint = endpointBuilder.buildObject();
			
	        samlEndpoint.setLocation(location);
	        
	        //this does not have to be set
	        if( StringUtils.isNotEmpty(responseLocation)) {
	        	samlEndpoint.setResponseLocation(responseLocation);
	        }
	        
	        return samlEndpoint;
		}

	}
	
	public class AuthnRequestGenerator {

		private XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
		
		private final String issuingEntityName;
		private final TimeService timeService; 
		private final IDService idService;
		private IssuerGenerator issuerGenerator;
			
		public AuthnRequestGenerator(String issuingEntityName, TimeService timeService, IDService idService) {
			super();
			this.issuingEntityName = issuingEntityName;
			this.timeService = timeService;
			this.idService = idService;
			
			issuerGenerator = new IssuerGenerator(this.issuingEntityName);
		}

		public AuthnRequest generateAuthnRequest(String destination, String responseLocation) {
			
			AuthnRequestBuilder authnRequestBuilder = (AuthnRequestBuilder) builderFactory.getBuilder(AuthnRequest.DEFAULT_ELEMENT_NAME);
			
			AuthnRequest authnRequest = authnRequestBuilder.buildObject();
			
			authnRequest.setAssertionConsumerServiceURL(responseLocation);
			authnRequest.setID(idService.generateID());
			authnRequest.setIssueInstant(timeService.getCurrentDateTime());
			authnRequest.setDestination(destination);
			
			authnRequest.setIssuer(issuerGenerator.generateIssuer());
			authnRequest.setProtocolBinding(SAMLConstants.SAML2_POST_BINDING_URI);
			authnRequest.setIsPassive(false);
			
			return authnRequest;
		}
	}
	
	public class IssuerGenerator {

		private final XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
		
		private final String issuingEntityName;
		
		
		public IssuerGenerator(String issuingEntityName) {
			super();
			this.issuingEntityName = issuingEntityName;
		}


		public Issuer generateIssuer() {
		
			IssuerBuilder issuerBuilder = (IssuerBuilder) builderFactory.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
			Issuer issuer = issuerBuilder.buildObject();
			

			issuer.setValue(issuingEntityName);
			issuer.setFormat(NameIDType.ENTITY);
			
			return issuer;
		}
	}
}
