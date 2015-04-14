package au.edu.esa.passthrough.controllers;


import au.edu.esa.passthrough.exceptions.ForbiddenException;
import au.edu.esa.passthrough.exceptions.ValidationException;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.builder.HashCodeBuilder;
import org.apache.log4j.Logger;
import org.jasig.cas.CentralAuthenticationService;
import org.jasig.cas.CentralAuthenticationServiceImpl;
import org.jasig.cas.authentication.*;
import org.jasig.cas.authentication.principal.*;
import org.jasig.cas.services.DefaultServicesManagerImpl;
import org.jasig.cas.services.RegexRegisteredService;
import org.jasig.cas.services.RegisteredService;
import org.jasig.cas.services.ServicesManager;
import org.jasig.cas.support.saml.authentication.principal.SamlService;
import org.jasig.cas.ticket.*;
import org.jasig.cas.ticket.registry.DefaultTicketRegistry;
import org.jasig.cas.ticket.support.HardTimeoutExpirationPolicy;
import org.jasig.cas.web.support.CookieRetrievingCookieGenerator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.ServletRequestBindingException;
import org.springframework.web.bind.ServletRequestUtils;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.WebUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.net.URL;
import java.util.HashMap;
import java.util.Map;


/**
 * @author blim
 *
 */
@Controller
public class SAMLAuthenticationController extends BaseController {

	private final Logger LOG = Logger.getLogger(SAMLAuthenticationController.class);

	private final static String PROVIDER_PARAM = "provider";
	private final static String PROVIDER_ATTRIBUTE = "saml_idp";

	@Autowired
	private SAMLAuthenticationEntryPoint samlAuthenticationEntryPoint;

	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	private DefaultTicketRegistry ticketRegistry;

	@Autowired
	private CentralAuthenticationService centralAuthenticationService;

	@Autowired
	private CookieRetrievingCookieGenerator ticketGrantingTicketCookieGenerator;



	@RequestMapping(value="/login", method = RequestMethod.GET)
	@ResponseBody
	public void login(HttpServletRequest request, HttpServletResponse response) throws Exception {
		LOG.info("handleSSOSaml: start...");
		/*
		 * If the request param "provider" not present
		 * redirect to the login page.
		 */
		if (!checkMandatoryRequestParams(request)) {
			throw new ForbiddenException("Invalid mandatory params");
		}

//		User user = (User) WebUtils.getSessionAttribute(request, "user");
//		/*
//		 * User already have a valid Scootle websession which
//		 * was created via SAML SSO.
//		 * return to the home page.
//		 */
//		if (user != null && (StringUtils.isNotBlank(user.getSamlSessionIndex())
//				|| StringUtils.isNotBlank(user.getSamlNameId()))) {
//			LOG.info("handleSSOSaml: user already have a valid websession via SAML SSO.");
//			String provider = getProviderFromRequest(request);
//			response.sendRedirect(Utils.postPendTimestampGetParam(getHomePage(provider)));
//			return null;
//		}

		String ssoUrl = lookupSSOServiceURL(request);
		if (!StringUtils.isBlank(ssoUrl)) {
			samlAuthenticationEntryPoint.setSingleSignOnServiceURL(ssoUrl);
			samlAuthenticationEntryPoint.sendAuthRequest(request, response, getSSOBinding(request));
		} else {
			throw new ForbiddenException("Your domain is not whitelisted");
		}

	}


	@RequestMapping(value="/consume", method = RequestMethod.POST)
	@ResponseBody
	public void consume(HttpServletRequest request, HttpServletResponse response) throws Exception {
		LOG.info("Consuming SAML request!");

//		UsernamePasswordCredential credential = new UsernamePasswordCredential();
//		credential.setUsername("benson.lim@esa.edu.au");
//		credential.setPassword("123");

		TestCredential credential = new TestCredential("benson.lim@esa.edu.au");
//		AcceptUsersAuthenticationHandler test = new AcceptUsersAuthenticationHandler();
//
//		test.setUsers(x);
//		HandlerResult result =  test.authenticate(credential);
//		LOG.info(((BasicCredentialMetaData)result.getCredentialMetaData()).getId());
//		ExpirationPolicy policy = new HardTimeoutExpirationPolicy(600000l);
//		Authentication authentication = authenticationManager.authenticate(credential);
//		TicketGrantingTicket ticketGrantingTicket = new TicketGrantingTicketImpl("benson.lim@esa.edu.au",authentication, policy);
//
//		ticketRegistry.addTicket(ticketGrantingTicket);
		String ticketId = centralAuthenticationService.createTicketGrantingTicket(credential);
		Ticket ticket = ticketRegistry.getTicket(ticketId);

		ticketGrantingTicketCookieGenerator.addCookie(request, response, ticket.getId());

		LOG.info("ticket = [" + ticketId + "]");

	}


	private boolean checkMandatoryRequestParams(HttpServletRequest request) {
		String param = request.getParameter(PROVIDER_PARAM);
		if (StringUtils.isNotBlank(param)) {
			return true;
		}

		return false;
	}

	private String lookupSSOServiceURL(HttpServletRequest request) throws Exception {
		String url = null;
		String provider = getProviderFromRequest(request);

		if (!StringUtils.isBlank(provider)) {
			provider = provider.trim();

			if(isTrustedProvider(provider)) {
				request.getSession(true).setAttribute(PROVIDER_ATTRIBUTE, provider);
				String key = "saml.sso.service.url." + provider.toLowerCase();
				url = getIDPURL(key);
				LOG.debug("lookupSSOServiceURL: url="+ url);

				if (StringUtils.isBlank(url)) {
					throw new ValidationException("lookupSSOServiceURL: configuration ["+ key +"] is not set in the application.properties.");
				}
			} else {
				throw new ValidationException("lookupSSOServiceURL: "+ provider +" is not defined in the trusted list");
			}
		}
		return url;
	}

	private String getProviderFromRequest(HttpServletRequest request) throws ServletRequestBindingException {
		String result = ServletRequestUtils.getStringParameter(request, PROVIDER_PARAM);
		if (!StringUtils.isEmpty(result)) {
			result = result.trim();
			result = result.toLowerCase();
		}
		return result;
	}

	/*
	need this to be dynamic and not load from properties
	 */
	private boolean isTrustedProvider(String provider) {
		return true;
	}

	private String getIDPURL(String key) {
		return "http://scootle-test-multi01.scootle.edu.au:9091/openam/SSOPOST/metaAlias/idp";
	}

	private RequestMethod getSSOBinding(HttpServletRequest request) {
//		String provider = (String) WebUtils.getSessionAttribute(request, PROVIDER_ATTRIBUTE);
//		String binding = propertiesConfig.getStringParam(ConfigKey.Saml.SAML_SSO_BINDING_CONFIG_PREFIX + provider);
//
//		if (StringUtils.isNotBlank(binding)) {
//			if (binding.equalsIgnoreCase(REDIRECT_BINDING)) {
//				return RequestMethod.GET;
//			}
//		}
		return RequestMethod.POST;
	}

	private class TestCredential implements RememberMeCredential {

		private String id;
		private boolean rememberMe = false;

		public TestCredential(String id) {
			this.id = id;
		}

		@Override
		public boolean isRememberMe() {
			return rememberMe;
		}

		@Override
		public void setRememberMe(boolean rememberMe) {
			this.rememberMe = rememberMe;
		}

		@Override
		public String getId() {
			return this.id;
		}

		@Override
		public int hashCode() {
			return new HashCodeBuilder()
					.append(id)
					.toHashCode();
		}

		@Override
		public String toString() {
			return this.id;
		}
	}
}
