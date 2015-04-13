package au.edu.esa.passthrough.handlers;

import org.jasig.cas.Message;
import org.jasig.cas.authentication.*;
import org.jasig.cas.authentication.handler.support.AbstractPreAndPostProcessingAuthenticationHandler;
import org.jasig.cas.authentication.principal.Principal;
import org.jasig.cas.authentication.principal.SimplePrincipal;

import java.security.GeneralSecurityException;
import java.util.List;

/**
 * Created by pugnusferreus on 13/04/2015.
 */
public class SAMLAuthenticationHandler extends AbstractPreAndPostProcessingAuthenticationHandler {

	@Override
	protected HandlerResult doAuthentication(Credential credential) throws GeneralSecurityException, PreventedException {
		return this.createHandlerResult(credential, new SimplePrincipal(credential.getId()), (List)null);
	}

	@Override
	public boolean supports(Credential credential) {
		return credential instanceof RememberMeCredential;
	}

	protected final HandlerResult createHandlerResult(Credential credential, Principal principal, List<Message> warnings) {
		return new HandlerResult(this, new BasicCredentialMetaData(credential), principal, warnings);
	}
}
