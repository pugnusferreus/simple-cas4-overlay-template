
package au.edu.esa.passthrough.managers.saml;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Map;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import org.apache.log4j.Logger;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.CredentialResolver;
import org.opensaml.xml.security.credential.KeyStoreCredentialResolver;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;



/**
 * 
 * This class attempts to load a Java keystore from the default configuration 
 * path (/var/local/tlf-ec/keystore/scootle-saml_sp-keystore.jks) first.
 * If it failed to load from the default config path then it loads the 
 * keystore from the application.properties. And then instantiates 
 * an Open SAML KeyStoreCredentialResolver. 
 *
 */
@Component("keyStoreCredentialResolverDelegate")
public class KeyStoreCredentialResolverDelegate implements CredentialResolver, InitializingBean  {

	private static class KeystoreLoader {
		private static final String DEFAULT_CONIGURATION_PATH = "/etc/cas/";
		
		public static byte[] loadKeystore(String keystoreFile) throws IOException {
			
			if (LOG.isInfoEnabled()) {
				LOG.info("loadKeystore: keystore file :" + keystoreFile);
			}
			
			Resource keystore = new FileSystemResource(
					System.getProperty("econtent.config.path", DEFAULT_CONIGURATION_PATH)
							+ keystoreFile);
			
			byte[] result = null;
			
			if(keystore.exists()) {
				
				if (LOG.isInfoEnabled()) {
					LOG.info("Loading SAML SP keystore file from " + keystore);
				}
				InputStream is = null;
				try {
					is = keystore.getInputStream();
					result = IOUtils.toByteArray(is);
				}
				catch (IOException ex) {
					LOG.error("Could not load SAML SP keystore from " + keystore + ": " + ex.getMessage());
					throw ex;
				}
				finally {
					if (is != null) {
						is.close();
					}
				}
			} else {
				LOG.error("Could not find SAML SP keystore from " + keystore);
			}
			
			return result;
		}
	}

	private static final Logger LOG = Logger.getLogger(KeyStoreCredentialResolverDelegate.class);
	
	private static final String DEFAULT_KEYSTORE_FILE = "keystore.jks";
	
	private KeyStoreCredentialResolver  keyStoreCredentialResolver;
	
	private String keystorePassword;
	
	private Map<String,String> privateKeyPasswordsByAlias;
	

	public void setKeystorePassword(String keystorePassword) {
		this.keystorePassword = keystorePassword;
	}

	public void setPrivateKeyPasswordsByAlias(
			Map<String, String> privateKeyPasswordsByAlias) {
		this.privateKeyPasswordsByAlias = privateKeyPasswordsByAlias;
	}

	public Iterable<Credential> resolve(CriteriaSet criteriaSet)
			throws SecurityException {
		return keyStoreCredentialResolver.resolve(criteriaSet);
	}

	public Credential resolveSingle(CriteriaSet criteriaSet) throws SecurityException {
		return keyStoreCredentialResolver.resolveSingle(criteriaSet);
	}

	public void afterPropertiesSet() throws KeyStoreException, IOException,
			NoSuchAlgorithmException, CertificateException {
		
		LOG.debug("afterPropertiesSet: privateKeyPasswordsByAlias: "+ privateKeyPasswordsByAlias.keySet());
		
		KeyStore ks = KeyStore.getInstance("JKS");
		
		//byte[] keyStoreBytes = KeystoreLoader.loadKeystore(
		//		propertiesConfig.getStringParam(ConfigKey.Saml.SAML_SP_KEYSTORE_FILE, DEFAULT_KEYSTORE_FILE));
		byte[] keyStoreBytes = KeystoreLoader.loadKeystore(DEFAULT_KEYSTORE_FILE); // TODO: proper config
		
		if(keyStoreBytes != null) {
			ks.load(new ByteArrayInputStream(keyStoreBytes), keystorePassword.toCharArray());
		} else {
			/*
			 * This is only here for the testing purpose.
			 * It allows the application to start up without 
			 * having to have a keystore in the default configuration
			 * path. 
			 * 
			 * Not recommend for the production. Always load the keystore from
			 * the default configuration path in the production environment.
			 */
			LOG.info("Load the base64 encoded keystore from the config.");
			throw new KeyStoreException("No keystore set");
//			String keystoreFromConfig = propertiesConfig.getStringParam("saml.keystore.base64_encoded");
//			ks.load(new ByteArrayInputStream(Base64.decodeBase64(keystoreFromConfig.getBytes())), keystorePassword.toCharArray());
		}

		LOG.debug("afterPropertiesSet: ks.size(): "+ ks.size());
		keyStoreCredentialResolver = new KeyStoreCredentialResolver(ks, privateKeyPasswordsByAlias);
	}
}
