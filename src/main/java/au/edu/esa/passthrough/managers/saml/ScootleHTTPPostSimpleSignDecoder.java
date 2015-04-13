package au.edu.esa.passthrough.managers.saml;

import org.apache.commons.lang3.StringUtils;
import org.opensaml.common.binding.decoding.BasicURLComparator;
import org.opensaml.saml2.binding.decoding.HTTPPostSimpleSignDecoder;
import org.opensaml.xml.parse.ParserPool;


public class ScootleHTTPPostSimpleSignDecoder extends HTTPPostSimpleSignDecoder {

	public ScootleHTTPPostSimpleSignDecoder(ParserPool pool) {
		super(pool);
		super.setURIComparator(new ConsumerServiceURLComparator());
	}
	
	public class ConsumerServiceURLComparator extends BasicURLComparator {
		
		/*
		 * (non-Javadoc)
		 * @see org.opensaml.common.binding.decoding.BasicURLComparator#compare(java.lang.String, java.lang.String)
		 * 
		 * We do not wish to compare the protocol, https vs http.
		 * Should just ignore the protocol and make sure that the rest of the
		 * URL matches.
		 * 
		 * The intended message destination endpoint URL should always be HTTPS
		 * for the security reason. So will just replace the actual 
		 * message receiver endpoint URL's protocol to https
		 */
		@Override
		public boolean compare(String uri1, String uri2) {
			return super.compare(manipulateUri(uri1), manipulateUri(uri2));
		}
		
		/*
		 * Replace "http://" with "https://"
		 * if the URI contains "http://".
		 * Otherwise return the given url.
		 */
		private String manipulateUri(String url) {
			String returnStr = url;
			
			if (!StringUtils.isBlank(url)) {
				int i = url.indexOf("http://");
				if (i > -1) {
					
					returnStr = "https://"+ url.substring(i+7);
				}
			}
			
			return returnStr;
		}
	}

}
