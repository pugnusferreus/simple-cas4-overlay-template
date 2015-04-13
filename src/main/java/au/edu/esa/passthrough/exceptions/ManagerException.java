package au.edu.esa.passthrough.exceptions;

/**
 * Created by blim on 24/11/2014.
 */
public class ManagerException extends Exception {

	public ManagerException(String msg) {
		super(msg);
	}

	public ManagerException(String msg, Throwable t) {
		super(msg, t);
	}
}
