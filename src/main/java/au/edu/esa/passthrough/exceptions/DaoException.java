package au.edu.esa.passthrough.exceptions;

/**
 * Created by blim on 24/11/2014.
 */
public class DaoException extends Exception {

	public DaoException(String msg) {
		super(msg);
	}

	public DaoException(String msg, Throwable t) {
		super(msg, t);
	}
}
