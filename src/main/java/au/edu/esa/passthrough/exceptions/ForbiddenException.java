package au.edu.esa.passthrough.exceptions;


import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Created by blim on 10/12/2014.
 */
@ResponseStatus(value = HttpStatus.FORBIDDEN)
public class ForbiddenException extends Exception {
	public ForbiddenException(String msg) {
		super(msg);
	}


	public ForbiddenException(String msg, Throwable t) {
		super(msg, t);
	}
}
