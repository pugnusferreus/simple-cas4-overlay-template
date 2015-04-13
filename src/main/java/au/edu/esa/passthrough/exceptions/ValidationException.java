package au.edu.esa.passthrough.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.ResponseStatus;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by blim on 8/12/2014.
 */
@ResponseStatus(value = HttpStatus.BAD_REQUEST)
public class ValidationException extends Exception {

	private static final long serialVersionUID = -9201671020371097688L;
	private List<FieldError> fieldErrors = null;

	public ValidationException(String msg) {
		this("", msg);
	}
	
	public ValidationException(String fieldId, String msg) {
		super(msg);
		fieldErrors = new ArrayList<FieldError>();
		fieldErrors.add(new FieldError("", fieldId, msg));
	}

	public ValidationException(String msg, Throwable t) {
		this("", msg, t);
	}
	
	public ValidationException(String fieldId, String msg, Throwable t) {
		super(msg, t);
		fieldErrors = new ArrayList<FieldError>();
		fieldErrors.add(new FieldError("", fieldId, msg));
	}

	public ValidationException(String msg, List<FieldError> fieldErrors) {
		super(msg);
		this.fieldErrors = fieldErrors;
	}

	public ValidationException(String msg, Throwable t, List<FieldError> fieldErrors) {
		super(msg, t);
		this.fieldErrors = fieldErrors;
	}

	public List<FieldError> getFieldErrors() {
		return fieldErrors;
	}
}
