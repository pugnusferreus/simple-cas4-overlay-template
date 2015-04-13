package au.edu.esa.passthrough.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Created by blim on 21/11/2014.
 */
@ResponseStatus(value = HttpStatus.NOT_FOUND)
public class NotFoundException extends Exception {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1455059127367454140L;
	
	private String fieldId;
	
	public NotFoundException(String fieldId, String msg) {
		super(msg);
		this.fieldId = fieldId;
	}


	public NotFoundException(String fieldId, String msg, Throwable t) {
		super(msg, t);
		this.fieldId = fieldId;
	}


	public String getFieldId() {
		return fieldId;
	}


	public void setFieldId(String fieldId) {
		this.fieldId = fieldId;
	}
	
}
