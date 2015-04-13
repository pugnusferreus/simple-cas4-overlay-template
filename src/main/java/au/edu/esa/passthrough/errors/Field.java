package au.edu.esa.passthrough.errors;

import java.io.Serializable;

/**
 * Created by blim on 8/12/2014.
 */
public class Field implements Serializable {


	private String field;
	private String message;

	public Field(String field, String message) {
		this.field = field;
		this.message = message;
	}

	public String getField() {
		return field;
	}

	public void setField(String field) {
		this.field = field;
	}

	public String getMessage() {
		return message;
	}

	public void setMessage(String message) {
		this.message = message;
	}
}
