package au.edu.esa.passthrough.errors;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by blim on 8/12/2014.
 */
public class ErrorList {
	private List<Field> fieldErrors = new ArrayList<>();

	public ErrorList() {

	}

	public void addField(String path, String message) {
		Field error = new Field(path, message);
		fieldErrors.add(error);
	}

	public List<Field> getFieldErrors() {
		return fieldErrors;
	}

	public void setFieldErrors(List<Field> fieldErrors) {
		this.fieldErrors = fieldErrors;
	}
}

