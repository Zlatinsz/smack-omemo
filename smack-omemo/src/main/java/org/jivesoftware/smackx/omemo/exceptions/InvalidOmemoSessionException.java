package org.jivesoftware.smackx.omemo.exceptions;

/**
 * Created by Paul Schaub on 29.03.17.
 */
public class InvalidOmemoSessionException extends Exception {
    public InvalidOmemoSessionException(Exception e) {
        super(e);
    }
}
