package io.getarrays.authorizationserver.query;

public class UserQuery {
    public static final String  SELECT_USER_BY_USER_UUID_QUERY = "SELECT * FROM Users WHERE userUuid = :userUuid";
    public static final String SELECT_USER_BY_EMAIL_QUERY = "";
    public static final String RESET_LOGIN_ATTEMPTS_QUERY = "";
    public static final String UPDATE_LOGIN_ATTEMPTS_QUERY = "";
    public static final String SET_LAST_LOGIN_QUERY = "";
    public static final String INSERT_NEW_DEVICE_QUERY = "";
}
